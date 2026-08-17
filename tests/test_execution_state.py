from trust_gateway.audit import AuditJournal
from trust_gateway.execution_state import SQLiteExecutionLedger
from trust_gateway.gateway import TrustGateway
from trust_gateway.models import ActionProposal
from trust_gateway.policy import PolicyEngine
from trust_gateway.tools import ToolRegistry


def _gateway(tmp_path):
    return TrustGateway(
        policy=PolicyEngine("policies/default.json"),
        audit=AuditJournal(tmp_path / "audit.jsonl"),
        tools=ToolRegistry(),
        executions=SQLiteExecutionLedger(tmp_path / "executions.db"),
    )


def test_completed_proposal_cannot_be_executed_twice(tmp_path):
    gateway = _gateway(tmp_path)
    proposal = ActionProposal(
        agent_id="research-agent",
        tool="notes",
        action="read",
        purpose="idempotency boundary test",
    )
    first = gateway.execute(proposal)
    second = gateway.execute(proposal)
    assert first.status == "completed"
    assert second.status == "execution_replay_blocked"


def test_reserved_after_crash_is_reported_in_doubt(tmp_path):
    gateway = _gateway(tmp_path)
    proposal = ActionProposal(
        agent_id="research-agent",
        tool="notes",
        action="read",
        purpose="simulate crash after authority reservation",
    )
    assert gateway.executions.reserve(proposal.proposal_id, proposal.digest()) is True
    result = gateway.execute(proposal)
    assert result.status == "execution_in_doubt"


def test_execution_terminal_state_survives_restart(tmp_path):
    database = tmp_path / "execution-state.db"
    first = SQLiteExecutionLedger(database)
    assert first.reserve("proposal-1", "digest-1") is True
    first.complete("proposal-1", "completed")

    restarted = SQLiteExecutionLedger(database)
    record = restarted.get("proposal-1")
    assert record is not None
    assert record.state == "terminal"
    assert record.terminal_status == "completed"
    assert restarted.reserve("proposal-1", "digest-1") is False
