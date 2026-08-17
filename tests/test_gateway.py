from datetime import datetime, timedelta, timezone

from trust_gateway.audit import AuditJournal
from trust_gateway.gateway import TrustGateway
from trust_gateway.models import ActionProposal, Approval, Decision
from trust_gateway.policy import PolicyEngine
from trust_gateway.tools import ToolRegistry


def make_gateway(tmp_path):
    return TrustGateway(
        policy=PolicyEngine("policies/default.json"),
        audit=AuditJournal(tmp_path / "audit.jsonl"),
        tools=ToolRegistry(),
    )


def test_unknown_agent_is_denied(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = ActionProposal(agent_id="intruder", tool="notes", action="read", purpose="test")
    decision = gateway.evaluate(proposal)
    assert decision.decision == Decision.DENY
    assert "unknown_agent" in decision.reasons


def test_research_agent_cannot_restart_service(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = ActionProposal(
        agent_id="research-agent",
        tool="service",
        action="restart",
        arguments={"service": "demo-api"},
        purpose="test privilege boundary",
    )
    assert gateway.execute(proposal).status == "denied"


def test_argument_constraints_fail_closed(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = ActionProposal(
        agent_id="research-agent",
        tool="notes",
        action="append",
        arguments={"text": "ok", "path": "/etc/passwd"},
        purpose="attempt parameter smuggling",
    )
    assert gateway.execute(proposal).status == "denied"


def test_high_risk_action_requires_human_approval(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = ActionProposal(
        agent_id="operations-agent",
        tool="service",
        action="restart",
        arguments={"service": "demo-api"},
        purpose="recover service",
    )
    result = gateway.execute(proposal)
    assert result.status == "approval_required"


def test_approval_is_bound_to_exact_proposal(tmp_path):
    gateway = make_gateway(tmp_path)
    original = ActionProposal(
        agent_id="operations-agent",
        tool="service",
        action="restart",
        arguments={"service": "demo-api"},
        purpose="recover service",
    )
    approval = Approval(
        proposal_digest=original.digest(),
        approver="human@example.test",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    modified = original.model_copy(update={"purpose": "different purpose"})
    assert gateway.execute(modified, approval).status == "approval_rejected"


def test_expired_approval_is_rejected(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = ActionProposal(
        agent_id="operations-agent",
        tool="service",
        action="restart",
        arguments={"service": "demo-api"},
        purpose="recover service",
    )
    approval = Approval(
        proposal_digest=proposal.digest(),
        approver="human@example.test",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    assert gateway.execute(proposal, approval).status == "approval_rejected"


def test_approved_high_risk_action_executes_and_verifies(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = ActionProposal(
        agent_id="operations-agent",
        tool="service",
        action="restart",
        arguments={"service": "demo-api"},
        purpose="recover service",
    )
    approval = Approval(
        proposal_digest=proposal.digest(),
        approver="human@example.test",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    result = gateway.execute(proposal, approval)
    assert result.status == "completed"
    assert result.verified is True


def test_tool_failure_does_not_become_success(tmp_path):
    gateway = make_gateway(tmp_path)
    gateway.tools.fail_next = True
    proposal = ActionProposal(agent_id="research-agent", tool="notes", action="read", purpose="test failure")
    assert gateway.execute(proposal).status == "failed"
