from datetime import datetime, timedelta, timezone

from trust_gateway.audit import AuditJournal
from trust_gateway.capabilities import CapabilityIssuer
from trust_gateway.gateway import TrustGateway
from trust_gateway.models import ActionProposal, Approval
from trust_gateway.policy import PolicyEngine
from trust_gateway.risk import RiskBudget
from trust_gateway.tools import ToolRegistry


SECRET = b"risk-budget-test-secret-32-bytes-minimum!"


def test_cumulative_high_risk_authority_is_bounded(tmp_path):
    gateway = TrustGateway(
        policy=PolicyEngine("policies/default.json"),
        audit=AuditJournal(tmp_path / "audit.jsonl"),
        tools=ToolRegistry(),
        capabilities=CapabilityIssuer(SECRET),
        risk_budget=RiskBudget(limit=3),
    )

    first = ActionProposal(
        agent_id="operations-agent",
        tool="service",
        action="restart",
        arguments={"service": "demo-api"},
        purpose="first authorized recovery",
    )
    first_token = gateway.capabilities.issue(subject=first.agent_id, tool=first.tool, action=first.action)
    first_approval = Approval(
        proposal_digest=first.digest(),
        approver="human@example.test",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    assert gateway.execute(first, first_approval, first_token).status == "completed"

    second = ActionProposal(
        agent_id="operations-agent",
        tool="service",
        action="restart",
        arguments={"service": "demo-api"},
        purpose="second recovery inside same budget window",
    )
    second_token = gateway.capabilities.issue(subject=second.agent_id, tool=second.tool, action=second.action)
    second_approval = Approval(
        proposal_digest=second.digest(),
        approver="human@example.test",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    assert gateway.execute(second, second_approval, second_token).status == "risk_budget_exceeded"
    assert gateway.approvals.is_consumed(second_approval.approval_id) is False
