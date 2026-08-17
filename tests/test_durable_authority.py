from datetime import datetime, timedelta, timezone

from trust_gateway.approvals import SQLiteApprovalLedger
from trust_gateway.audit import AuditJournal
from trust_gateway.capabilities import CapabilityError, CapabilityIssuer, CapabilityRevocationList
from trust_gateway.gateway import TrustGateway
from trust_gateway.models import ActionProposal, Approval, ApprovalSet
from trust_gateway.policy import PolicyEngine
from trust_gateway.tools import ToolRegistry


SECRET = b"durable-authority-secret-32-bytes-minimum"


def test_sqlite_approval_replay_protection_survives_restart(tmp_path):
    database = tmp_path / "authority.db"
    first_process = SQLiteApprovalLedger(database)
    assert first_process.consume("approval-123") is True
    restarted_process = SQLiteApprovalLedger(database)
    assert restarted_process.is_consumed("approval-123") is True
    assert restarted_process.consume("approval-123") is False


def test_capability_can_be_revoked_before_expiration():
    revocations = CapabilityRevocationList()
    issuer = CapabilityIssuer(SECRET, revocations=revocations)
    token = issuer.issue(subject="research-agent", tool="notes", action="append")
    claims = issuer.verify(token)
    revoked_id = issuer.revoke(token)
    assert revoked_id == claims.jti
    try:
        issuer.verify(token)
    except CapabilityError as exc:
        assert str(exc) == "capability_revoked"
    else:
        raise AssertionError("revoked capability was accepted")


def test_revocation_does_not_allow_tampered_token_to_name_arbitrary_id():
    revocations = CapabilityRevocationList()
    issuer = CapabilityIssuer(SECRET, revocations=revocations)
    token = issuer.issue(subject="research-agent", tool="notes", action="append")
    body, signature = token.split(".", 1)
    tampered = f"{body[:-1]}A.{signature}"
    try:
        issuer.revoke(tampered)
    except CapabilityError:
        pass
    else:
        raise AssertionError("tampered capability was accepted for revocation")


def _dual_control_gateway(tmp_path):
    return TrustGateway(
        policy=PolicyEngine("policies/default.json"),
        audit=AuditJournal(tmp_path / "dual-control-audit.jsonl"),
        tools=ToolRegistry(),
        capabilities=CapabilityIssuer(SECRET),
        approvals=SQLiteApprovalLedger(tmp_path / "approvals.db"),
        high_risk_approval_quorum=2,
    )


def _service_proposal():
    return ActionProposal(
        agent_id="operations-agent",
        tool="service",
        action="restart",
        arguments={"service": "demo-api"},
        purpose="dual-control recovery test",
    )


def _approval(proposal, approver):
    return Approval(
        proposal_digest=proposal.digest(),
        approver=approver,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )


def test_dual_control_requires_two_independent_approvers(tmp_path):
    gateway = _dual_control_gateway(tmp_path)
    proposal = _service_proposal()
    token = gateway.capabilities.issue(subject=proposal.agent_id, tool=proposal.tool, action=proposal.action)
    one = _approval(proposal, "operator-a@example.test")
    assert gateway.execute(proposal, one, token).status == "approval_required"
    duplicate_people = ApprovalSet(approvals=[
        _approval(proposal, "operator-a@example.test"),
        _approval(proposal, "operator-a@example.test"),
    ])
    assert gateway.execute(proposal, duplicate_people, token).status == "approval_rejected"
    independent = ApprovalSet(approvals=[
        _approval(proposal, "operator-a@example.test"),
        _approval(proposal, "operator-b@example.test"),
    ])
    assert gateway.execute(proposal, independent, token).status == "completed"
