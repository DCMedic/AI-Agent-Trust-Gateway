from datetime import datetime, timedelta, timezone

from trust_gateway.audit import AuditJournal
from trust_gateway.capabilities import CapabilityIssuer
from trust_gateway.gateway import TrustGateway
from trust_gateway.models import ActionProposal, Approval, Decision
from trust_gateway.policy import PolicyEngine
from trust_gateway.tools import ToolRegistry


SECRET = b"test-capability-secret-32-bytes-minimum!!"


def make_gateway(tmp_path):
    return TrustGateway(
        policy=PolicyEngine("policies/default.json"),
        audit=AuditJournal(tmp_path / "audit.jsonl"),
        tools=ToolRegistry(),
        capabilities=CapabilityIssuer(SECRET),
    )


def capability(gateway, proposal, constraints=None):
    return gateway.capabilities.issue(
        subject=proposal.agent_id,
        tool=proposal.tool,
        action=proposal.action,
        constraints=constraints,
    )


def service_proposal():
    return ActionProposal(
        agent_id="operations-agent",
        tool="service",
        action="restart",
        arguments={"service": "demo-api"},
        purpose="recover service",
    )


def approval_for(proposal):
    return Approval(
        proposal_digest=proposal.digest(),
        approver="human@example.test",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
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


def test_medium_risk_action_requires_capability(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = ActionProposal(
        agent_id="research-agent",
        tool="notes",
        action="append",
        arguments={"text": "finding"},
        purpose="store finding",
    )
    assert gateway.execute(proposal).status == "capability_required"


def test_capability_is_subject_and_scope_bound(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = ActionProposal(
        agent_id="research-agent",
        tool="notes",
        action="append",
        arguments={"text": "finding"},
        purpose="store finding",
    )
    wrong_scope = gateway.capabilities.issue(subject="research-agent", tool="notes", action="read")
    assert gateway.execute(proposal, capability_token=wrong_scope).status == "capability_rejected"


def test_capability_argument_expansion_is_rejected(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = ActionProposal(
        agent_id="research-agent",
        tool="notes",
        action="append",
        arguments={"text": "finding"},
        purpose="store finding",
    )
    token = capability(gateway, proposal, constraints={"allowed_keys": []})
    assert gateway.execute(proposal, capability_token=token).status == "capability_rejected"


def test_high_risk_action_requires_human_approval_after_capability(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = service_proposal()
    token = capability(
        gateway,
        proposal,
        constraints={"allowed_keys": ["service"], "allowed_values": {"service": ["demo-api"]}},
    )
    result = gateway.execute(proposal, capability_token=token)
    assert result.status == "approval_required"


def test_approval_is_bound_to_exact_proposal(tmp_path):
    gateway = make_gateway(tmp_path)
    original = service_proposal()
    approval = approval_for(original)
    modified = original.model_copy(update={"purpose": "different purpose"})
    token = capability(gateway, modified)
    assert gateway.execute(modified, approval, token).status == "approval_rejected"


def test_expired_approval_is_rejected(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = service_proposal()
    approval = Approval(
        proposal_digest=proposal.digest(),
        approver="human@example.test",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    token = capability(gateway, proposal)
    assert gateway.execute(proposal, approval, token).status == "approval_rejected"


def test_approval_is_single_use_and_replay_is_blocked(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = service_proposal()
    approval = approval_for(proposal)
    token = capability(gateway, proposal)
    first = gateway.execute(proposal, approval, token)
    second = gateway.execute(proposal, approval, token)
    assert first.status == "completed"
    assert second.status == "approval_rejected"


def test_approved_high_risk_action_executes_and_verifies(tmp_path):
    gateway = make_gateway(tmp_path)
    proposal = service_proposal()
    approval = approval_for(proposal)
    token = capability(gateway, proposal)
    result = gateway.execute(proposal, approval, token)
    assert result.status == "completed"
    assert result.verified is True
    assert result.capability_id is not None
    assert "unverified_tool_output" not in result.output_taints
    assert "simulated_effect" in result.output_taints


def test_read_output_retains_content_taint_after_verification(tmp_path):
    gateway = make_gateway(tmp_path)
    gateway.tools.notes.append("untrusted text")
    proposal = ActionProposal(agent_id="research-agent", tool="notes", action="read", purpose="read notes")
    result = gateway.execute(proposal)
    assert result.status == "completed"
    assert result.verified is True
    assert "stored_user_content" in result.output_taints


def test_tool_failure_does_not_become_success(tmp_path):
    gateway = make_gateway(tmp_path)
    gateway.tools.fail_next = True
    proposal = ActionProposal(agent_id="research-agent", tool="notes", action="read", purpose="test failure")
    assert gateway.execute(proposal).status == "failed"
