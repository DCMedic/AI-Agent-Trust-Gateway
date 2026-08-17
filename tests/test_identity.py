from datetime import timedelta

import pytest

from trust_gateway.audit import AuditJournal
from trust_gateway.gateway import TrustGateway
from trust_gateway.identity import IdentityError, WorkloadIdentity
from trust_gateway.models import ActionProposal
from trust_gateway.policy import PolicyEngine
from trust_gateway.tools import ToolRegistry


KEYS = {"dev-key": b"workload-identity-test-secret-32-bytes!!"}


def make_gateway(tmp_path):
    identities = WorkloadIdentity(KEYS)
    gateway = TrustGateway(
        policy=PolicyEngine("policies/default.json"),
        audit=AuditJournal(tmp_path / "audit.jsonl"),
        tools=ToolRegistry(),
        identities=identities,
    )
    return gateway, identities


def test_identity_is_required_when_identity_plane_is_configured(tmp_path):
    gateway, _ = make_gateway(tmp_path)
    proposal = ActionProposal(agent_id="research-agent", tool="notes", action="read", purpose="read")
    assert gateway.execute(proposal).status == "identity_required"


def test_identity_subject_must_match_proposal_agent(tmp_path):
    gateway, identities = make_gateway(tmp_path)
    proposal = ActionProposal(agent_id="research-agent", tool="notes", action="read", purpose="read")
    token = identities.issue(subject="operations-agent", key_id="dev-key")
    assert gateway.execute(proposal, identity_token=token).status == "identity_rejected"


def test_valid_identity_allows_policy_evaluation_and_execution(tmp_path):
    gateway, identities = make_gateway(tmp_path)
    proposal = ActionProposal(agent_id="research-agent", tool="notes", action="read", purpose="read")
    token = identities.issue(subject="research-agent", key_id="dev-key")
    result = gateway.execute(proposal, identity_token=token)
    assert result.status == "completed"
    assert result.identity_assertion_id is not None


def test_tampered_identity_assertion_is_rejected():
    identities = WorkloadIdentity(KEYS)
    token = identities.issue(subject="research-agent", key_id="dev-key")
    body, signature = token.split(".", 1)
    with pytest.raises(IdentityError):
        identities.verify(f"{body}x.{signature}", expected_subject="research-agent")


def test_expired_identity_assertion_is_rejected():
    identities = WorkloadIdentity(KEYS)
    token = identities.issue(subject="research-agent", key_id="dev-key", ttl=timedelta(seconds=-1))
    with pytest.raises(IdentityError, match="identity_assertion_expired"):
        identities.verify(token, expected_subject="research-agent")
