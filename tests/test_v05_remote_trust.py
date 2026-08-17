from datetime import timedelta

from trust_gateway.declassification import DeclassificationAuthority, DeclassificationError
from trust_gateway.information_flow import InformationFlowPolicy
from trust_gateway.models import ActionProposal, EvidenceClaim, RiskTier
from trust_gateway.policy import PolicyEngine
from trust_gateway.remote_trust import RemoteEndpointPolicy, RemoteTrustError


SECRET = b"declassification-secret-at-least-32-bytes"


def test_remote_endpoint_requires_https_by_default():
    policy = RemoteEndpointPolicy(endpoint="http://remote.example/mcp", trust_domain="external", expected_server_id="remote")
    try:
        policy.validate_endpoint()
    except RemoteTrustError as exc:
        assert str(exc) == "https_required"
    else:
        raise AssertionError("insecure remote MCP endpoint accepted")


def test_bearer_authorization_header_is_explicit():
    policy = RemoteEndpointPolicy(
        endpoint="https://remote.example/mcp",
        trust_domain="research",
        expected_server_id="remote",
        bearer_token="token-123",
    )
    policy.validate_endpoint()
    assert policy.authorization_headers() == {"Authorization": "Bearer token-123"}


def test_cross_domain_tainted_evidence_is_blocked_for_effects():
    flow = InformationFlowPolicy()
    decision = flow.evaluate(
        ["external_tool_output"],
        RiskTier.HIGH,
        source_domains=["research"],
        target_domain="operations",
    )
    assert decision.allowed is False
    assert "cross_domain_evidence:research->operations" in decision.reasons


def test_declassification_is_digest_and_domain_bound():
    authority = DeclassificationAuthority(SECRET)
    taints = ["external_tool_output", "unverified_tool_output"]
    digest = authority.evidence_digest(source="mcp://research/record", payload={"status": "nominal"}, taints=taints)
    grant = authority.issue(
        evidence_digest=digest,
        removable_taints=taints,
        target_domain="operations",
        reviewer="reviewer@example.test",
    )
    assert authority.verify(grant, evidence_digest=digest, target_domain="operations", current_taints=taints) == ()
    try:
        authority.verify(grant, evidence_digest=digest, target_domain="finance", current_taints=taints)
    except DeclassificationError as exc:
        assert str(exc) == "declassification_domain_mismatch"
    else:
        raise AssertionError("cross-domain declassification replay accepted")


def test_expired_declassification_fails_closed():
    authority = DeclassificationAuthority(SECRET)
    digest = authority.evidence_digest(source="x", payload={"x": 1}, taints=["external_tool_output"])
    grant = authority.issue(
        evidence_digest=digest,
        removable_taints=["external_tool_output"],
        target_domain="operations",
        reviewer="reviewer@example.test",
        ttl=timedelta(seconds=-1),
    )
    try:
        authority.verify(grant, evidence_digest=digest, target_domain="operations", current_taints=["external_tool_output"])
    except DeclassificationError as exc:
        assert str(exc) == "declassification_expired"
    else:
        raise AssertionError("expired declassification accepted")


def test_proposal_provenance_affects_policy_decision():
    proposal = ActionProposal(
        agent_id="operations-agent",
        tool="service",
        action="restart",
        arguments={"service": "demo-api"},
        purpose="act on research MCP evidence",
        evidence=[EvidenceClaim(
            source="mcp://research/recommendation",
            trust_domain="research",
            payload_digest="abc123",
            taints=["external_tool_output"],
        )],
        target_trust_domain="operations",
    )
    decision = PolicyEngine("policies/default.json").evaluate(proposal)
    assert decision.decision.value == "deny"
    assert any(reason.startswith("cross_domain_evidence:") for reason in decision.reasons)
