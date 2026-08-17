import json

import pytest

from trust_gateway.models import ActionProposal, Decision
from trust_gateway.policy import PolicyEngine
from trust_gateway.policy_bundle import PolicyBundleError, PolicyBundleVerifier


KEY = b"policy-signing-test-key-at-least-32-bytes"


def _policy():
    return {
        "agents": {
            "research-agent": {
                "tools": {
                    "notes": {
                        "read": {
                            "risk": "low",
                            "requires_approval": False,
                            "constraints": {"allowed_keys": []},
                        }
                    }
                }
            }
        }
    }


def _write_bundle(tmp_path):
    bundle = PolicyBundleVerifier.sign(
        policy=_policy(),
        policy_id="aatg-default",
        version="3.0.0",
        key_id="policy-test-1",
        secret=KEY,
    )
    path = tmp_path / "signed-policy.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path, bundle


def test_signed_policy_decision_carries_verified_provenance(tmp_path):
    path, bundle = _write_bundle(tmp_path)
    engine = PolicyEngine(
        path,
        verifier=PolicyBundleVerifier({"policy-test-1": KEY}),
        require_signed_bundle=True,
    )
    decision = engine.evaluate(
        ActionProposal(agent_id="research-agent", tool="notes", action="read", purpose="test")
    )
    assert decision.decision == Decision.ALLOW
    assert decision.policy_id == "aatg-default"
    assert decision.policy_version == "3.0.0"
    assert decision.policy_key_id == "policy-test-1"
    assert decision.policy_digest == bundle["digest"]


def test_tampered_signed_policy_is_rejected(tmp_path):
    path, bundle = _write_bundle(tmp_path)
    bundle["policy"]["agents"]["research-agent"]["tools"]["notes"]["read"]["risk"] = "high"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    with pytest.raises(PolicyBundleError):
        PolicyEngine(path, verifier=PolicyBundleVerifier({"policy-test-1": KEY}), require_signed_bundle=True)


def test_unsigned_policy_fails_when_signed_bundle_required(tmp_path):
    path = tmp_path / "unsigned.json"
    path.write_text(json.dumps(_policy()), encoding="utf-8")
    with pytest.raises(ValueError, match="signed_policy_bundle_required"):
        PolicyEngine(path, verifier=PolicyBundleVerifier({"policy-test-1": KEY}), require_signed_bundle=True)
