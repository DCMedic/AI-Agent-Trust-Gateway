from trust_gateway.approvals import SQLiteApprovalLedger
from trust_gateway.capabilities import CapabilityError, CapabilityIssuer, CapabilityRevocationList


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
    assert claims.subject == "research-agent"

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
