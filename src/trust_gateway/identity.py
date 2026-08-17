from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets


class IdentityError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


@dataclass(frozen=True)
class IdentityClaims:
    subject: str
    audience: str
    key_id: str
    assertion_id: str
    issued_at: datetime
    expires_at: datetime


class WorkloadIdentity:
    """Reference signed workload assertions with key IDs and audience binding.

    HMAC is used here to keep the reference implementation dependency-light. Production
    deployments should prefer an external workload identity plane such as SPIFFE/SPIRE,
    OIDC workload identity, or mTLS certificates backed by managed PKI.
    """

    def __init__(self, keys: dict[str, bytes], audience: str = "ai-agent-trust-gateway"):
        if not keys:
            raise ValueError("identity_keyring_empty")
        if any(len(secret) < 32 for secret in keys.values()):
            raise ValueError("identity_secret_too_short")
        self.keys = keys
        self.audience = audience

    def issue(self, *, subject: str, key_id: str, ttl: timedelta = timedelta(minutes=2)) -> str:
        secret = self.keys.get(key_id)
        if secret is None:
            raise IdentityError("unknown_identity_key")
        now = datetime.now(timezone.utc)
        payload = {
            "sub": subject,
            "aud": self.audience,
            "kid": key_id,
            "jti": secrets.token_urlsafe(16),
            "iat": int(now.timestamp()),
            "exp": int((now + ttl).timestamp()),
        }
        body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        signature = _b64(hmac.new(secret, body.encode(), hashlib.sha256).digest())
        return f"{body}.{signature}"

    def verify(self, token: str, *, expected_subject: str) -> IdentityClaims:
        try:
            body, signature = token.split(".", 1)
            payload = json.loads(_unb64(body))
        except Exception as exc:
            raise IdentityError("malformed_identity_assertion") from exc
        key_id = payload.get("kid")
        secret = self.keys.get(key_id)
        if secret is None:
            raise IdentityError("unknown_identity_key")
        expected = _b64(hmac.new(secret, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise IdentityError("invalid_identity_signature")
        if payload.get("aud") != self.audience:
            raise IdentityError("identity_audience_mismatch")
        if payload.get("sub") != expected_subject:
            raise IdentityError("identity_subject_mismatch")
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        issued_at = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        if expires_at <= now:
            raise IdentityError("identity_assertion_expired")
        if issued_at > now + timedelta(seconds=30):
            raise IdentityError("identity_assertion_from_future")
        return IdentityClaims(
            subject=payload["sub"],
            audience=payload["aud"],
            key_id=key_id,
            assertion_id=payload["jti"],
            issued_at=issued_at,
            expires_at=expires_at,
        )
