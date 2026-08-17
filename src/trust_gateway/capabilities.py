from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
from typing import Any


class CapabilityError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


@dataclass(frozen=True)
class CapabilityClaims:
    jti: str
    subject: str
    audience: str
    tool: str
    action: str
    constraints: dict[str, Any]
    issued_at: datetime
    expires_at: datetime


class CapabilityIssuer:
    """Minimal HMAC capability tokens for constraining delegated agent authority."""

    def __init__(self, secret: bytes, audience: str = "ai-agent-trust-gateway"):
        if len(secret) < 32:
            raise ValueError("capability_secret_too_short")
        self.secret = secret
        self.audience = audience

    def issue(
        self,
        *,
        subject: str,
        tool: str,
        action: str,
        constraints: dict[str, Any] | None = None,
        ttl: timedelta = timedelta(minutes=5),
    ) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "jti": secrets.token_urlsafe(16),
            "sub": subject,
            "aud": self.audience,
            "tool": tool,
            "action": action,
            "constraints": constraints or {},
            "iat": int(now.timestamp()),
            "exp": int((now + ttl).timestamp()),
        }
        body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        signature = _b64(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())
        return f"{body}.{signature}"

    def verify(self, token: str) -> CapabilityClaims:
        try:
            body, signature = token.split(".", 1)
        except ValueError as exc:
            raise CapabilityError("malformed_capability") from exc
        expected = _b64(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise CapabilityError("invalid_capability_signature")
        try:
            payload = json.loads(_unb64(body))
        except Exception as exc:
            raise CapabilityError("invalid_capability_payload") from exc
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        issued_at = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        if payload.get("aud") != self.audience:
            raise CapabilityError("capability_audience_mismatch")
        if expires_at <= now:
            raise CapabilityError("capability_expired")
        return CapabilityClaims(
            jti=payload["jti"],
            subject=payload["sub"],
            audience=payload["aud"],
            tool=payload["tool"],
            action=payload["action"],
            constraints=payload.get("constraints", {}),
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def authorize(self, token: str, *, subject: str, tool: str, action: str, arguments: dict[str, Any]) -> CapabilityClaims:
        claims = self.verify(token)
        if claims.subject != subject:
            raise CapabilityError("capability_subject_mismatch")
        if claims.tool != tool or claims.action != action:
            raise CapabilityError("capability_scope_mismatch")
        allowed_values = claims.constraints.get("allowed_values", {})
        for key, values in allowed_values.items():
            if arguments.get(key) not in values:
                raise CapabilityError(f"capability_constraint_violation:{key}")
        allowed_keys = claims.constraints.get("allowed_keys")
        if allowed_keys is not None and set(arguments) - set(allowed_keys):
            raise CapabilityError("capability_argument_expansion")
        return claims
