from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
from typing import Iterable


class DeclassificationError(ValueError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class DeclassificationGrant:
    grant_id: str
    evidence_digest: str
    removable_taints: tuple[str, ...]
    target_domain: str
    reviewer: str
    issued_at: datetime
    expires_at: datetime
    signature: str


class DeclassificationAuthority:
    """Reference authority for explicit human declassification of evidence.

    A grant removes only named taints, for one evidence digest and one target
    domain, for a bounded time. It never grants tool/action authorization.
    """

    def __init__(self, secret: bytes):
        if len(secret) < 32:
            raise ValueError("declassification_secret_too_short")
        self.secret = secret

    @staticmethod
    def evidence_digest(*, source: str, payload: object, taints: Iterable[str]) -> str:
        body = {"source": source, "payload": payload, "taints": sorted(set(taints))}
        return hashlib.sha256(_canonical(body)).hexdigest()

    def issue(
        self,
        *,
        evidence_digest: str,
        removable_taints: Iterable[str],
        target_domain: str,
        reviewer: str,
        ttl: timedelta = timedelta(minutes=10),
    ) -> DeclassificationGrant:
        reviewer = reviewer.strip()
        if not reviewer:
            raise DeclassificationError("reviewer_missing")
        allowed = tuple(sorted(set(removable_taints)))
        if not allowed:
            raise DeclassificationError("no_taints_selected")
        now = datetime.now(timezone.utc)
        expires_at = now + ttl
        grant_id = secrets.token_urlsafe(16)
        payload = {
            "grant_id": grant_id,
            "evidence_digest": evidence_digest,
            "removable_taints": allowed,
            "target_domain": target_domain,
            "reviewer": reviewer,
            "issued_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        signature = hmac.new(self.secret, _canonical(payload), hashlib.sha256).hexdigest()
        return DeclassificationGrant(
            grant_id=grant_id,
            evidence_digest=evidence_digest,
            removable_taints=allowed,
            target_domain=target_domain,
            reviewer=reviewer,
            issued_at=now,
            expires_at=expires_at,
            signature=signature,
        )

    def verify(
        self,
        grant: DeclassificationGrant,
        *,
        evidence_digest: str,
        target_domain: str,
        current_taints: Iterable[str],
    ) -> tuple[str, ...]:
        payload = {
            "grant_id": grant.grant_id,
            "evidence_digest": grant.evidence_digest,
            "removable_taints": grant.removable_taints,
            "target_domain": grant.target_domain,
            "reviewer": grant.reviewer,
            "issued_at": grant.issued_at.isoformat(),
            "expires_at": grant.expires_at.isoformat(),
        }
        expected = hmac.new(self.secret, _canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, grant.signature):
            raise DeclassificationError("invalid_declassification_signature")
        if grant.expires_at <= datetime.now(timezone.utc):
            raise DeclassificationError("declassification_expired")
        if grant.evidence_digest != evidence_digest:
            raise DeclassificationError("evidence_digest_mismatch")
        if grant.target_domain != target_domain:
            raise DeclassificationError("declassification_domain_mismatch")
        current = set(current_taints)
        removable = set(grant.removable_taints)
        if not removable <= current:
            raise DeclassificationError("declassification_taint_mismatch")
        return tuple(sorted(current - removable))
