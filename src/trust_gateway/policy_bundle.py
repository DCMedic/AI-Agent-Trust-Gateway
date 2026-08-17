from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any


class PolicyBundleError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass(frozen=True)
class PolicyProvenance:
    policy_id: str
    version: str
    key_id: str
    digest: str
    issued_at: datetime


class PolicyBundleVerifier:
    """Dependency-light signed policy bundle verifier using HMAC-SHA256.

    HMAC keeps the research implementation small. Production deployments should
    use asymmetric signatures or a KMS/HSM-backed signing service so verifiers do
    not possess policy-signing authority.
    """

    def __init__(self, keys: dict[str, bytes]):
        if not keys:
            raise ValueError("policy_keyring_empty")
        if any(len(value) < 32 for value in keys.values()):
            raise ValueError("policy_signing_key_too_short")
        self.keys = keys

    @staticmethod
    def canonical_payload(policy_id: str, version: str, issued_at: str, policy: dict[str, Any]) -> bytes:
        payload = {
            "policy_id": policy_id,
            "version": version,
            "issued_at": issued_at,
            "policy": policy,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def digest_payload(cls, policy_id: str, version: str, issued_at: str, policy: dict[str, Any]) -> str:
        return hashlib.sha256(cls.canonical_payload(policy_id, version, issued_at, policy)).hexdigest()

    @classmethod
    def sign(
        cls,
        *,
        policy: dict[str, Any],
        policy_id: str,
        version: str,
        key_id: str,
        secret: bytes,
        issued_at: datetime | None = None,
    ) -> dict[str, Any]:
        if len(secret) < 32:
            raise ValueError("policy_signing_key_too_short")
        issued = (issued_at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
        payload = cls.canonical_payload(policy_id, version, issued, policy)
        digest = hashlib.sha256(payload).hexdigest()
        signature = _b64(hmac.new(secret, payload, hashlib.sha256).digest())
        return {
            "schema": "aatg.policy-bundle.v1",
            "policy_id": policy_id,
            "version": version,
            "issued_at": issued,
            "key_id": key_id,
            "digest": digest,
            "signature": signature,
            "policy": policy,
        }

    def load(self, path: str | Path) -> tuple[dict[str, Any], PolicyProvenance]:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.verify(raw)

    def verify(self, bundle: dict[str, Any]) -> tuple[dict[str, Any], PolicyProvenance]:
        if bundle.get("schema") != "aatg.policy-bundle.v1":
            raise PolicyBundleError("unsupported_policy_bundle_schema")
        required = {"policy_id", "version", "issued_at", "key_id", "digest", "signature", "policy"}
        missing = required - set(bundle)
        if missing:
            raise PolicyBundleError(f"policy_bundle_missing:{','.join(sorted(missing))}")
        key_id = str(bundle["key_id"])
        secret = self.keys.get(key_id)
        if secret is None:
            raise PolicyBundleError("unknown_policy_signing_key")
        policy = bundle["policy"]
        if not isinstance(policy, dict):
            raise PolicyBundleError("invalid_policy_payload")
        payload = self.canonical_payload(
            str(bundle["policy_id"]),
            str(bundle["version"]),
            str(bundle["issued_at"]),
            policy,
        )
        digest = hashlib.sha256(payload).hexdigest()
        if not hmac.compare_digest(str(bundle["digest"]), digest):
            raise PolicyBundleError("policy_digest_mismatch")
        expected_signature = _b64(hmac.new(secret, payload, hashlib.sha256).digest())
        if not hmac.compare_digest(str(bundle["signature"]), expected_signature):
            raise PolicyBundleError("invalid_policy_signature")
        try:
            issued_at = datetime.fromisoformat(str(bundle["issued_at"]))
        except ValueError as exc:
            raise PolicyBundleError("invalid_policy_issued_at") from exc
        if issued_at.tzinfo is None:
            raise PolicyBundleError("policy_issued_at_timezone_required")
        if issued_at.astimezone(timezone.utc) > datetime.now(timezone.utc):
            raise PolicyBundleError("policy_bundle_from_future")
        provenance = PolicyProvenance(
            policy_id=str(bundle["policy_id"]),
            version=str(bundle["version"]),
            key_id=key_id,
            digest=digest,
            issued_at=issued_at.astimezone(timezone.utc),
        )
        return policy, provenance
