from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlparse


class RemoteTrustError(ValueError):
    pass


@dataclass(frozen=True)
class RemoteEndpointPolicy:
    endpoint: str
    trust_domain: str
    expected_server_id: str
    require_https: bool = True
    bearer_token: str | None = None
    tls_certificate_sha256: str | None = None

    def validate_endpoint(self) -> None:
        parsed = urlparse(self.endpoint)
        if parsed.scheme not in {"http", "https"}:
            raise RemoteTrustError("unsupported_remote_scheme")
        if self.require_https and parsed.scheme != "https":
            raise RemoteTrustError("https_required")
        if not parsed.hostname:
            raise RemoteTrustError("remote_hostname_missing")

    def authorization_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.bearer_token}"} if self.bearer_token else {}


def certificate_fingerprint(certificate_der: bytes) -> str:
    return sha256(certificate_der).hexdigest()


def require_certificate_pin(actual_der: bytes, expected_sha256: str | None) -> None:
    if expected_sha256 is None:
        return
    actual = certificate_fingerprint(actual_der)
    if actual.lower() != expected_sha256.lower():
        raise RemoteTrustError("tls_certificate_pin_mismatch")
