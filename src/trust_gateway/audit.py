from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    event_type: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str


class AuditJournal:
    GENESIS = "0" * 64

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event_type: str, payload: dict[str, Any]) -> AuditEvent:
        previous_hash = self._last_hash()
        timestamp = datetime.now(timezone.utc).isoformat()
        body = {
            "timestamp": timestamp,
            "event_type": event_type,
            "payload": payload,
            "previous_hash": previous_hash,
        }
        event_hash = sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
        event = AuditEvent(event_hash=event_hash, **body)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event), sort_keys=True, default=str) + "\n")
        return event

    def verify(self) -> bool:
        previous_hash = self.GENESIS
        if not self.path.exists():
            return True
        for line in self.path.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            if record["previous_hash"] != previous_hash:
                return False
            body = {
                "timestamp": record["timestamp"],
                "event_type": record["event_type"],
                "payload": record["payload"],
                "previous_hash": record["previous_hash"],
            }
            expected = sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
            ).hexdigest()
            if expected != record["event_hash"]:
                return False
            previous_hash = record["event_hash"]
        return True

    def _last_hash(self) -> str:
        if not self.path.exists():
            return self.GENESIS
        lines = self.path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return self.GENESIS
        return json.loads(lines[-1])["event_hash"]
