from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Protocol


class ApprovalStore(Protocol):
    """Storage contract for atomic single-use approval consumption."""

    def is_consumed(self, approval_id: str) -> bool: ...

    def consume(self, approval_id: str) -> bool: ...


@dataclass
class ApprovalLedger:
    """In-memory single-use approval ledger for tests and single-process demos."""

    consumed_ids: set[str] = field(default_factory=set)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def is_consumed(self, approval_id: str) -> bool:
        with self._lock:
            return approval_id in self.consumed_ids

    def consume(self, approval_id: str) -> bool:
        with self._lock:
            if approval_id in self.consumed_ids:
                return False
            self.consumed_ids.add(approval_id)
            return True


class SQLiteApprovalLedger:
    """Durable approval replay protection backed by an atomic SQLite insert.

    The database can survive gateway restarts. A UNIQUE primary key makes two
    competing consumers race safely: only one can commit a given approval ID.
    Production multi-node deployments should use a strongly consistent shared
    datastore with equivalent uniqueness semantics.
    """

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_approvals (
                    approval_id TEXT PRIMARY KEY,
                    consumed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def is_consumed(self, approval_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM consumed_approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        return row is not None

    def consume(self, approval_id: str) -> bool:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO consumed_approvals (approval_id) VALUES (?)",
                    (approval_id,),
                )
            return True
        except sqlite3.IntegrityError:
            return False
