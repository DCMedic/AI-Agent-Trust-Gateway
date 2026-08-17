from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Protocol


class ExecutionStateStore(Protocol):
    def reserve(self, proposal_id: str, proposal_digest: str) -> bool: ...
    def complete(self, proposal_id: str, status: str) -> None: ...
    def state(self, proposal_id: str) -> str | None: ...


@dataclass(frozen=True)
class ExecutionRecord:
    proposal_id: str
    proposal_digest: str
    state: str
    terminal_status: str | None


class SQLiteExecutionLedger:
    """Durable fail-safe execution state for external side effects.

    `reserve` is atomic. Once a proposal reaches RESERVED, a process crash leaves
    durable evidence that authority may already have been consumed. The gateway
    refuses automatic replay; an operator must reconcile the external state and
    deliberately create a new proposal if another attempt is appropriate.
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
                CREATE TABLE IF NOT EXISTS executions (
                    proposal_id TEXT PRIMARY KEY,
                    proposal_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    terminal_status TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def reserve(self, proposal_id: str, proposal_digest: str) -> bool:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO executions (proposal_id, proposal_digest, state) VALUES (?, ?, 'reserved')",
                    (proposal_id, proposal_digest),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def complete(self, proposal_id: str, status: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE executions
                SET state = 'terminal', terminal_status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE proposal_id = ?
                """,
                (status, proposal_id),
            )
            if cursor.rowcount != 1:
                raise KeyError("unknown_execution_reservation")

    def state(self, proposal_id: str) -> str | None:
        record = self.get(proposal_id)
        return record.state if record else None

    def get(self, proposal_id: str) -> ExecutionRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT proposal_id, proposal_digest, state, terminal_status FROM executions WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
        if row is None:
            return None
        return ExecutionRecord(
            proposal_id=row[0],
            proposal_digest=row[1],
            state=row[2],
            terminal_status=row[3],
        )
