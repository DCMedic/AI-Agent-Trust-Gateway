from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ApprovalLedger:
    """In-memory single-use approval ledger for the reference implementation."""

    consumed_ids: set[str] = field(default_factory=set)

    def is_consumed(self, approval_id: str) -> bool:
        return approval_id in self.consumed_ids

    def consume(self, approval_id: str) -> bool:
        if approval_id in self.consumed_ids:
            return False
        self.consumed_ids.add(approval_id)
        return True
