from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .models import RiskTier


RISK_COST = {
    RiskTier.LOW: 0,
    RiskTier.MEDIUM: 1,
    RiskTier.HIGH: 3,
}


@dataclass
class RiskEvent:
    timestamp: datetime
    cost: int


@dataclass
class RiskBudget:
    """Sliding-window authority budget for limiting cumulative agent impact."""

    limit: int = 5
    window: timedelta = timedelta(minutes=10)
    events: dict[str, list[RiskEvent]] = field(default_factory=dict)

    def _active(self, agent_id: str) -> list[RiskEvent]:
        cutoff = datetime.now(timezone.utc) - self.window
        active = [event for event in self.events.get(agent_id, []) if event.timestamp > cutoff]
        self.events[agent_id] = active
        return active

    def used(self, agent_id: str) -> int:
        return sum(event.cost for event in self._active(agent_id))

    def remaining(self, agent_id: str) -> int:
        return max(0, self.limit - self.used(agent_id))

    def can_consume(self, agent_id: str, risk: RiskTier) -> bool:
        return self.used(agent_id) + RISK_COST[risk] <= self.limit

    def consume(self, agent_id: str, risk: RiskTier) -> bool:
        cost = RISK_COST[risk]
        if not self.can_consume(agent_id, risk):
            return False
        if cost:
            self.events.setdefault(agent_id, []).append(
                RiskEvent(timestamp=datetime.now(timezone.utc), cost=cost)
            )
        return True
