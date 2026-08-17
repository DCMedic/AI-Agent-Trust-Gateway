from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import RiskTier


class InformationFlowError(ValueError):
    pass


@dataclass(frozen=True)
class FlowDecision:
    allowed: bool
    reasons: tuple[str, ...]


class InformationFlowPolicy:
    """Conservative policy for moving untrusted evidence into agent actions.

    The reference rule intentionally separates *retrieving information* from
    *granting that information authority*. External MCP content may be displayed
    or analyzed, but suspicious/unverified content cannot directly parameterize
    medium- or high-risk effects without an explicit declassification step.
    """

    blocked_for_effects = frozenset(
        {
            "unverified_tool_output",
            "untrusted_mcp_content",
            "prompt_injection_suspected",
            "suspicious_tool_metadata",
            "external_tool_output",
        }
    )

    def evaluate(self, taints: Iterable[str], target_risk: RiskTier) -> FlowDecision:
        taint_set = set(taints)
        if target_risk == RiskTier.LOW:
            return FlowDecision(True, ("low_risk_observation_allowed",))
        blocked = sorted(taint_set & self.blocked_for_effects)
        if blocked:
            return FlowDecision(False, tuple(f"blocked_taint:{item}" for item in blocked))
        return FlowDecision(True, ("information_flow_authorized",))

    def require(self, taints: Iterable[str], target_risk: RiskTier) -> None:
        decision = self.evaluate(taints, target_risk)
        if not decision.allowed:
            raise InformationFlowError(",".join(decision.reasons))
