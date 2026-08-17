from __future__ import annotations

from dataclasses import dataclass

from .models import ActionProposal, RiskTier


@dataclass(frozen=True)
class InformationFlowDecision:
    allowed: bool
    reasons: tuple[str, ...] = ()


class InformationFlowGuard:
    """Prevent untrusted tool evidence from directly authorizing consequential actions."""

    high_impact_blocked_taints = frozenset({
        "external_tool_output",
        "unverified_tool_output",
        "prompt_injection_suspected",
        "suspicious_tool_metadata",
        "stored_user_content",
    })

    medium_impact_blocked_taints = frozenset({
        "prompt_injection_suspected",
        "suspicious_tool_metadata",
    })

    def evaluate(self, proposal: ActionProposal, risk: RiskTier) -> InformationFlowDecision:
        taints = set(proposal.evidence_taints)
        if not taints:
            return InformationFlowDecision(True)
        blocked = self.high_impact_blocked_taints if risk == RiskTier.HIGH else self.medium_impact_blocked_taints
        violations = sorted(taints & blocked)
        if violations:
            return InformationFlowDecision(
                False,
                tuple(f"tainted_evidence_blocked:{taint}" for taint in violations),
            )
        return InformationFlowDecision(True)
