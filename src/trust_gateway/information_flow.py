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
    """Conservative information-flow policy for agent evidence.

    Low-risk observation is allowed. Medium/high-risk effects fail closed when
    evidence remains unverified/untrusted, or when evidence crosses trust domains
    carrying provenance that has not been explicitly declassified.
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

    def evaluate(
        self,
        taints: Iterable[str],
        target_risk: RiskTier,
        *,
        source_domains: Iterable[str] = (),
        target_domain: str = "local",
    ) -> FlowDecision:
        taint_set = set(taints)
        domains = {domain for domain in source_domains if domain}
        if target_risk == RiskTier.LOW:
            return FlowDecision(True, ("low_risk_observation_allowed",))

        reasons: list[str] = []
        blocked = sorted(taint_set & self.blocked_for_effects)
        reasons.extend(f"blocked_taint:{item}" for item in blocked)

        foreign = sorted(domain for domain in domains if domain != target_domain)
        if foreign and taint_set:
            reasons.extend(f"cross_domain_evidence:{domain}->{target_domain}" for domain in foreign)

        if reasons:
            return FlowDecision(False, tuple(reasons))
        return FlowDecision(True, ("information_flow_authorized",))

    def require(
        self,
        taints: Iterable[str],
        target_risk: RiskTier,
        *,
        source_domains: Iterable[str] = (),
        target_domain: str = "local",
    ) -> None:
        decision = self.evaluate(
            taints,
            target_risk,
            source_domains=source_domains,
            target_domain=target_domain,
        )
        if not decision.allowed:
            raise InformationFlowError(",".join(decision.reasons))
