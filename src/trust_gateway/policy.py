from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ActionProposal, Decision, PolicyDecision, RiskTier


class PolicyEngine:
    def __init__(self, policy_path: str | Path):
        self.policy_path = Path(policy_path)
        self.policy = json.loads(self.policy_path.read_text(encoding="utf-8"))

    def evaluate(self, proposal: ActionProposal) -> PolicyDecision:
        agents = self.policy.get("agents", {})
        agent = agents.get(proposal.agent_id)
        if agent is None:
            return PolicyDecision(
                decision=Decision.DENY,
                risk=RiskTier.HIGH,
                reasons=["unknown_agent"],
            )

        tool_rules = agent.get("tools", {}).get(proposal.tool)
        if tool_rules is None:
            return PolicyDecision(
                decision=Decision.DENY,
                risk=RiskTier.HIGH,
                reasons=["tool_not_authorized"],
            )

        action_rule = tool_rules.get(proposal.action)
        if action_rule is None:
            return PolicyDecision(
                decision=Decision.DENY,
                risk=RiskTier.HIGH,
                reasons=["action_not_authorized"],
            )

        constraint_errors = self._validate_constraints(
            proposal.arguments,
            action_rule.get("constraints", {}),
        )
        risk = RiskTier(action_rule.get("risk", "high"))
        if constraint_errors:
            return PolicyDecision(
                decision=Decision.DENY,
                risk=risk,
                reasons=constraint_errors,
            )

        if action_rule.get("requires_approval", False):
            return PolicyDecision(
                decision=Decision.REQUIRE_APPROVAL,
                risk=risk,
                reasons=["human_approval_required"],
            )

        return PolicyDecision(
            decision=Decision.ALLOW,
            risk=risk,
            reasons=["policy_authorized"],
        )

    @staticmethod
    def _validate_constraints(arguments: dict[str, Any], constraints: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        allowed_keys = set(constraints.get("allowed_keys", []))
        required_keys = set(constraints.get("required_keys", []))

        if allowed_keys:
            unexpected = set(arguments) - allowed_keys
            if unexpected:
                errors.append(f"unexpected_arguments:{','.join(sorted(unexpected))}")

        missing = required_keys - set(arguments)
        if missing:
            errors.append(f"missing_arguments:{','.join(sorted(missing))}")

        max_lengths = constraints.get("max_lengths", {})
        for key, maximum in max_lengths.items():
            value = arguments.get(key)
            if isinstance(value, str) and len(value) > int(maximum):
                errors.append(f"argument_too_long:{key}")

        allowed_values = constraints.get("allowed_values", {})
        for key, values in allowed_values.items():
            if key in arguments and arguments[key] not in values:
                errors.append(f"argument_value_denied:{key}")

        return errors
