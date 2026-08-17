from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ActionProposal, Decision, PolicyDecision, RiskTier
from .policy_bundle import PolicyBundleVerifier, PolicyProvenance


class PolicyEngine:
    def __init__(
        self,
        policy_path: str | Path,
        *,
        verifier: PolicyBundleVerifier | None = None,
        require_signed_bundle: bool = False,
    ):
        self.policy_path = Path(policy_path)
        raw = json.loads(self.policy_path.read_text(encoding="utf-8"))
        self.provenance: PolicyProvenance | None = None

        if raw.get("schema") == "aatg.policy-bundle.v1":
            if verifier is None:
                raise ValueError("policy_bundle_verifier_required")
            self.policy, self.provenance = verifier.verify(raw)
        else:
            if require_signed_bundle:
                raise ValueError("signed_policy_bundle_required")
            self.policy = raw

    def _decision(self, decision: Decision, risk: RiskTier, reasons: list[str]) -> PolicyDecision:
        provenance = self.provenance
        return PolicyDecision(
            decision=decision,
            risk=risk,
            reasons=reasons,
            policy_id=provenance.policy_id if provenance else None,
            policy_version=provenance.version if provenance else None,
            policy_digest=provenance.digest if provenance else None,
            policy_key_id=provenance.key_id if provenance else None,
        )

    def evaluate(self, proposal: ActionProposal) -> PolicyDecision:
        agents = self.policy.get("agents", {})
        agent = agents.get(proposal.agent_id)
        if agent is None:
            return self._decision(Decision.DENY, RiskTier.HIGH, ["unknown_agent"])

        tool_rules = agent.get("tools", {}).get(proposal.tool)
        if tool_rules is None:
            return self._decision(Decision.DENY, RiskTier.HIGH, ["tool_not_authorized"])

        action_rule = tool_rules.get(proposal.action)
        if action_rule is None:
            return self._decision(Decision.DENY, RiskTier.HIGH, ["action_not_authorized"])

        constraint_errors = self._validate_constraints(
            proposal.arguments,
            action_rule.get("constraints", {}),
        )
        risk = RiskTier(action_rule.get("risk", "high"))
        if constraint_errors:
            return self._decision(Decision.DENY, risk, constraint_errors)

        if action_rule.get("requires_approval", False):
            return self._decision(
                Decision.REQUIRE_APPROVAL,
                risk,
                ["human_approval_required"],
            )

        return self._decision(Decision.ALLOW, risk, ["policy_authorized"])

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
