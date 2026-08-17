from __future__ import annotations

import json

from trust_gateway.information_flow import FlowDecision, InformationFlowPolicy
from trust_gateway.models import ActionProposal
from trust_gateway.policy import PolicyEngine


class PermissiveInformationFlowPolicy(InformationFlowPolicy):
    def evaluate(self, taints, target_risk, *, source_domains=(), target_domain="local"):
        return FlowDecision(True, ("experimental_permissive_flow",))


def corpus():
    return [
        ActionProposal(
            agent_id="operations-agent",
            tool="service",
            action="restart",
            arguments={"service": "demo-api"},
            purpose="external MCP recommendation",
            evidence_taints=["external_tool_output", "unverified_tool_output"],
            target_trust_domain="operations",
        ),
        ActionProposal(
            agent_id="research-agent",
            tool="notes",
            action="read",
            arguments={},
            purpose="inspect external evidence",
            evidence_taints=["external_tool_output"],
            target_trust_domain="research",
        ),
    ]


def main():
    strict = PolicyEngine("policies/default.json")
    permissive = PolicyEngine("policies/default.json", information_flow=PermissiveInformationFlowPolicy())
    rows = []
    for proposal in corpus():
        a = strict.evaluate(proposal)
        b = permissive.evaluate(proposal)
        rows.append({
            "proposal_id": proposal.proposal_id,
            "tool_action": f"{proposal.tool}.{proposal.action}",
            "strict": a.decision.value,
            "permissive": b.decision.value,
            "changed": a.decision != b.decision,
            "strict_reasons": a.reasons,
            "permissive_reasons": b.reasons,
        })
    report = {
        "schema": "aatg.policy-differential.v1",
        "cases": rows,
        "changed_decisions": sum(1 for row in rows if row["changed"]),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if not any(row["tool_action"] == "service.restart" and row["strict"] == "deny" and row["permissive"] == "require_approval" for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
