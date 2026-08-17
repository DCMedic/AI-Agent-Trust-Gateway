# AI Agent Trust Gateway

**Treat agent actions as untrusted proposals. Authorize, constrain, verify, audit, and escalate them before they can affect real systems.**

AI Agent Trust Gateway (AATG) is a security reference architecture and runnable Python service for placing a policy-enforcement boundary between an AI agent and the tools it wants to use.

The gateway does **not** assume that a model is malicious. It assumes something more operationally useful: a model can be wrong, manipulated, overconfident, compromised by untrusted context, or granted more authority than a particular task requires.

## Security invariants

1. **No direct tool execution.** Agents submit action proposals; only the gateway invokes tools.
2. **Default deny.** Unknown agents, tools, actions, and argument patterns are rejected.
3. **Least authority.** Authorization is evaluated per agent, tool, action, and risk tier.
4. **High-impact actions require approval.** Human approval is bound to the exact proposal digest and expires.
5. **Argument constraints are enforced.** Permission to use a tool is not blanket permission to use every parameter.
6. **Policy is evaluated before execution.** Tool adapters cannot bypass the decision point.
7. **Every decision is auditable.** Proposal, decision, approval, execution, denial, and verification events are written to a hash-chained journal.
8. **Tool output is not automatically trusted.** Post-execution verification is a separate step.
9. **Failures fail closed.** Policy, approval, adapter, or verification errors do not silently become success.

## Architecture

```text
 AI agent / model
        |
        | ActionProposal
        v
+-----------------------+
|  AI Agent Trust       |
|  Gateway              |
|                       |
|  identity             |
|  policy evaluation    |
|  argument constraints |
|  risk classification  |
|  approval binding     |
|  audit journal        |
+-----------+-----------+
            |
      authorized action
            v
+-----------------------+
| Constrained tool      |
| adapters              |
+-----------+-----------+
            |
       tool result
            v
+-----------------------+
| Independent result /  |
| state verification    |
+-----------------------+
```

## Current reference tools

The initial implementation intentionally uses safe local adapters rather than giving a demonstration agent shell or arbitrary network access:

- `notes.read` — low-risk read operation
- `notes.append` — bounded write operation
- `service.restart` — simulated high-impact administrative operation requiring human approval

The architecture is designed so real adapters can later implement APIs, MCP tools, infrastructure operations, cyber-physical commands, or other agent capabilities without moving authorization logic into the model.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
uvicorn trust_gateway.app:app --reload
```

Then visit `http://127.0.0.1:8000/docs`.

## Example proposal

```json
{
  "agent_id": "research-agent",
  "tool": "notes",
  "action": "append",
  "arguments": {"text": "Candidate finding"},
  "purpose": "Store a research note"
}
```

The model does not decide whether this request is authorized. It proposes the action. The gateway independently evaluates policy and records the decision.

## Adversarial evaluation

`tools/run_scenarios.py` exercises cases including:

- unknown agent requesting a tool
- known agent attempting an unauthorized action
- argument-constraint violation
- high-impact action without approval
- approval replay against a modified proposal
- expired approval
- authorized low-risk action
- approved high-risk action
- simulated tool failure
- audit-chain integrity validation

The objective is not merely to demonstrate successful agent behavior; it is to demonstrate that unsafe or ambiguous behavior is contained.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Default Policy](policies/default.json)

## Research direction

This project explores a central question in trustworthy agentic systems:

> **How much authority should an AI system possess directly, and what evidence should be required before its requested actions are allowed to produce external effects?**

Future milestones include cryptographically signed agent identities, policy provenance, dual-control approvals, budget/rate constraints, MCP adapters, output taint tracking, independent verification providers, policy differential testing, and red-team evaluation datasets.

## Scope

AATG is a research and portfolio project. It is not a production authorization product and should not be treated as a substitute for mature identity, secrets-management, policy, sandboxing, and infrastructure-security controls.

## License

MIT
