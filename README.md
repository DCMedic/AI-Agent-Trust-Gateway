# AI Agent Trust Gateway

**Treat agent actions as untrusted proposals. Authorize, constrain, verify, audit, and escalate them before they can affect real systems.**

AI Agent Trust Gateway (AATG) is a security reference architecture and runnable Python service for placing a policy-enforcement boundary between an AI agent and the tools it wants to use.

The gateway does **not** assume that a model is malicious. It assumes something more operationally useful: a model can be wrong, manipulated, overconfident, compromised by untrusted context, impersonated, or granted more authority than a particular task requires.

## v0.2 trust model

AATG v0.2 separates forms of trust and authority that are often collapsed into one in agent systems:

1. **Workload identity** establishes which agent/workload is actually presenting the proposal.
2. **Static policy** answers whether that agent class is ever permitted to propose the action.
3. **Capability authority** delegates short-lived, cryptographically signed permission for a specific agent/tool/action/argument envelope.
4. **Risk budget** limits cumulative authority exercised by an agent inside a sliding time window.
5. **Human approval** authorizes one exact high-impact proposal and is consumed after one use.
6. **Independent verification** evaluates the result separately from the command path and preserves output provenance.

Passing one layer does not bypass the others. A high-risk action can therefore require a valid workload identity, policy permission, a valid delegated capability, available risk budget, and a fresh human approval before execution.

## Security invariants

1. **No direct tool execution.** Agents submit action proposals; only the gateway invokes tools.
2. **Identity and authorization are separate.** Proving which workload is calling does not imply that workload is permitted to perform the requested action.
3. **Default deny.** Unknown agents, tools, actions, and argument patterns are rejected.
4. **Least authority.** Authorization is evaluated per agent, tool, action, argument envelope, and risk tier.
5. **Delegation is explicit.** Medium/high-risk authority can be represented by short-lived HMAC-signed capabilities.
6. **Capabilities are scoped.** Tokens are bound to subject, audience, tool, action, expiration, and optional argument constraints.
7. **Cumulative impact is bounded.** Sliding-window risk budgets prevent a sequence of individually permitted actions from silently becoming excessive authority.
8. **High-impact actions require human approval.** Approval is bound to the exact proposal digest and expires.
9. **Approvals are single use.** Replaying an already consumed approval is blocked and audited.
10. **Argument constraints are enforced twice.** Static policy and delegated capability constraints can independently restrict parameters.
11. **Every decision is auditable.** Identity, proposal, policy, capability, budget, approval, execution, denial, replay, and verification events are written to a hash-chained journal.
12. **Tool output is not automatically trusted.** Results carry provenance/taint labels until independent verification resolves what it actually can prove.
13. **Verification does not erase provenance.** A verified result can still remain tainted as stored user content, simulated state, or external tool output.
14. **Failures fail closed.** Identity, policy, capability, budget, approval, adapter, or verification errors do not silently become success.

## Architecture

```text
 AI agent / workload
        |
        | signed identity assertion
        | ActionProposal
        v
+----------------------------+
| AI Agent Trust Gateway     |
|                            |
| workload identity          |
| static policy              |
| capability verification    |
| argument constraints       |
| risk classification        |
| cumulative risk budget     |
| single-use approval ledger |
| hash-chained audit journal |
+-------------+--------------+
              |
       authorized action
              v
+----------------------------+
| constrained adapters       |
| local / API / MCP boundary |
+-------------+--------------+
              |
        tainted result
              v
+----------------------------+
| independent verification   |
| + provenance preservation  |
+----------------------------+
```

## Workload identity

`WorkloadIdentity` provides dependency-light signed identity assertions for the reference implementation. Assertions contain a subject, audience, key ID, unique assertion ID, issuance time, and expiration time. The gateway can require the assertion subject to match the `agent_id` in the action proposal before policy evaluation proceeds.

The reference implementation uses HMAC-SHA256 so the identity boundary is inspectable without additional infrastructure. It is **not** presented as the preferred production identity architecture. A hardened deployment should use an external workload identity plane such as SPIFFE/SPIRE, cloud workload identity/OIDC, or mTLS certificates backed by managed PKI.

## Capability tokens

`CapabilityIssuer` implements a deliberately small reference capability format using HMAC-SHA256. Each token contains a unique identifier, subject, audience, tool, action, issuance/expiration time, and optional argument constraints.

Capabilities are **delegated authority**, not authentication by themselves. A valid identity assertion establishes who is calling; a capability establishes a bounded authority that has been delegated to that identity.

## Risk budgets

`RiskBudget` adds a sliding-window authority budget per agent. The reference implementation assigns low-risk actions a cost of `0`, medium-risk actions a cost of `1`, and high-risk actions a cost of `3`.

The purpose is to address sequence risk. A single action may be appropriate while a burst of repeated actions is not. The gateway therefore asks both:

- Is this action individually authorized?
- Has this agent already exercised too much authority recently?

The current budget state is intentionally in-memory for research clarity. A production deployment would require durable, shared state across replicas.

## Human approvals

High-risk approval is intentionally narrower than "approve this agent." An `Approval` is bound to the SHA-256 digest of one exact proposal, including its tool, action, arguments, purpose, identity, and creation time.

Once accepted for execution, the approval ID is consumed. Reusing it is treated as a replay attempt and produces an audit event.

## Output taint tracking

AATG distinguishes **execution success** from **information trust**. Tool results begin as `unverified_tool_output`. Independent verification may remove that specific label, but other provenance labels remain.

Examples:

- `stored_user_content` means the gateway verified the read operation, not the truth of the content.
- `simulated_effect` means the reference adapter verified simulated state, not a real external system.
- `external_tool_output` marks MCP-style data as externally supplied evidence until an independent verifier validates it.

This prevents a common trust-collapse error: treating "the tool returned this successfully" as equivalent to "this information is safe to trust for downstream decisions."

## MCP-style adapter boundary

`MCPToolAdapter` provides a small protocol boundary for MCP-like tools. Authorization remains outside the adapter. The adapter transports only an already-authorized call, labels the response as external tool output, and fails verification closed when no independent verifier is configured.

The current adapter is intentionally transport-agnostic so the security model can be evaluated independently of a specific MCP client library.

## Current reference tools

The reference implementation intentionally uses safe local adapters rather than giving a demonstration agent shell or arbitrary network access:

- `notes.read` — low-risk read operation
- `notes.append` — bounded medium-risk write; capability required when capability enforcement is enabled
- `service.restart` — simulated high-impact administrative operation requiring capability + human approval

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
python tools/run_scenarios.py
python tools/evaluate_redteam.py
uvicorn trust_gateway.app:app --reload
```

Optional API trust controls are enabled with environment secrets of at least 32 bytes:

```bash
export AATG_IDENTITY_SECRET='replace-with-a-development-identity-secret-at-least-32-bytes'
export AATG_IDENTITY_KEY_ID='dev-key'
export AATG_CAPABILITY_SECRET='replace-with-a-development-capability-secret-at-least-32-bytes'
```

Do not use application environment variables as the long-term key-management strategy for a production deployment.

## Adversarial evaluation

The project includes two complementary evaluation paths.

`tools/run_scenarios.py` provides a readable adversarial demonstration of policy denial, delegated capability checks, proposal-bound approval, approval replay prevention, taint propagation, tool failure, and audit integrity.

`tools/evaluate_redteam.py` runs a labeled benign/adversarial corpus and emits a machine-readable JSON report with:

- `adversarial_containment_rate`
- `benign_completion_rate`
- `total_pass_rate`

CI fails if either adversarial containment or benign completion drops below `1.0` for the current reference corpus. The corpus is intentionally small and deterministic; the important contribution is the evaluation interface and the separation of safety containment from useful task completion.

Current regression coverage includes:

- missing or mismatched workload identity
- tampered or expired identity assertion
- unknown agent requesting a tool
- known agent attempting an unauthorized action
- argument-constraint violation
- missing delegated capability
- capability subject/scope mismatch
- capability argument expansion
- capability tampering and expiration
- cumulative risk-budget exhaustion
- high-impact action without approval
- approval bound to a modified proposal
- single-use approval replay
- expired approval
- tool failure
- tainted output that remains tainted after execution verification
- MCP output without an independent verifier
- audit-chain integrity validation

The objective is not merely to demonstrate successful agent behavior. The project is designed to make unsafe, ambiguous, impersonated, over-privileged, cumulative, and replayed behavior observable and containable.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Default Policy](policies/default.json)

## Research direction

This project explores a central question in trustworthy agentic systems:

> **How much authority should an AI system possess directly, and what evidence should be required before its requested actions are allowed to produce external effects?**

Next research milestones include durable capability revocation, asymmetric/KMS-backed identity and capability signing, dual-control approval, live MCP integration, information-flow policy, independent verification providers, policy differential testing, richer sequence attacks, and a larger reproducible red-team corpus.

## Scope

AATG is a research and portfolio project. It is not a production authorization product and should not be treated as a substitute for mature identity, secrets management, policy, sandboxing, network isolation, and infrastructure-security controls.

## License

MIT
