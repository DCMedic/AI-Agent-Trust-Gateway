# AI Agent Trust Gateway

**Treat agent actions as untrusted proposals. Establish identity, verify policy provenance, constrain delegated authority, require independent approval, bound cumulative risk, and preserve evidence before external effects are allowed.**

AI Agent Trust Gateway (AATG) is a runnable security reference architecture for placing an independent trust boundary between an AI agent and the tools, APIs, infrastructure, or cyber-physical systems it can affect.

The project does not assume that an AI model is malicious. It assumes something operationally stronger: a useful model can still be wrong, manipulated by untrusted context, impersonated, overprivileged, replayed, or confidently mistaken about whether an external action succeeded.

## v0.3 — Durable Authority & Policy Provenance

v0.3 extends the original policy gateway into a layered authority system with durable state and cryptographically attributable policy decisions.

The execution chain is:

```text
workload identity
      |
      v
signed/versioned policy
      |
      v
delegated capability
      |
      v
cumulative risk budget
      |
      v
single- or dual-control human approval
      |
      v
durable execution reservation
      |
      v
constrained tool adapter
      |
      v
tainted output + independent verification
      |
      v
hash-chained audit evidence
```

Passing one layer never grants permission to bypass another.

## Core security invariants

1. **Agents do not directly execute tools.** They submit structured `ActionProposal` objects.
2. **Identity is not authorization.** A valid workload identity proves who is calling, not what that workload may do.
3. **Policy can be cryptographically attributable.** Signed policy bundles carry an ID, version, signing key ID, canonical digest, and signature.
4. **Policy tampering fails closed.** A modified signed policy bundle is rejected before the gateway begins serving decisions.
5. **Delegation is scoped.** Capabilities are bound to subject, audience, tool, action, expiration, unique ID, and optional argument constraints.
6. **Capabilities can be revoked.** v0.3 includes durable SQLite-backed revocation state for the single-node reference deployment.
7. **Cumulative authority is bounded.** A sliding-window risk budget limits sequences of individually permitted medium/high-risk actions.
8. **High-impact approval is proposal-bound.** Human approval applies to one exact proposal digest.
9. **Dual control is supported.** Critical deployments may require multiple independent approvers; duplicate approver identities do not satisfy quorum.
10. **Approval replay protection is durable.** Consumed approval IDs survive process restart.
11. **External effects are reservation-bound.** A proposal is durably reserved before authority is consumed and the tool is invoked.
12. **Crash ambiguity fails safe.** A proposal left reserved after interruption becomes `execution_in_doubt`; it is not silently executed again.
13. **Tool success is not truth.** Outputs carry provenance/taint labels and are independently verified where possible.
14. **Every transition is auditable.** Identity, policy provenance, capabilities, budgets, approvals, reservations, execution, verification, denial, and replay events enter a hash-chained journal.

## Signed policy bundles

`PolicyBundleVerifier` defines `aatg.policy-bundle.v1`. The signed payload includes:

- `policy_id`
- semantic `version`
- `issued_at`
- `key_id`
- canonical SHA-256 `digest`
- cryptographic signature
- the policy document itself

When a verified bundle is loaded, every `PolicyDecision` includes:

- `policy_id`
- `policy_version`
- `policy_digest`
- `policy_key_id`

Because the gateway already writes complete decisions to the audit journal, an investigator can establish exactly which authenticated policy revision authorized or denied a proposal.

The reference implementation uses HMAC-SHA256 to remain dependency-light and inspectable. Production systems should prefer asymmetric signatures or KMS/HSM-backed signing so policy verifiers do not possess signing authority.

### Create a signed policy bundle

```bash
export AATG_POLICY_SECRET='development-policy-secret-at-least-32-bytes'
python tools/sign_policy.py policies/default.json policies/default.signed.json \
  --policy-id aatg-default \
  --version 3.0.0 \
  --key-id dev-policy-key
```

Then require that bundle at startup:

```bash
export AATG_POLICY_PATH='policies/default.signed.json'
export AATG_POLICY_KEY_ID='dev-policy-key'
export AATG_POLICY_SECRET='development-policy-secret-at-least-32-bytes'
export AATG_REQUIRE_SIGNED_POLICY='true'
```

## Durable authority state

The reference API now uses SQLite-backed state for three security decisions:

- consumed human approvals
- revoked delegated capabilities
- execution reservations and terminal execution state

These mechanisms survive ordinary process restart and use database uniqueness constraints for atomic replay protection.

This is intentionally a **single-node reference architecture**. A distributed production deployment would need a strongly consistent shared datastore, transactional semantics across replicas, explicit recovery procedures, and carefully designed failure domains.

## Crash-safe execution semantics

External side effects create a difficult ambiguity: a process can fail after authorization has been consumed but before the caller learns whether the side effect occurred.

v0.3 therefore introduces `SQLiteExecutionLedger`.

Immediately before approval consumption, risk consumption, and tool execution, the gateway atomically reserves the proposal ID and digest. A later attempt to execute that same proposal is rejected.

If the reservation is still nonterminal after a restart, the gateway reports:

```text
execution_in_doubt
```

It does **not** automatically retry. The correct recovery path is to inspect independent external state, determine whether the effect occurred, and deliberately issue a new proposal when another attempt is appropriate.

This trades some availability for protection against duplicate high-impact effects.

## Dual-control approval

`high_risk_approval_quorum` controls how many independent human approvals a high-risk proposal requires. The default remains `1` for compatibility. Set:

```bash
export AATG_HIGH_RISK_APPROVAL_QUORUM=2
```

The `/v1/proposals/execute-controlled` endpoint accepts multiple proposal-bound approvals. Two approvals carrying the same approver identity are rejected as non-independent.

## Workload identity

`WorkloadIdentity` provides signed, short-lived reference workload assertions containing subject, audience, key ID, unique assertion ID, issuance time, and expiration.

The gateway can require the assertion subject to match the `agent_id` before policy evaluation begins.

The HMAC mechanism is intentionally a reference implementation. Production deployments should use a workload identity plane such as SPIFFE/SPIRE, cloud workload identity/OIDC, or mTLS certificates backed by managed PKI.

## Capability authority and revocation

`CapabilityIssuer` creates short-lived delegated authority scoped to an agent, tool, action, and optional argument envelope. A capability cannot expand static policy.

v0.3 adds revocation. The API can persist revoked capability IDs in the authority database and reject them even before their natural expiration.

## Risk budgets

`RiskBudget` addresses sequence risk. The reference cost model is:

```text
low    = 0
medium = 1
high   = 3
```

A proposal may be individually authorized and still be rejected because the same agent has exercised too much authority in the current sliding window.

The current risk-budget implementation remains in-memory. Durable/distributed budget accounting is a future research milestone.

## Tool output and taint tracking

Execution success is intentionally separated from information trust.

Tool output begins as `unverified_tool_output`. Independent verification may remove that specific label, but it does not erase unrelated provenance such as:

- `stored_user_content`
- `simulated_effect`
- `external_tool_output`

A successful database read proves that data was retrieved. It does not prove that the retrieved content is truthful, safe, or appropriate to use as authority for another high-impact action.

## MCP-style tool boundary

`MCPToolAdapter` models an MCP-like external tool server while keeping authorization outside the adapter. External results are marked as untrusted evidence and verification fails closed when no independent verifier exists.

The adapter remains transport-agnostic in v0.3. Live MCP protocol integration and adversarial tool-server testing are planned for the next research milestone.

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

Optional trust controls:

```bash
export AATG_IDENTITY_SECRET='development-identity-secret-at-least-32-bytes'
export AATG_IDENTITY_KEY_ID='dev-identity-key'
export AATG_CAPABILITY_SECRET='development-capability-secret-at-least-32-bytes'
export AATG_HIGH_RISK_APPROVAL_QUORUM=2
```

The reference API persists authority state at `runtime/authority.db` unless `AATG_AUTHORITY_DB` is set.

Do not use application environment variables or a local SQLite database as the final key-management or distributed-consistency architecture for production deployment.

## Adversarial evaluation

AATG has both readable scenario tests and a scored red-team harness. Current coverage includes:

- missing, forged, expired, or mismatched workload identity
- unknown agent and privilege-expansion attempts
- parameter smuggling
- missing, tampered, over-broad, expired, or revoked capabilities
- cumulative risk-budget exhaustion
- missing human approval
- bait-and-switch proposal mutation after approval
- approval replay
- durable approval replay after restart
- dual-control quorum failure and duplicate approvers
- signed-policy tampering
- unsigned policy when signatures are mandatory
- duplicate execution attempts
- simulated crash leaving execution state in doubt
- tool failure and misleading success
- persistent output taint
- MCP output without an independent verifier
- audit-chain integrity validation

CI continues to fail if the reference red-team corpus falls below its expected containment or benign-completion thresholds.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Default Policy](policies/default.json)

## Research direction

AATG asks a narrow but important question:

> **When an AI system requests an external effect, what independent evidence of identity, authority, intent, policy, and resulting state should exist before that effect is trusted?**

The next milestone is **v0.4 — Live MCP Adversarial Lab**, with emphasis on authenticated live MCP transport, malicious tool descriptions and outputs, prompt-injection propagation, confused-deputy behavior, cross-tool data exfiltration, information-flow restrictions, and richer reproducible adversarial evaluation.

## Scope

AATG is a research and portfolio project, not a production authorization product. It does not prove that a model is aligned, truthful, or non-deceptive, and it is not a substitute for production identity, policy, secrets management, sandboxing, egress control, durable distributed state, or infrastructure isolation.

## License

MIT
