# Architecture

## Design principle

AATG treats model output as a **proposal**, never as authority. v0.3 additionally treats policy provenance and execution state as security evidence that must survive ordinary process failure.

## v0.3 execution path

1. verify workload identity when enabled
2. parse a structured `ActionProposal`
3. verify signed policy provenance when signed-policy enforcement is enabled
4. evaluate policy and bind policy ID/version/digest/key ID to the decision
5. validate delegated capability authority for medium/high-risk actions when enabled
6. enforce cumulative risk budget
7. validate proposal-bound human approval and optional independent-approver quorum
8. atomically reserve the proposal in durable execution state
9. durably consume approval IDs
10. consume risk budget
11. invoke only a registered constrained adapter
12. preserve result provenance/taint
13. independently verify resulting state
14. mark execution terminal and append security events to the hash-chained audit journal

No step uses model confidence, chain-of-thought, or natural-language justification as an authorization primitive.

## Authority decomposition

### Workload identity

`WorkloadIdentity` establishes which reference workload is presenting a proposal. Authentication does not imply authorization.

### Signed policy provenance

`PolicyBundleVerifier` verifies `aatg.policy-bundle.v1`. A verified bundle supplies a policy ID, version, signing key ID, issue time, canonical SHA-256 digest, and signature. `PolicyEngine` copies that provenance into every `PolicyDecision`, which is then persisted by the audit journal.

The HMAC implementation is intentionally dependency-light. Production policy signing should use asymmetric signatures or KMS/HSM-backed signing so policy-verification nodes do not also hold signing authority.

### Delegated capability

`CapabilityIssuer` constrains delegated authority by subject, audience, tool, action, expiration, ID, and optional parameter envelope. `SQLiteCapabilityRevocationList` allows a capability to be durably revoked before natural expiration.

### Cumulative risk budget

`RiskBudget` limits the amount of medium/high-risk authority exercised by one agent inside a sliding window. The current state remains in-memory and is explicitly not a distributed accounting mechanism.

### Human approval and dual control

Human approval is bound to the exact proposal digest. `high_risk_approval_quorum` may require multiple distinct approver identities. `SQLiteApprovalLedger` durably prevents approval replay across process restarts.

### Durable execution reservation

`SQLiteExecutionLedger` atomically reserves the proposal ID and digest before approval/risk authority is consumed and before the adapter is invoked.

A duplicate reservation is never silently retried. If the existing record remains `reserved`, AATG returns `execution_in_doubt`. If it is already terminal, the duplicate returns `execution_replay_blocked`.

This implements **at-most-once intent at the gateway boundary**, not proof of exactly-once effects in an external system. Exactly-once semantics generally require cooperation from the target system, such as idempotency keys or transactional APIs.

## Crash semantics

The critical failure window is between authorization and observable completion.

```text
VALIDATED
   |
   v
RESERVE PROPOSAL  ----duplicate----> REPLAY_BLOCKED / IN_DOUBT
   |
   v
CONSUME AUTHORITY
   |
   v
EXECUTE TOOL
   |          \
 crash         success/failure
   |                |
   v                v
RESERVED        TERMINAL
IN_DOUBT
```

If the process crashes after reservation, a restart does not know whether the external effect happened. Retrying could duplicate a high-impact action, so the gateway fails safe and requires reconciliation against independent external state.

## Security state machine

```text
REQUEST
  |
IDENTITY_CHECK --------invalid--------> DENIED
  |
POLICY_VERIFY/EVALUATE -tampered/deny-> DENIED
  |
CAPABILITY_CHECK ------invalid--------> DENIED
  |
RISK_BUDGET_CHECK -----exceeded-------> DENIED
  |
APPROVAL/QUORUM -------invalid--------> DENIED
  |
EXECUTION_RESERVE -----duplicate------> REPLAY_BLOCKED / IN_DOUBT
  |
AUTHORITY_CONSUMED
  |
TOOL_EXECUTION --------error----------> FAILED
  |
TAINTED_RESULT
  |
INDEPENDENT_VERIFY ----not verified---> VERIFICATION_FAILED
  |
COMPLETED
```

## Why policy provenance matters

A policy engine that only returns `allow` or `deny` cannot later prove which rule set produced the decision. v0.3 records a cryptographic digest and version with every decision, making policy changes part of the evidence chain and enabling future policy-differential analysis.

## Why reservation precedes authority consumption

If approvals were consumed before any durable execution marker existed, a process could crash and leave a consumed human decision with no durable statement about whether execution began. Reserving first establishes an observable boundary before consumable authority changes state.

## Reference persistence model

The API uses SQLite for approval replay state, capability revocations, and execution reservations. SQLite provides durable single-node uniqueness and atomic inserts suitable for a reference architecture.

Production multi-replica deployments require a shared, strongly consistent authority datastore, explicit transaction design, backup/recovery policy, and controls for split brain and stale replicas.

## Production evolution

A hardened implementation should add:

- asymmetric/KMS-backed policy, identity, and capability signing
- external workload identity such as SPIFFE/SPIRE or managed OIDC/mTLS
- durable distributed risk budgets
- strongly consistent multi-replica replay state
- explicit recovery workflow for `execution_in_doubt`
- target-system idempotency keys or transaction support
- immutable remotely signed audit storage
- container/process isolation and egress controls for adapters
- live authenticated MCP transport
- information-flow enforcement for tainted results
- policy differential testing and a larger adversarial benchmark
