# Architecture

## Design principle

AATG treats model output as a **proposal**, never as authority. v0.4 extends that principle across live Model Context Protocol boundaries: MCP metadata and MCP output are external evidence, not authorization primitives.

## v0.4 execution and evidence path

1. verify workload identity when enabled
2. parse a structured `ActionProposal`
3. verify signed policy provenance when required
4. evaluate static policy and parameter constraints
5. evaluate the provenance/taint of evidence used by the proposal
6. validate delegated capability authority for medium/high-risk actions when enabled
7. enforce cumulative risk budget
8. validate proposal-bound human approval and optional independent-approver quorum
9. atomically reserve the proposal in durable execution state
10. durably consume approval authority
11. invoke only a registered constrained adapter or approved MCP boundary
12. preserve external result provenance/taint
13. independently verify resulting state where possible
14. mark execution terminal and append security events to the hash-chained audit journal

No step uses model confidence, chain-of-thought, a tool description, or natural-language justification as an authorization primitive.

## Live MCP boundary

`StatelessHTTPMCPClient` implements the lab subset of MCP `2026-07-28` over HTTP/JSON-RPC:

- `server/discover`
- `tools/list`
- `tools/call`

Each request carries protocol/client metadata rather than depending on the retired session initialization flow.

The reference lab pins an expected server identity and canonical SHA-256 digests of allowed tool input schemas. A server that presents a different identity, adds an unexpected tool, or changes a pinned schema fails closed.

Tool descriptions are deliberately excluded from authorization. They remain visible discovery content and can be taint-classified as suspicious without acquiring permission to alter policy.

The lab's server-identity header is a research control for a local adversarial process. Production remote MCP connections should rely on appropriate TLS, authorization, server identity, workload identity, and deployment trust infrastructure.

## Information-flow boundary

AATG distinguishes two questions:

1. **May the system inspect this external information?**
2. **May that information directly influence a side effect?**

`InformationFlowPolicy` permits tainted MCP evidence to remain available for low-risk analysis while blocking it from directly parameterizing medium/high-risk effects.

Reference taints include:

- `external_tool_output`
- `unverified_tool_output`
- `untrusted_mcp_content`
- `prompt_injection_suspected`
- `suspicious_tool_metadata`

`ActionProposal.evidence_taints` is part of the canonical proposal digest, so approval is bound to the provenance state presented at authorization time.

## Authority decomposition

### Workload identity

`WorkloadIdentity` establishes which reference workload is presenting a proposal. Authentication does not imply authorization.

### Signed policy provenance

`PolicyBundleVerifier` verifies `aatg.policy-bundle.v1`. A verified bundle supplies a policy ID, version, signing key ID, issue time, canonical SHA-256 digest, and signature. `PolicyEngine` copies that provenance into every `PolicyDecision`.

### Delegated capability

`CapabilityIssuer` constrains delegated authority by subject, audience, tool, action, expiration, ID, and optional parameter envelope. Durable revocation can invalidate a capability before natural expiration.

### Cumulative risk budget

`RiskBudget` constrains sequences of individually permitted medium/high-risk actions. The current reference budget remains process-local.

### Human approval and dual control

Approval is bound to the exact proposal digest. Critical configurations may require multiple distinct approver identities. Durable replay state prevents accepted approvals from silently being reused after restart.

### Durable execution reservation

`SQLiteExecutionLedger` reserves proposal identity before consumable authority and external execution. A nonterminal reservation returns `execution_in_doubt` after interruption rather than silently retrying an uncertain effect.

## Live MCP adversarial state model

```text
MCP ENDPOINT
   |
   v
SERVER IDENTITY CHECK ----mismatch----> REJECT
   |
   v
TOOLS/LIST
   |
   +----unknown tool------------------> REJECT
   |
   +----schema drift------------------> REJECT
   |
   v
UNTRUSTED TOOL METADATA
   |
   v
AUTHORIZED TOOL CALL
   |
   v
TAINTED MCP RESULT
   |
   +----low-risk inspection-----------> ALLOW ANALYSIS
   |
   +----medium/high-risk effect-------> INFORMATION-FLOW DENY
```

This protects against a common trust-collapse failure: treating information returned by an authenticated tool server as if the content itself were authorized to control another tool.

## Confused deputy resistance

An MCP server may tell one agent to perform an action reserved for another agent. That instruction does not change the caller's identity or policy scope. A `research-agent` remains unable to invoke an `operations-agent` capability simply because external content requests it.

## Cross-tool exfiltration resistance

External tool output may attempt to induce a later tool call that sends credentials or data elsewhere. The live lab marks such output as untrusted/prompt-injected evidence and tests that it cannot directly flow into medium/high-risk effects.

This is an information-flow control, not a claim that all semantic exfiltration strategies are detected.

## Crash semantics

The critical failure window remains between authorization and observable external completion.

```text
VALIDATED
   |
   v
RESERVE PROPOSAL ----duplicate----> REPLAY_BLOCKED / IN_DOUBT
   |
   v
CONSUME AUTHORITY
   |
   v
EXECUTE TOOL / MCP EFFECT
   |          \
 crash         success/failure
   |                |
   v                v
RESERVED        TERMINAL
IN_DOUBT
```

This provides at-most-once intent at the gateway boundary, not exactly-once semantics in arbitrary external systems.

## Evaluation architecture

CI runs four layers:

1. pytest security regression tests
2. core readable adversarial scenarios
3. scored general red-team corpus
4. live MCP adversarial lab

The live lab starts a separate HTTP server process with switchable adversarial modes and emits `aatg.mcp-live-lab.v2` results. Current cases include malicious metadata, prompt injection, schema replacement, server impersonation, confused-deputy escalation, cross-tool exfiltration, tainted high-risk flow, and benign transport behavior.

## Production evolution

A hardened implementation should add:

- TLS-backed authenticated remote MCP endpoints
- OAuth/OIDC authorization validation for remote MCP
- server certificate/attestation policy
- asymmetric or KMS/HSM-backed policy, identity, and capability signing
- external workload identity such as SPIFFE/SPIRE or managed OIDC/mTLS
- explicit trusted declassification workflows for external evidence
- durable distributed risk budgets and replay state
- target-system idempotency keys or transactional effect APIs
- immutable remotely signed audit storage
- process/container isolation and egress controls for adapters
- multi-server cross-domain information-flow policy
- policy differential testing and larger adversarial benchmarks
