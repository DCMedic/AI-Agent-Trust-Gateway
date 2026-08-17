# Architecture

## Design principle

The gateway treats model output as a **proposal**, not an instruction with inherent authority.

The v0.2 execution path deliberately decomposes identity, authority, cumulative impact, and evidence:

1. verify the proposing workload identity when identity enforcement is enabled
2. parse a structured `ActionProposal`
3. evaluate explicit static policy
4. validate arguments against policy constraints
5. classify risk
6. validate short-lived delegated capability authority for medium/high-risk actions when enabled
7. enforce the agent's sliding-window cumulative risk budget
8. require proposal-bound, single-use human approval when policy demands it
9. invoke only a registered constrained adapter
10. label returned data with provenance/taint information
11. independently verify the resulting state
12. persist tamper-evident audit events

No step relies on the model's confidence or natural-language justification as an authorization primitive.

## Trust and authority decomposition

AATG intentionally keeps identity, static permission, delegated authority, cumulative impact, and human authorization separate.

### Workload identity

`WorkloadIdentity` verifies a signed assertion containing subject, audience, key ID, assertion ID, issuance time, and expiration. When configured, the assertion subject must match the proposal's `agent_id` before execution proceeds.

The reference implementation uses HMAC-SHA256 to keep the mechanism inspectable and dependency-light. A production deployment should replace it with an external workload identity system such as SPIFFE/SPIRE, cloud OIDC workload identity, or mTLS certificates backed by managed PKI.

### Static policy

`PolicyEngine` answers whether an agent class is permitted to request a tool/action at all. Unknown agents, tools, actions, and parameter shapes fail closed.

### Delegated capability

`CapabilityIssuer` creates short-lived HMAC-SHA256 capability tokens. A token is bound to a subject, audience, tool, action, expiration, unique capability ID, and optional argument constraints.

A capability cannot expand static policy. Both checks must pass.

### Cumulative risk budget

`RiskBudget` assigns cumulative impact costs to risk tiers and maintains a sliding window per agent. The reference costs are low=0, medium=1, high=3. This limits sequences of individually permitted actions that collectively exceed the intended authority envelope.

### Human approval

High-risk actions can require a human decision bound to the canonical SHA-256 digest of one exact proposal. The `ApprovalLedger` makes accepted approvals single use.

A human approval cannot expand policy or capability scope. It authorizes one already-policy-compliant proposal to proceed.

## Components

### Action proposal model

A typed request containing agent identity, tool, action, arguments, declared purpose, proposal ID, and timestamp. A canonical SHA-256 digest binds human approval to the exact request.

### Policy decision point

`PolicyEngine` loads a declarative JSON policy. Rules constrain argument names, required values, string lengths, enumerated values, risk tier, and approval requirements.

### Capability verifier

The capability layer represents explicitly delegated authority. It validates signature, audience, subject, tool/action scope, expiration, and optional argument constraints before a medium/high-risk action can proceed when capability enforcement is enabled.

### Approval control

High-risk approval includes the exact proposal digest, human approver identity, expiration, and approval ID. Once accepted, its ID is consumed. A modified, expired, or replayed approval fails closed.

### Tool registry

Adapters are explicitly registered. The reference implementation does not expose shell execution, arbitrary HTTP requests, filesystem traversal, or dynamic import as agent tools.

### MCP adapter boundary

`MCPToolAdapter` models an MCP-style external tool boundary. Authorization stays in the gateway. The adapter transports an already-approved request, marks the result as external tool output, and fails verification closed when no independent verifier exists.

### Provenance and taint tracking

Tool output begins as `unverified_tool_output`. Verification can remove that particular label but does not erase unrelated provenance. For example, a verified database read may still be labeled `stored_user_content`, because successful retrieval is not evidence that the content itself is truthful or safe.

### Verification layer

Tool invocation and outcome verification are separate. A production adapter should verify using evidence meaningfully independent of the command path whenever possible.

### Audit journal

Security-relevant transitions are written as JSONL records linked by SHA-256 hashes. This is tamper-evident, not tamper-proof; production deployment should write to separately protected append-only storage and preferably sign events.

## Security state machine

```text
REQUEST
   |
   v
IDENTITY_CHECK ----missing/invalid----> DENIED
   |
   v
POLICY_EVALUATED ----deny-------------> DENIED
   |
   v
CAPABILITY_CHECK ----invalid/missing--> DENIED / CAPABILITY_REQUIRED
   |
   v
RISK_BUDGET_CHECK ----exceeded--------> DENIED
   |
   +----allow---------------------------> EXECUTING
   |
   +----approval required-----> PENDING_APPROVAL
                                  |
                       mismatch/expired/replay
                                  |
                                  v
                                DENIED
                                  |
                              fresh approval
                                  v
                              EXECUTING
                                  |
                         adapter success/fail
                         /                \
                    FAILED            TAINTED_RESULT
                                         |
                                      VERIFYING
                                         |
                              verified / not verified
                               /                 \
                         COMPLETED      VERIFICATION_FAILED
```

## Why identity is not authorization

A cryptographically valid assertion proves only that the caller controls the credential for the stated workload identity. It does not grant permission to use a tool. Static policy, delegated capabilities, risk budget, and human approval remain separate gates. This prevents the common mistake of treating authentication as blanket authority.

## Why approval is digest-bound and single-use

A generic approval such as "allow the agent to restart a service" is vulnerable to ambiguity, bait-and-switch changes, and replay. AATG instead approves a digest of the entire proposal. If the agent changes the service, argument set, stated purpose, ID, or timestamp, the digest changes and the approval no longer matches. After a matching approval is accepted, its ID is consumed so the same human decision cannot silently authorize repeated execution.

## Why cumulative risk budgets exist

Per-action authorization alone misses sequence risk. An agent could perform many medium-risk writes or repeated high-risk administrative actions that are each locally legitimate but collectively excessive. The sliding-window risk budget adds a second question: **even if this action is individually authorized, has this agent already exercised too much authority recently?**

## Research evaluation

`tools/evaluate_redteam.py` runs a labeled corpus of benign and adversarial cases and reports separate metrics for adversarial containment and benign completion. CI fails when either reference metric falls below 100 percent. The current corpus is intentionally small; its purpose is to establish an evaluation interface that can grow into a larger reproducible benchmark.

## Production evolution

A hardened implementation should replace demonstration components with:

- external workload identity backed by PKI/OIDC/SPIFFE-like infrastructure
- asymmetric or KMS/HSM-backed identity and capability signing, rotation, and revocation
- durable approval workflows with strong human identity and optional dual control
- durable risk-budget state and distributed replay protection
- external policy decision points or formally versioned policy bundles
- remote immutable audit storage and signed events
- process/container isolation for adapters
- outbound network allowlists and egress policy
- transaction boundaries and compensating actions
- independent state/evidence providers
- information-flow policy for tainted outputs
- larger adversarial-evaluation datasets and policy differential testing
