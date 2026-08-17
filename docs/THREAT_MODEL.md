# Threat Model

## Objective

AI Agent Trust Gateway reduces authority implicitly granted to an AI agent by inserting independent identity, policy-provenance, delegation, cumulative-risk, human-approval, durable-execution, adapter, and verification boundaries between model output and external side effects.

The model is assumed to be useful but fallible. It may be manipulated by untrusted context, impersonated, overprivileged, replayed, or confidently wrong about external state.

## Protected assets

- workload identity credentials and signing keys
- policy-signing keys and authenticated policy provenance
- delegated capabilities and revocation state
- external systems reachable through tools
- integrity of action parameters
- human approval decisions and approver independence
- durable approval replay state
- execution reservation state
- cumulative risk budget
- audit evidence
- post-action system state
- provenance of tool-returned information

## Trust boundaries

The model/agent remains outside the execution trust boundary. Natural-language reasoning, chain-of-thought, self-reported confidence, and stated intent are not authorization signals.

Identity, policy provenance, capability verification, risk budgeting, human approval, durable execution state, adapter execution, and result verification remain separate controls. Passing one does not make another unnecessary.

## Primary threats

### Workload impersonation

A caller may claim an authorized `agent_id` without controlling that workload's credential.

**Controls:** signed workload assertion, audience binding, subject binding, key ID, issuance/expiration checks, and proposal subject matching.

**Residual risk:** the reference mechanism uses symmetric HMAC assertions. Production should use SPIFFE/SPIRE, managed OIDC workload identity, or mTLS/PKI with protected private keys and rotation.

### Policy tampering or provenance substitution

An attacker may edit a policy file, replace it with an older or more permissive version, or cause the gateway to make decisions without preserving which rule set was active.

**Controls:** `aatg.policy-bundle.v1` binds policy ID, version, issue time, signing key ID, canonical policy content, digest, and signature. Signed-policy mode rejects unsigned input. Verified provenance is copied into every `PolicyDecision` and therefore into audit evidence.

**Residual risk:** v0.3 uses symmetric HMAC signing. A verifier holding the secret can also forge policy. Production should use asymmetric/KMS/HSM-backed signatures, key rotation, revocation, and deployment-time version constraints to resist rollback.

### Policy rollback

A validly signed but obsolete policy may be reintroduced.

**Control:** policy version and issue time are explicit and auditable.

**Residual risk:** v0.3 does not yet enforce monotonic policy versions or a minimum trusted version. That should be implemented by deployment policy or a future provenance registry.

### Prompt injection and untrusted context

An agent may convert instructions from web pages, documents, messages, or tool output into unsafe proposals.

**Controls:** authorization is not derived from natural language; tool output remains taint-labeled; external effects still require explicit identity, policy, capability, budget, approval, and execution-state checks.

### Excessive agency

A useful agent may request authority beyond the current task.

**Controls:** default deny, per-agent static policy, scoped capabilities, cumulative risk budgets, proposal-bound approval, optional dual control, and registered tool adapters.

### Parameter smuggling

An otherwise authorized tool call may contain additional or manipulated parameters.

**Controls:** static policy argument constraints plus optional independent capability constraints.

### Capability theft, misuse, or stale delegation

A capability may be copied, reused by the wrong workload, expanded beyond its intended scope, or remain valid after an operational decision to withdraw it.

**Controls:** signed subject/audience/tool/action binding, expiration, unique ID, argument envelope, workload-subject matching, and durable capability revocation.

**Residual risk:** capabilities are bearer-style HMAC tokens. Theft before expiration or revocation remains possible. Production should minimize TTL, use protected asymmetric/KMS-backed issuance, and consider proof-of-possession binding.

### Approval bait-and-switch

A human may approve one request while the agent later changes the action.

**Control:** every approval is bound to the exact canonical proposal digest.

### Approval replay

A valid human approval may be reused for another execution.

**Controls:** accepted approval IDs are durably consumed in `SQLiteApprovalLedger`; replay remains blocked across ordinary process restart.

**Residual risk:** SQLite is a single-node reference store. Distributed gateways require a strongly consistent shared replay store.

### Approval concentration / false dual control

A system may appear to use two-person control while both approvals are attributed to the same actor.

**Control:** quorum enforcement requires distinct approver identities.

**Residual risk:** the reference gateway validates distinct strings, not cryptographically strong human identity or organizational separation-of-duty policy. Production approval should integrate strong identity, roles, and anti-collusion controls where appropriate.

### Duplicate execution after process failure

A gateway may crash after authority is consumed or after an external effect occurs but before returning a result. Blind retry can repeat a high-impact action.

**Controls:** `SQLiteExecutionLedger` atomically reserves a proposal before approvals/risk are consumed and before tool execution. Duplicate terminal proposals are blocked. Nonterminal reservations are reported as `execution_in_doubt` instead of retried.

**Residual risk:** an execution reservation cannot prove whether an external effect occurred. Recovery requires independent reconciliation. Exactly-once effects require cooperation from the target system, such as idempotency keys or transactional semantics.

### Authority consumption without completion

A crash may occur after approval or risk authority is consumed but before execution completes.

**Control:** durable reservation occurs before consumable authority changes state, creating evidence that execution entered the hazardous window.

**Residual risk:** v0.3 does not transactionally couple SQLite authority state to arbitrary external tools. This is intentionally represented as an in-doubt state rather than hidden.

### Sequence/cumulative-impact abuse

Many locally permissible actions may collectively exceed acceptable authority.

**Control:** sliding-window `RiskBudget` limits medium/high-risk cost per agent.

**Residual risk:** risk-budget state remains process-local and uses coarse reference weights. It is not yet durable or distributed.

### Malicious or misleading tool output

A legitimate tool can return prompt-injected, false, or otherwise unsafe information.

**Controls:** output provenance/taint labels, independent verification, and separation between successful retrieval and semantic trust.

### Tool failure or misleading success

A tool may fail or claim success without producing the intended state.

**Controls:** adapter exceptions fail closed; execution and verification are separate; successful invocation is not equivalent to verified outcome.

### MCP/tool-server compromise

A remote MCP-style server may provide malicious descriptions, manipulated data, or false action results.

**Controls:** authorization remains outside the adapter; external output is labeled; no independent verifier means verification fails closed.

**Residual risk:** v0.3 does not yet implement live MCP transport authentication, server attestation, tool-description filtering, or cross-tool information-flow policy. These are primary v0.4 targets.

### Audit tampering

An attacker may rewrite historical decisions or execution evidence.

**Control:** JSONL records are SHA-256 hash chained and modification/reordering is detectable.

**Residual risk:** local files are not immutable against a privileged host attacker. Production should use remote append-only storage and signed events.

### Safety-control availability failure

Identity, policy verification, authority state, approval, capability, adapter, or result verification may be unavailable.

**Control:** safety-control failure does not become implicit authorization. The design favors fail-closed behavior and explicit in-doubt states.

## Evaluation threats

A safety system may look effective if it measures only blocked attacks while ignoring legitimate operations it unnecessarily prevents. AATG therefore reports adversarial containment and benign completion separately.

The current corpus is deterministic and deliberately small. Passing it is a regression guarantee for known scenarios, not proof of general agent safety.

## Out of scope for v0.3

- proof that a model is aligned, truthful, or non-deceptive
- defending model weights or the underlying model provider
- hardware-backed production secrets management and complete key lifecycle
- policy anti-rollback enforcement across deployments
- distributed transactions across gateway and arbitrary external systems
- exactly-once execution without target-system cooperation
- durable distributed risk-budget accounting
- strong cryptographic human identity and organizational approval workflows
- hostile operating-system, hypervisor, or cloud administrators
- full live MCP transport security or server attestation
- sandboxing arbitrary generated code
- formal policy verification
- semantic truth verification of arbitrary tool output
- universal prompt-injection prevention

These limitations are documented deliberately rather than implied to be solved.
