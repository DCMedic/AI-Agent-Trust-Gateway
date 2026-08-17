# Threat Model

## Objective

AI Agent Trust Gateway reduces the authority implicitly granted to an AI agent by inserting independent identity, policy, delegation, approval, budgeting, and verification boundaries between model output and external side effects.

The gateway assumes the agent can be useful while still being fallible, manipulated, overprivileged, compromised by untrusted context, impersonated, or inconsistent.

## Protected assets

- workload identity credentials and signing keys
- delegated capabilities and their signing keys
- external systems reachable through tools
- integrity of tool arguments
- human approval decisions
- cumulative authority/risk budget
- security policy and its provenance
- audit evidence
- post-action system state
- provenance of information returned by tools

## Trust boundaries

The agent/model is outside the execution trust boundary. Natural-language reasoning, model confidence, chain-of-thought, and self-reported intent are not authorization signals.

Workload identity, static policy, capability verification, human approval, risk budgeting, audit logging, constrained adapters, and independent verification are separate controls. Passing one control does not imply that another control should trust the request.

## Primary threats

### Workload impersonation

A caller may claim an authorized `agent_id` without actually controlling the workload credential associated with that identity.

**Controls:** when identity enforcement is configured, the gateway requires a signed workload assertion whose subject matches the proposal `agent_id`, whose audience matches the gateway, and whose signature, key ID, issuance time, and expiration validate.

**Residual risk:** the reference implementation uses symmetric HMAC assertions and an in-process keyring. Production should use external workload identity such as SPIFFE/SPIRE, cloud OIDC workload identity, or managed-PKI mTLS with protected private keys and rotation.

### Identity assertion tampering or replay

An attacker may alter a signed identity assertion or reuse a valid assertion during its lifetime.

**Controls:** HMAC integrity verification, audience binding, subject binding, short expiration, key IDs, assertion IDs, and clock-skew checks.

**Residual risk:** identity assertions are not single-use. Theft within the short validity window remains possible in the reference design.

### Prompt injection and untrusted context

An agent may consume instructions from documents, web pages, messages, tool output, or other external data and convert them into unsafe tool proposals.

**Controls:** gateway policy does not derive authority from natural-language instructions; tool output is taint-labeled; actions still require identity, tool/action/argument authorization, capability authority where enabled, and human approval where required.

### Excessive agency

A useful agent may attempt a tool or action outside the authority needed for its task.

**Controls:** default deny, verified identity, per-agent static policy, scoped delegated capabilities, cumulative risk budgets, and human approval for high-risk operations.

### Parameter smuggling

An agent authorized to call a tool may add unexpected arguments or manipulate parameters to expand the effect of an otherwise permitted action.

**Controls:** static policy allow-lists and required keys plus an optional second independent argument envelope inside the delegated capability.

### Capability theft or misuse

A capability token could be copied and presented by a different agent or used for a broader action than intended.

**Controls:** tokens are signed and bound to audience, subject, tool, action, expiration, unique ID, and optional argument constraints. A capability does not override static policy, and its subject can be independently tied to the authenticated workload identity.

**Residual risk:** v0.2 uses bearer-style HMAC capabilities. Theft within the validity window remains possible. Production should use protected asymmetric/KMS-backed keys, support revocation, and minimize TTL.

### Capability tampering

An attacker may alter a capability's scope or expiration.

**Control:** HMAC-SHA256 integrity verification with constant-time signature comparison. Modified tokens fail closed.

### Approval bait-and-switch

An agent may obtain human approval for one action and alter the request before execution.

**Control:** approval is bound to a SHA-256 digest of the exact proposal, including arguments, purpose, identity, and proposal metadata.

### Approval replay

A valid approval may be reused to repeat a high-impact action without another human decision.

**Control:** accepted approval IDs are consumed by a single-use ledger. Subsequent use is rejected and audited.

**Residual risk:** the reference ledger is in-memory. Production replay protection must be durable and shared across gateway replicas.

### Stale approval or delegated authority

Previously legitimate authority may remain usable beyond the operational context in which it was granted.

**Controls:** identity assertions, approvals, and capabilities expire.

### Sequence/cumulative-impact abuse

An agent may perform many individually authorized actions whose combined effect exceeds the intended authority envelope.

**Control:** `RiskBudget` limits cumulative medium/high-risk cost inside a sliding time window per agent.

**Residual risk:** v0.2 budget state is in-memory and uses coarse reference weights rather than empirically calibrated impact models.

### Misleading or malicious tool output

A tool may return false, prompt-injected, adversarial, or otherwise unsafe data even when the tool call itself was legitimate.

**Controls:** returned data begins with provenance/taint labels; execution success is distinct from verification; successful verification removes only the claim it can actually establish and does not erase unrelated provenance such as `stored_user_content`.

### Tool failure or misleading success

A tool may fail, return malformed output, or claim success without producing the intended external state.

**Controls:** adapter failures fail closed; execution and verification are separate events; successful invocation is not equivalent to verified outcome.

### MCP/tool-server compromise

An external MCP-style server may return manipulated data or claim to have performed actions it did not perform.

**Controls:** authorization remains outside the MCP adapter; MCP responses are labeled `external_tool_output`; no independent verifier means verification fails closed.

**Residual risk:** v0.2 does not yet implement transport authentication, live MCP protocol negotiation, server attestation, or certificate pinning.

### Audit tampering

An attacker may alter historical decisions or actions to obscure unsafe behavior.

**Control:** append-only-style JSONL journal with SHA-256 hash chaining. The reference implementation detects modification or reordering.

**Residual risk:** local files are not immutable against a privileged host attacker. Production should use separately protected remote storage and signed events.

### Policy bypass

An adapter or application path might execute a tool without passing through authorization.

**Control:** architecture requires external effects to be reachable only through constrained adapters owned by the gateway. Deployment isolation must enforce this invariant.

### Safety-control availability failure

An identity, policy, approval, capability, adapter, or verification component may become unavailable.

**Control:** the reference design fails closed rather than treating unavailable safety controls as implicit authorization.

## Evaluation threats

A safety system can appear strong if it only measures blocked attacks while ignoring legitimate work that it unnecessarily prevents. AATG therefore tracks adversarial containment and benign completion separately in its red-team harness.

The current evaluation corpus is small and deterministic. It is useful as a regression boundary, not evidence of general agent safety.

## Out of scope for v0.2

- defending the underlying model provider or model weights
- production-grade secrets management, hardware-backed keys, and key rotation
- production-grade external workload identity or certificate lifecycle management
- full MCP transport security or server attestation
- sandboxing arbitrary generated code
- distributed approval consensus or durable multi-replica replay protection
- hostile operating-system or cloud administrators
- formal policy verification
- semantic truth verification of arbitrary tool output
- protection against every possible prompt injection or social-engineering strategy
- proof that a model is aligned, truthful, or non-deceptive

These limitations are intentionally documented rather than implied to be solved.
