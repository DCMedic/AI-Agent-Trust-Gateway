# Threat Model

## Objective

AI Agent Trust Gateway reduces authority implicitly granted to an AI agent by inserting independent identity, policy-provenance, delegation, cumulative-risk, human-approval, durable-execution, MCP/tool, information-flow, and verification boundaries between model output and external side effects.

The model is assumed to be useful but fallible. It may be manipulated by untrusted context, impersonated, overprivileged, replayed, or confidently wrong about external state.

## Protected assets

- workload identity credentials and signing keys
- policy-signing keys and authenticated policy provenance
- delegated capabilities and revocation state
- external systems reachable through tools or MCP servers
- integrity of action parameters
- human approval decisions and approver independence
- durable approval replay state
- execution reservation state
- cumulative risk budget
- MCP server/tool trust configuration
- provenance of externally returned information
- audit evidence
- post-action system state

## Trust boundaries

The model/agent remains outside the execution trust boundary. Natural-language reasoning, chain-of-thought, self-reported confidence, stated intent, MCP descriptions, and MCP-returned text are not authorization signals.

Identity, policy provenance, capability verification, risk budgeting, human approval, durable execution state, MCP/tool transport, information flow, adapter execution, and result verification remain separate controls.

## Primary threats

### Workload impersonation

A caller may claim an authorized `agent_id` without controlling that workload's credential.

**Controls:** signed workload assertion, audience/subject binding, key ID, issuance/expiration checks, and proposal subject matching.

**Residual risk:** the reference mechanism uses symmetric HMAC assertions. Production should use managed OIDC, SPIFFE/SPIRE, or mTLS/PKI with protected keys and rotation.

### Policy tampering, substitution, or rollback

An attacker may edit policy content, replace it with a more permissive version, or obscure which policy produced a decision.

**Controls:** signed `aatg.policy-bundle.v1`, policy ID/version/issue time/key ID/canonical digest/signature, signed-policy-required mode, and policy provenance copied into decisions and audit evidence.

**Residual risk:** HMAC policy signing allows verifiers holding the shared secret to forge policy. The reference implementation also does not enforce monotonic policy versions across deployments.

### Prompt injection and untrusted context

An agent may translate instructions from documents, pages, messages, or tool output into unsafe proposals.

**Controls:** natural-language content does not grant authority; MCP output remains tainted; higher-risk proposals are independently checked by policy, information flow, capabilities, budgets, approval, and execution state.

### Excessive agency and confused deputy

A useful agent may request authority outside its task, or an external tool may instruct a lower-privilege agent to exercise another agent's permissions.

**Controls:** default deny, verified workload identity, per-agent policy, scoped capabilities, risk budgets, and proposal-bound approval. External instructions cannot change the proposal's authenticated identity or policy scope.

### Parameter smuggling

An authorized tool/action may include unexpected parameters that broaden the effect.

**Controls:** static policy argument allowlists/required fields and optional independent capability constraints.

### Capability theft, misuse, or stale delegation

A capability may be copied, replayed by the wrong workload, used outside its intended scope, or remain valid after authority should be withdrawn.

**Controls:** signature, subject/audience/tool/action binding, TTL, unique ID, argument constraints, workload matching, and durable revocation.

**Residual risk:** reference capabilities are bearer-style HMAC tokens. Production should consider proof-of-possession and hardware/KMS-backed asymmetric issuance.

### Approval bait-and-switch or replay

A human may approve one request while the agent later changes it, or an accepted approval may be reused.

**Controls:** approval is bound to the canonical proposal digest, which includes evidence taints; consumed approval IDs are durable; optional quorum requires distinct approver identities.

### Duplicate execution after failure

A gateway may crash after authority is consumed or after an external effect occurs but before returning a result.

**Controls:** durable proposal reservation before external execution; duplicate terminal proposals are blocked; nonterminal reservations return `execution_in_doubt` rather than retrying.

**Residual risk:** exactly-once effects require cooperation from the target system, such as idempotency keys or transactions.

### Sequence/cumulative-impact abuse

Many locally permissible actions may collectively exceed acceptable authority.

**Control:** sliding-window risk budgets constrain cumulative medium/high-risk cost.

**Residual risk:** reference budget state remains process-local and uses coarse weights.

## MCP-specific threats

### MCP server impersonation

A malicious endpoint may present itself as an expected server.

**Reference control:** the live lab pins an expected server identifier and rejects mismatches.

**Residual risk:** the lab identity header is not production authentication. Real remote deployments should use authenticated TLS, authorization, workload/server identity, certificate validation, and potentially attestation.

### Malicious tool descriptions

A server may advertise a tool whose description contains prompt injection, credential requests, or instructions to bypass controls.

**Controls:** descriptions are untrusted discovery content, never authorization input. `MCPMetadataGuard` labels suspicious metadata, while authorization continues to depend on AATG identity/policy/capabilities.

**Residual risk:** heuristic detection does not identify every adversarial description. Safety does not depend on complete detection because descriptions cannot grant authority.

### Runtime tool-schema replacement

A server may advertise one parameter schema and later replace it with a broader schema that requests sensitive fields.

**Control:** the live lab pins canonical SHA-256 digests of allowed input schemas and rejects schema drift.

**Residual risk:** production needs a controlled process for legitimate tool-version/schema rotation rather than static development pins.

### Prompt-injected MCP output

A legitimate tool response may contain instructions such as bypassing policy, restarting infrastructure, hiding actions from the user, or exfiltrating credentials.

**Controls:** MCP output receives `external_tool_output`, `unverified_tool_output`, and `untrusted_mcp_content`; suspicious instruction content can additionally receive `prompt_injection_suspected`. These labels are preserved as evidence provenance.

### Cross-tool data exfiltration

A compromised MCP server may instruct the agent to take credentials or sensitive data from one context and send them through another tool.

**Controls:** `InformationFlowPolicy` blocks external/unverified/prompt-injected evidence from directly driving medium/high-risk effects. The live lab explicitly tests exfiltration-style instructions.

**Residual risk:** v0.4 does not implement a complete semantic information-flow/type system or universal secret classification. The current control demonstrates provenance-aware boundaries, not comprehensive DLP.

### Untrusted evidence acquiring authority

An MCP result may recommend an administrative action and be treated as if the tool itself approved that action.

**Control:** retrieved evidence and authorization remain distinct. Tainted evidence can be inspected at low risk but cannot directly parameterize medium/high-risk actions without an explicit future declassification mechanism.

### MCP transport or routing confusion

Requests may be routed inconsistently or responses may not correspond to the request sent.

**Controls:** JSON-RPC request IDs are correlated, current protocol metadata is attached to each request, and the live HTTP server validates `Mcp-Method`/`Mcp-Name` routing headers.

**Residual risk:** the reference transport does not yet implement remote OAuth/OIDC authorization, TLS pinning, retries, streaming, tasks/extensions, or distributed server discovery.

## Malicious or misleading tool success

A tool may fail, lie about completion, or return stale state.

**Controls:** adapter failures fail closed; execution and verification are separate; successful invocation does not equal verified external state.

## Audit tampering

An attacker may rewrite historical security evidence.

**Control:** local JSONL records are SHA-256 hash chained so modification/reordering is detectable.

**Residual risk:** local files are not immutable against privileged host attackers. Production should use remote append-only storage and signed events.

## Safety-control availability failure

Identity, policy verification, authority state, MCP endpoint checks, approval, capability, adapter, or result verification may be unavailable.

**Control:** unavailable controls do not become implicit authorization. The design prefers fail-closed and explicit in-doubt states.

## Evaluation threats

A safety system can look effective if it blocks everything. AATG therefore preserves benign low-risk MCP use while measuring containment of adversarial behaviors.

CI includes deterministic regression and live-server cases for malicious metadata, prompt-injected output, server impersonation, schema replacement, confused-deputy escalation, cross-tool exfiltration, tainted high-risk flow, and benign MCP retrieval.

Passing this corpus demonstrates regression behavior for known cases only. It is not proof of general agent, MCP, or prompt-injection safety.

## Out of scope for v0.4

- proof that a model is aligned, truthful, or non-deceptive
- defending model weights or the underlying model provider
- complete production secrets/key lifecycle management
- universal prompt-injection detection or prevention
- semantic truth verification of arbitrary tool output
- comprehensive data-loss prevention or information-flow typing
- authenticated production remote MCP deployment and OAuth/OIDC flows
- hardware/server attestation
- full MCP extensions/tasks/streaming coverage
- distributed transactions across gateway and arbitrary external systems
- exactly-once execution without target-system cooperation
- durable distributed risk-budget accounting
- strong cryptographic human identity and organizational anti-collusion
- hostile operating-system, hypervisor, or cloud administrators
- sandboxing arbitrary generated code
- formal policy verification

These limitations are documented deliberately rather than implied to be solved.
