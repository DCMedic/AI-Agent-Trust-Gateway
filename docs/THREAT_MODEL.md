# Threat Model

## Objective

AI Agent Trust Gateway reduces the authority implicitly granted to an AI agent by inserting an independent policy and verification boundary between model output and external side effects.

The gateway assumes the agent can be useful while still being fallible, manipulated, overprivileged, or inconsistent.

## Protected assets

- credentials and delegated capabilities
- external systems reachable through tools
- integrity of tool arguments
- human approval decisions
- security policy and its provenance
- audit evidence
- post-action system state

## Trust boundaries

The agent/model is outside the execution trust boundary. Natural-language reasoning, model confidence, chain-of-thought, and self-reported intent are not authorization signals.

The gateway policy engine, approval verifier, audit journal, constrained adapters, and independent verification functions form separate controls. A production implementation should isolate these components further and use independent identity/secrets infrastructure.

## Primary threats

### Prompt injection and untrusted context
An agent may consume instructions from documents, web pages, messages, tool output, or other external data and convert them into unsafe tool proposals.

**Control:** authorization is based on gateway policy, agent identity, tool/action, and constrained arguments rather than natural-language instructions.

### Excessive agency
A useful agent may attempt a tool or action outside the authority needed for its task.

**Control:** default-deny, per-agent capability policy, explicit action rules, and human approval for high-risk operations.

### Parameter smuggling
An agent authorized to call a tool may add unexpected arguments or manipulate parameters to expand the effect of an otherwise permitted action.

**Control:** allow-listed keys, required keys, bounded string lengths, and allow-listed values.

### Approval replay or bait-and-switch
An agent may obtain approval for one action and then alter the request before execution.

**Control:** approval is bound to a SHA-256 digest of the exact proposal, including arguments, purpose, identity, and proposal metadata. Modified proposals require new approval.

### Stale approval
A previously legitimate approval may remain usable beyond the operational context in which it was granted.

**Control:** approvals expire and are rejected after their timestamp.

### Tool failure or misleading success
A tool may fail, return malformed output, or claim success without producing the intended state.

**Control:** adapter failures fail closed; execution and verification are separate events; successful invocation is not equivalent to verified outcome.

### Audit tampering
An attacker may alter historical decisions or actions to obscure unsafe behavior.

**Control:** append-only-style JSONL journal with SHA-256 hash chaining. The reference implementation detects modification or reordering. Production systems should additionally use protected remote storage and signed events.

### Policy bypass
An adapter or application path might execute a tool without passing through authorization.

**Control:** architecture requires all external effects to be reachable only through constrained adapters owned by the gateway. This is an architectural invariant that deployment isolation must enforce.

## Out of scope for v0.1

- defending the underlying model provider
- model-weight integrity
- production-grade secrets management
- sandboxing arbitrary generated code
- cryptographically strong user identity
- distributed approval consensus
- hostile operating-system administrators
- formal policy verification

These are intentionally documented rather than implied to be solved.
