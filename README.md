# AI Agent Trust Gateway

**Treat agent actions as untrusted proposals. Preserve provenance, verify remote trust, constrain delegated authority, and require explicit evidence declassification before consequential cross-domain effects are allowed.**

AI Agent Trust Gateway (AATG) is a runnable security reference architecture for placing an independent trust boundary between an AI agent and the tools, APIs, infrastructure, MCP servers, or cyber-physical systems it can affect.

## v0.5 — Remote Trust & Declassification

v0.5 extends the live MCP adversarial lab into a cross-domain trust system. The central question is no longer only whether external information is tainted, but **under what independently reviewable conditions that information may become acceptable evidence for a consequential action**.

```text
remote MCP endpoint
      |
      v
endpoint policy + HTTPS/auth requirements
      |
      v
server/tool/schema pinning
      |
      v
provenance-bearing evidence
(source + trust domain + payload digest + taints)
      |
      v
cross-domain information-flow policy
      |                     \
      | blocked              \ explicit declassification
      v                       v
low-risk analysis       reviewed evidence state
                              |
                              v
identity + signed policy + capability + risk budget
                              |
                              v
human approval / dual control
                              |
                              v
durable execution reservation + constrained effect
```

Passing one layer never grants permission to bypass another.

## New in v0.5

### Remote endpoint trust policy

`RemoteEndpointPolicy` binds a remote MCP endpoint to a trust domain and expected server identity. Remote endpoints require HTTPS by default and can attach an explicit bearer credential. Certificate SHA-256 pin helpers are included as a reference hook for deployments that need an additional server-certificate constraint.

The reference bearer mechanism is intentionally simple. Production OAuth/OIDC deployments should validate issuer, audience, token binding, scopes, expiration, and authorization-server metadata using a mature identity stack. MCP `2026-07-28` hardened authorization around issuer validation and moved the ecosystem toward client metadata documents rather than Dynamic Client Registration.

### Evidence provenance

`EvidenceClaim` carries provenance into `ActionProposal`:

- source identifier
- source trust domain
- payload digest
- active taint labels
- declassification grant IDs

The complete evidence context and target trust domain are part of the proposal digest. A human approval therefore cannot be obtained under one evidence classification and silently reused after provenance changes.

### Cross-domain information-flow control

`InformationFlowPolicy` now considers both taint and domain. Low-risk observation remains available, while medium/high-risk effects fail closed when untrusted evidence crosses from one domain into another.

Example:

```text
research MCP evidence -> operations service restart
```

is not authorized merely because the research server is authenticated or its response is syntactically valid.

### Explicit declassification

`DeclassificationAuthority` creates short-lived, signed grants bound to:

- one exact evidence digest
- a specific set of removable taints
- one destination trust domain
- a named reviewer
- issuance and expiration time

A grant changes information classification only. It **does not** grant tool permission, capability authority, risk budget, or human execution approval.

This preserves a critical separation:

> evidence may become acceptable for consideration without becoming authority to act.

### Policy-differential evaluation

`tools/evaluate_policy_differential.py` evaluates the same proposals under strict and deliberately permissive information-flow policies. CI verifies that weakening flow controls measurably changes the disposition of a high-impact MCP-derived proposal.

That provides a concrete answer to: **what security property did the stricter policy actually buy us?**

## MCP transport

The live lab targets MCP `2026-07-28` and uses stateless HTTP JSON-RPC with MCP routing metadata. `StatelessHTTPMCPClient` supports the lab subset of:

- `server/discover`
- `tools/list`
- `tools/call`

The client preserves the v0.4 protections:

- expected server identity
- pinned tool allowlist
- canonical SHA-256 input-schema pins
- suspicious tool-description classification
- prompt-injection tainting
- external-output provenance

Remote endpoint policy now adds HTTPS/authentication requirements and a trust-domain identity around that transport.

## Core security invariants

1. Agents submit proposals; they do not directly execute tools.
2. Identity is distinct from authorization.
3. Signed policy provenance identifies which policy authorized a decision.
4. Capabilities are scoped, expiring, and revocable.
5. Cumulative authority is bounded by risk budgets.
6. Human approval is proposal-bound and replay protected.
7. Critical configurations can require dual control.
8. External effects are durably reservation-bound.
9. MCP metadata never grants authority.
10. Remote endpoint authentication does not make returned content trustworthy.
11. Evidence carries source, trust domain, digest, and taint state.
12. Cross-domain tainted evidence cannot directly drive medium/high-risk effects.
13. Declassification is explicit, reviewer-bound, domain-bound, digest-bound, and expiring.
14. Declassification changes information trust only; it cannot expand execution authority.
15. Policy changes can be tested through differential evaluation.
16. Security-relevant transitions remain auditable.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
python tools/run_scenarios.py
python tools/evaluate_redteam.py
python lab/run_live_lab.py
python tools/evaluate_policy_differential.py
uvicorn trust_gateway.app:app --reload
```

## Key files

```text
src/trust_gateway/mcp_live.py          MCP 2026-07-28 client, server/tool/schema trust
src/trust_gateway/remote_trust.py      remote endpoint, HTTPS/auth, certificate-pin policy
src/trust_gateway/information_flow.py cross-domain information-flow rules
src/trust_gateway/declassification.py signed evidence declassification grants
src/trust_gateway/models.py           evidence provenance carried in proposals
tests/test_v05_remote_trust.py        v0.5 security regression tests
tools/evaluate_policy_differential.py strict-vs-permissive policy experiment
lab/run_live_lab.py                    live MCP adversarial evaluation
```

## Evaluation

CI runs the security regression suite, core adversarial scenarios, the scored red-team corpus, the live MCP adversarial lab, and the v0.5 policy-differential experiment.

The evaluation remains deterministic and intentionally bounded. Passing it demonstrates regression resistance for the documented threat cases; it does not prove general model alignment or universal prompt-injection resistance.

## Production evolution

A hardened implementation should replace reference mechanisms with mature infrastructure, including asymmetric/KMS-backed signing, SPIFFE/OIDC/mTLS workload identity, standards-compliant OAuth/OIDC validation, managed PKI and certificate rotation, strongly consistent shared replay/risk state, immutable remote audit storage, adapter isolation, egress controls, and organizational approval/declassification workflows.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Default Policy](policies/default.json)

## Research direction

AATG now asks two linked questions:

> **What authority should an AI system possess over external effects?**

and

> **What evidence is trustworthy enough to influence those effects, and who is allowed to change that classification?**

Future work includes full OAuth/OIDC issuer validation, proof-of-possession credentials, certificate transparency/attestation experiments, durable declassification ledgers, multi-reviewer declassification, provenance graphs, distributed risk accounting, and larger cross-server attack corpora.

## Scope

AATG is a research and portfolio project, not a production authorization product. It does not prove that a model is aligned, truthful, or non-deceptive, and it is not a substitute for production identity, authorization, policy, secrets management, sandboxing, egress control, or infrastructure isolation.

## License

MIT
