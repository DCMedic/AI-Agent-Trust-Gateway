# AI Agent Trust Gateway

**Treat agent actions as untrusted proposals. Establish identity, verify policy provenance, constrain delegated authority, preserve information provenance, and require independent evidence before external effects are allowed.**

AI Agent Trust Gateway (AATG) is a runnable security reference architecture for placing an independent trust boundary between an AI agent and the tools, APIs, infrastructure, or cyber-physical systems it can affect.

The project does not assume that a model is malicious. It assumes something operationally stronger: a useful model can still be wrong, manipulated by untrusted context, impersonated, overprivileged, replayed, or confidently mistaken about whether an external action succeeded.

## v0.4 — Live MCP Adversarial Lab

v0.4 adds a real Model Context Protocol transport boundary and an adversarial lab built against the stateless MCP `2026-07-28` protocol.

The lab does not give an MCP server implicit trust simply because the server is reachable or because its tool metadata is syntactically valid. Server identity, tool schemas, output provenance, information flow, and downstream authority remain separate controls.

```text
AI workload
    |
    v
workload identity
    |
    v
signed/versioned policy
    |
    v
delegated capability
    |
    v
risk budget + human approval
    |
    v
durable execution reservation
    |
    v
MCP / constrained tool boundary
    |
    +---- tool metadata --------> untrusted discovery evidence
    |
    +---- tool output ----------> tainted external evidence
                                      |
                                      v
                              information-flow policy
                                /                \
                         low-risk analysis    medium/high effect
                              allowed               blocked
                                      |
                                      v
                         independent verification
                                      |
                                      v
                           hash-chained audit trail
```

Passing one layer never grants permission to bypass another.

## What v0.4 tests

The live lab starts an actual local HTTP MCP server process and drives it through JSON-RPC requests. The adversarial server can change behavior between test cases so the gateway can evaluate:

- malicious tool descriptions containing instruction injection
- prompt-injected tool output
- MCP server impersonation
- runtime tool-schema replacement
- confused-deputy privilege escalation
- cross-tool credential/exfiltration instructions
- tainted external evidence attempting to parameterize high-impact actions
- benign MCP calls that should remain usable for low-risk analysis

The objective is not to prove that prompt injection is solved. It is to test whether untrusted MCP content is prevented from silently acquiring authority over downstream effects.

## Current MCP transport model

`StatelessHTTPMCPClient` implements the subset of MCP `2026-07-28` needed by the lab:

- `server/discover`
- `tools/list`
- `tools/call`

Each request carries the MCP protocol version, request-routing headers, JSON-RPC correlation ID, and client metadata. The lab server is a separate process and communicates over HTTP rather than an in-process mock.

The reference lab pins:

- expected server identity
- expected tool names
- canonical SHA-256 digests of tool input schemas

Tool **descriptions are never authorization inputs**. A malicious description can be surfaced and classified as suspicious without changing what the agent is permitted to do.

The lab identity header is intentionally a research mechanism, not production authentication. Remote production MCP deployments should use appropriate TLS, authorization, workload identity, and server-authentication controls.

## Information-flow control

AATG now explicitly separates information access from authority.

MCP output receives conservative provenance labels such as:

- `external_tool_output`
- `unverified_tool_output`
- `untrusted_mcp_content`
- `prompt_injection_suspected`

`InformationFlowPolicy` permits tainted content to remain available for low-risk inspection and analysis, but prevents those labels from directly flowing into medium- or high-risk effects.

For example, an MCP search result can be shown to an analyst. The same result cannot directly become the justification or parameter source for a service restart simply because the tool text says to perform one.

`ActionProposal.evidence_taints` is included in the proposal digest, so human approval cannot be obtained for one provenance state and then reused after that evidence context is changed.

## Security invariants

1. **Agents do not directly execute tools.** They submit structured action proposals.
2. **Identity is not authorization.** Authentication never implies tool permission.
3. **Policy is attributable.** Signed policy bundles identify the policy ID, version, key, and canonical digest used for a decision.
4. **Delegation is scoped and revocable.** Capabilities cannot expand static policy.
5. **Cumulative authority is bounded.** Risk budgets constrain sequences of individually legitimate actions.
6. **High-impact approval is proposal-bound.** Approval is tied to the complete proposal digest.
7. **Dual control is supported.** Critical configurations can require independent human approvers.
8. **Approval replay protection is durable.** Consumed approval IDs survive restart.
9. **External effects are reservation-bound.** Interrupted effects become `execution_in_doubt` rather than silently retrying.
10. **MCP metadata is not authority.** Tool descriptions cannot grant capabilities or alter policy.
11. **Tool schemas are pinned in the lab.** Runtime schema drift is detected before use.
12. **External tool output remains tainted.** Successful transport does not establish truth or safety.
13. **Tainted evidence cannot directly drive higher-risk effects.** Information flow is evaluated independently of tool execution.
14. **Every security transition is auditable.** Identity, policy, capabilities, approvals, reservations, MCP provenance, denials, execution, and verification remain inspectable.

## Durable authority and policy provenance

v0.3 controls remain part of v0.4:

- HMAC-signed reference workload identity
- signed/versioned policy bundles
- scoped HMAC capability tokens
- SQLite-backed capability revocation
- cumulative risk budgets
- proposal-bound human approval
- configurable dual-control quorum
- SQLite-backed approval replay protection
- SQLite execution reservations
- `execution_in_doubt` recovery semantics
- hash-chained audit records

These are intentionally inspectable reference mechanisms. Production deployments should replace symmetric application secrets and local SQLite state with appropriate PKI/OIDC/SPIFFE identity, KMS/HSM-backed keys, strongly consistent shared state, remote immutable audit storage, and deployment isolation.

## Live lab files

```text
src/trust_gateway/mcp_live.py          stateless MCP client + server/tool pinning
src/trust_gateway/information_flow.py information-flow policy for tainted evidence
tools/lab_mcp_server.py               adversarial MCP HTTP server
tests/test_live_mcp_lab.py            transport/security regression suite
lab/run_live_lab.py                    scored end-to-end live-lab evaluation
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
python tools/run_scenarios.py
python tools/evaluate_redteam.py
python lab/run_live_lab.py
uvicorn trust_gateway.app:app --reload
```

Optional reference trust controls:

```bash
export AATG_IDENTITY_SECRET='development-identity-secret-at-least-32-bytes'
export AATG_IDENTITY_KEY_ID='dev-identity-key'
export AATG_CAPABILITY_SECRET='development-capability-secret-at-least-32-bytes'
export AATG_HIGH_RISK_APPROVAL_QUORUM=2
```

Signed policy enforcement can additionally be enabled with `AATG_POLICY_PATH`, `AATG_POLICY_KEY_ID`, `AATG_POLICY_SECRET`, and `AATG_REQUIRE_SIGNED_POLICY=true`.

## Adversarial evaluation

CI executes four complementary layers:

1. the complete pytest security regression suite
2. readable core adversarial scenarios
3. the scored general red-team corpus
4. the live MCP adversarial lab

The live-lab report uses schema `aatg.mcp-live-lab.v2` and reports its protocol version, individual cases, pass count, total cases, and containment rate. CI fails if a reference live-lab case is not contained as expected.

The lab is intentionally deterministic. It is a reproducible regression boundary, not evidence that arbitrary agent behavior or arbitrary MCP servers are safe.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Default Policy](policies/default.json)

## Research direction

AATG asks a narrow but important question:

> **When an AI system requests an external effect, what independent evidence of identity, authority, provenance, policy, intent, and resulting state should exist before that effect is trusted?**

Potential next milestones include authenticated remote MCP endpoints, OAuth/OIDC authorization evaluation, certificate/server attestation, explicit declassification workflows, durable distributed risk budgets, policy differential testing, multi-server cross-domain information-flow controls, and a larger reproducible adversarial corpus.

## Scope

AATG is a research and portfolio project, not a production authorization product. It does not prove that a model is aligned, truthful, or non-deceptive, and it is not a substitute for production identity, policy, secrets management, sandboxing, egress control, durable distributed state, or infrastructure isolation.

## License

MIT
