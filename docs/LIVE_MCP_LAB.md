# Live MCP Adversarial Lab

## Objective

AATG v0.4 adds a live process boundary for evaluating how agent-security controls behave when tool discovery and tool results originate from an MCP server rather than an in-process mock.

The lab targets Model Context Protocol revision `2025-06-18` and implements the required initialization lifecycle plus `tools/list` and `tools/call` over the standard stdio transport.

The lab is intentionally adversarial. The included server exposes both benign tools and hostile behaviors so security regressions are reproducible in CI without contacting external systems.

## Threats exercised

### Malicious tool descriptions

A server may place instructions, credential requests, or security-bypass language inside tool metadata. `MCPMetadataGuard` treats descriptions as untrusted discovery data and marks suspicious metadata with `suspicious_tool_metadata`.

Metadata never grants tool authority. The gateway's policy, capability, approval, and information-flow controls remain authoritative.

### Prompt injection through tool output

A legitimate call can return content designed to manipulate the model into taking another action. Live results are labeled `external_tool_output` and `unverified_tool_output`; suspicious instruction/exfiltration language additionally receives `prompt_injection_suspected`.

### Tainted-data escalation

`ActionProposal.evidence_taints` records provenance inherited from evidence used to form a downstream proposal. `InformationFlowGuard` prevents high-impact actions from being authorized directly from external or unverified MCP output and blocks suspicious metadata/injection taints from medium-impact actions.

This is intentionally conservative. A future declassification mechanism should require an explicit independent verifier rather than allowing the model to remove its own taints.

### Confused deputy

A low-authority agent cannot obtain administrative authority merely because an MCP server recommends an administrative action. Static policy still evaluates the authenticated proposal identity and requested tool/action.

### Wrong-server detection

`StdioMCPClient` can require an expected `serverInfo.name` during initialization. A mismatch fails closed.

This is **not cryptographic server attestation**. A malicious server can self-report another name. Stronger production controls require trusted process/package provenance for stdio or authenticated transport, certificate/identity verification, and deployment policy for remote servers.

### Cross-tool exfiltration

The lab's taint model is designed to prevent untrusted data from silently crossing from a read/discovery tool into a consequential write/admin action. Future v0.4.x scenarios will expand this into explicit source-to-sink policies for secrets, personal data, and external destinations.

## Running the lab

```bash
python lab/run_live_lab.py
```

The command emits a machine-readable report using schema `aatg.mcp-live-lab.v1`. CI requires a containment rate of `1.0` for the current reference corpus.

The current cases cover:

- suspicious MCP tool metadata detection
- prompt-injected tool-output tainting
- prevention of tainted MCP evidence driving a high-impact action
- confused-deputy privilege escalation
- benign tool completion with preserved external provenance
- wrong-server identity detection during initialization

## Why stdio first

The stdio transport gives the lab a real client/server process boundary while remaining deterministic, offline, and safe for CI. The client launches a subprocess and exchanges newline-delimited UTF-8 JSON-RPC messages over stdin/stdout.

A future extension should add Streamable HTTP and test authenticated remote-server identity, session handling, origin validation, redirect behavior, SSRF-resistant endpoint policy, and egress restrictions.

## Research limitations

The current metadata/injection detector is intentionally simple and lexical. It is a tripwire for experiments, not a general prompt-injection classifier.

The lab does not claim to solve semantic truth verification, model alignment, cryptographic MCP server attestation, hostile local administrators, arbitrary-code sandboxing, or all possible indirect prompt-injection strategies.
