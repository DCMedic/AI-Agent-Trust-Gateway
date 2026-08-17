from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any
from urllib import error, request

from .remote_trust import RemoteEndpointPolicy

MCP_PROTOCOL_VERSION = "2026-07-28"
CLIENT_INFO_KEY = "io.modelcontextprotocol/clientInfo"

class MCPProtocolError(RuntimeError):
    pass

class MCPTrustError(RuntimeError):
    pass

def canonical_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

@dataclass(frozen=True)
class MCPToolDescriptor:
    name: str
    description: str
    input_schema: dict[str, Any]
    metadata_taints: tuple[str, ...] = ()

@dataclass(frozen=True)
class MCPToolPin:
    name: str
    input_schema_digest: str

@dataclass(frozen=True)
class MCPServerPin:
    server_id: str
    tools: dict[str, MCPToolPin]

@dataclass(frozen=True)
class LiveMCPResult:
    server_name: str
    trust_domain: str
    tool_name: str
    data: dict[str, Any]
    text: tuple[str, ...]
    taints: tuple[str, ...]

class MCPMetadataGuard:
    suspicious_fragments = (
        "ignore previous", "ignore all previous", "system prompt", "secret",
        "credential", "api key", "password", "send to", "exfiltrate",
        "do not tell", "bypass", "disable security",
    )
    def inspect(self, tool: dict[str, Any]) -> MCPToolDescriptor:
        description = str(tool.get("description", ""))
        lowered = description.lower()
        taints = ["suspicious_tool_metadata"] if any(f in lowered for f in self.suspicious_fragments) else []
        return MCPToolDescriptor(str(tool.get("name", "")), description, dict(tool.get("inputSchema") or {}), tuple(taints))

class StatelessHTTPMCPClient:
    """MCP 2026-07-28 client with endpoint policy, bearer auth, and provenance."""
    def __init__(self, endpoint: str, *, server_pin: MCPServerPin, endpoint_policy: RemoteEndpointPolicy | None = None, client_name: str = "aatg-live-lab", client_version: str = "0.5.0", timeout: float = 3.0):
        self.endpoint = endpoint
        self.server_pin = server_pin
        self.endpoint_policy = endpoint_policy or RemoteEndpointPolicy(endpoint=endpoint, trust_domain="local-lab", expected_server_id=server_pin.server_id, require_https=False)
        self.endpoint_policy.validate_endpoint()
        if self.endpoint_policy.expected_server_id != server_pin.server_id:
            raise MCPTrustError("endpoint_server_pin_mismatch")
        self.client_name = client_name
        self.client_version = client_version
        self.timeout = timeout
        self._request_id = 0
        self.server_name = server_pin.server_id

    @property
    def trust_domain(self) -> str:
        return self.endpoint_policy.trust_domain

    def discover(self) -> dict[str, Any]:
        result, headers = self._request("server/discover", {})
        self._verify_server(headers)
        return result

    def list_tools(self, guard: MCPMetadataGuard | None = None) -> list[MCPToolDescriptor]:
        guard = guard or MCPMetadataGuard()
        result, headers = self._request("tools/list", {})
        self._verify_server(headers)
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise MCPProtocolError("mcp_tools_missing")
        descriptors = []
        for raw in tools:
            if not isinstance(raw, dict):
                raise MCPTrustError("invalid_tool_metadata")
            self._verify_tool_pin(raw)
            descriptors.append(guard.inspect(raw))
        return descriptors

    def call_tool(self, name: str, arguments: dict[str, Any]) -> LiveMCPResult:
        if name not in self.server_pin.tools:
            raise MCPTrustError("tool_not_pinned")
        result, headers = self._request("tools/call", {"name": name, "arguments": arguments}, name=name)
        self._verify_server(headers)
        if result.get("isError") is True:
            raise MCPProtocolError("mcp_tool_reported_error")
        structured = result.get("structuredContent")
        data = dict(structured) if isinstance(structured, dict) else {}
        text_parts = [str(b.get("text", "")) for b in (result.get("content") or []) if isinstance(b, dict) and b.get("type") == "text"]
        taints = ["external_tool_output", "unverified_tool_output", "untrusted_mcp_content"]
        joined = "\n".join(text_parts).lower()
        if any(fragment in joined for fragment in MCPMetadataGuard.suspicious_fragments):
            taints.append("prompt_injection_suspected")
        return LiveMCPResult(self.server_name, self.trust_domain, name, data, tuple(text_parts), tuple(taints))

    def _request(self, method: str, params: dict[str, Any], *, name: str | None = None) -> tuple[dict[str, Any], Any]:
        self._request_id += 1
        request_id = self._request_id
        request_params = dict(params)
        request_params["_meta"] = {CLIENT_INFO_KEY: {"name": self.client_name, "version": self.client_version}}
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": request_params}
        headers = {"Content-Type": "application/json", "MCP-Protocol-Version": MCP_PROTOCOL_VERSION, "Mcp-Method": method, **self.endpoint_policy.authorization_headers()}
        if name is not None:
            headers["Mcp-Name"] = name
        req = request.Request(self.endpoint, data=json.dumps(payload, separators=(",", ":")).encode(), headers=headers, method="POST")
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                response_payload = json.loads(response.read())
                response_headers = response.headers
        except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise MCPProtocolError("mcp_transport_failure") from exc
        if response_payload.get("jsonrpc") != "2.0":
            raise MCPProtocolError("invalid_jsonrpc_version")
        if response_payload.get("id") != request_id:
            raise MCPProtocolError("mcp_response_id_mismatch")
        if "error" in response_payload:
            raise MCPProtocolError(f"mcp_error:{response_payload['error']}")
        result = response_payload.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError("mcp_result_missing")
        return result, response_headers

    def _verify_server(self, headers: Any) -> None:
        if headers.get("X-AATG-Lab-Server-ID") != self.server_pin.server_id:
            raise MCPTrustError("mcp_server_identity_mismatch")

    def _verify_tool_pin(self, tool: dict[str, Any]) -> None:
        name = str(tool.get("name", ""))
        pin = self.server_pin.tools.get(name)
        if pin is None:
            raise MCPTrustError(f"untrusted_tool:{name}")
        if canonical_digest(tool.get("inputSchema") or {}) != pin.input_schema_digest:
            raise MCPTrustError(f"tool_schema_mismatch:{name}")
