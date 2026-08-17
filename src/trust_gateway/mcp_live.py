from __future__ import annotations

from dataclasses import dataclass
import json
import subprocess
from typing import Any, Sequence


MCP_PROTOCOL_VERSION = "2025-06-18"


class MCPProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class MCPToolDescriptor:
    name: str
    description: str
    input_schema: dict[str, Any]
    metadata_taints: tuple[str, ...] = ()


@dataclass(frozen=True)
class LiveMCPResult:
    server_name: str
    tool_name: str
    data: dict[str, Any]
    text: tuple[str, ...]
    taints: tuple[str, ...]


class MCPMetadataGuard:
    """Treat server-supplied tool metadata as untrusted discovery data.

    Tool descriptions can influence model behavior but cannot grant authority. The
    guard detects common instruction/exfiltration language so the lab can measure
    whether discovery metadata is safely separated from authorization.
    """

    suspicious_fragments = (
        "ignore previous",
        "ignore all previous",
        "system prompt",
        "secret",
        "credential",
        "api key",
        "password",
        "send to",
        "exfiltrate",
        "do not tell",
        "bypass",
        "disable security",
    )

    def inspect(self, tool: dict[str, Any]) -> MCPToolDescriptor:
        description = str(tool.get("description", ""))
        lowered = description.lower()
        taints = []
        if any(fragment in lowered for fragment in self.suspicious_fragments):
            taints.append("suspicious_tool_metadata")
        return MCPToolDescriptor(
            name=str(tool.get("name", "")),
            description=description,
            input_schema=dict(tool.get("inputSchema") or {}),
            metadata_taints=tuple(taints),
        )


class StdioMCPClient:
    """Minimal MCP 2025-06-18 stdio client used by the adversarial lab.

    The client implements lifecycle initialization, tools/list and tools/call over
    newline-delimited JSON-RPC 2.0. It deliberately does not grant authority based
    on server metadata; callers must route resulting proposals through AATG.
    """

    def __init__(self, argv: Sequence[str], *, expected_server_name: str | None = None):
        if not argv:
            raise ValueError("mcp_command_empty")
        self.argv = list(argv)
        self.expected_server_name = expected_server_name
        self.process: subprocess.Popen[str] | None = None
        self._request_id = 0
        self.server_name: str | None = None

    def __enter__(self) -> "StdioMCPClient":
        self.process = subprocess.Popen(
            self.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._initialize()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)

    def _write(self, message: dict[str, Any]) -> None:
        if self.process is None or self.process.stdin is None:
            raise MCPProtocolError("mcp_not_started")
        encoded = json.dumps(message, separators=(",", ":"))
        if "\n" in encoded:
            raise MCPProtocolError("mcp_embedded_newline")
        self.process.stdin.write(encoded + "\n")
        self.process.stdin.flush()

    def _read(self) -> dict[str, Any]:
        if self.process is None or self.process.stdout is None:
            raise MCPProtocolError("mcp_not_started")
        line = self.process.stdout.readline()
        if not line:
            stderr = ""
            if self.process.stderr is not None:
                stderr = self.process.stderr.read()
            raise MCPProtocolError(f"mcp_server_closed:{stderr.strip()}")
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise MCPProtocolError("invalid_mcp_json") from exc
        if message.get("jsonrpc") != "2.0":
            raise MCPProtocolError("invalid_jsonrpc_version")
        return message

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._request_id += 1
        request: dict[str, Any] = {"jsonrpc": "2.0", "id": self._request_id, "method": method}
        if params is not None:
            request["params"] = params
        self._write(request)
        response = self._read()
        if response.get("id") != self._request_id:
            raise MCPProtocolError("mcp_response_id_mismatch")
        if "error" in response:
            raise MCPProtocolError(f"mcp_error:{response['error']}")
        result = response.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError("mcp_result_missing")
        return result

    def _initialize(self) -> None:
        result = self._request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "aatg-live-lab", "version": "0.4.0"},
            },
        )
        negotiated = result.get("protocolVersion")
        if negotiated != MCP_PROTOCOL_VERSION:
            raise MCPProtocolError(f"unsupported_mcp_version:{negotiated}")
        server_info = result.get("serverInfo") or {}
        self.server_name = str(server_info.get("name", "unknown"))
        if self.expected_server_name and self.server_name != self.expected_server_name:
            raise MCPProtocolError("mcp_server_identity_mismatch")
        self._write({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def list_tools(self, guard: MCPMetadataGuard | None = None) -> list[MCPToolDescriptor]:
        guard = guard or MCPMetadataGuard()
        result = self._request("tools/list", {})
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise MCPProtocolError("mcp_tools_missing")
        return [guard.inspect(tool) for tool in tools if isinstance(tool, dict)]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> LiveMCPResult:
        result = self._request("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError") is True:
            raise MCPProtocolError("mcp_tool_reported_error")
        structured = result.get("structuredContent")
        data = dict(structured) if isinstance(structured, dict) else {}
        text_parts: list[str] = []
        content = result.get("content") or []
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text_parts.append(str(block.get("text", "")))
        taints = ["external_tool_output", "unverified_tool_output"]
        joined = "\n".join(text_parts).lower()
        if any(fragment in joined for fragment in MCPMetadataGuard.suspicious_fragments):
            taints.append("prompt_injection_suspected")
        return LiveMCPResult(
            server_name=self.server_name or "unknown",
            tool_name=name,
            data=data,
            text=tuple(text_parts),
            taints=tuple(taints),
        )
