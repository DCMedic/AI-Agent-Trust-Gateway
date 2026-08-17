from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class MCPResult:
    server: str
    tool: str
    data: dict[str, Any]
    taints: tuple[str, ...] = ("external_tool_output",)


@dataclass
class MCPToolAdapter:
    """Small protocol boundary for MCP-style tools.

    The gateway owns authorization; this adapter only transports an already-approved call
    and labels the returned data as external/untrusted evidence until verification occurs.
    """

    server: str
    call: Callable[[str, dict[str, Any]], dict[str, Any]]
    verify_result: Callable[[str, dict[str, Any], dict[str, Any]], bool] | None = None

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> MCPResult:
        result = self.call(tool_name, arguments)
        if not isinstance(result, dict):
            raise TypeError("mcp_result_must_be_mapping")
        return MCPResult(server=self.server, tool=tool_name, data=result)

    def verify(self, tool_name: str, arguments: dict[str, Any], result: MCPResult) -> bool:
        if result.server != self.server or result.tool != tool_name:
            return False
        if self.verify_result is None:
            return False
        return bool(self.verify_result(tool_name, arguments, result.data))
