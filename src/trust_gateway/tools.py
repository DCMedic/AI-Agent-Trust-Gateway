from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ToolRegistry:
    notes: list[str] = field(default_factory=list)
    services: dict[str, str] = field(default_factory=lambda: {"demo-api": "running"})
    fail_next: bool = False

    def execute(self, tool: str, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("simulated_tool_failure")

        handler: Callable[[dict[str, Any]], dict[str, Any]] | None = {
            ("notes", "read"): self._notes_read,
            ("notes", "append"): self._notes_append,
            ("service", "restart"): self._service_restart,
        }.get((tool, action))
        if handler is None:
            raise KeyError(f"unknown_tool_action:{tool}.{action}")
        return handler(arguments)

    def verify(self, tool: str, action: str, arguments: dict[str, Any], output: dict[str, Any]) -> bool:
        if (tool, action) == ("notes", "read"):
            return output.get("count") == len(self.notes)
        if (tool, action) == ("notes", "append"):
            return bool(self.notes) and self.notes[-1] == arguments.get("text")
        if (tool, action) == ("service", "restart"):
            service = arguments.get("service")
            return self.services.get(service) == "running" and output.get("state") == "running"
        return False

    def _notes_read(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"notes": list(self.notes), "count": len(self.notes)}

    def _notes_append(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self.notes.append(arguments["text"])
        return {"index": len(self.notes) - 1, "stored": True}

    def _service_restart(self, arguments: dict[str, Any]) -> dict[str, Any]:
        service = arguments["service"]
        if service not in self.services:
            raise KeyError("unknown_service")
        self.services[service] = "running"
        return {"service": service, "state": "running", "simulated": True}
