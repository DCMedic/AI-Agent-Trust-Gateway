from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest

from trust_gateway.information_flow import InformationFlowPolicy
from trust_gateway.mcp_live import (
    MCPServerPin,
    MCPToolPin,
    MCPTrustError,
    StatelessHTTPMCPClient,
    canonical_digest,
)
from trust_gateway.models import RiskTier


SCHEMA = {
    "type": "object",
    "properties": {"query": {"type": "string", "maxLength": 200}},
    "required": ["query"],
    "additionalProperties": False,
}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def pin() -> MCPServerPin:
    return MCPServerPin(
        server_id="aatg-lab-server",
        tools={"lab.search": MCPToolPin("lab.search", canonical_digest(SCHEMA))},
    )


@contextmanager
def lab_server(mode: str):
    port = free_port()
    env = os.environ.copy()
    env["AATG_LAB_MODE"] = mode
    env["AATG_LAB_PORT"] = str(port)
    process = subprocess.Popen(
        [sys.executable, "tools/lab_mcp_server.py"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 3
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.03)
        else:
            raise RuntimeError("lab_server_start_timeout")
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def test_live_stateless_mcp_transport_and_pinned_schema():
    with lab_server("trusted") as endpoint:
        client = StatelessHTTPMCPClient(endpoint, server_pin=pin())
        discovery = client.discover()
        assert discovery["protocolVersion"] == "2026-07-28"
        tools = client.list_tools()
        assert [tool.name for tool in tools] == ["lab.search"]
        result = client.call_tool("lab.search", {"query": "gulf telemetry"})
        assert result.data["finding"] == "benign lab evidence"
        assert "untrusted_mcp_content" in result.taints


def test_malicious_tool_description_is_detected_but_not_authority():
    with lab_server("malicious_metadata") as endpoint:
        client = StatelessHTTPMCPClient(endpoint, server_pin=pin())
        tools = client.list_tools()
        assert "suspicious_tool_metadata" in tools[0].metadata_taints


def test_server_impersonation_is_rejected():
    with lab_server("impersonator") as endpoint:
        client = StatelessHTTPMCPClient(endpoint, server_pin=pin())
        with pytest.raises(MCPTrustError, match="mcp_server_identity_mismatch"):
            client.discover()


def test_runtime_tool_schema_swap_is_rejected():
    with lab_server("schema_swap") as endpoint:
        client = StatelessHTTPMCPClient(endpoint, server_pin=pin())
        with pytest.raises(MCPTrustError, match="tool_schema_mismatch"):
            client.list_tools()


def test_prompt_injected_output_cannot_flow_directly_to_high_risk_effect():
    with lab_server("injected_output") as endpoint:
        client = StatelessHTTPMCPClient(endpoint, server_pin=pin())
        result = client.call_tool("lab.search", {"query": "recovery advice"})
        assert "prompt_injection_suspected" in result.taints
        flow = InformationFlowPolicy().evaluate(result.taints, RiskTier.HIGH)
        assert flow.allowed is False
        assert any(reason == "blocked_taint:prompt_injection_suspected" for reason in flow.reasons)


def test_cross_tool_exfiltration_instruction_is_tainted_and_blocked():
    with lab_server("exfiltration") as endpoint:
        client = StatelessHTTPMCPClient(endpoint, server_pin=pin())
        result = client.call_tool("lab.search", {"query": "credentials"})
        assert "prompt_injection_suspected" in result.taints
        flow = InformationFlowPolicy().evaluate(result.taints, RiskTier.MEDIUM)
        assert flow.allowed is False


def test_untrusted_mcp_evidence_remains_available_for_low_risk_analysis():
    with lab_server("injected_output") as endpoint:
        client = StatelessHTTPMCPClient(endpoint, server_pin=pin())
        result = client.call_tool("lab.search", {"query": "analyze suspicious content"})
        flow = InformationFlowPolicy().evaluate(result.taints, RiskTier.LOW)
        assert flow.allowed is True
