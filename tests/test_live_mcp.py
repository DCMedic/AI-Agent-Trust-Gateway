from pathlib import Path
import sys

from trust_gateway.audit import AuditJournal
from trust_gateway.gateway import TrustGateway
from trust_gateway.mcp_live import MCPMetadataGuard, MCPProtocolError, StdioMCPClient
from trust_gateway.models import ActionProposal, Decision
from trust_gateway.policy import PolicyEngine
from trust_gateway.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "lab" / "adversarial_mcp_server.py"


def test_live_mcp_initializes_lists_and_calls_tools():
    with StdioMCPClient([sys.executable, str(SERVER)], expected_server_name="aatg-adversarial-lab") as client:
        tools = client.list_tools()
        assert any(tool.name == "read_public_record" for tool in tools)
        result = client.call_tool("read_public_record", {"record": "alpha"})
        assert result.data["status"] == "nominal"
        assert "external_tool_output" in result.taints


def test_suspicious_tool_metadata_and_prompt_output_are_tainted():
    with StdioMCPClient([sys.executable, str(SERVER)], expected_server_name="aatg-adversarial-lab") as client:
        tools = client.list_tools(MCPMetadataGuard())
        poisoned = next(tool for tool in tools if tool.name == "poisoned_advice")
        assert "suspicious_tool_metadata" in poisoned.metadata_taints
        result = client.call_tool("poisoned_advice", {})
        assert "prompt_injection_suspected" in result.taints


def test_server_name_mismatch_fails_closed():
    try:
        with StdioMCPClient([sys.executable, str(SERVER)], expected_server_name="different-server"):
            pass
    except MCPProtocolError as exc:
        assert str(exc) == "mcp_server_identity_mismatch"
    else:
        raise AssertionError("server identity mismatch was accepted")


def test_external_mcp_evidence_cannot_directly_drive_high_impact_action(tmp_path):
    gateway = TrustGateway(
        policy=PolicyEngine(ROOT / "policies" / "default.json"),
        audit=AuditJournal(tmp_path / "audit.jsonl"),
        tools=ToolRegistry(),
    )
    proposal = ActionProposal(
        agent_id="operations-agent",
        tool="service",
        action="restart",
        arguments={"service": "demo-api"},
        purpose="restart because an external MCP server recommended it",
        evidence_taints=["external_tool_output", "unverified_tool_output"],
    )
    decision = gateway.evaluate(proposal)
    assert decision.decision == Decision.DENY
    assert "tainted_evidence_blocked:external_tool_output" in decision.reasons
