from datetime import timedelta

import pytest

from trust_gateway.capabilities import CapabilityError, CapabilityIssuer
from trust_gateway.mcp import MCPToolAdapter


SECRET = b"another-test-capability-secret-32-bytes!!"


def test_capability_tampering_is_rejected():
    issuer = CapabilityIssuer(SECRET)
    token = issuer.issue(subject="agent-a", tool="notes", action="append")
    body, signature = token.split(".", 1)
    tampered = f"{body}x.{signature}"
    with pytest.raises(CapabilityError):
        issuer.verify(tampered)


def test_expired_capability_is_rejected():
    issuer = CapabilityIssuer(SECRET)
    token = issuer.issue(subject="agent-a", tool="notes", action="append", ttl=timedelta(seconds=-1))
    with pytest.raises(CapabilityError, match="capability_expired"):
        issuer.verify(token)


def test_mcp_output_is_tainted_until_verified():
    adapter = MCPToolAdapter(
        server="demo-mcp",
        call=lambda name, args: {"value": args["value"]},
        verify_result=lambda name, args, data: data["value"] == args["value"],
    )
    result = adapter.execute("echo", {"value": "hello"})
    assert "external_tool_output" in result.taints
    assert adapter.verify("echo", {"value": "hello"}, result) is True


def test_mcp_without_independent_verifier_fails_closed():
    adapter = MCPToolAdapter(server="demo-mcp", call=lambda name, args: {"ok": True})
    result = adapter.execute("unsafe", {})
    assert adapter.verify("unsafe", {}, result) is False
