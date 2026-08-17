from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from trust_gateway.audit import AuditJournal
from trust_gateway.capabilities import CapabilityIssuer
from trust_gateway.gateway import TrustGateway
from trust_gateway.models import ActionProposal, Approval
from trust_gateway.policy import PolicyEngine
from trust_gateway.tools import ToolRegistry


SECRET = b"scenario-capability-secret-32-bytes-min!!"


def main() -> None:
    with TemporaryDirectory() as tmp:
        gateway = TrustGateway(
            policy=PolicyEngine("policies/default.json"),
            audit=AuditJournal(Path(tmp) / "audit.jsonl"),
            tools=ToolRegistry(),
            capabilities=CapabilityIssuer(SECRET),
        )

        scenarios = []

        scenarios.append((
            "unknown agent",
            gateway.execute(ActionProposal(agent_id="unknown", tool="notes", action="read", purpose="probe")),
        ))

        scenarios.append((
            "unauthorized tool",
            gateway.execute(ActionProposal(
                agent_id="research-agent",
                tool="service",
                action="restart",
                arguments={"service": "demo-api"},
                purpose="attempt privilege expansion",
            )),
        ))

        scenarios.append((
            "parameter smuggling",
            gateway.execute(ActionProposal(
                agent_id="research-agent",
                tool="notes",
                action="append",
                arguments={"text": "hello", "path": "/tmp/escape"},
                purpose="test constraints",
            )),
        ))

        bounded_write = ActionProposal(
            agent_id="research-agent",
            tool="notes",
            action="append",
            arguments={"text": "bounded research note"},
            purpose="store research result",
        )
        scenarios.append(("capability required", gateway.execute(bounded_write)))
        write_cap = gateway.capabilities.issue(
            subject=bounded_write.agent_id,
            tool=bounded_write.tool,
            action=bounded_write.action,
            constraints={"allowed_keys": ["text"]},
        )
        scenarios.append(("capability-authorized write", gateway.execute(bounded_write, capability_token=write_cap)))

        high_risk = ActionProposal(
            agent_id="operations-agent",
            tool="service",
            action="restart",
            arguments={"service": "demo-api"},
            purpose="recover demo service",
        )
        high_cap = gateway.capabilities.issue(
            subject=high_risk.agent_id,
            tool=high_risk.tool,
            action=high_risk.action,
            constraints={"allowed_keys": ["service"], "allowed_values": {"service": ["demo-api"]}},
        )
        scenarios.append(("approval required", gateway.execute(high_risk, capability_token=high_cap)))

        valid_approval = Approval(
            proposal_digest=high_risk.digest(),
            approver="human@example.test",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        scenarios.append(("approved high-risk action", gateway.execute(high_risk, valid_approval, high_cap)))
        scenarios.append(("single-use approval replay", gateway.execute(high_risk, valid_approval, high_cap)))

        tampered = high_risk.model_copy(update={"purpose": "changed after approval"})
        tampered_cap = gateway.capabilities.issue(subject=tampered.agent_id, tool=tampered.tool, action=tampered.action)
        fresh_approval = Approval(
            proposal_digest=high_risk.digest(),
            approver="human@example.test",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        scenarios.append(("approval bound to exact proposal", gateway.execute(tampered, fresh_approval, tampered_cap)))

        gateway.tools.fail_next = True
        scenarios.append((
            "simulated adapter failure",
            gateway.execute(ActionProposal(agent_id="research-agent", tool="notes", action="read", purpose="test failure")),
        ))

        for name, result in scenarios:
            print(
                f"{name:40} -> {result.status:22} "
                f"verified={result.verified} taints={','.join(result.output_taints) or '-'}"
            )

        print(f"audit chain valid{'':23} -> {gateway.audit.verify()}")


if __name__ == "__main__":
    main()
