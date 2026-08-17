from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from trust_gateway.audit import AuditJournal
from trust_gateway.gateway import TrustGateway
from trust_gateway.models import ActionProposal, Approval
from trust_gateway.policy import PolicyEngine
from trust_gateway.tools import ToolRegistry


def main() -> None:
    with TemporaryDirectory() as tmp:
        gateway = TrustGateway(
            policy=PolicyEngine("policies/default.json"),
            audit=AuditJournal(Path(tmp) / "audit.jsonl"),
            tools=ToolRegistry(),
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

        high_risk = ActionProposal(
            agent_id="operations-agent",
            tool="service",
            action="restart",
            arguments={"service": "demo-api"},
            purpose="recover demo service",
        )
        scenarios.append(("approval required", gateway.execute(high_risk)))

        valid_approval = Approval(
            proposal_digest=high_risk.digest(),
            approver="human@example.test",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        scenarios.append(("approved high-risk action", gateway.execute(high_risk, valid_approval)))

        tampered = high_risk.model_copy(update={"purpose": "changed after approval"})
        scenarios.append(("approval replay after proposal mutation", gateway.execute(tampered, valid_approval)))

        low_risk = ActionProposal(
            agent_id="research-agent",
            tool="notes",
            action="append",
            arguments={"text": "bounded research note"},
            purpose="store research result",
        )
        scenarios.append(("authorized bounded write", gateway.execute(low_risk)))

        gateway.tools.fail_next = True
        scenarios.append((
            "simulated adapter failure",
            gateway.execute(ActionProposal(agent_id="research-agent", tool="notes", action="read", purpose="test failure")),
        ))

        for name, result in scenarios:
            print(f"{name:40} -> {result.status:22} verified={result.verified}")

        print(f"audit chain valid{'':23} -> {gateway.audit.verify()}")


if __name__ == "__main__":
    main()
