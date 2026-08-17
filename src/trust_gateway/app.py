from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path

from fastapi import FastAPI, Header

from .audit import AuditJournal
from .capabilities import CapabilityIssuer
from .gateway import TrustGateway
from .identity import WorkloadIdentity
from .models import ActionProposal, Approval, ExecutionResult, PolicyDecision
from .policy import PolicyEngine
from .tools import ToolRegistry

ROOT = Path(__file__).resolve().parents[2]
policy = PolicyEngine(ROOT / "policies" / "default.json")
audit = AuditJournal(ROOT / "runtime" / "audit.jsonl")
tools = ToolRegistry()

capability_secret = os.getenv("AATG_CAPABILITY_SECRET")
capabilities = CapabilityIssuer(capability_secret.encode()) if capability_secret else None

identity_secret = os.getenv("AATG_IDENTITY_SECRET")
identity_key_id = os.getenv("AATG_IDENTITY_KEY_ID", "default")
identities = WorkloadIdentity({identity_key_id: identity_secret.encode()}) if identity_secret else None

gateway = TrustGateway(
    policy=policy,
    audit=audit,
    tools=tools,
    capabilities=capabilities,
    identities=identities,
)

app = FastAPI(
    title="AI Agent Trust Gateway",
    version="0.2.0",
    description="Policy-enforced security boundary for AI agent tool execution.",
)


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "audit_chain_valid": audit.verify(),
        "capability_enforcement": capabilities is not None,
        "workload_identity_enforcement": identities is not None,
    }


@app.post("/v1/proposals/evaluate", response_model=PolicyDecision)
def evaluate(proposal: ActionProposal) -> PolicyDecision:
    return gateway.evaluate(proposal)


@app.post("/v1/proposals/execute", response_model=ExecutionResult)
def execute(
    proposal: ActionProposal,
    approval_digest: str | None = None,
    approver: str | None = None,
    approval_expires_at: datetime | None = None,
    approval_id: str | None = None,
    capability_token: str | None = Header(default=None, alias="X-AATG-Capability"),
    identity_token: str | None = Header(default=None, alias="X-AATG-Identity"),
) -> ExecutionResult:
    approval = None
    if approval_digest and approver and approval_expires_at:
        kwargs = {
            "proposal_digest": approval_digest,
            "approver": approver,
            "expires_at": approval_expires_at,
        }
        if approval_id:
            kwargs["approval_id"] = approval_id
        approval = Approval(**kwargs)
    return gateway.execute(
        proposal,
        approval=approval,
        capability_token=capability_token,
        identity_token=identity_token,
    )


@app.get("/v1/audit/verify")
def verify_audit() -> dict[str, bool]:
    return {"valid": audit.verify()}
