from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi import FastAPI

from .audit import AuditJournal
from .gateway import TrustGateway
from .models import ActionProposal, Approval, ExecutionResult, PolicyDecision
from .policy import PolicyEngine
from .tools import ToolRegistry

ROOT = Path(__file__).resolve().parents[2]
policy = PolicyEngine(ROOT / "policies" / "default.json")
audit = AuditJournal(ROOT / "runtime" / "audit.jsonl")
tools = ToolRegistry()
gateway = TrustGateway(policy=policy, audit=audit, tools=tools)

app = FastAPI(
    title="AI Agent Trust Gateway",
    version="0.1.0",
    description="Policy-enforced security boundary for AI agent tool execution.",
)


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "audit_chain_valid": audit.verify()}


@app.post("/v1/proposals/evaluate", response_model=PolicyDecision)
def evaluate(proposal: ActionProposal) -> PolicyDecision:
    return gateway.evaluate(proposal)


@app.post("/v1/proposals/execute", response_model=ExecutionResult)
def execute(proposal: ActionProposal, approval_digest: str | None = None, approver: str | None = None, approval_expires_at: datetime | None = None) -> ExecutionResult:
    approval = None
    if approval_digest and approver and approval_expires_at:
        approval = Approval(
            proposal_digest=approval_digest,
            approver=approver,
            expires_at=approval_expires_at,
        )
    return gateway.execute(proposal, approval=approval)


@app.get("/v1/audit/verify")
def verify_audit() -> dict[str, bool]:
    return {"valid": audit.verify()}
