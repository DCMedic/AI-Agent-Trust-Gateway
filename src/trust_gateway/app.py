from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path

from fastapi import FastAPI, Header
from pydantic import BaseModel, Field

from .approvals import SQLiteApprovalLedger
from .audit import AuditJournal
from .capabilities import CapabilityIssuer, SQLiteCapabilityRevocationList
from .execution_state import SQLiteExecutionLedger
from .gateway import TrustGateway
from .identity import WorkloadIdentity
from .models import ActionProposal, Approval, ApprovalSet, ExecutionResult, PolicyDecision
from .policy import PolicyEngine
from .policy_bundle import PolicyBundleVerifier
from .tools import ToolRegistry

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "runtime"
RUNTIME.mkdir(parents=True, exist_ok=True)
AUTHORITY_DB = Path(os.getenv("AATG_AUTHORITY_DB", str(RUNTIME / "authority.db")))

policy_path = Path(os.getenv("AATG_POLICY_PATH", str(ROOT / "policies" / "default.json")))
policy_secret = os.getenv("AATG_POLICY_SECRET")
policy_key_id = os.getenv("AATG_POLICY_KEY_ID", "default")
require_signed_policy = os.getenv("AATG_REQUIRE_SIGNED_POLICY", "false").lower() in {"1", "true", "yes"}
policy_verifier = PolicyBundleVerifier({policy_key_id: policy_secret.encode()}) if policy_secret else None
policy = PolicyEngine(
    policy_path,
    verifier=policy_verifier,
    require_signed_bundle=require_signed_policy,
)

audit = AuditJournal(RUNTIME / "audit.jsonl")
tools = ToolRegistry()
approvals = SQLiteApprovalLedger(AUTHORITY_DB)
executions = SQLiteExecutionLedger(AUTHORITY_DB)
revocations = SQLiteCapabilityRevocationList(AUTHORITY_DB)

capability_secret = os.getenv("AATG_CAPABILITY_SECRET")
capabilities = CapabilityIssuer(capability_secret.encode(), revocations=revocations) if capability_secret else None

identity_secret = os.getenv("AATG_IDENTITY_SECRET")
identity_key_id = os.getenv("AATG_IDENTITY_KEY_ID", "default")
identities = WorkloadIdentity({identity_key_id: identity_secret.encode()}) if identity_secret else None

approval_quorum = int(os.getenv("AATG_HIGH_RISK_APPROVAL_QUORUM", "1"))

gateway = TrustGateway(
    policy=policy,
    audit=audit,
    tools=tools,
    capabilities=capabilities,
    identities=identities,
    approvals=approvals,
    executions=executions,
    high_risk_approval_quorum=approval_quorum,
)

app = FastAPI(
    title="AI Agent Trust Gateway",
    version="0.4.0",
    description="Policy-provenanced AI agent security boundary with taint-aware MCP information-flow controls.",
)


class ControlledExecutionRequest(BaseModel):
    proposal: ActionProposal
    approvals: list[Approval] = Field(default_factory=list)


@app.get("/health")
def health() -> dict[str, object]:
    provenance = policy.provenance
    return {
        "status": "ok",
        "version": "0.4.0",
        "audit_chain_valid": audit.verify(),
        "capability_enforcement": capabilities is not None,
        "workload_identity_enforcement": identities is not None,
        "durable_authority_state": True,
        "taint_aware_information_flow": True,
        "high_risk_approval_quorum": approval_quorum,
        "signed_policy": provenance is not None,
        "policy_id": provenance.policy_id if provenance else None,
        "policy_version": provenance.version if provenance else None,
        "policy_digest": provenance.digest if provenance else None,
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


@app.post("/v1/proposals/execute-controlled", response_model=ExecutionResult)
def execute_controlled(
    request: ControlledExecutionRequest,
    capability_token: str | None = Header(default=None, alias="X-AATG-Capability"),
    identity_token: str | None = Header(default=None, alias="X-AATG-Identity"),
) -> ExecutionResult:
    approval = None
    if len(request.approvals) == 1:
        approval = request.approvals[0]
    elif len(request.approvals) > 1:
        approval = ApprovalSet(approvals=request.approvals)
    return gateway.execute(
        request.proposal,
        approval=approval,
        capability_token=capability_token,
        identity_token=identity_token,
    )


@app.post("/v1/capabilities/revoke")
def revoke_capability(
    capability_token: str = Header(alias="X-AATG-Capability"),
) -> dict[str, str]:
    if capabilities is None:
        return {"status": "capability_enforcement_disabled"}
    capability_id = capabilities.revoke(capability_token)
    audit.append("capability_revoked", {"capability_id": capability_id})
    return {"status": "revoked", "capability_id": capability_id}


@app.get("/v1/audit/verify")
def verify_audit() -> dict[str, bool]:
    return {"valid": audit.verify()}
