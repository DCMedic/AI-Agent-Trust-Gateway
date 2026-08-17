from __future__ import annotations

from datetime import datetime, timezone

from .audit import AuditJournal
from .models import ActionProposal, Approval, Decision, ExecutionResult, PolicyDecision
from .policy import PolicyEngine
from .tools import ToolRegistry


class TrustGateway:
    def __init__(self, policy: PolicyEngine, audit: AuditJournal, tools: ToolRegistry):
        self.policy = policy
        self.audit = audit
        self.tools = tools

    def evaluate(self, proposal: ActionProposal) -> PolicyDecision:
        self.audit.append("proposal_received", {"proposal": proposal.model_dump(mode="json")})
        decision = self.policy.evaluate(proposal)
        self.audit.append(
            "policy_decision",
            {
                "proposal_id": proposal.proposal_id,
                "proposal_digest": proposal.digest(),
                "decision": decision.model_dump(mode="json"),
            },
        )
        return decision

    def execute(self, proposal: ActionProposal, approval: Approval | None = None) -> ExecutionResult:
        decision = self.evaluate(proposal)

        if decision.decision == Decision.DENY:
            self.audit.append("execution_denied", {"proposal_id": proposal.proposal_id, "reasons": decision.reasons})
            return ExecutionResult(proposal_id=proposal.proposal_id, status="denied")

        if decision.decision == Decision.REQUIRE_APPROVAL:
            if approval is None:
                self.audit.append("approval_missing", {"proposal_id": proposal.proposal_id})
                return ExecutionResult(proposal_id=proposal.proposal_id, status="approval_required")
            approval_error = self._validate_approval(proposal, approval)
            if approval_error:
                self.audit.append(
                    "approval_rejected",
                    {"proposal_id": proposal.proposal_id, "approval_id": approval.approval_id, "reason": approval_error},
                )
                return ExecutionResult(proposal_id=proposal.proposal_id, status="approval_rejected")
            self.audit.append(
                "approval_accepted",
                {"proposal_id": proposal.proposal_id, "approval_id": approval.approval_id, "approver": approval.approver},
            )

        try:
            output = self.tools.execute(proposal.tool, proposal.action, proposal.arguments)
        except Exception as exc:
            self.audit.append(
                "execution_failed",
                {"proposal_id": proposal.proposal_id, "error": type(exc).__name__, "detail": str(exc)},
            )
            return ExecutionResult(proposal_id=proposal.proposal_id, status="failed")

        verified = self.tools.verify(proposal.tool, proposal.action, proposal.arguments, output)
        self.audit.append(
            "execution_completed",
            {"proposal_id": proposal.proposal_id, "output": output, "verified": verified},
        )
        return ExecutionResult(
            proposal_id=proposal.proposal_id,
            status="completed" if verified else "verification_failed",
            output=output,
            verified=verified,
        )

    @staticmethod
    def _validate_approval(proposal: ActionProposal, approval: Approval) -> str | None:
        if approval.proposal_digest != proposal.digest():
            return "proposal_digest_mismatch"
        if approval.expires_at <= datetime.now(timezone.utc):
            return "approval_expired"
        if not approval.approver.strip():
            return "approver_missing"
        return None
