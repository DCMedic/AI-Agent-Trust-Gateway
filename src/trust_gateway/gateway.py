from __future__ import annotations

from datetime import datetime, timezone

from .approvals import ApprovalLedger
from .audit import AuditJournal
from .capabilities import CapabilityError, CapabilityIssuer
from .models import ActionProposal, Approval, Decision, ExecutionResult, PolicyDecision, RiskTier
from .policy import PolicyEngine
from .tools import ToolRegistry


class TrustGateway:
    def __init__(
        self,
        policy: PolicyEngine,
        audit: AuditJournal,
        tools: ToolRegistry,
        approvals: ApprovalLedger | None = None,
        capabilities: CapabilityIssuer | None = None,
    ):
        self.policy = policy
        self.audit = audit
        self.tools = tools
        self.approvals = approvals or ApprovalLedger()
        self.capabilities = capabilities

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

    def execute(
        self,
        proposal: ActionProposal,
        approval: Approval | None = None,
        capability_token: str | None = None,
    ) -> ExecutionResult:
        decision = self.evaluate(proposal)

        if decision.decision == Decision.DENY:
            self.audit.append("execution_denied", {"proposal_id": proposal.proposal_id, "reasons": decision.reasons})
            return ExecutionResult(proposal_id=proposal.proposal_id, status="denied")

        capability_id: str | None = None
        if self.capabilities is not None and decision.risk in {RiskTier.MEDIUM, RiskTier.HIGH}:
            if not capability_token:
                self.audit.append("capability_missing", {"proposal_id": proposal.proposal_id})
                return ExecutionResult(proposal_id=proposal.proposal_id, status="capability_required")
            try:
                claims = self.capabilities.authorize(
                    capability_token,
                    subject=proposal.agent_id,
                    tool=proposal.tool,
                    action=proposal.action,
                    arguments=proposal.arguments,
                )
            except CapabilityError as exc:
                self.audit.append(
                    "capability_rejected",
                    {"proposal_id": proposal.proposal_id, "reason": str(exc)},
                )
                return ExecutionResult(proposal_id=proposal.proposal_id, status="capability_rejected")
            capability_id = claims.jti
            self.audit.append(
                "capability_accepted",
                {
                    "proposal_id": proposal.proposal_id,
                    "capability_id": claims.jti,
                    "subject": claims.subject,
                    "scope": f"{claims.tool}.{claims.action}",
                },
            )

        if decision.decision == Decision.REQUIRE_APPROVAL:
            if approval is None:
                self.audit.append("approval_missing", {"proposal_id": proposal.proposal_id})
                return ExecutionResult(proposal_id=proposal.proposal_id, status="approval_required", capability_id=capability_id)
            approval_error = self._validate_approval(proposal, approval)
            if approval_error:
                self.audit.append(
                    "approval_rejected",
                    {"proposal_id": proposal.proposal_id, "approval_id": approval.approval_id, "reason": approval_error},
                )
                return ExecutionResult(proposal_id=proposal.proposal_id, status="approval_rejected", capability_id=capability_id)
            if not self.approvals.consume(approval.approval_id):
                self.audit.append(
                    "approval_replay_blocked",
                    {"proposal_id": proposal.proposal_id, "approval_id": approval.approval_id},
                )
                return ExecutionResult(proposal_id=proposal.proposal_id, status="approval_rejected", capability_id=capability_id)
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
            return ExecutionResult(proposal_id=proposal.proposal_id, status="failed", capability_id=capability_id)

        taints = self.tools.taints(proposal.tool, proposal.action, output)
        verified = self.tools.verify(proposal.tool, proposal.action, proposal.arguments, output)
        if verified:
            taints = [t for t in taints if t != "unverified_tool_output"]
        self.audit.append(
            "execution_completed",
            {
                "proposal_id": proposal.proposal_id,
                "output": output,
                "verified": verified,
                "output_taints": taints,
                "capability_id": capability_id,
            },
        )
        return ExecutionResult(
            proposal_id=proposal.proposal_id,
            status="completed" if verified else "verification_failed",
            output=output,
            verified=verified,
            output_taints=taints,
            capability_id=capability_id,
        )

    def _validate_approval(self, proposal: ActionProposal, approval: Approval) -> str | None:
        if self.approvals.is_consumed(approval.approval_id):
            return "approval_already_consumed"
        if approval.proposal_digest != proposal.digest():
            return "proposal_digest_mismatch"
        if approval.expires_at <= datetime.now(timezone.utc):
            return "approval_expired"
        if not approval.approver.strip():
            return "approver_missing"
        return None
