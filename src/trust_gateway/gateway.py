from __future__ import annotations

from datetime import datetime, timezone

from .approvals import ApprovalLedger, ApprovalStore
from .audit import AuditJournal
from .capabilities import CapabilityError, CapabilityIssuer
from .execution_state import ExecutionStateStore
from .identity import IdentityError, WorkloadIdentity
from .models import ActionProposal, Approval, ApprovalSet, Decision, ExecutionResult, PolicyDecision, RiskTier
from .policy import PolicyEngine
from .risk import RiskBudget
from .tools import ToolRegistry


class TrustGateway:
    def __init__(
        self,
        policy: PolicyEngine,
        audit: AuditJournal,
        tools: ToolRegistry,
        approvals: ApprovalStore | None = None,
        capabilities: CapabilityIssuer | None = None,
        risk_budget: RiskBudget | None = None,
        identities: WorkloadIdentity | None = None,
        high_risk_approval_quorum: int = 1,
        executions: ExecutionStateStore | None = None,
    ):
        if high_risk_approval_quorum < 1:
            raise ValueError("approval_quorum_must_be_positive")
        self.policy = policy
        self.audit = audit
        self.tools = tools
        self.approvals = approvals or ApprovalLedger()
        self.capabilities = capabilities
        self.risk_budget = risk_budget or RiskBudget(limit=6)
        self.identities = identities
        self.high_risk_approval_quorum = high_risk_approval_quorum
        self.executions = executions

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
        approval: Approval | ApprovalSet | None = None,
        capability_token: str | None = None,
        identity_token: str | None = None,
    ) -> ExecutionResult:
        identity_assertion_id: str | None = None
        if self.identities is not None:
            if not identity_token:
                self.audit.append("identity_missing", {"proposal_id": proposal.proposal_id, "agent_id": proposal.agent_id})
                return ExecutionResult(proposal_id=proposal.proposal_id, status="identity_required")
            try:
                identity = self.identities.verify(identity_token, expected_subject=proposal.agent_id)
            except IdentityError as exc:
                self.audit.append("identity_rejected", {"proposal_id": proposal.proposal_id, "agent_id": proposal.agent_id, "reason": str(exc)})
                return ExecutionResult(proposal_id=proposal.proposal_id, status="identity_rejected")
            identity_assertion_id = identity.assertion_id
            self.audit.append(
                "identity_accepted",
                {"proposal_id": proposal.proposal_id, "agent_id": proposal.agent_id, "assertion_id": identity.assertion_id, "key_id": identity.key_id},
            )

        decision = self.evaluate(proposal)
        if decision.decision == Decision.DENY:
            self.audit.append("execution_denied", {"proposal_id": proposal.proposal_id, "reasons": decision.reasons})
            return ExecutionResult(proposal_id=proposal.proposal_id, status="denied", identity_assertion_id=identity_assertion_id)

        capability_id: str | None = None
        if self.capabilities is not None and decision.risk in {RiskTier.MEDIUM, RiskTier.HIGH}:
            if not capability_token:
                self.audit.append("capability_missing", {"proposal_id": proposal.proposal_id})
                return ExecutionResult(proposal_id=proposal.proposal_id, status="capability_required", identity_assertion_id=identity_assertion_id)
            try:
                claims = self.capabilities.authorize(
                    capability_token,
                    subject=proposal.agent_id,
                    tool=proposal.tool,
                    action=proposal.action,
                    arguments=proposal.arguments,
                )
            except CapabilityError as exc:
                self.audit.append("capability_rejected", {"proposal_id": proposal.proposal_id, "reason": str(exc)})
                return ExecutionResult(proposal_id=proposal.proposal_id, status="capability_rejected", identity_assertion_id=identity_assertion_id)
            capability_id = claims.jti
            self.audit.append(
                "capability_accepted",
                {"proposal_id": proposal.proposal_id, "capability_id": claims.jti, "subject": claims.subject, "scope": f"{claims.tool}.{claims.action}"},
            )

        if not self.risk_budget.can_consume(proposal.agent_id, decision.risk):
            self.audit.append(
                "risk_budget_exceeded",
                {"proposal_id": proposal.proposal_id, "agent_id": proposal.agent_id, "risk": decision.risk.value, "remaining": self.risk_budget.remaining(proposal.agent_id)},
            )
            return ExecutionResult(proposal_id=proposal.proposal_id, status="risk_budget_exceeded", capability_id=capability_id, identity_assertion_id=identity_assertion_id)

        approvals: list[Approval] = []
        if decision.decision == Decision.REQUIRE_APPROVAL:
            approvals = self._approval_list(approval)
            if not approvals:
                self.audit.append("approval_missing", {"proposal_id": proposal.proposal_id})
                return ExecutionResult(proposal_id=proposal.proposal_id, status="approval_required", capability_id=capability_id, identity_assertion_id=identity_assertion_id)
            if len(approvals) < self.high_risk_approval_quorum:
                self.audit.append("approval_quorum_missing", {"proposal_id": proposal.proposal_id, "required": self.high_risk_approval_quorum, "provided": len(approvals)})
                return ExecutionResult(proposal_id=proposal.proposal_id, status="approval_required", capability_id=capability_id, identity_assertion_id=identity_assertion_id)
            approvers = [item.approver.strip() for item in approvals]
            if len(set(approvers)) != len(approvers):
                self.audit.append("approval_rejected", {"proposal_id": proposal.proposal_id, "reason": "approvers_not_independent"})
                return ExecutionResult(proposal_id=proposal.proposal_id, status="approval_rejected", capability_id=capability_id, identity_assertion_id=identity_assertion_id)
            for item in approvals:
                approval_error = self._validate_approval(proposal, item)
                if approval_error:
                    self.audit.append("approval_rejected", {"proposal_id": proposal.proposal_id, "approval_id": item.approval_id, "reason": approval_error})
                    return ExecutionResult(proposal_id=proposal.proposal_id, status="approval_rejected", capability_id=capability_id, identity_assertion_id=identity_assertion_id)

        if self.executions is not None:
            if not self.executions.reserve(proposal.proposal_id, proposal.digest()):
                prior_state = self.executions.state(proposal.proposal_id)
                self.audit.append(
                    "execution_replay_blocked",
                    {"proposal_id": proposal.proposal_id, "prior_state": prior_state},
                )
                return ExecutionResult(
                    proposal_id=proposal.proposal_id,
                    status="execution_in_doubt" if prior_state == "reserved" else "execution_replay_blocked",
                    capability_id=capability_id,
                    identity_assertion_id=identity_assertion_id,
                )
            self.audit.append("execution_reserved", {"proposal_id": proposal.proposal_id, "proposal_digest": proposal.digest()})

        if approvals:
            for item in approvals:
                if not self.approvals.consume(item.approval_id):
                    self.audit.append("approval_replay_blocked", {"proposal_id": proposal.proposal_id, "approval_id": item.approval_id})
                    self._mark_terminal(proposal.proposal_id, "approval_rejected")
                    return ExecutionResult(proposal_id=proposal.proposal_id, status="approval_rejected", capability_id=capability_id, identity_assertion_id=identity_assertion_id)
            self.audit.append(
                "approval_accepted",
                {"proposal_id": proposal.proposal_id, "approval_ids": [item.approval_id for item in approvals], "approvers": [item.approver.strip() for item in approvals], "quorum": self.high_risk_approval_quorum},
            )

        self.risk_budget.consume(proposal.agent_id, decision.risk)
        self.audit.append(
            "risk_budget_consumed",
            {"proposal_id": proposal.proposal_id, "agent_id": proposal.agent_id, "risk": decision.risk.value, "remaining": self.risk_budget.remaining(proposal.agent_id)},
        )

        try:
            output = self.tools.execute(proposal.tool, proposal.action, proposal.arguments)
        except Exception as exc:
            self.audit.append("execution_failed", {"proposal_id": proposal.proposal_id, "error": type(exc).__name__, "detail": str(exc)})
            self._mark_terminal(proposal.proposal_id, "failed")
            return ExecutionResult(proposal_id=proposal.proposal_id, status="failed", capability_id=capability_id, identity_assertion_id=identity_assertion_id)

        taints = self.tools.taints(proposal.tool, proposal.action, output)
        verified = self.tools.verify(proposal.tool, proposal.action, proposal.arguments, output)
        if verified:
            taints = [item for item in taints if item != "unverified_tool_output"]
        status = "completed" if verified else "verification_failed"
        self.audit.append(
            "execution_completed",
            {"proposal_id": proposal.proposal_id, "output": output, "verified": verified, "output_taints": taints, "capability_id": capability_id, "identity_assertion_id": identity_assertion_id},
        )
        self._mark_terminal(proposal.proposal_id, status)
        return ExecutionResult(
            proposal_id=proposal.proposal_id,
            status=status,
            output=output,
            verified=verified,
            output_taints=taints,
            capability_id=capability_id,
            identity_assertion_id=identity_assertion_id,
        )

    def _mark_terminal(self, proposal_id: str, status: str) -> None:
        if self.executions is not None:
            self.executions.complete(proposal_id, status)

    @staticmethod
    def _approval_list(approval: Approval | ApprovalSet | None) -> list[Approval]:
        if approval is None:
            return []
        if isinstance(approval, ApprovalSet):
            return approval.approvals
        return [approval]

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
