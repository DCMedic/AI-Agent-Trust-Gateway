from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ActionProposal(BaseModel):
    proposal_id: str = Field(default_factory=lambda: str(uuid4()))
    agent_id: str
    tool: str
    action: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def digest(self) -> str:
        canonical = {
            "proposal_id": self.proposal_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "action": self.action,
            "arguments": self.arguments,
            "purpose": self.purpose,
            "created_at": self.created_at.isoformat(),
        }
        return sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class PolicyDecision(BaseModel):
    decision: Decision
    risk: RiskTier
    reasons: list[str] = Field(default_factory=list)


class Approval(BaseModel):
    approval_id: str = Field(default_factory=lambda: str(uuid4()))
    proposal_digest: str
    approver: str
    expires_at: datetime


class ApprovalSet(BaseModel):
    """A proposal-bound set of independent human approvals for dual control."""

    approvals: list[Approval] = Field(min_length=2)


class ExecutionResult(BaseModel):
    proposal_id: str
    status: str
    output: dict[str, Any] = Field(default_factory=dict)
    verified: bool = False
    output_taints: list[str] = Field(default_factory=list)
    capability_id: str | None = None
    identity_assertion_id: str | None = None
