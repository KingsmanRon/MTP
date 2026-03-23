"""
Typed admin response models aligned with the documented endpoint paths, enums,
and query parameters from the live OpenAPI spec.

Fields not confirmed as guaranteed by current route output are Optional.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ActionVerdict(str, Enum):
    approved = "approved"
    blocked = "blocked"
    rate_limited = "rate_limited"
    signature_invalid = "signature_invalid"


class AgentStatus(str, Enum):
    active = "active"
    suspended = "suspended"
    revoked = "revoked"
    pending_verification = "pending_verification"


class OrganizationResponse(BaseModel):
    id: Optional[str] = None  # TODO: not yet guaranteed by route — relax until confirmed
    name: Optional[str] = None
    billing_tier: Optional[str] = None
    contact_email: Optional[str] = None
    webhook_url: Optional[str] = None
    daily_limit_usd: Optional[float] = None
    monthly_limit_usd: Optional[float] = None
    metadata: Optional[dict[str, Any]] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class AgentSummary(BaseModel):
    id: str
    org_id: Optional[str] = None
    name: Optional[str] = None
    status: Optional[AgentStatus | str] = None
    public_key_fingerprint: Optional[str] = None
    trust_score: Optional[int] = Field(default=None, ge=0, le=100)
    daily_limit_usd: Optional[float] = None
    per_action_limit_usd: Optional[float] = None
    allowed_actions: Optional[list[str]] = None
    blocked_actions: Optional[list[str]] = None
    rate_limit_per_minute: Optional[int] = None
    last_action_at: Optional[str] = None
    total_actions_count: Optional[int] = None
    total_blocked_count: Optional[int] = None
    metadata: Optional[dict[str, Any]] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class PolicyRule(BaseModel):
    rule_id: Optional[str] = None
    description: Optional[str] = None
    action: Optional[str] = None


class Policy(BaseModel):
    policy_id: Optional[str] = None
    name: Optional[str] = None
    rules: Optional[list[PolicyRule]] = None
    created_at: Optional[str] = None
    raw: Optional[dict[str, Any]] = None


class AgentDetail(BaseModel):
    id: str
    org_id: Optional[str] = None
    name: Optional[str] = None
    status: Optional[AgentStatus | str] = None
    public_key_fingerprint: Optional[str] = None
    trust_score: Optional[int] = Field(default=None, ge=0, le=100)
    daily_limit_usd: Optional[float] = None
    per_action_limit_usd: Optional[float] = None
    allowed_actions: Optional[list[str]] = None
    blocked_actions: Optional[list[str]] = None
    rate_limit_per_minute: Optional[int] = None
    last_action_at: Optional[str] = None
    total_actions_count: Optional[int] = None
    total_blocked_count: Optional[int] = None
    policy: Optional[Policy] = None  # Optional at schema level.
                                     # Frontend must treat None as error state.
    metadata: Optional[dict[str, Any]] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class AuditLogSummary(BaseModel):
    id: str
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    timestamp: Optional[str] = None
    action_type: Optional[str] = None
    action_hash: Optional[str] = None
    payload: Optional[dict[str, Any]] = None
    verdict: Optional[ActionVerdict | str] = None
    verdict_reason: Optional[str] = None
    signature_valid: Optional[bool] = None
    request_ip: Optional[str] = None
    request_user_agent: Optional[str] = None
    response_time_ms: Optional[int] = None
    trust_score_at_time: Optional[int] = None
    risk_level: Optional[str] = None
    violations: Optional[list[str]] = None
    merkle_root_id: Optional[str] = None
    merkle_leaf_index: Optional[int] = None
    tx_hash: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class AuditSearchResponse(BaseModel):
    logs: list[AuditLogSummary]
    total: int
    limit: int   # reflects limit query param — not page
    offset: int  # reflects offset query param


class AuditLogDetail(BaseModel):
    id: str
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    timestamp: Optional[str] = None
    action_type: Optional[str] = None
    action_hash: Optional[str] = None
    payload: Optional[dict[str, Any]] = None
    verdict: Optional[ActionVerdict | str] = None
    verdict_reason: Optional[str] = None
    signature_valid: Optional[bool] = None
    request_ip: Optional[str] = None
    request_user_agent: Optional[str] = None
    response_time_ms: Optional[int] = None
    trust_score_at_time: Optional[int] = None
    policy_rule_triggered: Optional[str] = None
    risk_level: Optional[str] = None
    violations: Optional[list[str]] = None
    merkle_root_id: Optional[str] = None
    merkle_leaf_index: Optional[int] = None
    metadata: Optional[dict[str, Any]] = None


class AuditProof(BaseModel):
    leaf: Optional[str] = None
    proof: Optional[list[str]] = None
    positions: Optional[list[bool]] = None
    merkle_root: Optional[str] = None
    tx_hash: Optional[str] = None
    block_number: Optional[int] = None
    anchored_at: Optional[str] = None
    chain_id: Optional[int] = None
    basescan_url: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
