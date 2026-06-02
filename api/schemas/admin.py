"""
Typed admin response models aligned with the documented endpoint paths, enums,
and query parameters from the live OpenAPI spec.

Fields are required where the database schema uses NOT NULL constraints.
Fields remain Optional where the column is nullable or the data is derived/joined.
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
    id: str
    name: str
    billing_tier: str
    contact_email: str
    webhook_url: Optional[str] = None
    daily_limit_usd: float
    monthly_limit_usd: float
    metadata: Optional[dict[str, Any]] = None
    created_at: str
    updated_at: Optional[str] = None


class AgentSummary(BaseModel):
    id: str
    org_id: Optional[str] = None
    name: str
    status: AgentStatus | str
    public_key_fingerprint: Optional[str] = None
    trust_score: int = Field(..., ge=0, le=100)
    daily_limit_usd: float
    per_action_limit_usd: float
    allowed_actions: Optional[list[str]] = None
    blocked_actions: Optional[list[str]] = None
    rate_limit_per_minute: int
    last_action_at: Optional[str] = None
    total_actions_count: int
    total_blocked_count: int
    metadata: Optional[dict[str, Any]] = None
    created_at: str
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
    name: str
    status: AgentStatus | str
    public_key_fingerprint: Optional[str] = None
    trust_score: int = Field(..., ge=0, le=100)
    daily_limit_usd: float
    per_action_limit_usd: float
    allowed_actions: Optional[list[str]] = None
    blocked_actions: Optional[list[str]] = None
    rate_limit_per_minute: int
    last_action_at: Optional[str] = None
    total_actions_count: int
    total_blocked_count: int
    policy: Optional[Policy] = None
    metadata: Optional[dict[str, Any]] = None
    created_at: str
    updated_at: Optional[str] = None


class AuditLogSummary(BaseModel):
    id: str
    agent_id: str
    agent_name: Optional[str] = None
    timestamp: str
    action_type: str
    action_hash: str
    payload: Optional[dict[str, Any]] = None
    verdict: ActionVerdict | str
    verdict_reason: Optional[str] = None
    signature_valid: bool
    request_ip: Optional[str] = None
    request_user_agent: Optional[str] = None
    response_time_ms: Optional[int] = None
    trust_score_at_time: int
    risk_level: Optional[str] = None
    violations: Optional[list[str]] = None
    merkle_root_id: Optional[str] = None
    merkle_leaf_index: Optional[int] = None
    # On-chain anchor fields, joined from merkle_proofs. ``transaction_hash`` is
    # what the admin UI keys its "Anchored / Pending" badge on; ``tx_hash`` is a
    # legacy alias carrying the same value. NULL until the batch is anchored.
    transaction_hash: Optional[str] = None
    tx_hash: Optional[str] = None
    chain_id: Optional[int] = None
    block_number: Optional[int] = None
    policy_hash: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class AuditSearchResponse(BaseModel):
    logs: list[AuditLogSummary]
    total: int
    limit: int
    offset: int


class AuditLogDetail(BaseModel):
    id: str
    agent_id: str
    agent_name: Optional[str] = None
    timestamp: str
    action_type: str
    action_hash: str
    payload: Optional[dict[str, Any]] = None
    verdict: ActionVerdict | str
    verdict_reason: Optional[str] = None
    signature_valid: bool
    request_ip: Optional[str] = None
    request_user_agent: Optional[str] = None
    response_time_ms: Optional[int] = None
    trust_score_at_time: int
    policy_rule_triggered: Optional[str] = None
    risk_level: Optional[str] = None
    violations: Optional[list[str]] = None
    merkle_root_id: Optional[str] = None
    merkle_leaf_index: Optional[int] = None
    policy_hash: Optional[str] = None
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
