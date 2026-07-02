"""
Typed admin response models aligned with the documented endpoint paths, enums,
and query parameters from the live OpenAPI spec.

Fields are required where the database schema uses NOT NULL constraints.
Fields remain Optional where the column is nullable or the data is derived/joined.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ActionVerdict(StrEnum):
    approved = "approved"
    blocked = "blocked"
    rate_limited = "rate_limited"
    signature_invalid = "signature_invalid"


class AgentStatus(StrEnum):
    active = "active"
    suspended = "suspended"
    revoked = "revoked"
    pending_verification = "pending_verification"


class OrganizationResponse(BaseModel):
    id: str
    name: str
    billing_tier: str
    contact_email: str
    webhook_url: str | None = None
    daily_limit_usd: float
    monthly_limit_usd: float
    metadata: dict[str, Any] | None = None
    created_at: str
    updated_at: str | None = None


class AgentSummary(BaseModel):
    id: str
    org_id: str | None = None
    name: str
    status: AgentStatus | str
    public_key_fingerprint: str | None = None
    trust_score: int = Field(..., ge=0, le=100)
    daily_limit_usd: float
    per_action_limit_usd: float
    allowed_actions: list[str] | None = None
    blocked_actions: list[str] | None = None
    rate_limit_per_minute: int
    last_action_at: str | None = None
    total_actions_count: int
    total_blocked_count: int
    metadata: dict[str, Any] | None = None
    created_at: str
    updated_at: str | None = None


class PolicyRule(BaseModel):
    rule_id: str | None = None
    description: str | None = None
    action: str | None = None


class Policy(BaseModel):
    policy_id: str | None = None
    name: str | None = None
    rules: list[PolicyRule] | None = None
    created_at: str | None = None
    raw: dict[str, Any] | None = None


class AgentDetail(BaseModel):
    id: str
    org_id: str | None = None
    name: str
    status: AgentStatus | str
    public_key_fingerprint: str | None = None
    trust_score: int = Field(..., ge=0, le=100)
    daily_limit_usd: float
    per_action_limit_usd: float
    allowed_actions: list[str] | None = None
    blocked_actions: list[str] | None = None
    rate_limit_per_minute: int
    last_action_at: str | None = None
    total_actions_count: int
    total_blocked_count: int
    policy: Policy | None = None
    metadata: dict[str, Any] | None = None
    created_at: str
    updated_at: str | None = None
    key_version: int = 1
    key_rotated_at: str | None = None


class AuditLogSummary(BaseModel):
    id: str
    agent_id: str
    agent_name: str | None = None
    timestamp: str
    action_type: str
    action_hash: str
    payload: dict[str, Any] | None = None
    verdict: ActionVerdict | str
    verdict_reason: str | None = None
    signature_valid: bool
    request_ip: str | None = None
    request_user_agent: str | None = None
    response_time_ms: int | None = None
    trust_score_at_time: int
    risk_level: str | None = None
    violations: list[str] | None = None
    merkle_root_id: str | None = None
    merkle_leaf_index: int | None = None
    # On-chain anchor fields, joined from merkle_proofs. ``transaction_hash`` is
    # what the admin UI keys its "Anchored / Pending" badge on; ``tx_hash`` is a
    # legacy alias carrying the same value. NULL until the batch is anchored.
    transaction_hash: str | None = None
    tx_hash: str | None = None
    chain_id: int | None = None
    block_number: int | None = None
    policy_hash: str | None = None
    metadata: dict[str, Any] | None = None


class AuditSearchResponse(BaseModel):
    logs: list[AuditLogSummary]
    total: int
    limit: int
    offset: int


class AuditLogDetail(BaseModel):
    id: str
    agent_id: str
    agent_name: str | None = None
    timestamp: str
    action_type: str
    action_hash: str
    payload: dict[str, Any] | None = None
    verdict: ActionVerdict | str
    verdict_reason: str | None = None
    signature_valid: bool
    request_ip: str | None = None
    request_user_agent: str | None = None
    response_time_ms: int | None = None
    trust_score_at_time: int
    policy_rule_triggered: str | None = None
    risk_level: str | None = None
    violations: list[str] | None = None
    merkle_root_id: str | None = None
    merkle_leaf_index: int | None = None
    policy_hash: str | None = None
    metadata: dict[str, Any] | None = None


class AuditProof(BaseModel):
    status: str | None = None
    leaf: str | None = None
    proof: list[str] | None = None
    positions: list[bool] | None = None
    merkle_root: str | None = None
    tx_hash: str | None = None
    block_number: int | None = None
    anchored_at: str | None = None
    chain_id: int | None = None
    basescan_url: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] | None = None
