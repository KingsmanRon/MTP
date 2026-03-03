"""
Pydantic models for request/response validation.

All models are strictly typed and validated for forensic-grade operations.
"""

from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, ConfigDict


class BillingTier(str, Enum):
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class AgentStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    PENDING_VERIFICATION = "pending_verification"


class ActionVerdict(str, Enum):
    APPROVED = "approved"
    BLOCKED = "blocked"
    RATE_LIMITED = "rate_limited"
    SIGNATURE_INVALID = "signature_invalid"


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# REQUEST MODELS
# =============================================================================


class VerifyActionRequest(BaseModel):
    """
    Request payload for action verification.

    The agent sends this payload with its cryptographic signature.
    CRITICAL: The signature MUST cover the entire payload hash.
    """
    # UPDATED: strict=False allows JSON strings to be parsed into Types (UUID, Decimal)
    model_config = ConfigDict(strict=False)

    agent_id: UUID = Field(..., description="Unique identifier of the requesting agent")
    action_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Type of action being performed (e.g., 'financial_transaction', 'email_send')"
    )
    payload: dict[str, Any] = Field(
        ...,
        description="Action-specific payload containing all details"
    )
    signature: str = Field(
        ...,
        min_length=64,
        description="Base64-encoded Ed25519 signature of the payload hash"
    )
    nonce: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Unique nonce to prevent replay attacks"
    )
    
    # CRITICAL FIX: Accept timestamp as RAW STRING to prevent parsing mismatch
    # We removed the validator to ensure the string reaches the backend exactly as sent
    timestamp: str = Field(
        ...,
        description="Client-side timestamp (ISO 8601 string)"
    )

    @field_validator("action_type")
    @classmethod
    def validate_action_type(cls, v: str) -> str:
        """Ensure action type is alphanumeric with underscores only."""
        if not v.replace("_", "").isalnum():
            raise ValueError("action_type must be alphanumeric with underscores only")
        return v.lower()


class TestVerifyRequest(BaseModel):
    """
    Request payload for test verification (playground).

    Does not require cryptographic signature - uses API key auth instead.
    For testing policy evaluation without full integration.
    """
    model_config = ConfigDict(strict=False)

    agent_id: UUID = Field(..., description="Agent ID to test verification for")
    action_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Type of action being performed"
    )
    payload: dict[str, Any] = Field(
        ...,
        description="Action-specific payload containing all details"
    )

    @field_validator("action_type")
    @classmethod
    def validate_action_type(cls, v: str) -> str:
        """Ensure action type is alphanumeric with underscores only."""
        if not v.replace("_", "").isalnum():
            raise ValueError("action_type must be alphanumeric with underscores only")
        return v.lower()


class RegisterAgentRequest(BaseModel):
    """Request to register a new agent with the platform."""
    # UPDATED: strict=False allows JSON strings to be parsed into Types (UUID, Decimal)
    model_config = ConfigDict(strict=False)

    org_id: UUID = Field(..., description="Organization ID")
    name: str = Field(..., min_length=1, max_length=255, description="Agent display name")
    public_key: str = Field(
        ...,
        min_length=44,
        max_length=64,
        description="Base64-encoded Ed25519 public key"
    )
    daily_limit_usd: Decimal = Field(
        default=Decimal("100.00"),
        ge=0,
        le=1000000,
        description="Daily spending limit in USD"
    )
    per_action_limit_usd: Decimal = Field(
        default=Decimal("50.00"),
        ge=0,
        le=100000,
        description="Per-action spending limit in USD"
    )
    allowed_actions: list[str] = Field(
        default=["financial_transaction", "email_send", "api_call"],
        description="List of allowed action types"
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class CreateOrganizationRequest(BaseModel):
    """Request to create a new organization."""
    # UPDATED: strict=False allows JSON strings to be parsed into Types (UUID, Decimal)
    model_config = ConfigDict(strict=False)

    name: str = Field(..., min_length=1, max_length=255, description="Organization name")
    contact_email: str = Field(..., description="Primary contact email")
    billing_tier: BillingTier = Field(default=BillingTier.FREE, description="Billing tier")
    webhook_url: Optional[str] = Field(None, description="Webhook URL for notifications")


# =============================================================================
# RESPONSE MODELS
# =============================================================================


class VerifyActionResponse(BaseModel):
    """
    Response from action verification.

    Contains the verdict and an optional signed approval token.
    """
    model_config = ConfigDict(strict=True)

    verdict: ActionVerdict = Field(..., description="The verification verdict")
    verdict_reason: Optional[str] = Field(None, description="Human-readable reason for the verdict")
    approval_token: Optional[str] = Field(
        None,
        description="Signed approval token if verdict is APPROVED"
    )
    trust_score: int = Field(..., ge=0, le=100, description="Current trust score of the agent")
    audit_id: UUID = Field(..., description="Audit log entry ID for this verification")
    timestamp: datetime = Field(..., description="Server timestamp of the verification")
    limits_remaining: Optional[dict[str, Any]] = Field(
        None,
        description="Remaining limits for the agent"
    )


class AgentPublicInfo(BaseModel):
    """Public information about an agent for the trust badge."""
    model_config = ConfigDict(strict=True)

    agent_id: UUID = Field(..., description="Agent unique identifier")
    name: str = Field(..., description="Agent display name")
    organization_name: str = Field(..., description="Parent organization name")
    trust_score: int = Field(..., ge=0, le=100, description="Current trust score")
    status: AgentStatus = Field(..., description="Current agent status")
    is_verified: bool = Field(..., description="Whether the agent is verified and active")
    verified_since: Optional[datetime] = Field(None, description="Date of initial verification")
    total_actions: int = Field(..., ge=0, description="Total verified actions")
    last_action_at: Optional[datetime] = Field(None, description="Timestamp of last action")


class HealthResponse(BaseModel):
    """API health check response."""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    database: str = Field(..., description="Database connection status")
    redis: str = Field(..., description="Redis connection status")
    timestamp: datetime = Field(..., description="Current server time")


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[dict[str, Any]] = Field(None, description="Additional error details")
    request_id: Optional[str] = Field(None, description="Request tracking ID")


# =============================================================================
# INTERNAL MODELS
# =============================================================================


class AgentRecord(BaseModel):
    """Internal representation of an agent from the database."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    org_id: UUID
    name: str
    public_key: bytes
    public_key_fingerprint: str
    trust_score: int
    status: AgentStatus
    daily_limit_usd: Decimal
    per_action_limit_usd: Decimal
    allowed_actions: list[str]
    blocked_actions: list[str]
    rate_limit_per_minute: int
    last_action_at: Optional[datetime]
    total_actions_count: int
    total_blocked_count: int
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class OrganizationRecord(BaseModel):
    """Internal representation of an organization from the database."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    billing_tier: BillingTier
    contact_email: str
    webhook_url: Optional[str]
    daily_limit_usd: Decimal
    monthly_limit_usd: Decimal
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class AuditLogEntry(BaseModel):
    """Audit log entry for database insertion."""
    agent_id: UUID
    action_type: str
    action_hash: str
    payload: dict[str, Any]
    verdict: ActionVerdict
    verdict_reason: Optional[str]
    signature: bytes
    signature_valid: bool
    request_ip: Optional[str]
    request_user_agent: Optional[str]
    response_time_ms: Optional[int]
    trust_score_at_time: int
    chain_previous_hash: Optional[str]
    metadata: dict[str, Any] = Field(default_factory=dict)
