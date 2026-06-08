"""
Pydantic models for request/response validation.

All models are strictly typed and validated for forensic-grade operations.
"""

from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, ConfigDict, model_validator


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

    ## Minimum Required Fields (checked at model level)
    - agent_id, action_type, payload, signature, nonce, timestamp, policy_hash

    ## Expected Payload Sub-fields (not enforced at model level, adapter-specific)
    The ``payload`` dict is adapter-specific. For the standard runtime envelope,
    the following keys are expected:

    - ``resource``      (str)  — class of resource being acted on, e.g. "file", "database"
    - ``resource_id``   (str)  — specific resource identifier
    - ``operation``     (str)  — operation name, e.g. "read", "write", "delete"
    - ``risk_flags``    (list) — caller-declared risk signals, e.g. ["pii", "financial"]
    - ``payload_hash``  (str)  — SHA-256 of the inner payload, for additional integrity
    - ``policy_context`` (dict) — adapter-specific policy evaluation context

    For attestation actions (e.g. ``promptfoo_eval``), ``risk_flags`` and
    ``resource_id`` are optional. The adapter is responsible for documenting
    its own payload contract.

    ## Platform Field
    Callers may include ``platform`` in ``payload`` or ``adapter_metadata``
    to identify the integration (e.g. ``"promptfoo"``, ``"langchain"``).
    This is surfaced in audit logs but not validated at the API level.
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
    policy_hash: Optional[str] = Field(
        None,
        max_length=64,
        description="SHA-256 hash of .inntris.yml policy file"
    )

    # Signing-envelope version. Phase 0.4 introduced this field so the wire
    # format of ``compute_action_hash`` can evolve without silently breaking
    # older SDKs. Clients should pin the version they signed with; the
    # server uses it to select the matching canonicalization.
    #
    #   1 = legacy form: timestamp embedded verbatim via ``.isoformat()`` with
    #       no tz normalization (pre-Phase-0.3 behavior).
    #   2 = current form: timestamp normalized to UTC with a ``Z`` suffix by
    #       ``CryptoService.canonicalize_timestamp``; see Phase 0.3.
    #   3 = JCS form (Phase 1B.1): payload + signing envelope canonicalized
    #       via RFC 8785. Required for byte-identical hashes from non-Python
    #       SDKs. See tests/fixtures/canonicalization/jcs_vectors.json.
    #
    # Requests without ``sig_version`` are treated as version 2 — matching the
    # current reference implementation.
    sig_version: int = Field(
        2,
        ge=1,
        le=3,
        description=(
            "Signing-envelope version. 3 = RFC 8785 JCS (Phase 1B.1). "
            "2 = UTC-normalized timestamp (current default). "
            "1 = legacy isoformat without tz normalization. "
            "Defaults to 2 when omitted."
        ),
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


class UpdateAgentRequest(BaseModel):
    """Validated mutable policy controls for an existing agent."""

    model_config = ConfigDict(strict=False)

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    daily_limit_usd: Optional[Decimal] = Field(None, ge=0, le=1000000)
    per_action_limit_usd: Optional[Decimal] = Field(None, ge=0, le=100000)
    allowed_actions: Optional[list[str]] = Field(None, max_length=100)
    blocked_actions: Optional[list[str]] = Field(None, max_length=100)
    rate_limit_per_minute: Optional[int] = Field(None, ge=1, le=10000)
    metadata: Optional[dict[str, Any]] = None

    @field_validator("allowed_actions", "blocked_actions")
    @classmethod
    def validate_action_lists(cls, values: Optional[list[str]]) -> Optional[list[str]]:
        if values is None:
            return None

        normalized: list[str] = []
        for value in values:
            action = value.strip().lower()
            if not action or len(action) > 100 or not action.replace("_", "").isalnum():
                raise ValueError(
                    "action types must be 1-100 characters using letters, numbers, and underscores"
                )
            if action not in normalized:
                normalized.append(action)
        return normalized

    @model_validator(mode="after")
    def validate_policy_consistency(self) -> "UpdateAgentRequest":
        for field_name in (
            "name",
            "daily_limit_usd",
            "per_action_limit_usd",
            "allowed_actions",
            "blocked_actions",
            "rate_limit_per_minute",
            "metadata",
        ):
            if field_name in self.model_fields_set and getattr(self, field_name) is None:
                raise ValueError(f"{field_name} cannot be null")

        if (
            self.daily_limit_usd is not None
            and self.per_action_limit_usd is not None
            and self.per_action_limit_usd > self.daily_limit_usd
        ):
            raise ValueError("per_action_limit_usd cannot exceed daily_limit_usd")

        if self.allowed_actions is not None and self.blocked_actions is not None:
            overlap = sorted(set(self.allowed_actions) & set(self.blocked_actions))
            if overlap:
                raise ValueError(
                    f"actions cannot be both allowed and blocked: {', '.join(overlap)}"
                )

        return self


class PublicRegisterAgentRequest(BaseModel):
    """
    Request to bootstrap an agent via the public (no-auth) registration endpoint.

    The agent provides its own Ed25519 public key; Inntris assigns an org and
    returns a stable agent_id that can be used immediately for /verify calls.
    """
    model_config = ConfigDict(strict=False)

    email: str = Field(
        ...,
        max_length=255,
        description="Contact email for the registrant — used for org lookup/creation",
    )
    public_key: str = Field(
        ...,
        min_length=44,
        max_length=64,
        description="Base64-encoded Ed25519 public key (32 raw bytes)",
    )
    adapter_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Adapter-specific metadata (e.g. platform, version, config)",
    )


class PublicRegisterAgentResponse(BaseModel):
    """Response from public agent registration."""
    model_config = ConfigDict(strict=False)

    agent_id: str = Field(..., description="Newly created agent UUID")
    public_key_fingerprint: str = Field(
        ...,
        description="SHA-256 fingerprint of the registered public key",
    )
    org_id: str = Field(..., description="Organization UUID the agent was assigned to")
    status: str = Field(default="active", description="Initial agent status")
    created_at: str = Field(..., description="ISO 8601 creation timestamp")
    message: str = Field(
        default="Agent registered. Use agent_id with POST /verify.",
        description="Human-readable confirmation",
    )


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


class PublicVerificationRecord(BaseModel):
    """Public, read-only verification receipt for the shareable audit page."""
    model_config = ConfigDict(strict=True)

    # Core identity
    audit_id: UUID = Field(..., description="Audit log entry ID")
    timestamp: datetime = Field(..., description="Verification timestamp")

    # Verdict
    verdict: ActionVerdict = Field(..., description="APPROVED or BLOCKED")
    verdict_reason: Optional[str] = Field(None, description="Human-readable reason")
    action_type: str = Field(..., description="Action type verified")

    # Agent info
    agent_id: UUID = Field(..., description="Agent unique identifier")
    agent_name: str = Field(..., description="Agent display name")
    organization_name: str = Field(..., description="Parent organization name")
    trust_score: int = Field(..., ge=0, le=100, description="Trust score at time of verification")

    # Policy decision
    risk_level: Optional[str] = Field(None, description="Risk level from payload")
    violations: list[str] = Field(default_factory=list, description="Policy violations if any")

    # Policy binding
    policy_hash: Optional[str] = Field(None, description="SHA-256 hash of policy file at verification time")

    # On-chain proof
    action_hash: str = Field(..., description="SHA-256 hash of the action")
    signature_valid: bool = Field(..., description="Whether Ed25519 signature was valid")
    merkle_root: Optional[str] = Field(None, description="Merkle root hash")
    tx_hash: Optional[str] = Field(None, description="Base L2 transaction hash")
    block_number: Optional[int] = Field(None, description="Block number on Base L2")
    chain_id: int = Field(default=8453, description="Chain ID (Base L2)")
    anchored_at: Optional[datetime] = Field(None, description="When the proof was anchored on-chain")

    # Receipt integrity
    schema_version: str = Field(default="v1", description="Receipt schema version")
    receipt_fingerprint: str = Field(..., description="SHA-256 of canonical core fields for integrity verification")
    integrity_status: str = Field(default="verified", description="Server-side integrity verification status")


class PublicProofResponse(BaseModel):
    """Public Merkle proof response for an audit log entry."""
    model_config = ConfigDict(strict=False)

    audit_id: str = Field(..., description="Audit log ID")
    status: str = Field(..., description="'anchored' or 'pending_anchor'")
    action_hash: str = Field(..., description="Leaf hash (SHA-256 of action)")
    proof: list[str] = Field(default_factory=list, description="Sibling hashes in proof path")
    positions: list[bool] = Field(
        default_factory=list,
        description="True = sibling is on the right, False = on the left",
    )
    merkle_root: Optional[str] = Field(None, description="Merkle root hash of the anchor batch")
    tx_hash: Optional[str] = Field(None, description="On-chain transaction hash")
    chain_id: Optional[int] = Field(None, description="Chain ID (8453 for Base Mainnet)")
    block_number: Optional[int] = Field(None, description="Block number of the anchor transaction")
    anchored_at: Optional[str] = Field(None, description="ISO 8601 timestamp of on-chain anchor")
    submitter: Optional[str] = Field(None, description="Wallet address that submitted the Merkle root")
    receipt_fingerprint: Optional[str] = Field(None, description="SHA-256 receipt fingerprint from the audit log")
    policy_hash: Optional[str] = Field(None, description="Policy hash bound to this receipt, if any")
    timestamp: Optional[str] = Field(None, description="ISO 8601 timestamp of the original verification event")


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
    policy_hash: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
