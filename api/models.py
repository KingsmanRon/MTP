"""
Pydantic models for request/response validation.

All models are strictly typed and validated for forensic-grade operations.
"""

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class BillingTier(StrEnum):
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class AgentStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    PENDING_VERIFICATION = "pending_verification"


class ActionVerdict(StrEnum):
    APPROVED = "approved"
    BLOCKED = "blocked"
    RATE_LIMITED = "rate_limited"
    SIGNATURE_INVALID = "signature_invalid"


class AlertSeverity(StrEnum):
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
    policy_hash: str | None = Field(
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


class VerifyTokenRequest(BaseModel):
    """Request to verify an HMAC approval token issued by ``/verify``.

    This is the downstream-enforcement primitive: a system about to execute a
    guarded action can hand its approval token (and, optionally, the action
    parameters) to ``/verify-token`` and refuse to proceed unless the token is
    cryptographically valid, unexpired, and bound to *this* action.
    """
    model_config = ConfigDict(strict=False)

    approval_token: str = Field(
        ...,
        min_length=1,
        description="Base64 approval token returned by POST /verify",
    )
    agent_id: UUID | None = Field(
        None,
        description="If provided, must match the agent_id embedded in the token",
    )
    # Optional for a stateless authenticity check. All four are mandatory when
    # consume=true because execution must bind to the complete approved action.
    action_type: str | None = Field(None, max_length=100)
    payload: dict[str, Any] | None = None
    nonce: str | None = Field(None, max_length=64)
    timestamp: str | None = None
    sig_version: int = Field(2, ge=1, le=3)
    consume: bool = Field(
        default=False,
        description=(
            "If true, atomically mark this token used (single-use). A second "
            "consume of the same token returns valid:false. action_type, payload, "
            "nonce, and timestamp are required. Use this in the execution gate "
            "so one approval cannot authorize two executions."
        ),
    )
    execution_ref: str | None = Field(
        None,
        min_length=1,
        max_length=512,
        description=(
            "Stable downstream execution reference. When supplied with consume=true, "
            "a retry using the same reference is idempotent; a different reference conflicts."
        ),
    )


class VerifyTokenResponse(BaseModel):
    """Result of verifying an approval token."""
    model_config = ConfigDict(strict=False)

    valid: bool = Field(..., description="True only if the token is authentic, unexpired, and (if action params supplied) action-bound")
    reason: str | None = Field(None, description="Why the token was rejected, when invalid")
    verdict: str | None = Field(None, description="Verdict embedded in the token (e.g. 'approved')")
    agent_id: str | None = Field(None, description="Agent the token was issued to")
    action_hash: str | None = Field(None, description="Action hash the token authorizes")
    expires_at: datetime | None = Field(None, description="Token expiry (UTC)")
    action_hash_matches: bool | None = Field(
        None,
        description="Whether supplied action params recompute to the token's action hash (null if params not supplied)",
    )
    consumption_audit_id: str | None = Field(
        None,
        description=(
            "Audit ID of the token_consumed event, set only when consume=true "
            "succeeded. Fetch its public receipt as proof the pre-execution "
            "check happened. Sandbox consumption remains unanchored."
        ),
    )
    consumption_status: Literal["consumed", "idempotent"] | None = Field(
        None,
        description="Whether this request first consumed the token or replayed the same execution.",
    )
    execution_ref: str | None = Field(
        None,
        description="Stable execution reference accepted during token consumption.",
    )
    sandbox: bool | None = Field(
        None,
        description=(
            "Sandbox state embedded in the token. A consumed execution token is "
            "valid only when this is false and the current agent is production eligible."
        ),
    )


class VerifyDebugResponse(BaseModel):
    """Dry-run signing diagnostics for POST /verify/debug (no side effects)."""
    model_config = ConfigDict(strict=False)

    agent_id: str = Field(..., description="Agent the request was built for")
    agent_found: bool = Field(..., description="Whether the agent_id resolves to a registered agent")
    action_type: str = Field(..., description="Action type from the request")
    sig_version: int = Field(..., description="Signing-envelope version the server used")
    canonical_timestamp: str = Field(..., description="Canonical UTC timestamp the server hashed")
    expected_action_hash: str = Field(
        ..., description="Action hash the server verifies the signature against (sign bytes.fromhex of this)"
    )
    signature_valid: bool | None = Field(
        None, description="True/False when the agent exists; null when the agent is not found"
    )
    public_key_fingerprint: str | None = Field(
        None, description="SHA-256 fingerprint of the agent public key checked against"
    )
    note: str = Field(..., description="How to use this diagnostic")


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


class RotateAgentKeyRequest(BaseModel):
    """Rotate an agent's Ed25519 signing key (leak response / hygiene).

    Replaces the public key in place, preserving trust, history, and policy.
    The old key stops verifying immediately. The caller submits only the new
    public key; the private seed is generated client-side and never sent.
    """

    model_config = ConfigDict(strict=False)

    public_key: str = Field(
        ...,
        min_length=44,
        max_length=64,
        description="Base64-encoded new Ed25519 public key (32 bytes).",
    )
    reason: str | None = Field(
        None,
        max_length=500,
        description="Why the key is being rotated (recorded for audit).",
    )


class PromoteAgentRequest(BaseModel):
    """Explicit approval to move a sandbox agent into production."""

    model_config = ConfigDict(strict=False)

    approval_reference: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Organisation approval, change, or ticket reference.",
    )

    @field_validator("approval_reference")
    @classmethod
    def normalise_approval_reference(cls, value: str) -> str:
        reference = value.strip()
        if not reference:
            raise ValueError("approval_reference cannot be blank")
        return reference


class UpdateAgentRequest(BaseModel):
    """Validated mutable policy controls for an existing agent."""

    model_config = ConfigDict(strict=False)

    name: str | None = Field(None, min_length=1, max_length=255)
    daily_limit_usd: Decimal | None = Field(None, ge=0, le=1000000)
    per_action_limit_usd: Decimal | None = Field(None, ge=0, le=100000)
    allowed_actions: list[str] | None = Field(None, max_length=100)
    blocked_actions: list[str] | None = Field(None, max_length=100)
    rate_limit_per_minute: int | None = Field(None, ge=1, le=10000)
    # Operator override for the agent's trust score. The runtime accrues trust
    # automatically (+1 per approval), but operators need a direct lever to
    # promote a vetted agent to a high-trust action (e.g. raise to 80 so it can
    # run protected_branch_merge) or to demote a suspicious one without waiting
    # for behavioral decay.
    trust_score: int | None = Field(None, ge=0, le=100)
    metadata: dict[str, Any] | None = None

    @field_validator("allowed_actions", "blocked_actions")
    @classmethod
    def validate_action_lists(cls, values: list[str] | None) -> list[str] | None:
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
            "trust_score",
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
    sandbox: bool = Field(
        default=True,
        description=(
            "Accepted for backwards compatibility but ignored. Public registration "
            "always creates a sandbox agent that cannot anchor on chain."
        ),
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
    webhook_url: str | None = Field(None, description="Webhook URL for notifications")


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
    verdict_reason: str | None = Field(None, description="Human-readable reason for the verdict")
    approval_token: str | None = Field(
        None,
        description="Signed approval token if verdict is APPROVED"
    )
    trust_score: int = Field(..., ge=0, le=100, description="Current trust score of the agent")
    audit_id: UUID = Field(..., description="Audit log entry ID for this verification")
    timestamp: datetime = Field(..., description="Server timestamp of the verification")
    limits_remaining: dict[str, Any] | None = Field(
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
    verified_since: datetime | None = Field(None, description="Date of initial verification")
    total_actions: int = Field(..., ge=0, description="Total verified actions")
    last_action_at: datetime | None = Field(None, description="Timestamp of last action")


class PublicVerificationRecord(BaseModel):
    """Public, read-only verification receipt for the shareable audit page."""
    model_config = ConfigDict(strict=True)

    # Core identity
    audit_id: UUID = Field(..., description="Audit log entry ID")
    timestamp: datetime = Field(..., description="Verification timestamp")

    # Verdict
    verdict: ActionVerdict = Field(..., description="APPROVED or BLOCKED")
    verdict_reason: str | None = Field(None, description="Human-readable reason")
    action_type: str = Field(..., description="Action type verified")

    # Agent info
    agent_id: UUID = Field(..., description="Agent unique identifier")
    agent_name: str = Field(..., description="Agent display name")
    organization_name: str = Field(..., description="Parent organization name")
    trust_score: int = Field(..., ge=0, le=100, description="Trust score at time of verification")

    # Policy decision
    risk_level: str | None = Field(None, description="Risk level from payload")
    violations: list[str] = Field(default_factory=list, description="Policy violations if any")

    # Policy binding
    policy_hash: str | None = Field(None, description="SHA-256 hash of policy file at verification time")

    # On-chain proof
    action_hash: str = Field(..., description="SHA-256 hash of the action")
    signature_valid: bool = Field(..., description="Whether Ed25519 signature was valid")
    signature_b64: str | None = Field(
        None,
        description="Base64 Ed25519 signature over the action hash, for independent re-verification (null unless a 64-byte signature was supplied)",
    )
    public_key_b64: str | None = Field(
        None,
        description="Base64 Ed25519 public key the signature verifies against",
    )
    merkle_root: str | None = Field(None, description="Merkle root hash")
    tx_hash: str | None = Field(None, description="Base L2 transaction hash")
    block_number: int | None = Field(None, description="Block number on Base L2")
    chain_id: int = Field(default=8453, description="Chain ID (Base L2)")
    anchored_at: datetime | None = Field(None, description="When the proof was anchored on-chain")

    # Receipt integrity
    schema_version: str = Field(default="v1", description="Receipt schema version")
    receipt_fingerprint: str = Field(..., description="SHA-256 of canonical core fields for integrity verification")
    integrity_status: str = Field(default="verified", description="Server-side integrity verification status")
    sandbox: bool = Field(default=False, description="True for sandbox/test receipts that never anchor on-chain")


class PublicProofResponse(BaseModel):
    """Public Merkle proof response for an audit log entry."""
    model_config = ConfigDict(strict=False)

    audit_id: str = Field(..., description="Audit log ID")
    status: str = Field(..., description="'anchored', 'pending_anchor', 'failed', or 'sandbox'")
    action_hash: str = Field(..., description="Leaf hash (SHA-256 of action)")
    proof: list[str] = Field(default_factory=list, description="Sibling hashes in proof path")
    positions: list[bool] = Field(
        default_factory=list,
        description="True = sibling is on the right, False = on the left",
    )
    merkle_root: str | None = Field(None, description="Merkle root hash of the anchor batch")
    tx_hash: str | None = Field(None, description="On-chain transaction hash")
    chain_id: int | None = Field(None, description="Chain ID (8453 for Base Mainnet)")
    block_number: int | None = Field(None, description="Block number of the anchor transaction")
    anchored_at: str | None = Field(None, description="ISO 8601 timestamp of on-chain anchor")
    submitter: str | None = Field(None, description="Wallet address that submitted the Merkle root")
    receipt_fingerprint: str | None = Field(None, description="SHA-256 receipt fingerprint from the audit log")
    policy_hash: str | None = Field(None, description="Policy hash bound to this receipt, if any")
    timestamp: str | None = Field(None, description="ISO 8601 timestamp of the original verification event")


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
    details: dict[str, Any] | None = Field(None, description="Additional error details")
    request_id: str | None = Field(None, description="Request tracking ID")


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
    last_action_at: datetime | None
    total_actions_count: int
    total_blocked_count: int
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    # Signing-key rotation (migration 011). Defaults keep older callers and
    # test fixtures that construct AgentRecord without these fields valid.
    key_version: int = 1
    key_rotated_at: datetime | None = None


class RegisteredPolicy(BaseModel):
    """An agent's server-registered governing policy (Tier A).

    The registered ``.inntris.yml``: its hash (for binding) plus the mapping
    and protected_branches the server uses to re-derive a change's minimum
    action type independently of the client's asserted action_type.
    """
    model_config = ConfigDict(from_attributes=True)

    policy_hash: str
    mapping: dict[str, list[str]] = Field(default_factory=dict)
    protected_branches: list[str] = Field(default_factory=list)
    version: int = 1


class RegisterPolicyRequest(BaseModel):
    """Register (or re-register) an agent's governing policy.

    The caller submits only the enforced content (mapping + protected
    branches); the server derives the canonical policy hash from it, so it
    always matches what the action computes and cannot be spoofed.
    """

    mapping: dict[str, list[str]] = Field(
        default_factory=dict,
        description="action_type -> path globs, for server-side re-derivation.",
    )
    protected_branches: list[str] = Field(
        default_factory=list,
        description="Branch patterns that gate as protected_branch_merge.",
    )


class OrganizationRecord(BaseModel):
    """Internal representation of an organization from the database."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    billing_tier: BillingTier
    contact_email: str
    webhook_url: str | None
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
    verdict_reason: str | None
    signature: bytes
    signature_valid: bool
    request_ip: str | None
    request_user_agent: str | None
    response_time_ms: int | None
    trust_score_at_time: int
    chain_previous_hash: str | None
    policy_hash: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
