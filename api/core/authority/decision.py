"""Decision vocabulary for the core authority boundary.

Compatibility with the existing policy vocabulary
-------------------------------------------------
:class:`DecisionReason` is a superset of the deployed
``api.policy.PolicyViolation`` vocabulary: every existing violation code
appears here with an identical string value, so a decision produced by
this boundary can report an existing policy failure without inventing a
second name for it. Core does not import the policy engine at runtime —
the inner layer must not depend on the outer one — so the correspondence
is pinned by a test rather than by an import. New codes are added only
for the authority lifecycle, which has no truthful equivalent in the
existing vocabulary.

REQUIRE_APPROVAL
----------------
``REQUIRE_APPROVAL`` is vocabulary in this phase. It exists so that a
domain policy can express "a human must resolve this" without lying by
returning ``ALLOW`` or ``BLOCK``. The contract rule is absolute:
**a REQUIRE_APPROVAL decision MUST NOT produce executable authority.**
No grant may be issued from it until a separate approval workflow
resolves it to ``ALLOW``. That workflow is not implemented here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from api.core.authority._validation import (
    require_digest,
    require_optional_identifier,
    require_utc,
)
from api.core.authority.errors import CoreAuthorityError


class Decision(StrEnum):
    """What the organisation's current policy says about a proposed act."""

    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class ConsequenceClass(StrEnum):
    """How much damage the act does if it turns out to be unauthorised."""

    #: Low impact and reversible without material cost.
    C1 = "c1"
    #: Material impact; reversible only with effort or cost.
    C2 = "c2"
    #: High impact; reversal is uncertain.
    C3 = "c3"
    #: Critical and irreversible once performed.
    C4 = "c4"


class DecisionReason(StrEnum):
    """Stable, typed reasons a decision came out the way it did."""

    # --- Compatibility: identical values to api.policy.PolicyViolation ---
    AGENT_NOT_ACTIVE = "agent_not_active"
    ACTION_NOT_ALLOWED = "action_not_allowed"
    ACTION_BLOCKED = "action_blocked"
    DAILY_LIMIT_EXCEEDED = "daily_limit_exceeded"
    PER_ACTION_LIMIT_EXCEEDED = "per_action_limit_exceeded"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    TRUST_SCORE_TOO_LOW = "trust_score_too_low"
    TIMESTAMP_INVALID = "timestamp_invalid"
    AMOUNT_INVALID = "amount_invalid"
    POLICY_HASH_MISMATCH = "policy_hash_mismatch"
    ACTION_TYPE_DOWNGRADE = "action_type_downgrade"
    ACTION_TYPE_UNKNOWN = "action_type_unknown"
    WALLET_CHAIN_NOT_ALLOWED = "wallet_chain_not_allowed"
    WALLET_RECIPIENT_NOT_ALLOWED = "wallet_recipient_not_allowed"
    WALLET_RECIPIENT_REQUIRED = "wallet_recipient_required"
    WALLET_POLICY_INVALID = "wallet_policy_invalid"

    # --- New: delegated-authority lifecycle ---
    # Required because the existing vocabulary describes policy limits, not
    # the presence, verification state or binding of external authority.
    AUTHORITY_REQUIRED_BUT_MISSING = "authority_required_but_missing"
    AUTHORITY_UNVERIFIED = "authority_unverified"
    AUTHORITY_VERIFICATION_FAILED = "authority_verification_failed"
    AUTHORITY_PROVIDER_UNAVAILABLE = "authority_provider_unavailable"
    AUTHORITY_NOT_YET_VALID = "authority_not_yet_valid"
    AUTHORITY_EXPIRED = "authority_expired"
    AUTHORITY_REVOKED = "authority_revoked"
    AUTHORITY_PRINCIPAL_MISMATCH = "authority_principal_mismatch"
    AUTHORITY_DELEGATE_NOT_BOUND = "authority_delegate_not_bound"
    AUTHORITY_SCOPE_EXCEEDED = "authority_scope_exceeded"

    # --- New: execution-authority grant lifecycle ---
    GRANT_NOT_FOUND = "grant_not_found"
    GRANT_MALFORMED = "grant_malformed"
    GRANT_REVOKED = "grant_revoked"
    GRANT_EXPIRED = "grant_expired"
    GRANT_ALREADY_CONSUMED = "grant_already_consumed"
    GRANT_ACTION_MISMATCH = "grant_action_mismatch"
    GRANT_EXECUTOR_MISMATCH = "grant_executor_mismatch"
    EXECUTION_REF_CONFLICT = "execution_ref_conflict"

    # --- New: approval workflow ---
    APPROVAL_REQUIRED = "approval_required"


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """Which policy content a decision was evaluated against.

    This is *evidence of what was evaluated*, not a licence to skip
    re-validation later. The evaluation-time policy is never permanently
    authoritative: first consumption of the resulting authority is
    subject to the policy, principal, delegation and executor validity
    current **at consumption time**. Phase 3/4 defines the race-safe
    persistence that enforces that; nothing in this phase may be read as
    freezing a decision in time.
    """

    policy_hash: str
    captured_at: datetime
    source: str | None = None

    def __post_init__(self) -> None:
        require_digest(self.policy_hash, "policy_hash", error=CoreAuthorityError)
        object.__setattr__(
            self,
            "captured_at",
            require_utc(self.captured_at, "captured_at", error=CoreAuthorityError),
        )
        require_optional_identifier(self.source, "source", error=CoreAuthorityError)


@dataclass(frozen=True, slots=True)
class ApprovalRequirement:
    """What a ``REQUIRE_APPROVAL`` decision is waiting for.

    A type only. Carrying one of these means executable authority has
    **not** been issued and must not be issued until a separate approval
    workflow — out of scope for this phase — resolves it.
    """

    reason: DecisionReason = DecisionReason.APPROVAL_REQUIRED
    consequence_class: ConsequenceClass | None = None
    approver_scope: str | None = None
    expires_at: datetime | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reason, DecisionReason):
            raise CoreAuthorityError(
                f"reason must be a DecisionReason, got {type(self.reason).__name__}"
            )
        require_optional_identifier(
            self.approver_scope, "approver_scope", error=CoreAuthorityError
        )


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """A decision together with the reasons and the policy it was made under.

    ``DomainPolicy.evaluate`` returns this rather than a bare
    :class:`Decision`. A bare enum would drop the two things the rest of
    the boundary depends on: the typed reasons a caller must be able to
    render stably, and the policy snapshot the decision was evaluated
    against.
    """

    decision: Decision
    policy_snapshot: PolicySnapshot
    reasons: tuple[DecisionReason, ...] = ()
    consequence_class: ConsequenceClass | None = None
    approval_requirement: ApprovalRequirement | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.decision, Decision):
            raise CoreAuthorityError(
                f"decision must be a Decision, got {type(self.decision).__name__}"
            )
        if not isinstance(self.policy_snapshot, PolicySnapshot):
            raise CoreAuthorityError(
                "policy_snapshot must be a PolicySnapshot, got "
                f"{type(self.policy_snapshot).__name__}"
            )
        reasons = tuple(self.reasons)
        for reason in reasons:
            if not isinstance(reason, DecisionReason):
                raise CoreAuthorityError(
                    f"reasons must be DecisionReason members, got {type(reason).__name__}"
                )
        object.__setattr__(self, "reasons", reasons)

        if self.decision is Decision.BLOCK and not reasons:
            raise CoreAuthorityError("a BLOCK decision must carry at least one reason")
        if self.decision is Decision.REQUIRE_APPROVAL and self.approval_requirement is None:
            raise CoreAuthorityError(
                "a REQUIRE_APPROVAL decision must carry an ApprovalRequirement"
            )
        if self.decision is not Decision.REQUIRE_APPROVAL and (
            self.approval_requirement is not None
        ):
            raise CoreAuthorityError(
                "an ApprovalRequirement is only meaningful on a REQUIRE_APPROVAL decision"
            )

    @property
    def authorises_execution(self) -> bool:
        """Only ``ALLOW`` may lead to executable authority being issued.

        ``REQUIRE_APPROVAL`` is not a soft allow. It yields no grant.
        """
        return self.decision is Decision.ALLOW
