"""Durable issuance and consumption of execution authority.

What is authoritative, and why it is not new
--------------------------------------------
Three questions have to be answered under concurrency, and this module
answers none of them with machinery of its own:

* **"Has this grant been spent?"** — ``approval_token_consumptions``.
  That table already is the single-use authority for approval tokens: a
  primary key on ``token_id``, a unique ``token_digest``, a unique
  ``(agent_id, execution_ref)`` partial index for retries, and
  append-only triggers. A grant carries an ``approval_token_id``, so
  claiming the grant *is* inserting that row, through the same
  ``Database.insert_token_consumption_on`` the executor gate uses.
* **"Is there capacity left?"** — ``spend_reservations``, reserved
  through ``Database.reserve_rate_and_spend_on``: the advisory-locked
  increment-and-test where the increment *is* the check. Two different
  transactions competing for the same remaining capacity serialise on
  that lock, so they cannot both observe the same headroom.
* **"Is this the same issuance?"** — a unique index on
  ``(agent_id, issuance_ref)``. A retry carrying identical material
  returns the original grant; a reused reference carrying different
  material is a conflict, not a retry.

Lock order
----------
Every path takes locks in the SAME order, so two of them can never form a
cycle:

1. the entry advisory lock — ``authority-issuance:<agent>:<ref>`` for
   issuance, ``authority-grant:<grant>`` for consumption;
2. the ``agents`` row, ``FOR SHARE`` — this is the mutable principal and
   policy state that authorisation is derived from. Taking it here, and
   holding it until commit, is what closes the window in which a
   concurrent ``UPDATE agents`` could change policy after it was read but
   before the claim committed. ``FOR SHARE`` rather than ``FOR UPDATE``:
   concurrent consumptions of *different* grants for one agent may all
   read it at once, while any writer to that row waits;
3. the ``execution_authority_grants`` row, ``FOR UPDATE``;
4. the spend advisory lock ``spend-reservation:<agent>`` (issuance only,
   inside the reused reservation primitive);
5. inserts into ``audit_logs`` / ``approval_token_consumptions``, then the
   grant and reservation updates.

Nothing acquires a lock earlier in this list while holding one later in
it.

The evaluation-time snapshot is not permission
----------------------------------------------
A grant records the policy digest it was issued under. That is evidence,
not standing authority. Before the claim, consumption re-derives the
policy digest from **current** state and refuses a grant whose policy,
principal or delegated scope has moved since the decision. The
re-validation and the claim happen in one transaction under the grant's
advisory lock, so a policy change racing with a consumption lands either
wholly before it (and refuses it) or wholly after it (and finds the grant
already terminal). There is no window between them.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

import asyncpg

from api import jcs
from api.core.authority.decision import DecisionReason
from api.core.authority.grant import GrantStatus, first_rejection
from api.core.authority.lifecycle import ConsumptionOutcome
from api.database import Database, LimitReservationError
from api.models import ActionVerdict, AuditLogEntry

logger = logging.getLogger(__name__)

#: Versioned preimage identifier for the issuance-identity digest.
ISSUANCE_DIGEST_FORMAT: Final[str] = "inntris-authority-issuance-v1"

#: Version of the TTL policy applied at issuance. Bound into the issuance
#: identity so a build that changes how long authority lives produces a
#: different logical issuance rather than silently reusing an old grant.
TTL_PROFILE_VERSION: Final[str] = "execution-authority-ttl-v1"

#: Versioned preimage identifier for the delegated-authority scope digest.
AUTHORITY_SCOPE_DIGEST_FORMAT: Final[str] = "inntris-authority-scope-v1"

#: Ceiling on how long execution authority may live, whatever a caller asks
#: for. Bounded authority that outlives the decision it rests on is not
#: bounded.
MAX_EXECUTION_AUTHORITY_TTL: Final[timedelta] = timedelta(minutes=5)


def clamp_grant_expiry(
    *,
    issued_at: datetime,
    requested_expires_at: datetime | None = None,
    authority_expires_at: datetime | None = None,
    additional_bounds: tuple[datetime, ...] = (),
    max_ttl: timedelta = MAX_EXECUTION_AUTHORITY_TTL,
) -> datetime:
    """The latest instant this grant may remain valid.

    The earliest of: the configured TTL ceiling, whatever the caller asked
    for, the delegated authority's own expiry, and any tighter trusted
    bound. A grant must never outlive the authority it rests on, so this
    takes a minimum and never a maximum.
    """
    bounds = [issued_at + max_ttl]
    if requested_expires_at is not None:
        bounds.append(requested_expires_at.astimezone(UTC))
    if authority_expires_at is not None:
        bounds.append(authority_expires_at.astimezone(UTC))
    bounds.extend(bound.astimezone(UTC) for bound in additional_bounds)
    return min(bounds)


class GrantLifetimeError(ValueError):
    """The clamped validity window is empty, so no authority can be issued.

    Reached when the delegated authority has already expired, or a trusted
    bound sits at or before issuance. Issuing a zero-length grant would be
    issuing authority that is dead on arrival while looking valid.
    """


class IssueOutcome(StrEnum):
    """What an issuance attempt did."""

    #: A new grant was created and capacity reserved for it.
    ISSUED = "issued"
    #: An identical earlier issuance was returned. Nothing new was reserved.
    IDEMPOTENT = "idempotent"
    #: The issuance reference is already in use for different material.
    CONFLICT = "conflict"
    #: Organisation capacity refused the reservation. No grant exists.
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class IssueResult:
    """Typed outcome of one issuance attempt."""

    outcome: IssueOutcome
    grant_id: UUID | None = None
    approval_token_id: str | None = None
    reason: DecisionReason | None = None
    detail: str | None = None
    #: Lifecycle state of the grant this result refers to, as of the attempt.
    #: An idempotent retry recovers the historical grant identity whatever
    #: state it is in, so this is how the caller learns it is spent.
    grant_status: GrantStatus | None = None

    @property
    def authorises_execution(self) -> bool:
        """Whether USABLE authority exists as a result of this attempt.

        An idempotent retry is not automatically usable. Recovering the
        identity of a grant that has since been consumed, revoked or
        expired tells the caller which grant it was; it does not hand back
        authority that is gone. Treating every IDEMPOTENT as usable is how
        a spent single-use grant gets executed a second time.
        """
        if self.outcome is IssueOutcome.ISSUED:
            return True
        if self.outcome is IssueOutcome.IDEMPOTENT:
            return self.grant_status is GrantStatus.ACTIVE
        return False


@dataclass(frozen=True, slots=True)
class ConsumeResult:
    """Typed outcome of one consumption attempt."""

    outcome: ConsumptionOutcome
    grant_id: UUID | None = None
    consumption_audit_id: UUID | None = None
    execution_ref: str | None = None
    rejection_reason: DecisionReason | None = None

    @property
    def spent_authority(self) -> bool:
        """Whether *this* attempt is the one that spent the grant.

        ``RECOVERED`` echoes an earlier authorisation and spends nothing.
        """
        return self.outcome is ConsumptionOutcome.AUTHORISED

    @property
    def may_execute(self) -> bool:
        """Whether the caller may proceed to perform the act.

        False for a recovery: that path returns the record of an execution
        that was already authorised and must never start a second one.
        """
        return self.outcome is ConsumptionOutcome.AUTHORISED


def issuance_digest(
    *,
    organisation_id: UUID | str,
    agent_id: UUID | str,
    issuance_ref: str,
    execution_action_hash: str,
    signed_action_hash: str | None,
    policy_hash: str,
    policy_revision: str,
    policy_snapshot_format: str,
    executor_binding_digest: str,
    amount_usd: Decimal,
    domain: str,
    action_type: str,
    consequence_class: str | None,
    authority_scope_digest: str | None,
    ttl_profile: str = TTL_PROFILE_VERSION,
    requested_expires_at: datetime | None = None,
    authority_expires_at: datetime | None = None,
) -> str:
    """Digest of the material an issuance is *about*.

    Deliberately excludes anything derived from the *time of the attempt*
    — the minted token id, ``issued_at``, and the TTL-derived effective
    expiry — so a retry of the same request digests identically however
    long after the first attempt it arrives. A legitimate late retry must
    still be a retry.

    The validity *inputs* are bound, because they define which logical
    issuance this is: the TTL profile version, an explicitly requested
    expiry when the caller supplied one, and the delegated authority's own
    bound. Changing any of them is a different issuance, not a retry of
    the same one.
    """
    return jcs.sha256_hex(
        {
            "format": ISSUANCE_DIGEST_FORMAT,
            "organisation_id": str(organisation_id),
            "agent_id": str(agent_id),
            "issuance_ref": issuance_ref,
            "execution_action_hash": execution_action_hash,
            "signed_action_hash": signed_action_hash,
            "policy_hash": policy_hash,
            "policy_revision": policy_revision,
            "policy_snapshot_format": policy_snapshot_format,
            "executor_binding_digest": executor_binding_digest,
            "amount_usd": str(amount_usd),
            "domain": domain,
            "action_type": action_type,
            "consequence_class": consequence_class,
            "authority_scope_digest": authority_scope_digest,
            "ttl_profile": ttl_profile,
            "requested_expires_at": (
                requested_expires_at.astimezone(UTC).isoformat()
                if requested_expires_at is not None
                else None
            ),
            "authority_expires_at": (
                authority_expires_at.astimezone(UTC).isoformat()
                if authority_expires_at is not None
                else None
            ),
        }
    )


def authority_scope_digest(
    *,
    issuer: str,
    external_reference_id: str,
    artefact_digest: str,
    scope: Mapping[str, Any] | None,
) -> str:
    """Digest of the delegated authority a decision was made under.

    Covers the artefact's identity and the scope's content, so a scope
    that was narrowed, re-issued or revoked between the decision and the
    execution produces a different digest and is refused at consumption.
    """
    return jcs.sha256_hex(
        {
            "format": AUTHORITY_SCOPE_DIGEST_FORMAT,
            "issuer": issuer,
            "external_reference_id": external_reference_id,
            "artefact_digest": artefact_digest,
            "scope": dict(sorted((scope or {}).items())),
        }
    )


#: Resolves the policy digest and revision that apply to an agent RIGHT NOW.
#: Signature: ``(agent_row, action_type, domain) -> (policy_hash, revision)``.
CurrentPolicyResolver = Callable[[Any, str, str], "tuple[str, str]"]


def default_current_policy_resolver(
    agent_row: Any, action_type: str, domain: str
) -> tuple[str, str]:
    """Re-derive the current policy digest for a persisted grant's domain.

    Dispatches on the grant's own ``domain`` column. Only the payment
    domain has a module today; anything else raises rather than being
    waved through, because a grant whose current policy cannot be
    re-derived cannot be shown to still be permitted.
    """
    if domain != "payment":
        raise ValueError(
            f"no current-policy resolver for domain {domain!r}; a grant whose "
            "policy cannot be re-derived must not be consumed"
        )
    from api.domains.payment.policy import PAYMENT_ACTION_TYPES
    from api.domains.payment.snapshot import build_payment_authority_policy_snapshot
    from api.policy import PolicyEngine

    if action_type not in PAYMENT_ACTION_TYPES:
        raise ValueError(f"{action_type!r} is not governed by the payment domain")

    snapshot = build_payment_authority_policy_snapshot(
        agent_row,
        action_type,
        trust_threshold=PolicyEngine.TRUST_THRESHOLDS.get(action_type),
    )
    return snapshot.digest, snapshot.revision


@dataclass(frozen=True, slots=True)
class ResolvedAuthorityEvidence:
    """Trusted current evidence about the delegated authority, supplied to the store.

    One input binding all four things consumption has to know, so they
    cannot be presented separately or partially:

    * ``scope_digest`` — WHICH authority this is evidence about. Compared
      against the digest the grant was issued under, so evidence for a
      different or re-issued authority cannot be passed off as evidence
      for this one.
    * ``verified`` — whether it still verifies;
    * ``revoked`` — whether the issuer has withdrawn it;
    * ``expires_at`` — its own validity bound.

    Phase 3 is provider-neutral and performs no network call. The caller
    that can reach the provider resolves it *before* entering the atomic
    consume section and hands the result here; the store validates that
    evidence, it does not re-resolve the issuer itself.
    """

    scope_digest: str | None = None
    verified: bool = True
    revoked: bool = False
    expires_at: datetime | None = None


class OutcomeState(StrEnum):
    """What is known about the external side effect this authority permitted.

    Modelled on the reconciliation failure model used by the adapter
    repository: a thrown or timed-out executor is ``OUTCOME_UNKNOWN``, never
    ``FAILED_FINAL``, because a timeout is not proof that nothing happened.
    """

    PENDING = "pending"
    SUCCEEDED = "succeeded"
    #: Proven not to have happened. Only for evidence that actually proves it.
    FAILED_FINAL = "failed_final"
    #: Blocks retries until authoritative evidence resolves it.
    OUTCOME_UNKNOWN = "outcome_unknown"


class AuthorityStore:
    """Durable execution authority, over the mechanisms that already exist."""

    def __init__(
        self,
        database: Database,
        *,
        current_policy_resolver: CurrentPolicyResolver | None = None,
    ) -> None:
        self._db = database
        self._resolve_current_policy = (
            current_policy_resolver or default_current_policy_resolver
        )

    # -- issuance ---------------------------------------------------------

    async def issue(
        self,
        *,
        agent_id: UUID,
        organisation_id: UUID,
        issuance_ref: str,
        execution_action_hash: str,
        policy_hash: str,
        policy_snapshot_format: str,
        policy_revision: str,
        executor_binding_digest: str,
        domain: str,
        action_type: str,
        expires_at: datetime | None = None,
        authority_expires_at: datetime | None = None,
        issued_at: datetime | None = None,
        minute_start: datetime,
        day_start: datetime,
        rate_limit_per_minute: int | None = None,
        daily_limit_usd: Decimal | None = None,
        amount_usd: Decimal = Decimal("0"),
        signed_action_hash: str | None = None,
        executor_reference: str | None = None,
        consequence_class: str | None = None,
        authority_scope_digest: str | None = None,
    ) -> IssueResult:
        """Issue bounded, single-use authority, reserving capacity for it.

        Everything happens in one transaction, in the module's documented
        lock order. The issuance identity is locked first, so a concurrent
        retry of the same reference waits and then finds the committed
        grant instead of reserving capacity a second time.

        **Capacity comes from trusted state, never from the caller.**
        ``rate_limit_per_minute`` and ``daily_limit_usd`` are read from the
        locked ``agents`` row. If a caller supplies them anyway they are
        treated as an assertion about current state and must match it
        exactly; a mismatch refuses the issuance rather than letting a
        caller name its own ceiling.
        """
        issued = (issued_at or datetime.now(UTC)).astimezone(UTC)
        effective_expiry = clamp_grant_expiry(
            issued_at=issued,
            requested_expires_at=expires_at,
            authority_expires_at=authority_expires_at,
        )
        if effective_expiry <= issued:
            raise GrantLifetimeError(
                "the clamped validity window is empty; the delegated authority "
                "or a trusted bound has already expired"
            )

        digest = issuance_digest(
            organisation_id=organisation_id,
            agent_id=agent_id,
            issuance_ref=issuance_ref,
            execution_action_hash=execution_action_hash,
            signed_action_hash=signed_action_hash,
            policy_hash=policy_hash,
            policy_revision=policy_revision,
            policy_snapshot_format=policy_snapshot_format,
            executor_binding_digest=executor_binding_digest,
            amount_usd=amount_usd,
            domain=domain,
            action_type=action_type,
            consequence_class=consequence_class,
            authority_scope_digest=authority_scope_digest,
            requested_expires_at=expires_at,
            authority_expires_at=authority_expires_at,
        )
        approval_token_id = secrets.token_urlsafe(24)

        try:
            async with self._db.acquire() as conn, conn.transaction():
                # Serialise this issuance identity before touching capacity.
                # Without this, two concurrent retries of one request could
                # both reserve before either could see the other's row.
                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
                    f"authority-issuance:{agent_id}:{issuance_ref}",
                )

                # Lock order step 2: the principal's own policy row. This is
                # where capacity comes from, and holding it means a concurrent
                # limit change cannot land between reading the ceiling and
                # reserving against it.
                agent_row = await conn.fetchrow(
                    "SELECT * FROM agents WHERE id = $1 FOR SHARE",
                    agent_id,
                )
                if agent_row is None or agent_row["org_id"] != organisation_id:
                    return IssueResult(
                        outcome=IssueOutcome.REFUSED,
                        reason=DecisionReason.AGENT_NOT_ACTIVE,
                        detail="no such agent for this organisation",
                    )
                if agent_row["status"] != "active":
                    return IssueResult(
                        outcome=IssueOutcome.REFUSED,
                        reason=DecisionReason.AGENT_NOT_ACTIVE,
                        detail=f"agent status is {agent_row['status']}",
                    )

                trusted_rate_limit = int(agent_row["rate_limit_per_minute"])
                trusted_daily_limit = Decimal(agent_row["daily_limit_usd"])
                if (
                    rate_limit_per_minute is not None
                    and int(rate_limit_per_minute) != trusted_rate_limit
                ) or (
                    daily_limit_usd is not None
                    and Decimal(daily_limit_usd) != trusted_daily_limit
                ):
                    # A caller asserting limits that do not match trusted state
                    # is either stale or trying to name its own ceiling. Either
                    # way the request is not the one the organisation permits.
                    return IssueResult(
                        outcome=IssueOutcome.REFUSED,
                        reason=DecisionReason.POLICY_HASH_MISMATCH,
                        detail=(
                            "supplied limits do not match current trusted state "
                            f"(rate {trusted_rate_limit}, daily {trusted_daily_limit})"
                        ),
                    )

                existing = await conn.fetchrow(
                    """
                    SELECT id, issuance_digest, approval_token_id, status, expires_at
                    FROM execution_authority_grants
                    WHERE agent_id = $1 AND issuance_ref = $2
                    FOR UPDATE
                    """,
                    agent_id,
                    issuance_ref,
                )
                if existing is not None:
                    if existing["issuance_digest"] != digest:
                        return IssueResult(
                            outcome=IssueOutcome.CONFLICT,
                            grant_id=existing["id"],
                            reason=DecisionReason.GRANT_ACTION_MISMATCH,
                            grant_status=GrantStatus(existing["status"]),
                            detail=(
                                "issuance_ref is already in use for different "
                                "material; a changed request is not a retry"
                            ),
                        )
                    # Report the grant's state so the caller can tell a
                    # recovered-and-usable retry from a recovered-but-spent one.
                    # Expiry is time-derived: a stored 'active' row whose window
                    # has closed is expired, whatever the column says.
                    status = GrantStatus(existing["status"])
                    if status is GrantStatus.ACTIVE and issued >= existing["expires_at"]:
                        status = GrantStatus.EXPIRED
                    return IssueResult(
                        outcome=IssueOutcome.IDEMPOTENT,
                        grant_id=existing["id"],
                        approval_token_id=existing["approval_token_id"],
                        grant_status=status,
                    )

                _minute, _daily, reservation_id = (
                    await self._db.reserve_rate_and_spend_on(
                        conn,
                        agent_id=agent_id,
                        minute_start=minute_start,
                        day_start=day_start,
                        amount=amount_usd,
                        rate_limit_per_minute=trusted_rate_limit,
                        daily_limit_usd=trusted_daily_limit,
                        action_hash=execution_action_hash,
                        approval_token_id=approval_token_id,
                        expires_at=effective_expiry,
                    )
                )

                grant_id = await conn.fetchval(
                    """
                    INSERT INTO execution_authority_grants (
                        agent_id, org_id, issuance_ref, issuance_digest,
                        execution_action_hash, signed_action_hash,
                        policy_hash, policy_snapshot_format, policy_revision,
                        executor_binding_digest, executor_reference,
                        consequence_class, domain, action_type,
                        authority_scope_digest,
                        amount_usd, spend_reservation_id, approval_token_id,
                        issued_at, expires_at, authority_expires_at
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                        $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
                    )
                    RETURNING id
                    """,
                    agent_id,
                    organisation_id,
                    issuance_ref,
                    digest,
                    execution_action_hash,
                    signed_action_hash,
                    policy_hash,
                    policy_snapshot_format,
                    policy_revision,
                    executor_binding_digest,
                    executor_reference,
                    consequence_class,
                    domain,
                    action_type,
                    authority_scope_digest,
                    amount_usd,
                    reservation_id,
                    approval_token_id,
                    issued,
                    effective_expiry,
                    authority_expires_at,
                )
                return IssueResult(
                    outcome=IssueOutcome.ISSUED,
                    grant_id=grant_id,
                    approval_token_id=approval_token_id,
                    grant_status=GrantStatus.ACTIVE,
                )
        except LimitReservationError as exc:
            # The transaction rolled back, so nothing was reserved and no
            # grant exists. This is the capacity refusal, not an error.
            return IssueResult(
                outcome=IssueOutcome.REFUSED,
                reason=(
                    DecisionReason.RATE_LIMIT_EXCEEDED
                    if exc.kind == "rate"
                    else DecisionReason.DAILY_LIMIT_EXCEEDED
                ),
                detail=str(exc),
            )

    # -- consumption ------------------------------------------------------

    async def consume(
        self,
        *,
        grant_id: UUID,
        execution_action_hash: str,
        executor_binding_digest: str,
        execution_ref: str | None = None,
        authority_evidence: ResolvedAuthorityEvidence | None = None,
        audit_entry_factory: Callable[[Any], AuditLogEntry] | None = None,
        recovery_only: bool = False,
        at: datetime | None = None,
    ) -> ConsumeResult:
        """Spend the grant once, or recover the record of an earlier spend.

        ``execution_ref`` is required on this path. Single-use authority
        whose consumption cannot be recovered turns any lost response into
        an unanswerable question: did it execute? The legacy
        ``/verify-token`` contract still permits omitting it, and that
        contract is unchanged; this generic path does not.
        """
        now = (at or datetime.now(UTC)).astimezone(UTC)

        if not isinstance(execution_ref, str) or not execution_ref.strip():
            return ConsumeResult(
                outcome=ConsumptionOutcome.REJECTED,
                grant_id=grant_id,
                rejection_reason=DecisionReason.EXECUTION_REF_CONFLICT,
            )

        async with self._db.acquire() as conn, conn.transaction():
            # Lock order step 1: serialise consumers of this grant.
            await conn.execute(
                "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
                f"authority-grant:{grant_id}",
            )

            # Lock order step 2: pin the mutable principal/policy state BEFORE
            # anything is derived from it, and hold it until this transaction
            # commits. Without this row lock a concurrent UPDATE agents could
            # commit between the read and the claim, and the claim would land
            # under policy that no longer exists.
            agent_row = await conn.fetchrow(
                """
                SELECT a.*
                FROM agents a
                JOIN execution_authority_grants g ON g.agent_id = a.id
                WHERE g.id = $1
                FOR SHARE OF a
                """,
                grant_id,
            )

            # Lock order step 3: the grant itself.
            grant = await conn.fetchrow(
                """
                SELECT g.*
                FROM execution_authority_grants g
                WHERE g.id = $1
                FOR UPDATE OF g
                """,
                grant_id,
            )
            if grant is None or agent_row is None:
                return ConsumeResult(
                    outcome=ConsumptionOutcome.REJECTED,
                    rejection_reason=DecisionReason.GRANT_NOT_FOUND,
                )

            # --- Immutable identity is checked BEFORE recovery -----------
            # Recovery may bypass MUTABLE policy and lifecycle state, because
            # it returns a historical fact rather than authorising anything.
            # It must not bypass the executor binding, which is immutable and
            # is the whole reason a grant belongs to one executor: otherwise
            # anybody holding the token could read back somebody else's
            # committed execution.
            if grant["executor_binding_digest"] != executor_binding_digest:
                return ConsumeResult(
                    outcome=ConsumptionOutcome.REJECTED,
                    grant_id=grant_id,
                    rejection_reason=DecisionReason.GRANT_EXECUTOR_MISMATCH,
                )

            # --- Recovery comes before every LIFECYCLE rejection ----------
            # A committed consumption with this exact reference is returned
            # even after the grant expired: the authority was spent while it
            # was valid, and this only hands back the record of it.
            claimed = await conn.fetchrow(
                """
                SELECT token_id, action_hash, audit_log_id, execution_ref
                FROM approval_token_consumptions
                WHERE token_id = $1
                """,
                grant["approval_token_id"],
            )
            if (
                claimed is not None
                and execution_ref is not None
                and claimed["execution_ref"] == execution_ref
                and claimed["action_hash"] == execution_action_hash
            ):
                return ConsumeResult(
                    outcome=ConsumptionOutcome.RECOVERED,
                    grant_id=grant_id,
                    consumption_audit_id=claimed["audit_log_id"],
                    execution_ref=execution_ref,
                )

            # A reference already bound to a DIFFERENT token belongs to another
            # execution attempt entirely. That is a reference conflict, not
            # "this grant is spent" -- reporting it as the latter would send an
            # operator looking at the wrong grant.
            foreign_ref = await conn.fetchval(
                """
                SELECT 1 FROM approval_token_consumptions
                WHERE agent_id = $1 AND execution_ref = $2 AND token_id <> $3
                LIMIT 1
                """,
                grant["agent_id"],
                execution_ref,
                grant["approval_token_id"],
            )
            if foreign_ref is not None:
                return ConsumeResult(
                    outcome=ConsumptionOutcome.REJECTED,
                    grant_id=grant_id,
                    rejection_reason=DecisionReason.EXECUTION_REF_CONFLICT,
                )

            if recovery_only:
                # The caller's token is authentic but expired. It may read
                # back an already committed result -- handled above -- and
                # nothing else. With no matching consumption there is no
                # historical fact to return, and an expired token must never
                # authorise a NEW execution.
                return ConsumeResult(
                    outcome=ConsumptionOutcome.REJECTED,
                    grant_id=grant_id,
                    rejection_reason=DecisionReason.GRANT_EXPIRED,
                )

            # --- Deterministic rejection precedence ---------------------
            candidates: list[DecisionReason] = []
            if grant["execution_action_hash"] != execution_action_hash:
                candidates.append(DecisionReason.GRANT_ACTION_MISMATCH)
            if grant["executor_binding_digest"] != executor_binding_digest:
                candidates.append(DecisionReason.GRANT_EXECUTOR_MISMATCH)
            if claimed is not None:
                if claimed["execution_ref"] != execution_ref:
                    candidates.append(DecisionReason.EXECUTION_REF_CONFLICT)
                candidates.append(DecisionReason.GRANT_ALREADY_CONSUMED)

            status = GrantStatus(grant["status"])
            if status is GrantStatus.REVOKED:
                candidates.append(DecisionReason.GRANT_REVOKED)
            elif status is GrantStatus.CONSUMED:
                candidates.append(DecisionReason.GRANT_ALREADY_CONSUMED)
            elif status is GrantStatus.EXPIRED or now >= grant["expires_at"]:
                # Expiry is time-derived: a stored 'active' row whose window
                # has closed is expired, whatever the column says.
                candidates.append(DecisionReason.GRANT_EXPIRED)

            rejection = first_rejection(candidates)
            if rejection is not None:
                return ConsumeResult(
                    outcome=ConsumptionOutcome.REJECTED,
                    grant_id=grant_id,
                    rejection_reason=rejection,
                )

            # --- Current mutable state decides, not the snapshot ---------
            revalidation = self._revalidate(grant, agent_row, authority_evidence, now)
            if revalidation is not None:
                return ConsumeResult(
                    outcome=ConsumptionOutcome.REJECTED,
                    grant_id=grant_id,
                    rejection_reason=revalidation,
                )

            # --- The claim, through the existing single-use authority ----
            entry = (
                audit_entry_factory(grant)
                if audit_entry_factory is not None
                else _default_audit_entry(grant, execution_ref)
            )
            token_id = grant["approval_token_id"]
            token_digest = hashlib.sha256(token_id.encode("utf-8")).digest()
            try:
                async with conn.transaction():
                    claim = await self._db.insert_token_consumption_on(
                        conn,
                        entry,
                        token_id=token_id,
                        token_digest=token_digest,
                        approved_action_hash=grant["execution_action_hash"],
                        execution_ref=execution_ref,
                        audit_query=_AUTHORITY_CONSUMPTION_AUDIT_QUERY,
                    )
            except asyncpg.UniqueViolationError as exc:
                claim = None
                # Classify rather than assume. A violation on the
                # (agent_id, execution_ref) index is a reference conflict; a
                # violation on the token key is a second claim of this grant.
                constraint = getattr(exc, "constraint_name", "") or ""
                unique_reason = (
                    DecisionReason.EXECUTION_REF_CONFLICT
                    if "execution_ref" in constraint
                    else DecisionReason.GRANT_ALREADY_CONSUMED
                )
            else:
                unique_reason = DecisionReason.GRANT_ALREADY_CONSUMED
            if claim is None:
                # Another consumer won the claim inside this window, or the
                # reference is spoken for.
                return ConsumeResult(
                    outcome=ConsumptionOutcome.REJECTED,
                    grant_id=grant_id,
                    rejection_reason=unique_reason,
                )
            audit_id, _mode = claim

            await conn.execute(
                """
                UPDATE execution_authority_grants
                SET status = 'consumed', consumed_at = NOW(),
                    consumption_audit_id = $2, execution_ref = $3
                WHERE id = $1 AND status = 'active'
                """,
                grant_id,
                audit_id,
                execution_ref,
            )
            return ConsumeResult(
                outcome=ConsumptionOutcome.AUTHORISED,
                grant_id=grant_id,
                consumption_audit_id=audit_id,
                execution_ref=execution_ref,
            )

    def _revalidate(
        self,
        grant: Any,
        agent_row: Any,
        authority_evidence: ResolvedAuthorityEvidence | None,
        now: datetime,
    ) -> DecisionReason | None:
        """Re-check current policy, principal and delegation. ``None`` = fine.

        Ordered most specific first, so an operator reading a refusal learns
        the actual cause rather than whichever check happened to run first.
        """
        if agent_row["status"] != "active":
            return DecisionReason.AGENT_NOT_ACTIVE
        if agent_row["org_id"] != grant["org_id"]:
            # The composite foreign key makes this unreachable through normal
            # writes. Checked anyway: if it is ever true, the ownership record
            # is inconsistent and nothing below can be trusted.
            return DecisionReason.AGENT_NOT_ACTIVE

        # Delegated authority, when the caller re-resolved it. Revocation and
        # expiry are reported distinctly from "the scope changed" so the
        # refusal names what actually happened.
        if grant["authority_scope_digest"] is not None and authority_evidence is None:
            # The decision rested on delegated authority. Consuming it without
            # any current evidence about that authority would spend a grant
            # whose basis may have been revoked minutes ago. Absent evidence is
            # not evidence of validity.
            return DecisionReason.AUTHORITY_UNVERIFIED

        if authority_evidence is not None:
            if authority_evidence.revoked:
                return DecisionReason.AUTHORITY_REVOKED
            if (
                authority_evidence.expires_at is not None
                and now >= authority_evidence.expires_at.astimezone(UTC)
            ):
                return DecisionReason.AUTHORITY_EXPIRED
            if not authority_evidence.verified:
                return DecisionReason.AUTHORITY_VERIFICATION_FAILED
            if authority_evidence.scope_digest != grant["authority_scope_digest"]:
                # Evidence about a different authority than the one this grant
                # was issued under.
                return DecisionReason.AUTHORITY_SCOPE_EXCEEDED

        if (
            grant["authority_expires_at"] is not None
            and now >= grant["authority_expires_at"]
        ):
            return DecisionReason.AUTHORITY_EXPIRED


        try:
            current_hash, _revision = self._resolve_current_policy(
                _AgentView(agent_row), grant["action_type"], grant["domain"]
            )
        except ValueError:
            return DecisionReason.POLICY_HASH_MISMATCH

        if current_hash != grant["policy_hash"]:
            return DecisionReason.POLICY_HASH_MISMATCH
        return None

    # -- lifecycle --------------------------------------------------------

    async def record_outcome(
        self,
        *,
        grant_id: UUID,
        outcome_state: OutcomeState,
        outcome_reference: str | None = None,
        detail: str | None = None,
    ) -> bool:
        """Record what became of the execution this authority permitted.

        **Reserved spend is never released here, in any outcome.** A
        reservation moved to 'consumed' when the grant was claimed, and it
        stays charged:

        * ``SUCCEEDED`` — money moved. Obviously charged.
        * ``FAILED_FINAL`` — proven not to have happened. Still not released
          by this call: releasing capacity belongs to a reconciliation path
          that has the rail's own evidence, not to the executor's opinion.
        * ``OUTCOME_UNKNOWN`` — an executor timed out or threw. This is the
          case the rule exists for. A timeout is not proof that no money
          moved, so releasing the reservation here would hand the same
          capacity to a second transaction while the first may well have
          settled. It stays charged until authoritative evidence resolves it.

        An unknown outcome may later be resolved to succeeded or failed_final
        by evidence; nothing returns to pending.
        """
        async with self._db.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE execution_authority_grants
                SET outcome_state = $2,
                    outcome_reference = $3,
                    outcome_detail = $4,
                    outcome_recorded_at = NOW()
                WHERE id = $1 AND status = 'consumed'
                """,
                grant_id,
                outcome_state.value,
                outcome_reference,
                (detail or None) if detail is None else detail[:1000],
            )
        return result == "UPDATE 1"

    async def revoke(self, *, grant_id: UUID, reason: str) -> bool:
        """Withdraw unspent authority. Terminal states are left alone."""
        async with self._db.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE execution_authority_grants
                SET status = 'revoked', revoked_at = NOW(), revocation_reason = $2
                WHERE id = $1 AND status = 'active'
                """,
                grant_id,
                reason[:255],
            )
        return result == "UPDATE 1"

    async def get(self, grant_id: UUID) -> Any:
        async with self._db.acquire() as conn:
            return await conn.fetchrow(
                "SELECT * FROM execution_authority_grants WHERE id = $1", grant_id
            )


_AUTHORITY_CONSUMPTION_AUDIT_QUERY: Final[str] = """
    INSERT INTO audit_logs (
        agent_id, action_type, action_hash, payload, verdict,
        verdict_reason, signature, signature_valid, request_ip,
        request_user_agent, response_time_ms, trust_score_at_time,
        chain_previous_hash, policy_hash, metadata
    )
    VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
        NULL, $13, $14
    )
    RETURNING id
"""


class _AgentView:
    """Adapts an ``agents`` row to what the policy snapshot builder reads.

    ``metadata`` is decoded here because the driver hands back a JSONB
    column as text unless a codec is registered, and the snapshot builder
    reads it only when it is a mapping. Left as text it silently reads as
    "no wallet policy configured", so re-deriving the current policy for a
    principal that HAS one produced a different digest from the one the
    grant was issued under and every consumption failed with
    ``policy_hash_mismatch``. Decoding is what makes the two derivations
    read the same record.
    """

    __slots__ = ("_row",)

    #: Row columns stored as JSON and read as structured values.
    _JSON_COLUMNS: Final[frozenset[str]] = frozenset({"metadata"})

    def __init__(self, row: Any) -> None:
        self._row = row

    def __getattr__(self, name: str) -> Any:
        try:
            value = self._row[name]
        except KeyError as exc:
            raise AttributeError(name) from exc
        if name in self._JSON_COLUMNS and isinstance(value, (str, bytes, bytearray)):
            try:
                return json.loads(value)
            except (TypeError, ValueError):
                # Unparseable metadata is returned as-is rather than
                # replaced with {}. The snapshot builder records an
                # unreadable wallet policy as "invalid"; handing it an
                # empty mapping instead would claim no policy was
                # configured, which is a different and untrue statement.
                return value
        return value


def _default_audit_entry(grant: Any, execution_ref: str | None) -> AuditLogEntry:
    """The consumption receipt written when the caller supplies no entry."""
    return AuditLogEntry(
        agent_id=grant["agent_id"],
        action_type=grant["action_type"],
        action_hash=grant["execution_action_hash"],
        payload={
            "grant_id": str(grant["id"]),
            "execution_action_hash": grant["execution_action_hash"],
            "signed_action_hash": grant["signed_action_hash"],
            "domain": grant["domain"],
            "execution_ref": execution_ref,
        },
        verdict=ActionVerdict.APPROVED,
        verdict_reason="Execution authority consumed",
        # audit_logs requires non-empty signature bytes, and a consumption
        # carries no agent signature of its own -- the grant's claim key is
        # the authority. So record an explicitly labelled marker, and mark it
        # NOT valid: this is not an Ed25519 signature, and claiming otherwise
        # would corrupt what signature_valid means in v1/v2 receipts, where it
        # asserts that a real agent signature verified.
        signature=f"AUTHORITY_GRANT:{grant['id']}".encode("ascii"),
        signature_valid=False,
        request_ip=None,
        request_user_agent=None,
        response_time_ms=None,
        trust_score_at_time=0,
        chain_previous_hash=None,
        policy_hash=grant["policy_hash"],
        metadata={
            "grant_id": str(grant["id"]),
            "policy_revision": grant["policy_revision"],
            "policy_snapshot_format": grant["policy_snapshot_format"],
            # What actually authorised this row, since no agent signature did.
            "signature_kind": "authority_grant",
            "evidence_kind": "authority_grant",
            "approval_token_id": grant["approval_token_id"],
        },
    )
