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

    @property
    def authorises_execution(self) -> bool:
        """Whether a usable grant exists as a result of this attempt."""
        return self.outcome in (IssueOutcome.ISSUED, IssueOutcome.IDEMPOTENT)


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
    executor_binding_digest: str,
    amount_usd: Decimal,
    domain: str,
    action_type: str,
    consequence_class: str | None,
    authority_scope_digest: str | None,
) -> str:
    """Digest of the material an issuance is *about*.

    Deliberately excludes timestamps and the minted token id: a retry of
    the same request must digest identically however long after the first
    attempt it arrives. Everything that changes what was authorised is in
    here, so a reused reference carrying different material cannot pass
    as a retry.
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
            "executor_binding_digest": executor_binding_digest,
            "amount_usd": str(amount_usd),
            "domain": domain,
            "action_type": action_type,
            "consequence_class": consequence_class,
            "authority_scope_digest": authority_scope_digest,
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
class AuthorityState:
    """The delegated authority as it stands RIGHT NOW, re-resolved by the caller.

    Passed to ``consume`` so revocation and expiry can be reported
    distinctly. Core cannot poll an external issuer itself; the caller that
    can is the one that must supply this.
    """

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
        rate_limit_per_minute: int,
        daily_limit_usd: Decimal,
        amount_usd: Decimal = Decimal("0"),
        signed_action_hash: str | None = None,
        executor_reference: str | None = None,
        consequence_class: str | None = None,
        authority_scope_digest: str | None = None,
    ) -> IssueResult:
        """Issue bounded, single-use authority, reserving capacity for it.

        Everything happens in one transaction. The issuance identity is
        locked first, so a concurrent retry of the same reference waits
        and then finds the committed grant instead of reserving capacity
        a second time.
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
            executor_binding_digest=executor_binding_digest,
            amount_usd=amount_usd,
            domain=domain,
            action_type=action_type,
            consequence_class=consequence_class,
            authority_scope_digest=authority_scope_digest,
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

                existing = await conn.fetchrow(
                    """
                    SELECT id, issuance_digest, approval_token_id, status
                    FROM execution_authority_grants
                    WHERE agent_id = $1 AND issuance_ref = $2
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
                            detail=(
                                "issuance_ref is already in use for different "
                                "material; a changed request is not a retry"
                            ),
                        )
                    return IssueResult(
                        outcome=IssueOutcome.IDEMPOTENT,
                        grant_id=existing["id"],
                        approval_token_id=existing["approval_token_id"],
                    )

                _minute, _daily, reservation_id = (
                    await self._db.reserve_rate_and_spend_on(
                        conn,
                        agent_id=agent_id,
                        minute_start=minute_start,
                        day_start=day_start,
                        amount=amount_usd,
                        rate_limit_per_minute=rate_limit_per_minute,
                        daily_limit_usd=daily_limit_usd,
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
        authority_scope_digest: str | None = None,
        authority_state: AuthorityState | None = None,
        audit_entry_factory: Callable[[Any], AuditLogEntry] | None = None,
        at: datetime | None = None,
    ) -> ConsumeResult:
        """Spend the grant once, or recover the record of an earlier spend."""
        now = (at or datetime.now(UTC)).astimezone(UTC)

        async with self._db.acquire() as conn, conn.transaction():
            await conn.execute(
                "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
                f"authority-grant:{grant_id}",
            )

            grant = await conn.fetchrow(
                """
                SELECT g.*, a.status AS agent_status, a.org_id AS org_id
                FROM execution_authority_grants g
                JOIN agents a ON a.id = g.agent_id
                WHERE g.id = $1
                FOR UPDATE OF g
                """,
                grant_id,
            )
            if grant is None:
                return ConsumeResult(
                    outcome=ConsumptionOutcome.REJECTED,
                    rejection_reason=DecisionReason.GRANT_NOT_FOUND,
                )

            # --- Recovery comes before every lifecycle rejection ---------
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
            revalidation = await self._revalidate(
                conn, grant, authority_scope_digest, authority_state, now
            )
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
            except asyncpg.UniqueViolationError:
                claim = None
            if claim is None:
                # Another consumer won the claim inside this window.
                return ConsumeResult(
                    outcome=ConsumptionOutcome.REJECTED,
                    grant_id=grant_id,
                    rejection_reason=DecisionReason.GRANT_ALREADY_CONSUMED,
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

    async def _revalidate(
        self,
        conn: Any,
        grant: Any,
        presented_scope_digest: str | None,
        authority_state: AuthorityState | None,
        now: datetime,
    ) -> DecisionReason | None:
        """Re-check current policy, principal and delegation. ``None`` = fine.

        Ordered most specific first, so an operator reading a refusal learns
        the actual cause rather than whichever check happened to run first.
        """
        agent_row = await conn.fetchrow(
            """
            SELECT a.*, o.id AS organisation_id
            FROM agents a
            JOIN organizations o ON o.id = a.org_id
            WHERE a.id = $1
            """,
            grant["agent_id"],
        )
        if agent_row is None or agent_row["status"] != "active":
            return DecisionReason.AGENT_NOT_ACTIVE
        if agent_row["org_id"] != grant["org_id"]:
            # The composite foreign key makes this unreachable through normal
            # writes. Checked anyway: if it is ever true, the ownership record
            # is inconsistent and nothing below can be trusted.
            return DecisionReason.AGENT_NOT_ACTIVE

        # Delegated authority, when the caller re-resolved it. Revocation and
        # expiry are reported distinctly from "the scope changed" so the
        # refusal names what actually happened.
        if authority_state is not None:
            if authority_state.revoked:
                return DecisionReason.AUTHORITY_REVOKED
            if (
                authority_state.expires_at is not None
                and now >= authority_state.expires_at.astimezone(UTC)
            ):
                return DecisionReason.AUTHORITY_EXPIRED
            if not authority_state.verified:
                return DecisionReason.AUTHORITY_VERIFICATION_FAILED

        if (
            grant["authority_expires_at"] is not None
            and now >= grant["authority_expires_at"]
        ):
            return DecisionReason.AUTHORITY_EXPIRED

        if grant["authority_scope_digest"] != presented_scope_digest:
            # The delegated authority is not the one the decision was made
            # under. It may have been narrowed or re-issued.
            return DecisionReason.AUTHORITY_SCOPE_EXCEEDED

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
    """Adapts an ``agents`` row to what the policy snapshot builder reads."""

    __slots__ = ("_row",)

    def __init__(self, row: Any) -> None:
        self._row = row

    def __getattr__(self, name: str) -> Any:
        try:
            return self._row[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


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
        # audit_logs requires a non-empty signature. A consumption carries no
        # agent signature of its own -- the grant's claim key is the authority
        # -- so record a labelled marker, the same shape the verify path uses
        # when no usable signature exists, rather than a blank that would read
        # as "signed with nothing".
        signature=f"AUTHORITY_GRANT:{grant['id']}".encode("ascii"),
        signature_valid=True,
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
        },
    )
