"""Where "is delegated authority required here?" is answered from.

Phase 7A, Gate 2. Until this module the answer came from
``INNTRIS_AUTHORITY_REQUIRED_ORGS`` — an environment variable, organisation
granularity only, changed by redeploy, with no record of who changed it.
That is not a production control for something that decides whether money
can move without a delegation.

The answer now comes from two tables, read server-side:

``authority_requirements``
    The requirement, scoped to an organisation and optionally narrowed to a
    principal, an action class, or both.

``authority_controls``
    Two named kill switches. ``requirement_enforcement`` suppresses the
    requirement (the rollback for a rollout that went too wide);
    ``authority_issuance`` halts new grants entirely.

Three answers, deliberately distinguished
-----------------------------------------
There are three different things "we have no requirement row" can mean, and
collapsing them is how a rollout control becomes a bypass:

**No row exists.**
    Determinate: nobody enrolled this scope, so authority is not required.
    This is today's behaviour for every existing organisation and is why
    the migration changes nothing until somebody deliberately configures it.

**The tables do not exist.**
    Also determinate. If the relation is absent no organisation can ever
    have been enrolled, so "not required" is the truthful answer rather
    than a guess. This is the mixed-version window — new application code
    against a schema that predates migration 0023 — and failing closed
    there would block every organisation, including the ones that never
    asked for any of this, over a deployment-ordering fault.

**The tables exist and could not be read.**
    Indeterminate, and the only one of the three that is. Not knowing is
    not permission: the resolver answers ``required=True`` and the decision
    path blocks. See :class:`RequirementResolutionUnavailable`.

Why a snapshot rather than a lookup callback
--------------------------------------------
``AuthorityRequirementResolver`` in ``api.core.authority.ports`` is a
synchronous protocol, and it should stay one: Core makes decisions from
values it already holds, not by reaching for I/O mid-decision. So the rows
are read once, asynchronously, before the decision path is entered, and
frozen into a :class:`RequirementSnapshot` that satisfies the sync port.

The snapshot is built per evaluation and never cached across requests.
Requirement rows are a handful per organisation behind a covering index, so
the read is cheap; and a cache here would be a window in which an
organisation that just turned the requirement ON still issued authority
without it.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Final
from uuid import UUID

import asyncpg

logger = logging.getLogger(__name__)

#: The two named kill switches. Anything else is refused by a CHECK
#: constraint in migration 027, so a typo cannot create a switch that looks
#: configured and is never read.
CONTROL_REQUIREMENT_ENFORCEMENT: Final[str] = "requirement_enforcement"
CONTROL_AUTHORITY_ISSUANCE: Final[str] = "authority_issuance"

KNOWN_CONTROLS: Final[frozenset[str]] = frozenset(
    {CONTROL_REQUIREMENT_ENFORCEMENT, CONTROL_AUTHORITY_ISSUANCE}
)

#: ``source`` values a resolved requirement reports. These reach the audit
#: record, so an operator reading a BLOCK can tell which row produced it —
#: or that no row did and the resolver failed closed.
SOURCE_UNCONFIGURED: Final[str] = "database-requirement:unconfigured"
SOURCE_NOT_DEPLOYED: Final[str] = "database-requirement:not-deployed"
SOURCE_SUPPRESSED: Final[str] = "database-requirement:kill-switch-engaged"
SOURCE_UNAVAILABLE: Final[str] = "database-requirement:unavailable"


class RequirementResolutionUnavailable(RuntimeError):
    """The requirement tables exist and could not be read.

    Raised only for the indeterminate case. A missing relation is not this:
    that is a determinate "nothing is enrolled" (see the module docstring).
    """


@dataclass(frozen=True, slots=True)
class RequirementRow:
    """One configured requirement, with the scope it was configured at."""

    agent_id: UUID | None
    action_class: str | None
    required: bool
    reason: str
    changed_by: str
    approval_reference: str

    @property
    def specificity(self) -> int:
        """How narrowly this row was configured. Higher wins.

        3 = this principal doing this class of act
        2 = this principal doing anything
        1 = anyone in the organisation doing this class of act
        0 = the whole organisation
        """
        return (2 if self.agent_id is not None else 0) + (1 if self.action_class is not None else 0)

    @property
    def scope_label(self) -> str:
        return f"agent={self.agent_id or '*'} action_class={self.action_class or '*'}"


@dataclass(frozen=True, slots=True)
class RequirementSnapshot:
    """A frozen answer for one organisation and principal.

    Satisfies the synchronous ``AuthorityRequirementResolver`` port. It holds
    only the rows that could possibly apply to the principal it was built
    for, so ``requirement()`` is a comparison over at most a few candidates
    and performs no I/O.
    """

    organisation_id: str
    principal_id: str
    rows: tuple[RequirementRow, ...] = ()
    #: True when ``requirement_enforcement`` is engaged for this scope. The
    #: snapshot still carries the rows it suppresses, so the audit record can
    #: say what WOULD have applied.
    enforcement_suppressed: bool = False
    #: True when ``authority_issuance`` is engaged for this scope.
    issuance_halted: bool = False
    #: Which of the three determinate/indeterminate cases produced this.
    fallback_source: str | None = None

    def _winner(self, action_class: str) -> RequirementRow | None:
        """The most specific configured row for this act, if any.

        Ties are impossible: the unique index in migration 027 permits one
        row per (organisation, agent, action class) scope, and the four
        scopes have four distinct specificities.
        """
        best: RequirementRow | None = None
        for row in self.rows:
            if row.agent_id is not None and str(row.agent_id) != self.principal_id:
                continue
            if row.action_class is not None and row.action_class != action_class:
                continue
            if best is None or row.specificity > best.specificity:
                best = row
        return best

    def requirement(self, organisation_id: str, principal_id: str, action_class: str) -> Any:
        """Answer the port. See the module docstring for the three cases."""
        from api.core.authority.authority import (
            AuthorityRequirement,
            trusted_authority_construction,
        )

        if str(organisation_id) != self.organisation_id or str(principal_id) != (self.principal_id):
            # A snapshot answers for the subject it was built for and nothing
            # else. Answering anyway would silently apply one principal's
            # configuration to another.
            raise RequirementResolutionUnavailable(
                "requirement snapshot was built for a different subject"
            )

        winner = self._winner(action_class)

        if self.enforcement_suppressed:
            if winner is not None and winner.required:
                # Loud, every time. This is the one control in the subsystem
                # that weakens enforcement, and a silent weakening is how a
                # temporary rollback becomes a permanent hole.
                logger.warning(
                    "authority requirement SUPPRESSED by kill switch: org=%s "
                    "principal=%s action_class=%s configured_at=%s",
                    self.organisation_id,
                    self.principal_id,
                    action_class,
                    winner.scope_label,
                )
            return AuthorityRequirement(
                trusted_authority_construction(),
                organisation_id=self.organisation_id,
                principal_id=self.principal_id,
                action_class=action_class,
                required=False,
                source=SOURCE_SUPPRESSED,
            )

        if winner is None:
            return AuthorityRequirement(
                trusted_authority_construction(),
                organisation_id=self.organisation_id,
                principal_id=self.principal_id,
                action_class=action_class,
                required=False,
                source=self.fallback_source or SOURCE_UNCONFIGURED,
            )

        return AuthorityRequirement(
            trusted_authority_construction(),
            organisation_id=self.organisation_id,
            principal_id=self.principal_id,
            action_class=action_class,
            required=winner.required,
            source=f"database-requirement:{winner.scope_label}",
        )


@dataclass(frozen=True, slots=True)
class FailClosedRequirementResolver:
    """The answer when the configuration exists and could not be read.

    Every act is treated as requiring delegated authority. Callers on the
    ``/authority/*`` surface can satisfy that by presenting one; the legacy
    ``/verify`` surface cannot, and blocks. Both are the safe direction.
    """

    organisation_id: str
    principal_id: str
    detail: str = "requirement configuration could not be read"

    #: Kept for interface parity with :class:`RequirementSnapshot`; a
    #: resolver that could not read the configuration also could not read
    #: the kill switches, so it must not report them as disengaged.
    enforcement_suppressed: bool = False
    issuance_halted: bool = True

    def requirement(self, organisation_id: str, principal_id: str, action_class: str) -> Any:
        from api.core.authority.authority import (
            AuthorityRequirement,
            trusted_authority_construction,
        )

        logger.error(
            "authority requirement resolution unavailable; failing closed: "
            "org=%s principal=%s action_class=%s detail=%s",
            organisation_id,
            principal_id,
            action_class,
            self.detail,
        )
        return AuthorityRequirement(
            trusted_authority_construction(),
            organisation_id=str(organisation_id),
            principal_id=str(principal_id),
            action_class=action_class,
            required=True,
            source=SOURCE_UNAVAILABLE,
        )


_REQUIREMENT_QUERY: Final[str] = """
    SELECT agent_id, action_class, required, reason, changed_by, approval_reference
    FROM authority_requirements
    WHERE org_id = $1
      AND (agent_id IS NULL OR agent_id = $2)
"""

#: Global rows (``org_id IS NULL``) apply to every organisation. A global
#: engagement is not something one tenant can opt out of, so the aggregation
#: below is a boolean OR over whichever rows came back.
_CONTROL_QUERY: Final[str] = """
    SELECT control, org_id, engaged
    FROM authority_controls
    WHERE org_id IS NULL OR org_id = $1
"""


def _is_missing_relation(exc: BaseException) -> bool:
    """Whether ``exc`` says the relation does not exist.

    Matched on the SQLSTATE asyncpg exposes rather than on message text, so
    a localised server or a reworded error cannot turn a determinate answer
    into an indeterminate one. 42P01 is ``undefined_table``.
    """
    sqlstate = getattr(exc, "sqlstate", None)
    return sqlstate == "42P01"


#: What counts as "the database could not answer".
#:
#: Deliberately NOT ``Exception``. A ``TypeError`` or ``AttributeError`` here
#: is a bug in Core, and turning a bug into ``required=True`` would refuse
#: every request with "delegated authority is required and was not
#: presented" — a security control giving a false reason for its refusal,
#: on an organisation that never enrolled. A programming fault is allowed to
#: propagate and become a 500: visible, attributable and fixed, rather than
#: disguised as a policy decision.
_DATABASE_FAILURES: Final[tuple[type[BaseException], ...]] = (
    asyncpg.PostgresError,
    asyncpg.InterfaceError,
    OSError,
    TimeoutError,
)


async def load_requirement_snapshot(
    database: Any,
    *,
    organisation_id: UUID | str,
    principal_id: UUID | str,
) -> RequirementSnapshot:
    """Read the requirement configuration and kill switches for one subject.

    Raises :class:`RequirementResolutionUnavailable` only for the
    indeterminate case. A missing relation returns an unconfigured snapshot
    tagged :data:`SOURCE_NOT_DEPLOYED`, because an absent table is proof
    that nothing was enrolled rather than an inability to find out.
    """
    org_uuid = organisation_id if isinstance(organisation_id, UUID) else UUID(str(organisation_id))
    principal_uuid = principal_id if isinstance(principal_id, UUID) else UUID(str(principal_id))

    try:
        async with database.acquire() as conn:
            requirement_records = await conn.fetch(_REQUIREMENT_QUERY, org_uuid, principal_uuid)
            control_records = await conn.fetch(_CONTROL_QUERY, org_uuid)
    except _DATABASE_FAILURES as exc:
        if _is_missing_relation(exc):
            logger.warning(
                "authority requirement tables are not deployed; treating every "
                "organisation as unenrolled (this is the pre-0023 schema)"
            )
            return RequirementSnapshot(
                organisation_id=str(org_uuid),
                principal_id=str(principal_uuid),
                fallback_source=SOURCE_NOT_DEPLOYED,
            )
        raise RequirementResolutionUnavailable(
            f"requirement configuration could not be read: {type(exc).__name__}"
        ) from exc

    rows = tuple(
        RequirementRow(
            agent_id=record["agent_id"],
            action_class=record["action_class"],
            required=bool(record["required"]),
            reason=record["reason"],
            changed_by=record["changed_by"],
            approval_reference=record["approval_reference"],
        )
        for record in requirement_records
    )

    suppressed = False
    halted = False
    for record in control_records:
        if not record["engaged"]:
            continue
        if record["control"] == CONTROL_REQUIREMENT_ENFORCEMENT:
            suppressed = True
        elif record["control"] == CONTROL_AUTHORITY_ISSUANCE:
            halted = True

    return RequirementSnapshot(
        organisation_id=str(org_uuid),
        principal_id=str(principal_uuid),
        rows=rows,
        enforcement_suppressed=suppressed,
        issuance_halted=halted,
    )


async def resolve_requirement_context(
    database: Any,
    *,
    organisation_id: UUID | str,
    principal_id: UUID | str,
) -> RequirementSnapshot | FailClosedRequirementResolver:
    """The one call both HTTP surfaces make. Never raises for a read failure.

    Returns whichever resolver truthfully describes what could be
    established: a snapshot when the configuration was read, and a
    fail-closed resolver when it exists and could not be.
    """
    try:
        return await load_requirement_snapshot(
            database, organisation_id=organisation_id, principal_id=principal_id
        )
    except RequirementResolutionUnavailable as exc:
        return FailClosedRequirementResolver(
            organisation_id=str(organisation_id),
            principal_id=str(principal_id),
            detail=str(exc),
        )


# =============================================================================
# Administration
# =============================================================================
# Every write below appends to ``administrative_audit_events`` in the SAME
# transaction as the change itself. That table is append-only by trigger
# (migration 015), so the record of who enabled a requirement, under what
# approval reference and why cannot be edited or removed afterwards —
# including by whoever made the change.
#
# There is deliberately no "silent" write path. A requirement change with no
# actor and no approval reference is refused by NOT NULL and CHECK
# constraints, not merely discouraged.

#: Event types written to ``administrative_audit_events``.
EVENT_REQUIREMENT_SET: Final[str] = "authority.requirement_set"
EVENT_REQUIREMENT_CLEARED: Final[str] = "authority.requirement_cleared"
EVENT_CONTROL_SET: Final[str] = "authority.control_set"


def _require_known_control(control: str) -> str:
    if control not in KNOWN_CONTROLS:
        raise ValueError(
            f"unknown authority control {control!r}; known controls are "
            f"{', '.join(sorted(KNOWN_CONTROLS))}"
        )
    return control


async def set_requirement(
    database: Any,
    *,
    organisation_id: UUID,
    required: bool,
    changed_by: str,
    approval_reference: str,
    reason: str,
    agent_id: UUID | None = None,
    action_class: str | None = None,
) -> dict[str, Any]:
    """Configure the requirement for one scope, with its audit evidence.

    ``agent_id=None`` means every principal in the organisation;
    ``action_class=None`` means every action class. A more specific row
    overrides a broader one in both directions, so an organisation-wide
    requirement can be lifted for a single principal without deleting the
    organisation-wide row and losing the record of what it used to be.
    """
    async with database.acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
            INSERT INTO authority_requirements (
                org_id, agent_id, action_class, required, reason, changed_by,
                approval_reference
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (org_id, scope_key) DO UPDATE
                SET required = EXCLUDED.required,
                    reason = EXCLUDED.reason,
                    changed_by = EXCLUDED.changed_by,
                    approval_reference = EXCLUDED.approval_reference,
                    updated_at = NOW()
            RETURNING id, org_id, agent_id, action_class, required, updated_at
            """,
            organisation_id,
            agent_id,
            action_class,
            required,
            reason,
            changed_by,
            approval_reference,
        )
        await conn.execute(
            """
            INSERT INTO administrative_audit_events (
                org_id, event_type, actor, approval_reference, details
            ) VALUES ($1, $2, $3, $4, $5::jsonb)
            """,
            organisation_id,
            EVENT_REQUIREMENT_SET,
            changed_by,
            approval_reference,
            json.dumps(
                {
                    "agent_id": str(agent_id) if agent_id else None,
                    "action_class": action_class,
                    "required": required,
                    "reason": reason,
                }
            ),
        )
    return dict(row)


async def clear_requirement(
    database: Any,
    *,
    organisation_id: UUID,
    changed_by: str,
    approval_reference: str,
    reason: str,
    agent_id: UUID | None = None,
    action_class: str | None = None,
) -> bool:
    """Remove one configured scope, recording that it was removed.

    Removing a row restores the *default* for that scope, which is whatever
    a broader row says — or "not required" if none does. The audit event is
    written whether or not a row existed, because "someone tried to clear
    this" is itself worth knowing.
    """
    scope_key = f"{agent_id or '*'}|{action_class or '*'}"
    async with database.acquire() as conn, conn.transaction():
        deleted = await conn.fetchval(
            """
            DELETE FROM authority_requirements
            WHERE org_id = $1 AND scope_key = $2
            RETURNING id
            """,
            organisation_id,
            scope_key,
        )
        await conn.execute(
            """
            INSERT INTO administrative_audit_events (
                org_id, event_type, actor, approval_reference, details
            ) VALUES ($1, $2, $3, $4, $5::jsonb)
            """,
            organisation_id,
            EVENT_REQUIREMENT_CLEARED,
            changed_by,
            approval_reference,
            json.dumps(
                {
                    "agent_id": str(agent_id) if agent_id else None,
                    "action_class": action_class,
                    "existed": deleted is not None,
                    "reason": reason,
                }
            ),
        )
    return deleted is not None


async def set_control(
    database: Any,
    *,
    control: str,
    engaged: bool,
    changed_by: str,
    approval_reference: str,
    reason: str,
    organisation_id: UUID | None = None,
) -> dict[str, Any]:
    """Engage or release a kill switch, with its audit evidence.

    ``organisation_id=None`` engages it globally. A global engagement wins
    over any per-organisation row: a platform-wide halt is not something one
    tenant can opt out of.

    The audit event needs an ``org_id`` and a global control has none, so a
    global change is recorded against every organisation it can affect would
    be wrong (it would forge per-tenant evidence) — instead it is recorded
    once under the platform organisation when one is configured, and
    otherwise only in the control row itself, whose ``changed_by``,
    ``approval_reference`` and ``updated_at`` carry the same facts.
    """
    _require_known_control(control)
    async with database.acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
            INSERT INTO authority_controls (
                control, org_id, engaged, reason, changed_by, approval_reference
            ) VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (control, scope_key) DO UPDATE
                SET engaged = EXCLUDED.engaged,
                    reason = EXCLUDED.reason,
                    changed_by = EXCLUDED.changed_by,
                    approval_reference = EXCLUDED.approval_reference,
                    updated_at = NOW()
            RETURNING id, control, org_id, engaged, updated_at
            """,
            control,
            organisation_id,
            engaged,
            reason,
            changed_by,
            approval_reference,
        )
        if organisation_id is not None:
            await conn.execute(
                """
                INSERT INTO administrative_audit_events (
                    org_id, event_type, actor, approval_reference, details
                ) VALUES ($1, $2, $3, $4, $5::jsonb)
                """,
                organisation_id,
                EVENT_CONTROL_SET,
                changed_by,
                approval_reference,
                json.dumps({"control": control, "engaged": engaged, "reason": reason}),
            )
    if engaged:
        logger.warning(
            "authority kill switch ENGAGED: control=%s scope=%s by=%s approval=%s " "reason=%s",
            control,
            organisation_id or "global",
            changed_by,
            approval_reference,
            reason,
        )
    else:
        logger.info(
            "authority kill switch released: control=%s scope=%s by=%s approval=%s",
            control,
            organisation_id or "global",
            changed_by,
            approval_reference,
        )
    return dict(row)


async def list_requirements(database: Any, *, organisation_id: UUID) -> list[dict[str, Any]]:
    """Every configured requirement scope for one organisation."""
    async with database.acquire() as conn:
        records = await conn.fetch(
            """
            SELECT id, agent_id, action_class, required, reason, changed_by,
                   approval_reference, created_at, updated_at
            FROM authority_requirements
            WHERE org_id = $1
            ORDER BY scope_key
            """,
            organisation_id,
        )
    return [dict(record) for record in records]


async def list_controls(
    database: Any, *, organisation_id: UUID | None = None
) -> list[dict[str, Any]]:
    """Every control row in scope, global rows included."""
    async with database.acquire() as conn:
        records = await conn.fetch(
            """
            SELECT id, control, org_id, engaged, reason, changed_by,
                   approval_reference, created_at, updated_at
            FROM authority_controls
            WHERE org_id IS NULL OR org_id = $1
            ORDER BY control, scope_key
            """,
            organisation_id,
        )
    return [dict(record) for record in records]


__all__ = [
    "CONTROL_AUTHORITY_ISSUANCE",
    "CONTROL_REQUIREMENT_ENFORCEMENT",
    "FailClosedRequirementResolver",
    "KNOWN_CONTROLS",
    "RequirementResolutionUnavailable",
    "RequirementRow",
    "RequirementSnapshot",
    "SOURCE_NOT_DEPLOYED",
    "SOURCE_SUPPRESSED",
    "SOURCE_UNAVAILABLE",
    "SOURCE_UNCONFIGURED",
    "EVENT_CONTROL_SET",
    "EVENT_REQUIREMENT_CLEARED",
    "EVENT_REQUIREMENT_SET",
    "clear_requirement",
    "list_controls",
    "list_requirements",
    "load_requirement_snapshot",
    "resolve_requirement_context",
    "set_control",
    "set_requirement",
]
