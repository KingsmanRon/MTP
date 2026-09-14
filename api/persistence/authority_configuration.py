"""The effective authority configuration for one operation, read once.

Why this is a snapshot and not three lookups
--------------------------------------------
Three questions decide whether an operation may proceed:

1. is new issuance halted for this scope?
2. which requirement row wins for this principal and action class?
3. is enforcement of that requirement suspended for this organisation?

Asked separately against a mutable table they can disagree with each other.
An operator engaging a kill switch between question 1 and question 2 would
produce a decision that never corresponded to any actual configuration --
half from before the change and half from after. So all three are answered
by ONE statement, which PostgreSQL evaluates against a single snapshot, and
the immutable result is then carried through the rest of the evaluation.

Nothing downstream may re-read this configuration for the same decision.

Failure is not a value
----------------------
If the configuration cannot be read, the service does not know whether
authority is required AND does not know whether issuance is halted. There
is no safe way to continue: "assume required" still leaves the halt
unanswered, and every other fallback -- environment configuration, legacy
behaviour, "not required" -- silently substitutes a different policy for
the one the operator configured. :class:`AuthorityConfigurationUnavailable`
is raised instead, and callers turn it into a typed BLOCK.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID

import asyncpg

#: Failures that mean "the database could not answer". A programming fault
#: must NOT be swallowed into a fail-closed decision -- it would present a
#: bug as a policy outcome and hide it for as long as the block looks
#: plausible. Only genuine unavailability is translated.
_DATABASE_FAILURES: Final[tuple[type[BaseException], ...]] = (
    asyncpg.PostgresError,
    asyncpg.InterfaceError,
    OSError,
    TimeoutError,
)

#: One statement, one snapshot. The specificity ladder is expressed in the
#: ORDER BY: a row naming this principal outranks one naming any principal,
#: and within that a row naming this action class outranks one naming any.
#:
#: Only ENGAGED control rows are considered, which is what makes a global
#: halt un-overridable: an organisation row saying `engaged = FALSE` does
#: not match, so it cannot cancel the global row. Global sorts first so the
#: id carried into the audit record names the broader cause.
_RESOLVE: Final[str] = """
WITH winning_requirement AS (
    SELECT id, required, agent_id, action_class
    FROM authority_requirements
    WHERE org_id = $1
      AND (agent_id IS NULL OR agent_id = $2)
      AND (action_class IS NULL OR action_class = $3)
    ORDER BY (agent_id IS NOT NULL) DESC, (action_class IS NOT NULL) DESC
    LIMIT 1
),
issuance_halt AS (
    SELECT id, org_id
    FROM authority_controls
    WHERE control = 'authority_issuance'
      AND engaged
      AND (org_id IS NULL OR org_id = $1)
    ORDER BY (org_id IS NULL) DESC
    LIMIT 1
),
enforcement_suspension AS (
    -- Organisation scoped only; migration 028 makes a global row impossible.
    SELECT id
    FROM authority_controls
    WHERE control = 'requirement_enforcement'
      AND engaged
      AND org_id = $1
    LIMIT 1
)
SELECT
    (SELECT id FROM winning_requirement)                    AS requirement_id,
    COALESCE((SELECT required FROM winning_requirement), FALSE)
                                                            AS configured_required,
    (SELECT agent_id FROM winning_requirement)              AS requirement_agent_id,
    (SELECT action_class FROM winning_requirement)          AS requirement_action_class,
    (SELECT id FROM issuance_halt)                          AS issuance_halt_id,
    (SELECT org_id IS NULL FROM issuance_halt)              AS issuance_halt_is_global,
    (SELECT id FROM enforcement_suspension)                 AS enforcement_suspension_id
"""


#: The SHARED configuration locks. Any transaction that will COMMIT a
#: decision derived from the authority configuration takes them before
#: reading it and holds them to commit; every mutation of
#: authority_requirements / authority_controls takes the EXCLUSIVE form
#: (migrations 029 and 030 take it from a BEFORE trigger, so a writer
#: cannot forget).
#:
#: EVERY part of both keys is derived by PostgreSQL.
#: ``authority_config_lock_namespace()`` and ``authority_config_lock_key()``
#: are the SAME functions the write trigger calls, so there is one
#: definition of each key and nothing here to fall out of step with it. A
#: reader and a writer that each built the key their own way would believe
#: they were serialising while addressing two different locks -- the one
#: failure mode that looks like serialisation and provides none. A hash
#: collision merely serialises two scopes that did not need it; it can
#: never produce a missed lock.
#:
#: The organisation id is passed as a UUID and rendered by PostgreSQL, not
#: by Python: ``uuid::text`` is the canonical form on both sides, and
#: leaving the conversion to the database removes the last place the two
#: could disagree.
_SHARED_LOCK: Final[str] = (
    "SELECT pg_advisory_xact_lock_shared("
    "hashtext(authority_config_lock_namespace()), "
    "hashtext(authority_config_lock_key($1)))"
)

#: The PLATFORM-WIDE configuration lock, SHARED. ``authority_config_lock_key``
#: maps NULL to the global scope, so the global key is never spelled here
#: either.
_GLOBAL_SHARED_LOCK: Final[str] = (
    "SELECT pg_advisory_xact_lock_shared("
    "hashtext(authority_config_lock_namespace()), "
    "hashtext(authority_config_lock_key(NULL)))"
)


#: The EXCLUSIVE forms. Migrations 029/030 take these from a BEFORE trigger
#: on every configuration write, so nothing has to remember them -- but a
#: management transaction that must read the row it is about to change takes
#: them itself, FIRST, in the same order. Without that the pre-image it
#: records could be a version another writer has already replaced by the time
#: the trigger fires, and the audit record would name a transition that never
#: happened. Re-taking a lock the transaction already holds is free.
_GLOBAL_EXCLUSIVE_LOCK: Final[str] = (
    "SELECT pg_advisory_xact_lock("
    "hashtext(authority_config_lock_namespace()), "
    "hashtext(authority_config_lock_key(NULL)))"
)

_EXCLUSIVE_LOCK: Final[str] = (
    "SELECT pg_advisory_xact_lock("
    "hashtext(authority_config_lock_namespace()), "
    "hashtext(authority_config_lock_key($1)))"
)


async def lock_authority_configuration_global_exclusive(conn: Any) -> None:
    """Take the EXCLUSIVE platform-wide configuration lock.

    The top of the hierarchy, and the first lock any configuration writer
    takes -- whatever the scope of the row it is about to write.
    """
    await conn.execute(_GLOBAL_EXCLUSIVE_LOCK)


async def lock_authority_configuration_exclusive(
    conn: Any, *, organisation_id: Any
) -> None:
    """Take the EXCLUSIVE configuration lock for one organisation.

    ``lock_authority_configuration_global_exclusive`` must already have been
    taken on this connection. ``CONFIG_ORG -> CONFIG_GLOBAL`` is the one edge
    that must never be built.
    """
    await conn.execute(
        _EXCLUSIVE_LOCK,
        organisation_id
        if isinstance(organisation_id, UUID)
        else UUID(str(organisation_id)),
    )


async def lock_authority_configuration_global_shared(conn: Any) -> None:
    """Take the shared PLATFORM-WIDE configuration lock.

    The top of the configuration hierarchy. Issuance takes this BEFORE the
    organisation's own lock, because the effective configuration for any
    organisation consults the global ``authority_issuance`` control: a halt
    that is not locked against is a halt that can commit underneath an
    issuance already in flight, and that issuance would still write its
    grant.

    Consumption deliberately does not take it. Consumption does not consult
    the global control -- halting new issuance must not invalidate authority
    already issued -- so taking it would serialise every spend on the
    platform behind a lock that changes no decision it makes.
    """
    await conn.execute(_GLOBAL_SHARED_LOCK)


async def lock_authority_configuration_shared(
    conn: Any, *, organisation_id: Any
) -> None:
    """Take the shared configuration lock for this organisation.

    Must be called on the connection whose transaction will commit the
    decision, before the configuration is read, and the transaction must
    hold it through commit. Reading the configuration without it, or
    acquiring it after the read, leaves the window this exists to close.

    A caller that also needs the global lock must take that one FIRST. The
    write trigger takes global-then-organisation unconditionally, so
    CONFIG_ORG -> CONFIG_GLOBAL is the one edge that must never be built.
    """
    await conn.execute(
        _SHARED_LOCK,
        organisation_id
        if isinstance(organisation_id, UUID)
        else UUID(str(organisation_id)),
    )


class AuthorityConfigurationUnavailable(RuntimeError):
    """The effective configuration could not be established."""


@dataclass(frozen=True, slots=True)
class AuthorityRuntimeConfiguration:
    """What the configuration said, at one instant, for one operation."""

    organisation_id: str
    principal_id: str
    action_class: str
    resolved_at: datetime

    #: What the winning requirement row says, before any suspension.
    configured_required: bool = False
    requirement_id: UUID | None = None
    #: Which rung of the ladder answered: "agent+class", "agent", "class",
    #: "organisation", or None when no row matched.
    requirement_scope: str | None = None

    #: New issuance halted. Consumption of existing authority is unaffected.
    issuance_halted: bool = False
    issuance_halt_id: UUID | None = None
    issuance_halt_is_global: bool = False

    #: Enforcement of the requirement temporarily suspended for this
    #: organisation. It suspends ONLY a requirement that was configured; it
    #: is never a general fail-open, and it does not lift an issuance halt.
    enforcement_suspended: bool = False
    enforcement_suspension_id: UUID | None = None

    @property
    def effective_required(self) -> bool:
        """Whether delegated authority is actually required right now."""
        return self.configured_required and not self.enforcement_suspended

    def audit_fields(self) -> dict[str, Any]:
        """Flat, JSON-safe provenance for the decision record."""
        return {
            "configured_required": self.configured_required,
            "effective_required": self.effective_required,
            "requirement_id": str(self.requirement_id) if self.requirement_id else None,
            "requirement_scope": self.requirement_scope,
            "issuance_halted": self.issuance_halted,
            "issuance_halt_id": (
                str(self.issuance_halt_id) if self.issuance_halt_id else None
            ),
            "issuance_halt_is_global": self.issuance_halt_is_global,
            "enforcement_suspended": self.enforcement_suspended,
            "enforcement_suspension_id": (
                str(self.enforcement_suspension_id)
                if self.enforcement_suspension_id
                else None
            ),
            "source": "database",
        }


def _scope_label(agent_id: Any, action_class: Any) -> str:
    if agent_id is not None and action_class is not None:
        return "agent+class"
    if agent_id is not None:
        return "agent"
    if action_class is not None:
        return "class"
    return "organisation"


async def resolve_authority_configuration_on(
    conn: Any,
    *,
    organisation_id: Any,
    principal_id: Any,
    action_class: str,
) -> AuthorityRuntimeConfiguration:
    """Resolve on a CALLER-SUPPLIED connection, inside the caller's transaction.

    Consumption needs this. Acquiring a fresh connection would put the read
    in a different transaction from the claim, so a control committed in
    between could let a claim commit that the configuration no longer
    permits. Reading on the consuming connection, after its locks and
    immediately before the claim, makes the window as short as the
    transaction itself.

    It deliberately takes NO lock on the configuration rows. Adding one
    would introduce a new lock class into the consume path, and a future
    management surface that writes an administrative audit row would then
    take (configuration -> forensic chain) while consumption takes
    (forensic chain -> configuration) -- the same shape of inversion Gate 7
    was opened to remove.
    """
    organisation_uuid = (
        organisation_id if isinstance(organisation_id, UUID) else UUID(str(organisation_id))
    )
    principal_uuid = (
        principal_id if isinstance(principal_id, UUID) else UUID(str(principal_id))
    )
    try:
        row = await conn.fetchrow(
            _RESOLVE, organisation_uuid, principal_uuid, action_class
        )
    except _DATABASE_FAILURES as exc:
        raise AuthorityConfigurationUnavailable(
            "the effective authority configuration could not be read"
        ) from exc
    return _from_row(row, organisation_uuid, principal_uuid, action_class)


async def resolve_authority_configuration(
    database: Any,
    *,
    organisation_id: Any,
    principal_id: Any,
    action_class: str,
) -> AuthorityRuntimeConfiguration:
    """Read the whole effective configuration in one snapshot.

    ``organisation_id`` and ``principal_id`` must come from trusted
    server-side state -- the authenticated agent record -- never from the
    request body. They are passed as explicit predicates rather than relying
    on row level security, because the trusted worker connection is
    BYPASSRLS and because the tenant policy deliberately hides the global
    control rows this resolution must see.
    """
    organisation_uuid = (
        organisation_id if isinstance(organisation_id, UUID) else UUID(str(organisation_id))
    )
    principal_uuid = (
        principal_id if isinstance(principal_id, UUID) else UUID(str(principal_id))
    )

    try:
        async with database.acquire() as conn:
            row = await conn.fetchrow(
                _RESOLVE, organisation_uuid, principal_uuid, action_class
            )
    except _DATABASE_FAILURES as exc:
        raise AuthorityConfigurationUnavailable(
            "the effective authority configuration could not be read"
        ) from exc

    return _from_row(row, organisation_uuid, principal_uuid, action_class)


def _from_row(
    row: Any, organisation_uuid: UUID, principal_uuid: UUID, action_class: str
) -> AuthorityRuntimeConfiguration:
    if row is None:
        # The statement always returns exactly one row, so this means the
        # database answered something this code does not understand. Treat
        # it as unavailable rather than inventing a permissive default.
        raise AuthorityConfigurationUnavailable(
            "the authority configuration query returned no row"
        )

    requirement_id = row["requirement_id"]
    return AuthorityRuntimeConfiguration(
        organisation_id=str(organisation_uuid),
        principal_id=str(principal_uuid),
        action_class=action_class,
        resolved_at=datetime.now(UTC),
        configured_required=bool(row["configured_required"]),
        requirement_id=requirement_id,
        requirement_scope=(
            _scope_label(row["requirement_agent_id"], row["requirement_action_class"])
            if requirement_id is not None
            else None
        ),
        issuance_halted=row["issuance_halt_id"] is not None,
        issuance_halt_id=row["issuance_halt_id"],
        issuance_halt_is_global=bool(row["issuance_halt_is_global"]),
        enforcement_suspended=row["enforcement_suspension_id"] is not None,
        enforcement_suspension_id=row["enforcement_suspension_id"],
    )
