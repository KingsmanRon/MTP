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
