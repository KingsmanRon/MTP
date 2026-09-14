"""Changing authority configuration, and recording that it changed, as one act.

Invariant 7
-----------
A configuration change and its administrative audit record commit together,
or neither commits. There is deliberately no path that produces:

* configuration changed, no audit -- a policy change nobody can attribute;
* audit written, configuration rolled back -- a record of something that
  never happened, which is worse, because it is believed.

Both rows are written by :func:`apply_authority_configuration_change_on`
inside ONE transaction. Nothing here catches a failure and continues: an
audit insert that fails takes the configuration change down with it, because
that is the only outcome that keeps the two honest.

Why this is not a trigger
-------------------------
An AFTER trigger on the configuration tables could write the audit row
automatically, and would be harder to forget. It is not done, for two
reasons:

1. the record has to name the actor, the reason and the approval reference.
   A trigger sees only the row, so those would travel in session GUCs --
   unset by an emergency operator, and the audit then records nobody;
2. it would make every direct SQL write to those tables acquire whatever the
   audit path acquires, inside transactions whose lock graph nobody has
   proved. The Gate-7 deadlock was exactly that shape.

So the primitive writes both rows explicitly, configuration first.

Lock order
----------
::

    CONFIG_GLOBAL exclusive
        -> CONFIG_ORG exclusive        (organisation-scoped changes only)
        -> read the row being replaced
        -> write the configuration row  (the 029/030 trigger re-takes the
                                         same two locks; already held, free)
        -> append the administrative audit row
        -> COMMIT

The two locks are taken BEFORE the read on purpose. The trigger would take
them anyway, but only once the write statement runs -- and a pre-image read
before that could report a version another writer had already replaced,
making the recorded transition one that never occurred. Taking them first
puts the read and the write inside the same exclusive window.

It is the same order the trigger uses, not a different one, so nothing about
the accepted hierarchy changes. The trigger remains the enforcement for any
writer that does not come through here.

``administrative_audit_events`` carries no forensic-chain trigger, so this
path never acquires the per-agent chain lock. ``CONFIG -> FORENSIC CHAIN``
cannot invert with consumption's ``CONFIG_ORG -> FORENSIC CHAIN`` because
this side of it does not exist.

Who may call it
---------------
Whoever holds the connection. The privilege is the enforcement, not a check
in this module: the runtime role is SELECT-only on both configuration tables
(migration 028) and the tenant role is SELECT-only and blind to the
administrative audit trail, so handing this a runtime or tenant connection
fails in the database with nothing written. Migration 031 adds
``inntris_authority_admin`` as the identity that can actually perform it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Literal
from uuid import UUID, uuid4

from api.persistence.authority_configuration import (
    lock_authority_configuration_exclusive,
    lock_authority_configuration_global_exclusive,
)

#: The event types this primitive writes. They are the contract the audit
#: trail is read back with, so they are named here rather than composed at
#: the call site.
REQUIREMENT_EVENT: Final[str] = "authority.configuration.requirement_changed"
CONTROL_EVENT: Final[str] = "authority.configuration.control_changed"

KNOWN_CONTROLS: Final[frozenset[str]] = frozenset(
    {"requirement_enforcement", "authority_issuance"}
)

#: Migration 028 refuses a platform-wide requirement_enforcement row: it
#: would suspend enforcement everywhere, which is a decision no single
#: control should be able to make silently. Refuse it here too, with a
#: message that says why, rather than surfacing a constraint violation.
PLATFORM_CAPABLE_CONTROLS: Final[frozenset[str]] = frozenset({"authority_issuance"})


class AuthorityConfigurationManagementError(RuntimeError):
    """The change was refused before anything was written."""


@dataclass(frozen=True, slots=True)
class AuthorityConfigurationChange:
    """What committed, and the audit record that is inseparable from it."""

    audit_event_id: UUID
    configuration_table: str
    configuration_row_id: UUID
    scope: Literal["organisation", "platform"]
    organisation_id: UUID | None
    principal_id: UUID | None
    action_class: str | None
    setting: str
    #: ``None`` when no row existed -- the change created the configuration.
    old_value: bool | None
    new_value: bool
    actor: str
    reason: str
    approval_reference: str
    changed_at: datetime

    @property
    def created_configuration(self) -> bool:
        return self.old_value is None

    def audit_details(self) -> dict[str, Any]:
        """The detail payload as it was written. Flat and JSON-safe."""
        return {
            "configuration_table": self.configuration_table,
            "configuration_row_id": str(self.configuration_row_id),
            "scope": self.scope,
            "organisation_id": (
                str(self.organisation_id) if self.organisation_id else None
            ),
            "principal_id": str(self.principal_id) if self.principal_id else None,
            "action_class": self.action_class,
            "setting": self.setting,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "reason": self.reason,
            "correlation_id": str(self.audit_event_id),
        }


def _required_text(value: Any, field: str) -> str:
    """A management change names its actor, its reason and its approval.

    Absent, blank or whitespace-only is refused here rather than allowed to
    reach the database, so the caller gets the field name back instead of a
    constraint violation. The CHECK constraints behind this are the backstop,
    not the contract.
    """
    if value is None:
        raise AuthorityConfigurationManagementError(
            f"{field} is required for an authority configuration change"
        )
    if not isinstance(value, str):
        raise AuthorityConfigurationManagementError(
            f"{field} must be text, got {type(value).__name__}"
        )
    text = value.strip()
    if not text:
        raise AuthorityConfigurationManagementError(
            f"{field} is required for an authority configuration change"
        )
    return text


def _as_uuid(value: Any, field: str) -> UUID:
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise AuthorityConfigurationManagementError(
            f"{field} must be a UUID"
        ) from exc


_SELECT_REQUIREMENT: Final[str] = """
SELECT id, required FROM authority_requirements
 WHERE org_id = $1
   AND scope_key = COALESCE($2::UUID::TEXT, '*') || '|' || COALESCE($3::TEXT, '*')
"""

_UPSERT_REQUIREMENT: Final[str] = """
INSERT INTO authority_requirements
    (org_id, agent_id, action_class, required, reason, changed_by, approval_reference)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (org_id, scope_key) DO UPDATE SET
    required = EXCLUDED.required,
    reason = EXCLUDED.reason,
    changed_by = EXCLUDED.changed_by,
    approval_reference = EXCLUDED.approval_reference
RETURNING id, required, updated_at
"""

_SELECT_CONTROL: Final[str] = """
SELECT id, engaged FROM authority_controls
 WHERE control = $1 AND scope_key = COALESCE($2::UUID::TEXT, '*')
"""

_UPSERT_CONTROL: Final[str] = """
INSERT INTO authority_controls
    (control, org_id, engaged, reason, changed_by, approval_reference)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (control, scope_key) DO UPDATE SET
    engaged = EXCLUDED.engaged,
    reason = EXCLUDED.reason,
    changed_by = EXCLUDED.changed_by,
    approval_reference = EXCLUDED.approval_reference
RETURNING id, engaged, updated_at
"""

_INSERT_AUDIT: Final[str] = """
INSERT INTO administrative_audit_events
    (id, org_id, scope, event_type, actor, approval_reference, details)
VALUES ($1, $2, $3, $4, $5, $6, $7::JSONB)
RETURNING created_at
"""


async def apply_authority_configuration_change_on(
    conn: Any,
    *,
    setting: str,
    new_value: bool,
    actor: Any,
    reason: Any,
    approval_reference: Any,
    organisation_id: Any = None,
    principal_id: Any = None,
    action_class: Any = None,
) -> AuthorityConfigurationChange:
    """Apply one change on a CALLER-SUPPLIED connection, in its transaction.

    The caller owns the transaction, which is what makes this composable: a
    management surface that needs to do something else in the same atomic
    act can, and the audit record still cannot be separated from the change.
    The public :func:`apply_authority_configuration_change` wraps this in a
    transaction of its own for the ordinary single-change case.

    ``setting`` is ``"requirement"`` or the name of a control.
    """
    actor_text = _required_text(actor, "actor")
    reason_text = _required_text(reason, "reason")
    approval_text = _required_text(approval_reference, "approval_reference")

    if not isinstance(new_value, bool):
        raise AuthorityConfigurationManagementError(
            "new_value must be a boolean; a configuration change is a "
            "deliberate on or off"
        )

    is_requirement = setting == "requirement"
    if not is_requirement and setting not in KNOWN_CONTROLS:
        raise AuthorityConfigurationManagementError(
            f"unknown authority configuration setting {setting!r}; expected "
            f"'requirement' or one of {sorted(KNOWN_CONTROLS)}"
        )

    org_uuid = None if organisation_id is None else _as_uuid(organisation_id, "organisation_id")
    principal_uuid = (
        None if principal_id is None else _as_uuid(principal_id, "principal_id")
    )

    if is_requirement:
        # A requirement is always about one organisation's principals. There
        # is no platform-wide requirement, and inventing one here would
        # create a second way to say what a control already says.
        if org_uuid is None:
            raise AuthorityConfigurationManagementError(
                "a requirement change must name an organisation"
            )
    else:
        if principal_uuid is not None or action_class is not None:
            raise AuthorityConfigurationManagementError(
                "a control is engaged for a scope, not for one principal or "
                "action class"
            )
        if org_uuid is None and setting not in PLATFORM_CAPABLE_CONTROLS:
            raise AuthorityConfigurationManagementError(
                f"{setting} cannot be engaged platform-wide; it must name an "
                "organisation"
            )

    if principal_uuid is not None and org_uuid is None:
        raise AuthorityConfigurationManagementError(
            "a principal-scoped change must name the owning organisation"
        )

    class_text: str | None = None
    if action_class is not None:
        class_text = _required_text(action_class, "action_class")

    scope: Literal["organisation", "platform"] = (
        "organisation" if org_uuid is not None else "platform"
    )

    # --- Lock order step 1: the configuration locks, exclusive -------------
    # Taken here rather than left to the write trigger, so the pre-image read
    # below and the write that replaces it happen inside one exclusive
    # window. The trigger takes the same two keys in the same order when the
    # write runs; a lock already held costs nothing.
    await lock_authority_configuration_global_exclusive(conn)
    if org_uuid is not None:
        await lock_authority_configuration_exclusive(conn, organisation_id=org_uuid)

    # --- Lock order step 2: what is being replaced ------------------------
    if is_requirement:
        previous = await conn.fetchrow(
            _SELECT_REQUIREMENT, org_uuid, principal_uuid, class_text
        )
        old_value = None if previous is None else bool(previous["required"])
    else:
        previous = await conn.fetchrow(_SELECT_CONTROL, setting, org_uuid)
        old_value = None if previous is None else bool(previous["engaged"])

    # --- Lock order step 3: the configuration row -------------------------
    # BEFORE the audit row, always. The write trigger takes the configuration
    # locks at this moment, so a path that wrote its audit row first would
    # invert the accepted order even though both rows still committed
    # together.
    if is_requirement:
        written = await conn.fetchrow(
            _UPSERT_REQUIREMENT,
            org_uuid, principal_uuid, class_text, new_value,
            reason_text, actor_text, approval_text,
        )
    else:
        written = await conn.fetchrow(
            _UPSERT_CONTROL,
            setting, org_uuid, new_value, reason_text, actor_text, approval_text,
        )

    if written is None:
        # An upsert that matched an existing row but was filtered out by a
        # row level security policy returns nothing. Refusing loudly beats
        # writing an audit record for a change that did not happen.
        raise AuthorityConfigurationManagementError(
            "the authority configuration row was not written; this "
            "connection may not change authority configuration"
        )

    table = "authority_requirements" if is_requirement else "authority_controls"
    change = AuthorityConfigurationChange(
        audit_event_id=uuid4(),
        configuration_table=table,
        configuration_row_id=written["id"],
        scope=scope,
        organisation_id=org_uuid,
        principal_id=principal_uuid,
        action_class=class_text,
        setting=setting,
        old_value=old_value,
        new_value=new_value,
        actor=actor_text,
        reason=reason_text,
        approval_reference=approval_text,
        changed_at=written["updated_at"],
    )

    # --- Lock order step 4: the administrative audit record ---------------
    # Same transaction, no exception handling around it. If this fails the
    # configuration change fails with it, which is the invariant.
    created_at = await conn.fetchval(
        _INSERT_AUDIT,
        change.audit_event_id,
        org_uuid,
        scope,
        REQUIREMENT_EVENT if is_requirement else CONTROL_EVENT,
        actor_text,
        approval_text,
        json.dumps(change.audit_details()),
    )
    if created_at is None:
        raise AuthorityConfigurationManagementError(
            "the administrative audit record was not written; the "
            "configuration change is being rolled back"
        )

    return change


async def apply_authority_configuration_change(
    management_db: Any, **change: Any
) -> AuthorityConfigurationChange:
    """Apply one change in a transaction of its own.

    ``management_db`` must be a pool for a connection that may change
    authority configuration -- ``inntris_authority_admin``, not the runtime
    or tenant role. Handing it either of those fails in the database with
    neither row written.
    """
    async with management_db.acquire() as conn, conn.transaction():
        return await apply_authority_configuration_change_on(conn, **change)
