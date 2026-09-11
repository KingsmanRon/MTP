"""Which external-issuer identity a principal actually is.

Phase 7A, Gate 3. A verified delegation says "the holder of account X may
spend up to Y". Turning that into a decision needs one more fact: is the
agent in front of us account X? These rows are that fact, and they live
where a caller cannot write them (see migration 029 for why
``agents.metadata`` is not usable for this).

Scoped per issuer, deliberately
-------------------------------
A binding value is meaningful only to the issuer that assigned it. Two
issuers may spell account references identically and mean different
accounts, so a binding recorded for one issuer is never offered to
another.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Final
from uuid import UUID

import asyncpg

logger = logging.getLogger(__name__)

EVENT_BINDING_SET: Final[str] = "authority.principal_binding_set"
EVENT_BINDING_CLEARED: Final[str] = "authority.principal_binding_cleared"


class PrincipalBindingUnavailable(RuntimeError):
    """The principal's issuer identity could not be established."""


_LOOKUP: Final[
    str
] = """
    SELECT binding_key, binding_value
    FROM authority_principal_bindings
    WHERE agent_id = $1 AND issuer = $2
"""


async def load_principal_binding(
    database: Any, *, agent_id: UUID, issuer: str
) -> dict[str, str]:
    """Every binding recorded for this principal at this issuer.

    An empty mapping is a real answer: this principal has no identity at
    this issuer. The provider then refuses to tie any delegation to it,
    which is correct — a delegation that cannot be tied to a principal
    would otherwise be usable against every principal in the organisation.

    Raises :class:`PrincipalBindingUnavailable` when the read failed,
    including when the table is absent. A missing table is not evidence
    that no binding exists; it means this deployment cannot establish
    identity at all, and proceeding would accept delegations it has no
    basis to accept.
    """
    try:
        async with database.acquire() as conn:
            records = await conn.fetch(_LOOKUP, agent_id, issuer)
    except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError, TimeoutError) as exc:
        raise PrincipalBindingUnavailable(
            f"principal binding could not be read: {type(exc).__name__}"
        ) from exc
    return {record["binding_key"]: record["binding_value"] for record in records}


async def set_principal_binding(
    database: Any,
    *,
    organisation_id: UUID,
    agent_id: UUID,
    issuer: str,
    binding_key: str,
    binding_value: str,
    changed_by: str,
    approval_reference: str,
    reason: str,
) -> dict[str, Any]:
    """Record one binding, with immutable audit evidence."""
    async with database.acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """
            INSERT INTO authority_principal_bindings (
                org_id, agent_id, issuer, binding_key, binding_value, reason,
                changed_by, approval_reference
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (agent_id, issuer, binding_key) DO UPDATE
                SET binding_value = EXCLUDED.binding_value,
                    reason = EXCLUDED.reason,
                    changed_by = EXCLUDED.changed_by,
                    approval_reference = EXCLUDED.approval_reference,
                    updated_at = NOW()
            RETURNING id, agent_id, issuer, binding_key, updated_at
            """,
            organisation_id,
            agent_id,
            issuer,
            binding_key,
            binding_value,
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
            EVENT_BINDING_SET,
            changed_by,
            approval_reference,
            # The VALUE is deliberately not recorded here. It is an external
            # account identifier belonging to a customer, the audit table is
            # broadly readable within the tenant, and the row itself already
            # holds it. Recording which binding changed is the audit fact;
            # copying the identifier around is not.
            json.dumps(
                {
                    "agent_id": str(agent_id),
                    "issuer": issuer,
                    "binding_key": binding_key,
                    "reason": reason,
                }
            ),
        )
    logger.info(
        "authority principal binding set: agent=%s issuer=%s key=%s by=%s approval=%s",
        agent_id,
        issuer,
        binding_key,
        changed_by,
        approval_reference,
    )
    return dict(row)


async def clear_principal_binding(
    database: Any,
    *,
    organisation_id: UUID,
    agent_id: UUID,
    issuer: str,
    binding_key: str,
    changed_by: str,
    approval_reference: str,
    reason: str,
) -> bool:
    """Remove one binding. The principal then has no identity at that issuer."""
    async with database.acquire() as conn, conn.transaction():
        deleted = await conn.fetchval(
            """
            DELETE FROM authority_principal_bindings
            WHERE agent_id = $1 AND issuer = $2 AND binding_key = $3
            RETURNING id
            """,
            agent_id,
            issuer,
            binding_key,
        )
        await conn.execute(
            """
            INSERT INTO administrative_audit_events (
                org_id, event_type, actor, approval_reference, details
            ) VALUES ($1, $2, $3, $4, $5::jsonb)
            """,
            organisation_id,
            EVENT_BINDING_CLEARED,
            changed_by,
            approval_reference,
            json.dumps(
                {
                    "agent_id": str(agent_id),
                    "issuer": issuer,
                    "binding_key": binding_key,
                    "existed": deleted is not None,
                    "reason": reason,
                }
            ),
        )
    return deleted is not None


async def list_principal_bindings(
    database: Any, *, agent_id: UUID
) -> list[dict[str, Any]]:
    """Every binding recorded for one principal, across issuers."""
    async with database.acquire() as conn:
        records = await conn.fetch(
            """
            SELECT id, issuer, binding_key, binding_value, reason, changed_by,
                   approval_reference, created_at, updated_at
            FROM authority_principal_bindings
            WHERE agent_id = $1
            ORDER BY issuer, binding_key
            """,
            agent_id,
        )
    return [dict(record) for record in records]


__all__ = [
    "EVENT_BINDING_CLEARED",
    "EVENT_BINDING_SET",
    "PrincipalBindingUnavailable",
    "clear_principal_binding",
    "list_principal_bindings",
    "load_principal_binding",
    "set_principal_binding",
]
