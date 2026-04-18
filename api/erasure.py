"""GDPR / CCPA erasure with forensic-integrity preservation (Phase 4B).

The DB function ``app.erase_personal_data`` does the heavy lifting (see
``database/migrations/006_gdpr_erasure.sql``). This module is a typed
Python wrapper so the operator-facing admin endpoint does not have to
hand-build the SQL every time, and so we have a unit-test surface for
the preservation invariants.

Design contract:
  * action_hash, signature, and merkle_* fields are NEVER touched.
  * payload becomes ``{erased: true, erased_at, erasure_request_id}``.
  * request_ip / request_user_agent become NULL.
  * metadata becomes ``{erased: true}`` (with test_request=true preserved
    so the anchor worker's filter still excludes dev rows).
  * Re-running erasure on an already-tombstoned row is a no-op.

The wrapper validates inputs, opens a transaction on the caller's
connection, and returns the UUID of the recorded erasure_request row
— the caller must persist this id in their ticketing system so the
chain of custody (request -> redaction -> row count) is auditable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

from asyncpg import Connection

logger = logging.getLogger(__name__)

# Legal bases we accept. An unknown value is rejected rather than
# silently written to the ledger — a typo ("gdpr_17", "art17") would
# make future auditing of the ledger harder.
_ALLOWED_LEGAL_BASES = frozenset({
    "gdpr_art17",
    "ccpa_1798_105",
    "operator_request",
})


@dataclass(frozen=True)
class ErasureResult:
    request_id: UUID
    rows_affected: int


async def erase_personal_data(
    conn: Connection,
    *,
    organization_id: UUID,
    requested_by: str,
    legal_basis: str,
    agent_id: UUID | None = None,
    reason: str | None = None,
) -> ErasureResult:
    """Run the erasure function and return the audit record."""
    if legal_basis not in _ALLOWED_LEGAL_BASES:
        raise ValueError(
            f"unsupported legal_basis {legal_basis!r}; must be one of "
            f"{sorted(_ALLOWED_LEGAL_BASES)}"
        )
    if not requested_by or not requested_by.strip():
        raise ValueError("requested_by is required (operator or DPO identity)")

    request_id: UUID = await conn.fetchval(
        "SELECT app.erase_personal_data($1, $2, $3, $4, $5)",
        organization_id,
        agent_id,
        requested_by.strip(),
        legal_basis,
        reason,
    )
    rows_affected = await conn.fetchval(
        "SELECT rows_affected FROM erasure_requests WHERE id = $1",
        request_id,
    )
    logger.info(
        "gdpr.erasure.completed",
        extra={
            "erasure_request_id": str(request_id),
            "organization_id": str(organization_id),
            "agent_id": str(agent_id) if agent_id else None,
            "legal_basis": legal_basis,
            "rows_affected": rows_affected,
        },
    )
    return ErasureResult(request_id=request_id, rows_affected=rows_affected)


def is_row_erased(payload: dict) -> bool:
    """True if an audit_logs.payload JSON is a tombstone.

    Exposed so the verify path can label erased rows distinctly from
    still-PII rows when rendering forensic output.
    """
    return bool(payload.get("erased"))
