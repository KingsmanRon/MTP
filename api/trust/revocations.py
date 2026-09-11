"""Runtime distrust: which issuers, keys and delegations are revoked.

Phase 7A, Gate 3 and Gate 8. Trust is configured (reviewable in the
deployment, not silently mutable); distrust is data (changeable in seconds
at 03:00, which is when it is needed).

Fails closed, and why that is not the usual trade-off
-----------------------------------------------------
Most availability/safety trade-offs are genuinely uncomfortable. This one
is not. The read happens only while resolving a *new* delegated authority,
and issuance cannot proceed without the same database anyway — a grant is a
row. So a database failure already refuses the request; failing closed here
adds no outage that was not already happening, and closes the window in
which a revoked key keeps working because nobody could ask.

Consumption of authority already issued is a separate question with a
separate answer: it is decided by the grant's own lifecycle, not by this
table. Revoking a key does not retroactively strand an executor that is
mid-flight on a grant issued while the key was good; it stops the next one.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

import asyncpg

logger = logging.getLogger(__name__)

EVENT_TRUST_REVOCATION: Final[str] = "authority.trust_revocation_set"


class RevocationSubject(StrEnum):
    """What is being distrusted."""

    ISSUER = "issuer"
    ISSUER_KEY = "issuer_key"
    DELEGATE_KEY = "delegate_key"
    AUTHORITY_REFERENCE = "authority_reference"


class RevocationLookupUnavailable(RuntimeError):
    """Revocation state could not be established. Nothing new is accepted."""


@dataclass(frozen=True, slots=True)
class RevocationSnapshot:
    """The revoked subjects relevant to one resolution attempt.

    Built per resolution from an exact-match query over at most four
    subjects, so it is one indexed read and cannot go stale between being
    read and being used.
    """

    revoked: frozenset[tuple[str, str, str]] = frozenset()

    @staticmethod
    def _key(
        subject_type: RevocationSubject, subject_id: str, issuer: str | None
    ) -> tuple[str, str, str]:
        return (subject_type.value, issuer or "*", subject_id)

    def is_revoked(
        self,
        subject_type: RevocationSubject,
        subject_id: str,
        *,
        issuer: str | None = None,
    ) -> bool:
        return self._key(subject_type, subject_id, issuer) in self.revoked


#: Over-fetches deliberately: a composite ANY() would need a declared SQL
#: type, which is more schema coupling than a lookup shape deserves. The
#: exact triples are intersected in Python below, so an issuer_key
#: revocation recorded for one issuer can never be read as applying to
#: another issuer that happens to use the same fingerprint.
_LOOKUP_QUERY: Final[
    str
] = """
    SELECT subject_type, subject_id, COALESCE(issuer, '*') AS issuer
    FROM authority_trust_revocations
    WHERE revoked
      AND subject_type = ANY($1::TEXT[])
      AND subject_id = ANY($2::TEXT[])
"""


async def load_revocations(
    database: Any,
    *,
    subjects: list[tuple[RevocationSubject, str, str | None]],
) -> RevocationSnapshot:
    """Read which of ``subjects`` are currently revoked.

    Raises :class:`RevocationLookupUnavailable` when the state could not be
    established, including when the table is absent: unlike the requirement
    configuration, a missing revocation table is NOT evidence that nothing
    is revoked. It means this deployment cannot honour a revocation at all,
    and accepting delegated authority in that state would make every
    revocation an operator has issued silently ineffective.
    """
    if not subjects:
        return RevocationSnapshot()

    subject_types = sorted({subject.value for subject, _id, _issuer in subjects})
    subject_ids = sorted({subject_id for _s, subject_id, _issuer in subjects})

    try:
        async with database.acquire() as conn:
            records = await conn.fetch(_LOOKUP_QUERY, subject_types, subject_ids)
    except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError, TimeoutError) as exc:
        raise RevocationLookupUnavailable(
            f"revocation state could not be read: {type(exc).__name__}"
        ) from exc

    # The query over-fetches (any subject_type paired with any subject_id);
    # narrow to the exact triples asked about so a revocation recorded for a
    # different issuer cannot be misread as applying here.
    wanted = {
        RevocationSnapshot._key(subject, subject_id, issuer)
        for subject, subject_id, issuer in subjects
    }
    found = {
        (record["subject_type"], record["issuer"], record["subject_id"])
        for record in records
    }
    return RevocationSnapshot(revoked=frozenset(wanted & found))


async def set_revocation(
    database: Any,
    *,
    subject_type: RevocationSubject,
    subject_id: str,
    revoked: bool,
    changed_by: str,
    approval_reference: str,
    reason: str,
    issuer: str | None = None,
) -> dict[str, Any]:
    """Revoke or reinstate one subject.

    Reinstatement is deliberately possible: a revocation made in error
    during an incident must be reversible without a schema change.

    No ``administrative_audit_events`` row is written here, and that is not
    an oversight. That table is tenant-scoped (``org_id`` is NOT NULL) and
    trust revocation is platform state that belongs to no organisation;
    writing it against an arbitrary tenant would forge per-tenant evidence
    for a change that tenant did not make. The row itself carries the
    evidence instead — ``changed_by``, ``approval_reference``, ``reason``
    and ``updated_at`` — and the write is logged at WARNING.
    """
    if subject_type is RevocationSubject.ISSUER:
        issuer = None
    elif not issuer:
        raise ValueError(
            f"{subject_type.value} revocations must name the issuer they apply to"
        )

    async with database.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO authority_trust_revocations (
                subject_type, subject_id, issuer, revoked, reason, changed_by,
                approval_reference
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (scope_key) DO UPDATE
                SET revoked = EXCLUDED.revoked,
                    reason = EXCLUDED.reason,
                    changed_by = EXCLUDED.changed_by,
                    approval_reference = EXCLUDED.approval_reference,
                    updated_at = NOW()
            RETURNING id, subject_type, subject_id, issuer, revoked, updated_at
            """,
            subject_type.value,
            subject_id,
            issuer,
            revoked,
            reason,
            changed_by,
            approval_reference,
        )

    (logger.warning if revoked else logger.info)(
        "authority trust %s: %s %s (issuer=%s) by=%s approval=%s reason=%s",
        "REVOKED" if revoked else "reinstated",
        subject_type.value,
        subject_id,
        issuer or "-",
        changed_by,
        approval_reference,
        reason,
    )
    return dict(row)


async def list_revocations(database: Any, *, include_reinstated: bool = False) -> list[
    dict[str, Any]
]:
    """Every revocation row, newest change first."""
    clause = "" if include_reinstated else "WHERE revoked"
    async with database.acquire() as conn:
        records = await conn.fetch(
            f"""
            SELECT id, subject_type, subject_id, issuer, revoked, reason,
                   changed_by, approval_reference, created_at, updated_at
            FROM authority_trust_revocations
            {clause}
            ORDER BY updated_at DESC
            """
        )
    return [dict(record) for record in records]


__all__ = [
    "EVENT_TRUST_REVOCATION",
    "RevocationLookupUnavailable",
    "RevocationSnapshot",
    "RevocationSubject",
    "list_revocations",
    "load_revocations",
    "set_revocation",
]
