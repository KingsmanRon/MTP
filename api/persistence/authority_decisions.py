"""The durable record of an authority decision — ALLOW and BLOCK alike.

Why the audit log, and not a new table
--------------------------------------
A decision needs a stable identity, a durable instant and enough canonical
material to reconstruct its receipt truthfully. ``audit_logs`` already
provides all three, and it is the record the rest of the system treats as
authoritative: append-only by trigger, hash-chained per agent, and swept
into the Merkle anchoring pipeline. Adding a second decision table would
create a second answer to "what did the server decide", which is exactly
the failure this phase exists to remove — and it would widen the Phase-3
migration, which must stay frozen until Phase 7A.

Only an ALLOW produces an ``execution_authority_grants`` row, because only
an ALLOW produces something spendable. A BLOCK produces this record and
nothing else, so a refusal is as provable after the fact as a permission.

What this row is NOT
--------------------
It carries no agent Ed25519 signature, because this surface authenticates
a *service*, not an agent. So ``signature_valid`` is ``False`` and the
signature column holds an explicitly labelled marker. Claiming otherwise
would corrupt what ``signature_valid`` means in v1/v2 receipts, where it
asserts that a real agent signature verified.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Final
from uuid import UUID

from api.models import ActionVerdict

#: Marks an audit row as the durable record of an authority decision.
AUTHORITY_DECISION_EVIDENCE_KIND: Final[str] = "authority_decision"

#: Versioned shape of the canonical decision material in ``payload``.
AUTHORITY_DECISION_PAYLOAD_FORMAT: Final[str] = "inntris-authority-decision-v1"

#: The action_type recorded for a decision row.
AUTHORITY_DECISION_ACTION_TYPE: Final[str] = "authority_decision"

_INSERT: Final[str] = """
    INSERT INTO audit_logs (
        agent_id, action_type, action_hash, payload, verdict,
        verdict_reason, signature, signature_valid, request_ip,
        request_user_agent, response_time_ms, trust_score_at_time,
        chain_previous_hash, policy_hash, metadata
    )
    VALUES (
        $1, $2, $3, $4, $5, $6, $7, FALSE, NULL, NULL, NULL, $8,
        (
            SELECT action_hash FROM audit_logs
            WHERE agent_id = $1
            ORDER BY chain_sequence DESC
            LIMIT 1
        ),
        $9, $10
    )
    RETURNING id, timestamp
"""


def build_decision_payload(
    *,
    organisation_id: Any,
    action_type: str,
    domain: str | None,
    decision: str,
    reasons: tuple[str, ...],
    execution_action_hash: str,
    policy_snapshot_format: str | None,
    policy_snapshot_digest: str | None,
    policy_revision: str | None,
    executor_binding_digest: str,
    executor_reference: str | None,
    consequence_class: str | None,
    authority_scope_digest: str | None,
    grant_id: Any | None,
    grant_expires_at: datetime | None,
    detail: str | None,
) -> dict[str, Any]:
    """The canonical decision material, in one versioned shape.

    Everything the v3 decision event needs lives here, so reconstruction
    reads one immutable row rather than re-deriving facts from whatever
    the caller happens to pass at read time.

    ``authority_scope_digest`` is the digest of the delegated scope this
    decision was bound by. It is deliberately not called an artefact
    digest: nothing here has seen the issuer's artefact.
    """
    return {
        "format": AUTHORITY_DECISION_PAYLOAD_FORMAT,
        "organisation_id": str(organisation_id),
        "action_type": action_type,
        "domain": domain,
        "decision": decision,
        "reasons": list(reasons),
        "execution_action_hash": execution_action_hash,
        "policy_snapshot_format": policy_snapshot_format,
        "policy_snapshot_digest": policy_snapshot_digest,
        "policy_revision": policy_revision,
        "executor_binding_digest": executor_binding_digest,
        "executor_reference": executor_reference,
        "consequence_class": consequence_class,
        "authority_scope_digest": authority_scope_digest,
        "grant_id": str(grant_id) if grant_id else None,
        "grant_expires_at": (
            grant_expires_at.isoformat().replace("+00:00", "Z")
            if grant_expires_at is not None
            else None
        ),
        "detail": detail,
    }


async def record_authority_decision(
    database: Any,
    *,
    agent_id: UUID,
    trust_score: int,
    execution_action_hash: str,
    policy_snapshot_digest: str | None,
    payload: dict[str, Any],
    allowed: bool,
    verdict_reason: str,
) -> tuple[UUID, datetime]:
    """Append the decision and return its durable identity and instant.

    The returned ``(id, timestamp)`` is what makes the v3 decision event
    stable: both are database-assigned, immutable once written, and read
    back rather than regenerated.
    """
    verdict = ActionVerdict.APPROVED if allowed else ActionVerdict.BLOCKED
    async with database.acquire() as conn, conn.transaction():
        # Same per-agent lock the /verify path takes, so a concurrent
        # decision for this agent cannot fork the local hash chain.
        await conn.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)", str(agent_id)
        )
        row = await conn.fetchrow(
            _INSERT,
            agent_id,
            AUTHORITY_DECISION_ACTION_TYPE,
            execution_action_hash,
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            verdict.value,
            verdict_reason[:1000],
            f"AUTHORITY_DECISION:{execution_action_hash}".encode("ascii"),
            trust_score,
            policy_snapshot_digest,
            json.dumps(
                {
                    "evidence_kind": AUTHORITY_DECISION_EVIDENCE_KIND,
                    # What actually authorised this row, since no agent
                    # signature did. Named so a reader never mistakes the
                    # marker in the signature column for a real signature.
                    "signature_kind": "authority_decision",
                    "source": "authority_evaluate",
                    "non_cryptographic": True,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    return row["id"], row["timestamp"]


async def get_authority_decision(database: Any, audit_id: UUID) -> Any:
    """Read one decision record back, for reconstruction."""
    async with database.acquire() as conn:
        return await conn.fetchrow(
            "SELECT * FROM audit_logs WHERE id = $1 AND action_type = $2",
            audit_id,
            AUTHORITY_DECISION_ACTION_TYPE,
        )


__all__ = [
    "AUTHORITY_DECISION_ACTION_TYPE",
    "AUTHORITY_DECISION_EVIDENCE_KIND",
    "AUTHORITY_DECISION_PAYLOAD_FORMAT",
    "build_decision_payload",
    "get_authority_decision",
    "record_authority_decision",
]
