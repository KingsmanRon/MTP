"""The durable record of an authority decision — ALLOW and BLOCK alike.

Two rows, one decision, and why both are needed
-----------------------------------------------
A decision needs a stable identity, a durable instant and enough canonical
material to reconstruct its receipt truthfully. Every decision is written
to BOTH of these, in one transaction:

``audit_logs``
    The request record. Append-only by trigger, hash-chained per agent,
    and swept into the Merkle anchoring pipeline — and deliberately
    erasable: ``app.erase_personal_data`` is authorised to replace its
    ``payload`` and ``metadata`` with a tombstone.

``authority_decision_evidence`` (migration 0020, hardened by 0021)
    The forensic authority commitment. Reconstruction reads THIS, not
    ``audit_logs``, precisely because the audit payload can be tombstoned
    by a legitimate erasure and a receipt that has already been quoted
    must not stop verifying.

This is not a second answer to "what did the server decide" — the audit
row remains the decision of record and the two are written together or
not at all. It is the same answer kept where erasure does not reach.

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

#: No ON CONFLICT clause, deliberately. The decision row and its forensic
#: evidence are one atomic write over a freshly generated audit id, so a
#: conflict here is not a replay -- it means something is wrong about the
#: identity we are writing under. Swallowing it would commit a decision
#: whose evidence is somebody else's row.
_INSERT_EVIDENCE: Final[str] = """
    INSERT INTO authority_decision_evidence (
        audit_log_id, agent_id, org_id, recorded_at, decision_body, sandbox,
        audit_action_type
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7)
"""

_SELECT_EVIDENCE: Final[str] = """
    SELECT audit_log_id, agent_id, org_id, recorded_at, decision_body, sandbox
    FROM authority_decision_evidence
    WHERE audit_log_id = $1
"""

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
    signed_action_hash: str | None = None,
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
        # Only ever populated by a path that ALREADY verified the agent's
        # Ed25519 signature over this hash. The service-authenticated
        # endpoint has verified none, so it stores NULL here and the
        # receipt cannot claim an agent-signed hash it never saw.
        "signed_action_hash": signed_action_hash,
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


def _decision_metadata(*, sandbox: bool) -> dict[str, Any]:
    """Audit metadata for a decision row, sandbox classification included."""
    metadata: dict[str, Any] = {
        "evidence_kind": AUTHORITY_DECISION_EVIDENCE_KIND,
        # What actually authorised this row, since no agent signature did.
        # Named so a reader never mistakes the marker in the signature
        # column for a real signature.
        "signature_kind": "authority_decision",
        "source": "authority_evaluate",
        "non_cryptographic": True,
    }
    if sandbox:
        # The same two keys the legacy path writes: test_request is the
        # anchor worker's exclusion key, sandbox is the human-facing flag
        # on the public receipt.
        metadata["test_request"] = True
        metadata["sandbox"] = True
    return metadata


def evidence_body(
    payload: dict[str, Any], *, audit_id: Any, agent_id: Any
) -> dict[str, Any]:
    """The canonical v3 decision body, in the shape the receipt publishes.

    Built here, at decision time, and stored verbatim — so the historical
    event stays byte-identical even if the builder is refactored later,
    and so it does not depend on ``audit_logs.payload``, which authorised
    erasure is allowed to replace.

    Deliberately carries no request content: identifiers, digests, the
    decision and its reasons. The act appears only as a hash.
    """
    return {
        "audit_id": str(audit_id),
        "agent_id": str(agent_id),
        "organisation_id": payload["organisation_id"],
        "action_type": payload["action_type"],
        "domain": payload["domain"] or "unknown",
        "decision": payload["decision"],
        "execution_action_hash": payload["execution_action_hash"],
        "policy_snapshot_format": payload["policy_snapshot_format"] or "none",
        "policy_snapshot_digest": payload["policy_snapshot_digest"] or "none",
        "signed_action_hash": payload.get("signed_action_hash"),
        "consequence_class": payload["consequence_class"],
        "grant_id": payload["grant_id"],
        "grant_expires_at": payload["grant_expires_at"],
        "authority_scope_digest": payload["authority_scope_digest"],
        "executor_binding_digest": payload["executor_binding_digest"] or None,
        "reasons": list(payload["reasons"]),
    }


async def record_authority_decision(
    database: Any,
    *,
    agent_id: UUID,
    organisation_id: UUID,
    trust_score: int,
    execution_action_hash: str,
    policy_snapshot_digest: str | None,
    payload: dict[str, Any],
    allowed: bool,
    verdict_reason: str,
    sandbox: bool = False,
) -> tuple[UUID, datetime]:
    """Append the decision and return its durable identity and instant.

    The returned ``(id, timestamp)`` is what makes the v3 decision event
    stable: both are database-assigned and read back rather than
    regenerated.

    ``sandbox`` classifies the row for the anchoring pipeline. It is not
    cosmetic: ``test_request`` is the key ``get_unanchored_logs`` already
    excludes on, so a sandbox decision that omitted it would be swept onto
    the mainnet anchor path with production activity.
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
                _decision_metadata(sandbox=sandbox),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        # The forensic half, in the SAME transaction. If the evidence row
        # could not be written, the decision row must not exist either:
        # a decision whose receipt can never be reconstructed is worse
        # than a decision that was refused outright.
        await conn.execute(
            _INSERT_EVIDENCE,
            row["id"],
            agent_id,
            organisation_id,
            row["timestamp"],
            json.dumps(
                evidence_body(payload, audit_id=row["id"], agent_id=agent_id),
                sort_keys=True,
                separators=(",", ":"),
            ),
            sandbox,
            AUTHORITY_DECISION_ACTION_TYPE,
        )
    return row["id"], row["timestamp"]


async def get_authority_decision(database: Any, audit_id: UUID) -> Any:
    """Read the forensic decision evidence back, for reconstruction.

    Deliberately reads ``authority_decision_evidence`` and not
    ``audit_logs``: an authorised erasure replaces ``audit_logs.payload``
    with a tombstone, which is correct for the request record and fatal
    for a receipt that has already been quoted. This row survives it and
    holds no request content to erase.
    """
    async with database.acquire() as conn:
        return await conn.fetchrow(_SELECT_EVIDENCE, audit_id)


async def get_authority_decision_audit_row(database: Any, audit_id: UUID) -> Any:
    """The audit row itself — erasable, and used for audit-trail questions."""
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
    "evidence_body",
    "get_authority_decision",
    "get_authority_decision_audit_row",
    "record_authority_decision",
]
