"""Deriving the v3 evidence chain from the durable authority lifecycle.

No read-time facts
------------------
Every field of every event comes from a durable row. The builders take a
record and a signing key, and **nothing else** — no ``audit_id`` to pass
in, no issuer, no policy hash supplied at the call site. That is not
tidiness: a value accepted at read time can differ between two reads of
the same history, and then one event has two signatures and the signature
means nothing.

Stability without a new table
-----------------------------
Two reads of one event return the *same* signed bytes, because:

* ``event_id`` is derived from a durable identifier, not generated;
* ``recorded_at`` is a durable column (the decision row's ``timestamp``,
  then ``consumed_at``, ``outcome_recorded_at``) — never "now";
* the body is built only from columns that are append-only by trigger, or
  that Phase 3 makes immutable or write-once;
* Ed25519 is deterministic (RFC 8032): the same key over the same message
  always yields the same signature.

No signed material has to be stored to make evidence quotable: the
signature is re-derivable from the stored facts.

The stored facts themselves do need a home that authorised erasure will
not overwrite, which is what ``authority_decision_evidence`` (migration
0020, hardened by 0021) is for. Phase 4 therefore does add migrations of
its own; they are Phase-7A release gates alongside the Phase-3 one.

**What this depends on, stated plainly:** stability holds for as long as
the signing key is stable. A key rotation produces different signatures
for the same history, which is why publication and rotation are a
deliberate Phase 7A release action with its own key registry.

Decisions, not just permissions
-------------------------------
The decision event is built from the ``audit_logs`` decision record, so a
BLOCK has evidence exactly as an ALLOW does. Consumption and outcome are
separate, later links off the grant, so a decision receipt is never
rewritten when they appear.

Delegated authority: only what is stored
----------------------------------------
This phase durably stores one delegation fact, ``authority_scope_digest``,
and that is the only one published. Issuer, external reference and
artefact digest stay absent until a provider phase persists them.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from api.receipts.v3 import (
    AuthorityEvidenceChain,
    ConsumptionEvidenceV3,
    DecisionEvidenceV3,
    EvidenceError,
    EvidenceEventType,
    EvidenceSigningKey,
    OutcomeEvidenceV3,
    SignedEvidenceEvent,
    evidence_chain_continuity_failures,
    sign_evidence_event,
)


def decision_event_id(decision_audit_id: Any) -> str:
    """Derived, not generated, so it is the same on every read.

    Keyed on the DECISION record, not on a grant, because a BLOCK has no
    grant and still has a decision worth proving.
    """
    return f"decision:{decision_audit_id}"


def consumption_event_id(consumption_audit_id: Any) -> str:
    return f"consumption:{consumption_audit_id}"


def outcome_event_id(grant_id: Any) -> str:
    return f"outcome:{grant_id}"


def build_decision_evidence(
    decision_record: Any,
    *,
    key: EvidenceSigningKey,
) -> SignedEvidenceEvent:
    """Evidence of what was decided, from the durable decision row alone.

    **Every input is a column of ``decision_record``.** There are
    deliberately no other parameters: an argument supplied at read time
    could differ between two reads of the same history, and then the
    "same" event would carry two different signatures. Identity comes from
    ``id``, the instant from ``timestamp``, and the body from the
    canonical decision payload written when the decision was made.

    Works for BLOCK exactly as it works for ALLOW. A refusal is a decision
    and gets a receipt; it simply carries no ``grant_id``.

    ``signed_action_hash`` is read from the payload, where it is populated
    only by a path that actually verified the agent's Ed25519 signature.
    The service-authenticated surface writes ``null``, so evidence from
    that surface cannot claim an agent-signed hash.
    """
    payload = _decision_body(decision_record)
    missing = _REQUIRED_BODY_FIELDS.difference(payload)
    if missing:
        raise EvidenceError(
            "decision evidence is incomplete; cannot sign a partial history "
            f"(missing: {', '.join(sorted(missing))})"
        )

    body = DecisionEvidenceV3(
        audit_id=payload["audit_id"],
        agent_id=payload["agent_id"],
        organisation_id=payload["organisation_id"],
        action_type=payload["action_type"],
        domain=payload["domain"],
        decision=payload["decision"],
        execution_action_hash=payload["execution_action_hash"],
        policy_snapshot_format=payload["policy_snapshot_format"],
        policy_snapshot_digest=payload["policy_snapshot_digest"],
        signed_action_hash=payload.get("signed_action_hash"),
        consequence_class=payload["consequence_class"],
        grant_id=payload["grant_id"],
        grant_expires_at=_instant_or_none(payload["grant_expires_at"]),
        # The scope digest, under its own name. See DecisionEvidenceV3.
        authority_scope_digest=payload["authority_scope_digest"],
        executor_binding_digest=payload["executor_binding_digest"],
        reasons=tuple(payload["reasons"]),
    ).to_body()
    return sign_evidence_event(
        event_id=decision_event_id(decision_record["audit_log_id"]),
        event_type=EvidenceEventType.DECISION,
        body=body,
        key=key,
        # Durable decision time, never "now".
        recorded_at=decision_record["recorded_at"],
    )


def build_consumption_evidence(
    grant: Any,
    *,
    key: EvidenceSigningKey,
    parent: SignedEvidenceEvent,
) -> SignedEvidenceEvent | None:
    """Evidence that the authority was spent. ``None`` until it actually was.

    Produced only from a COMMITTED consumption: the grant must be in the
    consumed state and carry both its receipt id and the execution
    reference. An in-flight or refused attempt yields no evidence,
    because nothing happened that evidence could describe.
    """
    if (
        grant["status"] != "consumed"
        or grant["consumption_audit_id"] is None
        or grant["consumed_at"] is None
        or not grant["execution_ref"]
    ):
        return None

    body = ConsumptionEvidenceV3(
        consumption_audit_id=str(grant["consumption_audit_id"]),
        grant_id=str(grant["id"]),
        execution_action_hash=grant["execution_action_hash"],
        execution_ref=grant["execution_ref"],
        outcome="authorised",
        executor_binding_digest=grant["executor_binding_digest"],
        agent_id=str(grant["agent_id"]),
        organisation_id=str(grant["org_id"]),
        executor_reference=grant["executor_reference"],
        consumed_at=grant["consumed_at"],
    ).to_body()
    return sign_evidence_event(
        event_id=consumption_event_id(grant["consumption_audit_id"]),
        event_type=EvidenceEventType.CONSUMPTION,
        body=body,
        key=key,
        recorded_at=grant["consumed_at"],
        parent=parent,
    )


def build_outcome_evidence(
    grant: Any,
    *,
    key: EvidenceSigningKey,
    parent: SignedEvidenceEvent,
) -> SignedEvidenceEvent | None:
    """Evidence of what happened. ``None`` unless it is trustworthily known.

    A ``pending`` outcome is the absence of knowledge, and an
    ``outcome_unknown`` is explicitly the absence of trustworthy
    knowledge. Neither is published as evidence: signing "we do not know"
    as though it were a finding is worse than publishing nothing.
    """
    state = grant["outcome_state"]
    if state in (None, "pending", "outcome_unknown") or grant["outcome_recorded_at"] is None:
        return None

    body = OutcomeEvidenceV3(
        grant_id=str(grant["id"]),
        outcome_state=state,
        outcome_reference=grant["outcome_reference"],
        recorded_at=grant["outcome_recorded_at"],
    ).to_body()
    return sign_evidence_event(
        event_id=outcome_event_id(grant["id"]),
        event_type=EvidenceEventType.OUTCOME,
        body=body,
        key=key,
        recorded_at=grant["outcome_recorded_at"],
        parent=parent,
    )


def build_evidence_chain(
    decision_record: Any,
    *,
    key: EvidenceSigningKey,
    grant: Any | None = None,
) -> AuthorityEvidenceChain:
    """The whole chain for one decision, as far as its history has gone.

    The decision is always present. Consumption and outcome exist only
    when a grant does — a BLOCK never produced one — and only when the
    grant's own columns say those things actually happened.
    """
    decision = build_decision_evidence(decision_record, key=key)
    if grant is None:
        return AuthorityEvidenceChain(decision)

    consumption = build_consumption_evidence(grant, key=key, parent=decision)
    outcome = (
        build_outcome_evidence(grant, key=key, parent=consumption)
        if consumption is not None
        else None
    )
    # Refuse to SIGN a false history, rather than leaving it to the verifier
    # to catch. A signature is an assertion; producing one over events that
    # do not belong together asserts something untrue, even if a checker
    # would later notice. The verifier repeats these checks independently,
    # because a third party cannot take this builder's word for it.
    mismatches = evidence_chain_continuity_failures(
        decision=decision, consumption=consumption, outcome=outcome
    )
    if mismatches:
        raise EvidenceError(
            "refusing to sign an evidence chain whose events describe "
            "different histories: " + "; ".join(mismatches)
        )
    return AuthorityEvidenceChain(decision, consumption, outcome)


def _decision_body(decision_record: Any) -> dict[str, Any]:
    """The stored canonical decision body, however the driver returned it."""
    raw = decision_record["decision_body"]
    if isinstance(raw, str):
        return json.loads(raw)
    return dict(raw)


def _instant_or_none(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


#: Every field the signed decision body commits to. Checked before signing
#: so a truncated or tombstoned row is refused loudly rather than producing
#: an event that verifies but says less than the original did.
_REQUIRED_BODY_FIELDS: frozenset[str] = frozenset(
    {
        "audit_id",
        "agent_id",
        "organisation_id",
        "action_type",
        "domain",
        "decision",
        "execution_action_hash",
        "policy_snapshot_format",
        "policy_snapshot_digest",
        "consequence_class",
        "grant_id",
        "grant_expires_at",
        "authority_scope_digest",
        "executor_binding_digest",
        "reasons",
    }
)
