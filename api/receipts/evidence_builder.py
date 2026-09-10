"""Deriving the v3 evidence chain from the durable authority lifecycle.

Stability without a new table
-----------------------------
Evidence must not be a fresh random object on every read: two reads of
one event have to return the *same* signed bytes, or the signature is
worthless as a reference.

That does not require storing the signed material, because every input is
already durable and the signature is deterministic:

* ``event_id`` is derived from durable identifiers, not generated;
* ``recorded_at`` is a durable column (``issued_at``, ``consumed_at``,
  ``outcome_recorded_at``) — never "now";
* the body is built only from columns the Phase-3 trigger makes immutable
  or write-once;
* Ed25519 is deterministic (RFC 8032): the same key over the same message
  always yields the same signature.

So the same lifecycle row always produces byte-identical evidence, and
nothing here widens the Phase-3 migration.

**What this depends on, stated plainly:** stability holds for as long as
the signing key is stable. A key rotation produces different signatures
for the same history, which is why publication and rotation are a
deliberate Phase 7A release action with its own key registry.

The decision event is built only from issuance-time columns. Consumption
and outcome events are separate, later links, so a decision receipt is
never rewritten when they appear.
"""

from __future__ import annotations

from typing import Any

from api.receipts.v3 import (
    AuthorityEvidenceChain,
    ConsumptionEvidenceV3,
    DecisionEvidenceV3,
    EvidenceEventType,
    EvidenceSigningKey,
    OutcomeEvidenceV3,
    SignedEvidenceEvent,
    sign_evidence_event,
)


def decision_event_id(grant_id: Any) -> str:
    """Derived, not generated, so it is the same on every read."""
    return f"decision:{grant_id}"


def consumption_event_id(consumption_audit_id: Any) -> str:
    return f"consumption:{consumption_audit_id}"


def outcome_event_id(grant_id: Any) -> str:
    return f"outcome:{grant_id}"


def build_decision_evidence(
    grant: Any,
    *,
    key: EvidenceSigningKey,
    audit_id: Any | None = None,
    legacy_policy_hash: str | None = None,
    authority_issuer: str | None = None,
    authority_reference_id: str | None = None,
    decision: str = "allow",
    reasons: tuple[str, ...] = (),
) -> SignedEvidenceEvent:
    """Evidence that this act was decided, under this policy and authority.

    ``signed_action_hash`` is copied from the grant, where it is only ever
    populated by a path that actually verified the agent's Ed25519
    signature. The service-authenticated surface stores ``NULL`` there, so
    evidence from that surface cannot claim an agent-signed hash.
    """
    body = DecisionEvidenceV3(
        audit_id=str(audit_id or grant["id"]),
        agent_id=str(grant["agent_id"]),
        organisation_id=str(grant["org_id"]),
        action_type=grant["action_type"],
        domain=grant["domain"],
        decision=decision,
        execution_action_hash=grant["execution_action_hash"],
        policy_snapshot_format=grant["policy_snapshot_format"],
        policy_snapshot_digest=grant["policy_hash"],
        signed_action_hash=grant["signed_action_hash"],
        legacy_policy_hash=legacy_policy_hash,
        consequence_class=grant["consequence_class"],
        grant_id=str(grant["id"]),
        grant_expires_at=grant["expires_at"],
        authority_issuer=authority_issuer,
        authority_reference_id=authority_reference_id,
        authority_artefact_digest=grant["authority_scope_digest"],
        executor_binding_digest=grant["executor_binding_digest"],
        reasons=reasons,
    ).to_body()
    return sign_evidence_event(
        event_id=decision_event_id(grant["id"]),
        event_type=EvidenceEventType.DECISION,
        body=body,
        key=key,
        # Durable issuance time, never "now".
        recorded_at=grant["issued_at"],
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
    grant: Any,
    *,
    key: EvidenceSigningKey,
    audit_id: Any | None = None,
    legacy_policy_hash: str | None = None,
    authority_issuer: str | None = None,
    authority_reference_id: str | None = None,
) -> AuthorityEvidenceChain:
    """The whole chain for one grant, as far as its lifecycle has gone."""
    decision = build_decision_evidence(
        grant,
        key=key,
        audit_id=audit_id,
        legacy_policy_hash=legacy_policy_hash,
        authority_issuer=authority_issuer,
        authority_reference_id=authority_reference_id,
    )
    consumption = build_consumption_evidence(grant, key=key, parent=decision)
    outcome = (
        build_outcome_evidence(grant, key=key, parent=consumption)
        if consumption is not None
        else None
    )
    return AuthorityEvidenceChain(decision, consumption, outcome)
