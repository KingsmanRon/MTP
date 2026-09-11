"""Compatibility adapter: a ``/verify`` request becomes an ``ActionEnvelope``.

This is a translation layer and nothing else. It is not wired into the
deployed ``/verify`` route in this phase; no route, request shape or
response shape changes. It exists so the core authority boundary can be
driven from the same inputs the deployed path already authenticates, and
so the two hashes stay separate and correct.

Three properties matter.

**The signed hash is carried, never recomputed.** ``signed_action_hash``
is the existing client-signed ``action_hash`` exactly as ``/verify``
computed it. This adapter does not re-derive it, does not reinterpret it
and does not fold it into anything. It rides along on the envelope.

**The execution hash is new and separate.** It is derived from the
Phase-1 canonical representation under
``inntris-execution-action-v1``. The two hashes answer different
questions — "did this agent sign this request" versus "what act is this"
— and they are never interchanged.

**Identity comes from the server.** ``principal_id`` and
``organisation_id`` are read from the authenticated ``AgentRecord``, never
from the request payload. A payload field claiming an organisation is
data, not identity.

Target lifting
--------------
The legacy payload expresses its target in whichever field the calling
integration chose: ``recipient`` for a wallet transfer, ``resource`` plus
``resource_id`` for the generic runtime envelope, and so on. Phase 1
requires the target to be expressed exactly once, in
``ExecutableAction.target``, and rejects a payload that also carries a
target-designating key. So this adapter lifts the target out of the
payload and strips the keys it consumed.

A destination and a resource are different dimensions, and a real
payload legitimately carries both — a wallet transfer names the acting
account in ``resource_id`` and the recipient in ``recipient``. So the
destination becomes the target when one is present, the resource does
otherwise, and every reserved key that did not become the target is
preserved under ``legacy_target_references`` — nested, because Phase 1
reserves those names only at the top level. Lifting therefore never drops
a value out of the hash.

It fails closed rather than guessing:

* two *destinations* that disagree are rejected: a request that does not
  say where value goes cannot be authorised;
* a target type with no id is rejected, because a reference needs both
  halves and inventing an id would fabricate a target.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final

from api.core.authority.authority import DelegatedAuthorityClaim
from api.core.authority.decision import (
    ConsequenceClass,
    Decision,
    DecisionReason,
    PolicyDecision,
)
from api.core.authority.envelope import ActionEnvelope, ExecutableAction, ResourceReference
from api.domains.payment.policy import PAYMENT_ACTION_TYPES, PAYMENT_DOMAIN
from api.models import ActionVerdict
from api.policy_contracts import PolicyResult, PolicyViolation

#: Domain label for anything without a domain module of its own yet. Other
#: domains get their own labels when their modules land; inventing names for
#: modules that do not exist would be inventing policy that does not exist.
GENERAL_DOMAIN: Final[str] = "general"

#: Legacy payload keys naming WHERE value goes. These are the security-critical
#: dimension: two of them disagreeing means the request does not say where the
#: act lands, and that fails closed.
DESTINATION_KEYS: Final[tuple[str, ...]] = (
    "recipient",
    "recipient_id",
    "destination",
    "destination_id",
    "payee",
    "payee_id",
    "counterparty",
    "counterparty_id",
    "target",
    "target_id",
)

#: Legacy payload keys naming WHAT is acted on. A resource is not a
#: destination — a wallet payload legitimately carries both, naming the
#: acting account and the recipient — so these never conflict with the keys
#: above. They become the target only when no destination is named.
RESOURCE_ID_KEYS: Final[tuple[str, ...]] = ("resource_id",)

#: Legacy payload keys naming the resource's type.
RESOURCE_TYPE_KEYS: Final[tuple[str, ...]] = ("resource", "resource_type", "target_type")

#: Where reserved keys that did not become the target are preserved. Nesting
#: them keeps their values inside the execution action hash — Phase 1 reserves
#: these names only at the payload's top level — so lifting a target never
#: silently drops a field the act depended on.
LEGACY_REFERENCES_KEY: Final[str] = "legacy_target_references"

#: Fallback target type per action type, used when a destination is the target
#: and the payload names no type for it. ``chain`` wins over these.
DEFAULT_TARGET_TYPES: Final[dict[str, str]] = {
    "financial_transaction": "account",
    "wallet_transaction": "wallet",
    "wallet_signature": "wallet",
}

_FALLBACK_TARGET_TYPE: Final[str] = "resource"


class EnvelopeAdapterError(ValueError):
    """The request cannot be represented as a canonical executable action."""


class AmbiguousTargetError(EnvelopeAdapterError):
    """The payload names its target more than one way, and they disagree."""


def domain_for_action_type(action_type: str) -> str:
    """The domain label an action type belongs to."""
    return PAYMENT_DOMAIN if action_type in PAYMENT_ACTION_TYPES else GENERAL_DOMAIN


def _coerce_timestamp(value: datetime | str | None) -> datetime | None:
    """Parse a wire timestamp, tolerating naive values as UTC.

    The legacy timestamp check treats a naive datetime as UTC, and this
    adapter must be able to represent every request that path accepts.
    Phase 1 rejects naive datetimes on its own types, so the tolerance is
    applied here, once, where the wire format is known.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EnvelopeAdapterError(f"timestamp {value!r} is not ISO-8601") from exc
    else:
        raise EnvelopeAdapterError(
            f"timestamp must be a datetime or ISO-8601 string, got {type(value).__name__}"
        )
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _read_reserved(payload: dict[str, Any], keys: tuple[str, ...]) -> dict[str, str]:
    found: dict[str, str] = {}
    for key in keys:
        if key not in payload:
            continue
        value = payload[key]
        if not isinstance(value, str) or not value.strip():
            raise EnvelopeAdapterError(
                f"payload.{key} takes part in naming the action's target and must "
                "be a non-empty string"
            )
        found[key] = value
    return found


def lift_target(
    payload: Mapping[str, Any],
    action_type: str,
) -> tuple[dict[str, Any], ResourceReference | None]:
    """Split a legacy payload into (payload without target keys, target).

    Returns the payload unchanged and ``None`` when it names no target.

    A destination, when present, is the target: that is where the executor
    sends value. Otherwise the resource is. Every reserved key that did not
    become the target is preserved under
    :data:`LEGACY_REFERENCES_KEY` so its value still reaches the hash.
    """
    remaining = dict(payload)

    destinations = _read_reserved(remaining, DESTINATION_KEYS)
    resource_ids = _read_reserved(remaining, RESOURCE_ID_KEYS)
    resource_types = _read_reserved(remaining, RESOURCE_TYPE_KEYS)

    consumed = {**destinations, **resource_ids, **resource_types}
    if not consumed:
        return remaining, None

    if len({*destinations.values()}) > 1:
        pairs = ", ".join(f"{key}={value!r}" for key, value in sorted(destinations.items()))
        raise AmbiguousTargetError(
            f"the payload names more than one destination ({pairs}); a request that "
            "does not say where value goes cannot be authorised"
        )
    if len({*resource_ids.values()}) > 1:  # pragma: no cover - single key today
        raise AmbiguousTargetError("the payload names more than one resource id")

    if destinations:
        resource_id = next(iter(destinations.values()))
        chain = remaining.get("chain")
        if action_type in DEFAULT_TARGET_TYPES and isinstance(chain, str) and chain.strip():
            resource_type = chain
        else:
            resource_type = DEFAULT_TARGET_TYPES.get(action_type, _FALLBACK_TARGET_TYPE)
        leftover = {**resource_ids, **resource_types}
    elif resource_ids:
        resource_id = next(iter(resource_ids.values()))
        if len({*resource_types.values()}) > 1:
            pairs = ", ".join(f"{key}={value!r}" for key, value in sorted(resource_types.items()))
            raise AmbiguousTargetError(
                f"the payload names more than one resource type ({pairs}); an action "
                "expresses its target exactly once"
            )
        resource_type = (
            next(iter(resource_types.values()))
            if resource_types
            else DEFAULT_TARGET_TYPES.get(action_type, _FALLBACK_TARGET_TYPE)
        )
        leftover = {}
    else:
        raise EnvelopeAdapterError(
            f"payload names a target type ({', '.join(sorted(resource_types))}) with "
            "no target id; a reference needs both halves and one cannot be invented"
        )

    for key in consumed:
        remaining.pop(key, None)
    if leftover:
        if LEGACY_REFERENCES_KEY in remaining:
            raise EnvelopeAdapterError(
                f"payload.{LEGACY_REFERENCES_KEY} is reserved for lifted target "
                "references and must not be sent by the caller"
            )
        remaining[LEGACY_REFERENCES_KEY] = dict(sorted(leftover.items()))

    return remaining, ResourceReference(resource_type=resource_type, resource_id=resource_id)


def build_action_envelope(
    *,
    agent: Any,
    action_type: str,
    payload: Mapping[str, Any],
    signed_action_hash: str | None = None,
    nonce: str | None = None,
    timestamp: datetime | str | None = None,
    delegated_authority_reference: DelegatedAuthorityClaim | None = None,
    consequence_class: ConsequenceClass | None = None,
) -> ActionEnvelope:
    """Build the canonical envelope for an already-authenticated request.

    ``agent`` is the trusted server-side record. Identity is taken from it
    and from nowhere else.
    """
    if agent is None:
        raise EnvelopeAdapterError(
            "an authenticated agent record is required; identity is never read "
            "from the request payload"
        )

    stripped_payload, target = lift_target(payload, action_type)

    action = ExecutableAction(
        principal_id=str(agent.id),
        organisation_id=str(agent.org_id),
        domain=domain_for_action_type(action_type),
        action_type=action_type,
        payload=stripped_payload,
        target=target,
    )
    return ActionEnvelope(
        action=action,
        signed_action_hash=signed_action_hash,
        delegated_authority_reference=delegated_authority_reference,
        consequence_class=consequence_class,
        occurred_at=_coerce_timestamp(timestamp),
        nonce=nonce,
    )


def _violation_for(reason: DecisionReason) -> PolicyViolation | None:
    """The legacy violation code for a reason, when one exists.

    Authority-lifecycle reasons have no legacy code and deliberately get
    none: the ``/verify`` wire vocabulary is not extended by this phase.
    They surface in the human-readable reason string instead.
    """
    try:
        return PolicyViolation(reason.value)
    except ValueError:
        return None


def decision_to_policy_result(
    decision: PolicyDecision,
    *,
    limits_remaining: dict[str, Any] | None = None,
) -> PolicyResult:
    """Map a core decision back onto the deployed ``/verify`` result shape.

    ``REQUIRE_APPROVAL`` maps to ``BLOCKED``. There is no approval verdict
    on the wire, and the core contract is explicit that a
    ``REQUIRE_APPROVAL`` decision yields no executable authority — so
    reporting anything other than "not approved" would be false.
    """
    if decision.decision is Decision.ALLOW:
        return PolicyResult(
            allowed=True,
            verdict=ActionVerdict.APPROVED,
            limits_remaining=limits_remaining,
        )

    first_reason = decision.reasons[0] if decision.reasons else DecisionReason.ACTION_BLOCKED
    if decision.decision is Decision.REQUIRE_APPROVAL:
        first_reason = DecisionReason.APPROVAL_REQUIRED

    return PolicyResult(
        allowed=False,
        verdict=ActionVerdict.BLOCKED,
        violation=_violation_for(first_reason),
        reason=first_reason.value,
        limits_remaining=limits_remaining,
    )
