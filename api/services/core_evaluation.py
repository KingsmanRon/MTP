"""The one Core organisation-policy evaluation, shared by both surfaces.

Why this exists
---------------
``PaymentDomainPolicy`` is a *domain* policy. It knows about money,
wallet allowlists and delegated scope. It does not know about agent
status, allowed and blocked actions, action-type registration, policy
binding, trust thresholds, timestamp skew or rate limits — all of which
``/verify`` has always enforced through ``PolicyEngine``.

A new endpoint that called only the domain policy would therefore be a
*lower-security path to the same act*. That is the failure this module
prevents: both surfaces run the same ``PolicyEngine.evaluate`` first, and
the domain policy runs after it, never instead of it.

The pipeline
------------
::

    HTTP / auth / signature / replay preconditions   (route level)
        -> trusted internal request context           (route level)
        -> shared Core policy evaluation              (HERE)
        -> domain policy                              (payment domain)
        -> delegated-authority intersection           (payment domain)
        -> ALLOW / BLOCK

HTTP-specific security — Ed25519 request verification, nonce replay,
abuse and concurrency limits, sandbox rules — stays at the route level
where the request actually is. It is not smuggled into a policy object
that has no request to inspect.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from api.core.authority.decision import DecisionReason
from api.models import AgentRecord, RegisteredPolicy
from api.policy import PolicyEngine, PolicyResult


@dataclass(frozen=True, slots=True)
class CorePolicyInputs:
    """Everything the Core evaluation needs, all from trusted state."""

    agent: AgentRecord
    action_type: str
    payload: dict[str, Any]
    timestamp: datetime
    daily_spend: Decimal = Decimal("0")
    minute_request_count: int = 0
    registered_policy: RegisteredPolicy | None = None
    client_policy_hash: str | None = None


def evaluate_core_policy(inputs: CorePolicyInputs) -> PolicyResult:
    """Run the complete Core organisation policy.

    This is a thin, deliberate wrapper: the rules themselves stay in
    ``PolicyEngine`` and are not reimplemented here. Both surfaces call
    this, so there is exactly one place where "what does the organisation
    permit" is answered, and adding a rule to the engine adds it to both
    surfaces at once.
    """
    engine = PolicyEngine(
        daily_spend=inputs.daily_spend,
        minute_request_count=inputs.minute_request_count,
    )
    return engine.evaluate(
        agent=inputs.agent,
        action_type=inputs.action_type,
        payload=inputs.payload,
        timestamp=inputs.timestamp,
        registered_policy=inputs.registered_policy,
        client_policy_hash=inputs.client_policy_hash,
    )


def core_violation_to_reason(result: PolicyResult) -> DecisionReason | None:
    """Map a Core violation onto the typed decision vocabulary.

    The codes are identical strings by construction (Phase 2 pinned that),
    so this is a lookup, not a translation. ``None`` means the result was
    an allow.
    """
    if result.allowed or result.violation is None:
        return None
    return DecisionReason(result.violation.value)


def now_utc() -> datetime:
    return datetime.now(UTC)
