"""Bounded execution authority.

A grant is the answer to "may this exact act be performed, now, by this
executor". It is not a receipt and it is not a policy decision: it is the
bounded, single-use authority that a decision produced.

State model (v0.5)
------------------
::

    ACTIVE ──► CONSUMED     the authority was spent on an execution attempt
      │
      ├─────► REVOKED       withdrawn before it was spent
      │
      └─────► EXPIRED       the validity window closed unspent

``CONSUMED``, ``REVOKED`` and ``EXPIRED`` are terminal **for new
execution**. Nothing transitions out of them.

``EXPIRED`` is time-derived: a stored row may still read ``ACTIVE`` after
its window closes, so every reader must ask
:meth:`ExecutionAuthorityGrant.effective_status` with the current time
rather than trusting the persisted value. A sweeper that materialises
``EXPIRED`` is an optimisation, never the source of truth.

Recovery is not authorisation
-----------------------------
A lookup by the same ``execution_ref`` against an already-committed
``CONSUMED`` result may return that original result even after the grant
or its token has expired. That path exists so a caller that lost the
response can recover it. It returns evidence of an execution that was
already authorised; it **MUST NOT** authorise another one. See
:mod:`api.core.authority.lifecycle`.

Single use
----------
v0.5 defines exactly one consumption per grant. ``single_use`` is
therefore fixed at ``True`` and there is no ``max_consumptions``: a
counter would invite a policy that quietly permits several executions
from one decision.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final

from api.core.authority._validation import (
    require_digest,
    require_identifier,
    require_optional_digest,
    require_optional_identifier,
    require_utc,
)
from api.core.authority.authority import DelegatedAuthorityReference
from api.core.authority.decision import ConsequenceClass, DecisionReason, PolicySnapshot
from api.core.authority.errors import InvalidGrantError


class GrantStatus(StrEnum):
    """Lifecycle state of one execution-authority grant."""

    ACTIVE = "active"
    CONSUMED = "consumed"
    REVOKED = "revoked"
    EXPIRED = "expired"


#: States from which no new execution may be authorised.
TERMINAL_GRANT_STATUSES: Final[frozenset[GrantStatus]] = frozenset(
    {GrantStatus.CONSUMED, GrantStatus.REVOKED, GrantStatus.EXPIRED}
)

#: The complete transition table. Everything absent from it is forbidden.
ALLOWED_GRANT_TRANSITIONS: Final[dict[GrantStatus, frozenset[GrantStatus]]] = {
    GrantStatus.ACTIVE: frozenset(
        {GrantStatus.CONSUMED, GrantStatus.REVOKED, GrantStatus.EXPIRED}
    ),
    GrantStatus.CONSUMED: frozenset(),
    GrantStatus.REVOKED: frozenset(),
    GrantStatus.EXPIRED: frozenset(),
}


def is_allowed_transition(current: GrantStatus, target: GrantStatus) -> bool:
    """Whether ``current -> target`` is a defined transition."""
    return target in ALLOWED_GRANT_TRANSITIONS[current]


#: Deterministic precedence for rejecting a consumption attempt, most
#: specific first. Phase 3 evaluates candidate rejections in this order and
#: reports the first match, so the same broken attempt always produces the
#: same typed outcome regardless of check ordering in the implementation.
#:
#: Identity and integrity come before lifecycle: an attempt that does not
#: match the grant is reported as a mismatch, not as "expired", because the
#: caller's problem is that they are holding the wrong authority. Within
#: lifecycle, an explicit withdrawal outranks a passive timeout, which
#: outranks "you already spent this".
#:
#: Recovery is evaluated *before* any of these — a committed consumption
#: with a matching ``execution_ref`` returns the original result rather
#: than a rejection, which is what lets an expired grant still answer a
#: retry.
CONSUMPTION_REJECTION_PRECEDENCE: Final[tuple[DecisionReason, ...]] = (
    DecisionReason.GRANT_NOT_FOUND,
    DecisionReason.GRANT_MALFORMED,
    DecisionReason.GRANT_ACTION_MISMATCH,
    DecisionReason.GRANT_EXECUTOR_MISMATCH,
    DecisionReason.EXECUTION_REF_CONFLICT,
    DecisionReason.GRANT_REVOKED,
    DecisionReason.GRANT_EXPIRED,
    DecisionReason.GRANT_ALREADY_CONSUMED,
)


def first_rejection(candidates: Iterable[DecisionReason]) -> DecisionReason | None:
    """The highest-precedence rejection among ``candidates``, or ``None``.

    ``candidates`` is any iterable of :class:`DecisionReason`. A reason
    outside :data:`CONSUMPTION_REJECTION_PRECEDENCE` is rejected rather
    than silently ordered last, so a new failure mode cannot be added
    without deciding where it ranks.
    """
    if isinstance(candidates, (str, bytes)):
        raise InvalidGrantError("candidates must be an iterable of DecisionReason")
    seen = set()
    for candidate in candidates:
        if candidate not in CONSUMPTION_REJECTION_PRECEDENCE:
            raise InvalidGrantError(
                f"{candidate!r} has no defined consumption-rejection precedence"
            )
        seen.add(candidate)
    for reason in CONSUMPTION_REJECTION_PRECEDENCE:
        if reason in seen:
            return reason
    return None


@dataclass(frozen=True, slots=True)
class ExecutorBinding:
    """Which executor this authority was issued to.

    ``binding_digest`` is the binding: an opaque internal digest that a
    later phase compares against *authenticated* executor context.

    ``executor_reference`` is a label for humans reading an audit trail.
    It is not proof of anything. A caller that presents a matching
    ``executor_reference`` has demonstrated only that it can read a
    string. Never gate execution on it.
    """

    binding_digest: str
    executor_reference: str | None = None

    def __post_init__(self) -> None:
        require_digest(self.binding_digest, "binding_digest", error=InvalidGrantError)
        require_optional_identifier(
            self.executor_reference, "executor_reference", error=InvalidGrantError
        )

    def matches(self, presented_binding_digest: str) -> bool:
        """Whether an authenticated executor's binding digest matches this one."""
        require_digest(
            presented_binding_digest, "presented_binding_digest", error=InvalidGrantError
        )
        return presented_binding_digest == self.binding_digest


@dataclass(frozen=True, slots=True)
class ExecutionAuthorityGrant:
    """Bounded authority to perform one specific act, once.

    The grant records the policy snapshot it was issued under. That
    snapshot is evidence, not a standing permission: consumption remains
    subject to the policy, principal, delegation and executor validity
    current at the moment of consumption.
    """

    grant_id: str
    execution_action_hash: str
    policy_snapshot: PolicySnapshot
    executor_binding: ExecutorBinding
    issued_at: datetime
    expires_at: datetime
    signed_action_hash: str | None = None
    authority_reference: DelegatedAuthorityReference | None = None
    consequence_class: ConsequenceClass | None = None
    single_use: bool = True
    status: GrantStatus = GrantStatus.ACTIVE

    def __post_init__(self) -> None:
        require_identifier(self.grant_id, "grant_id", error=InvalidGrantError)
        require_digest(
            self.execution_action_hash, "execution_action_hash", error=InvalidGrantError
        )
        require_optional_digest(
            self.signed_action_hash, "signed_action_hash", error=InvalidGrantError
        )
        if not isinstance(self.policy_snapshot, PolicySnapshot):
            raise InvalidGrantError(
                "policy_snapshot must be a PolicySnapshot, got "
                f"{type(self.policy_snapshot).__name__}"
            )
        if not isinstance(self.executor_binding, ExecutorBinding):
            raise InvalidGrantError(
                "executor_binding must be an ExecutorBinding, got "
                f"{type(self.executor_binding).__name__}"
            )
        if self.authority_reference is not None and not isinstance(
            self.authority_reference, DelegatedAuthorityReference
        ):
            raise InvalidGrantError(
                "authority_reference must be a DelegatedAuthorityReference or None, "
                f"got {type(self.authority_reference).__name__}"
            )
        if self.consequence_class is not None and not isinstance(
            self.consequence_class, ConsequenceClass
        ):
            raise InvalidGrantError(
                "consequence_class must be a ConsequenceClass or None, got "
                f"{type(self.consequence_class).__name__}"
            )
        if not isinstance(self.status, GrantStatus):
            raise InvalidGrantError(
                f"status must be a GrantStatus, got {type(self.status).__name__}"
            )
        if self.single_use is not True:
            raise InvalidGrantError(
                "v0.5 execution authority is single-use; multi-use grants are not "
                "defined and there is deliberately no max_consumptions"
            )
        object.__setattr__(
            self, "issued_at", require_utc(self.issued_at, "issued_at", error=InvalidGrantError)
        )
        object.__setattr__(
            self,
            "expires_at",
            require_utc(self.expires_at, "expires_at", error=InvalidGrantError),
        )
        if self.expires_at <= self.issued_at:
            raise InvalidGrantError("expires_at must be strictly after issued_at")

    @property
    def policy_hash(self) -> str:
        """The policy digest the issuing decision was evaluated against."""
        return self.policy_snapshot.policy_hash

    def is_expired_at(self, at: datetime) -> bool:
        """Whether the validity window has closed at ``at`` (inclusive of the edge)."""
        return require_utc(at, "at", error=InvalidGrantError) >= self.expires_at

    def effective_status(self, at: datetime) -> GrantStatus:
        """The status a reader must act on at time ``at``.

        A persisted ``ACTIVE`` row whose window has closed is ``EXPIRED``.
        Terminal states are returned unchanged — expiry never overwrites
        the record of a consumption or a revocation.
        """
        if self.status is GrantStatus.ACTIVE and self.is_expired_at(at):
            return GrantStatus.EXPIRED
        return self.status

    def authorises_new_execution_at(self, at: datetime) -> bool:
        """Whether a *new* execution may be authorised from this grant at ``at``.

        Never true for a terminal state. Recovering an already-committed
        result by ``execution_ref`` is a separate path and does not go
        through here.
        """
        return self.effective_status(at) is GrantStatus.ACTIVE
