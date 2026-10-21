"""Reserving and consuming execution authority.

Consumption is the moment authority becomes an act. Two properties have
to hold at once and they pull in opposite directions:

* a grant authorises **one** execution, and
* a caller whose response was lost must be able to find out what
  happened without risking a second execution.

``execution_ref`` is what reconciles them. It is a stable reference the
caller generates *before* its first attempt and reuses on every retry, so
the server can tell "the same attempt again" apart from "a second
attempt". This mirrors the existing ``/verify-token`` contract in
``docs/EXECUTION_BINDING.md``, where a retry with the same reference
returns the original consumption receipt and a different reference is
refused.

Recovery is not authorisation
-----------------------------
When a consumption has already been committed, a lookup with the *same*
``execution_ref`` may return that original result — including after the
grant or its token has expired, because the authority was already spent
while it was valid and the caller is only recovering the record of it.
That path yields :attr:`ConsumptionOutcome.RECOVERED`. It must never
issue new authority, never re-enter the executor, and never move a grant
out of a terminal state.

A caller that omits ``execution_ref`` gets strict single-use semantics
and cannot recover a lost response. That is a deliberate carry-over of
the existing behaviour, not an oversight.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from api.core.authority._validation import (
    require_identifier,
    require_optional_identifier,
    require_utc,
)
from api.core.authority.decision import DecisionReason
from api.core.authority.errors import CoreAuthorityError
from api.core.authority.grant import ExecutorBinding
from api.core.authority.outcome import OutcomeReference


class ReservationStatus(StrEnum):
    """State of an intent to consume a grant."""

    #: Held; the executor has not reported back yet.
    HELD = "held"
    #: Turned into a committed consumption.
    COMMITTED = "committed"
    #: Released without consuming, e.g. the executor refused to start.
    RELEASED = "released"
    #: The hold aged out before it was committed or released.
    LAPSED = "lapsed"


class ConsumptionOutcome(StrEnum):
    """What a consumption attempt actually did."""

    #: The grant was spent on this attempt. Happens at most once per grant.
    AUTHORISED = "authorised"
    #: A prior committed consumption with the same execution_ref was
    #: returned. Authorises nothing.
    RECOVERED = "recovered"
    #: Refused. ``rejection_reason`` carries the typed reason.
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class AuthorityReservation:
    """A short-lived hold taken on a grant before the executor is called.

    The hold is what a race-safe implementation contends on: Phase 3/4
    defines how it is persisted and made atomic. Phase 1 only fixes its
    shape and the fact that it is bound to one ``execution_ref`` and one
    executor.
    """

    reservation_id: str
    grant_id: str
    executor_binding: ExecutorBinding
    reserved_at: datetime
    expires_at: datetime
    execution_ref: str | None = None
    status: ReservationStatus = ReservationStatus.HELD

    def __post_init__(self) -> None:
        require_identifier(self.reservation_id, "reservation_id", error=CoreAuthorityError)
        require_identifier(self.grant_id, "grant_id", error=CoreAuthorityError)
        if not isinstance(self.executor_binding, ExecutorBinding):
            raise CoreAuthorityError(
                "executor_binding must be an ExecutorBinding, got "
                f"{type(self.executor_binding).__name__}"
            )
        require_optional_identifier(
            self.execution_ref, "execution_ref", error=CoreAuthorityError
        )
        if not isinstance(self.status, ReservationStatus):
            raise CoreAuthorityError(
                f"status must be a ReservationStatus, got {type(self.status).__name__}"
            )
        object.__setattr__(
            self,
            "reserved_at",
            require_utc(self.reserved_at, "reserved_at", error=CoreAuthorityError),
        )
        object.__setattr__(
            self,
            "expires_at",
            require_utc(self.expires_at, "expires_at", error=CoreAuthorityError),
        )
        if self.expires_at <= self.reserved_at:
            raise CoreAuthorityError("expires_at must be strictly after reserved_at")

    @property
    def is_recoverable(self) -> bool:
        """Whether a lost response could be recovered by retrying this attempt.

        False without an ``execution_ref``: strict single-use, no retry.
        """
        return self.execution_ref is not None


@dataclass(frozen=True, slots=True)
class AuthorityConsumption:
    """The committed record that a grant was spent on one execution attempt.

    ``AUTHORISED`` and ``RECOVERED`` differ in exactly one way that
    matters: only the first one ever spent authority. A ``RECOVERED``
    record describes the same underlying execution as the ``AUTHORISED``
    one it echoes.
    """

    consumption_id: str
    grant_id: str
    outcome: ConsumptionOutcome
    consumed_at: datetime
    execution_ref: str | None = None
    reservation_id: str | None = None
    outcome_reference: OutcomeReference | None = None
    rejection_reason: DecisionReason | None = None

    def __post_init__(self) -> None:
        require_identifier(self.consumption_id, "consumption_id", error=CoreAuthorityError)
        require_identifier(self.grant_id, "grant_id", error=CoreAuthorityError)
        require_optional_identifier(
            self.execution_ref, "execution_ref", error=CoreAuthorityError
        )
        require_optional_identifier(
            self.reservation_id, "reservation_id", error=CoreAuthorityError
        )
        if not isinstance(self.outcome, ConsumptionOutcome):
            raise CoreAuthorityError(
                f"outcome must be a ConsumptionOutcome, got {type(self.outcome).__name__}"
            )
        object.__setattr__(
            self,
            "consumed_at",
            require_utc(self.consumed_at, "consumed_at", error=CoreAuthorityError),
        )
        if self.outcome_reference is not None and not isinstance(
            self.outcome_reference, OutcomeReference
        ):
            raise CoreAuthorityError(
                "outcome_reference must be an OutcomeReference or None, got "
                f"{type(self.outcome_reference).__name__}"
            )
        if self.outcome is ConsumptionOutcome.REJECTED:
            if self.rejection_reason is None:
                raise CoreAuthorityError(
                    "a REJECTED consumption must carry a rejection_reason"
                )
        elif self.rejection_reason is not None:
            raise CoreAuthorityError(
                "a rejection_reason is only meaningful on a REJECTED consumption"
            )
        if self.rejection_reason is not None and not isinstance(
            self.rejection_reason, DecisionReason
        ):
            raise CoreAuthorityError(
                "rejection_reason must be a DecisionReason, got "
                f"{type(self.rejection_reason).__name__}"
            )
        if self.outcome is ConsumptionOutcome.RECOVERED and self.execution_ref is None:
            raise CoreAuthorityError(
                "a RECOVERED consumption is only reachable through a matching "
                "execution_ref; without one there is strict single-use and "
                "nothing to recover"
            )

    @property
    def spent_authority(self) -> bool:
        """Whether *this* record is the one that consumed the grant.

        ``RECOVERED`` echoes an earlier authorisation and spends nothing,
        so it must never be counted as a second consumption.
        """
        return self.outcome is ConsumptionOutcome.AUTHORISED
