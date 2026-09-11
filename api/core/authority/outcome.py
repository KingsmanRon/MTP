"""References to what actually happened downstream.

Core issues authority; it does not perform acts and it does not know what
any executor's identifiers mean. An :class:`OutcomeReference` is
therefore an opaque handle plus a coarse status — enough to reconcile an
authorisation against a real-world effect, and no more.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from api.core.authority._validation import (
    require_identifier,
    require_optional_digest,
    require_optional_utc,
)
from api.core.authority.errors import CoreAuthorityError


class OutcomeStatus(StrEnum):
    """Coarse, domain-independent state of a downstream execution."""

    #: Handed to the executor; the effect is not yet known to have landed.
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    #: The executor could not be asked. Never read as "did not happen".
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class OutcomeReference:
    """An opaque handle on one downstream execution and its coarse state."""

    domain: str
    outcome_reference: str
    status: OutcomeStatus = OutcomeStatus.PENDING
    observed_at: datetime | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        require_identifier(self.domain, "domain", error=CoreAuthorityError)
        require_identifier(self.outcome_reference, "outcome_reference", error=CoreAuthorityError)
        if not isinstance(self.status, OutcomeStatus):
            raise CoreAuthorityError(
                f"status must be an OutcomeStatus, got {type(self.status).__name__}"
            )
        object.__setattr__(
            self,
            "observed_at",
            require_optional_utc(self.observed_at, "observed_at", error=CoreAuthorityError),
        )

    @property
    def is_settled(self) -> bool:
        """Whether the downstream effect is known one way or the other."""
        return self.status in (OutcomeStatus.SUCCEEDED, OutcomeStatus.FAILED)


@dataclass(frozen=True, slots=True)
class EvidenceLink:
    """A pointer to evidence about an outcome, held outside Core.

    ``digest`` pins the artefact's content when the producer can supply
    one, so an auditor can tell whether the evidence changed after it was
    linked. ``locator`` is an opaque address in whatever system holds it.
    """

    evidence_type: str
    locator: str
    digest: str | None = None
    recorded_at: datetime | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        require_identifier(self.evidence_type, "evidence_type", error=CoreAuthorityError)
        require_identifier(self.locator, "locator", error=CoreAuthorityError)
        require_optional_digest(self.digest, "digest", error=CoreAuthorityError)
        object.__setattr__(
            self,
            "recorded_at",
            require_optional_utc(self.recorded_at, "recorded_at", error=CoreAuthorityError),
        )
