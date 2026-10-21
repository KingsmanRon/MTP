"""Delegated-authority evidence, as Core is allowed to see it.

Two very different objects live here and the difference is the whole
point of the module.

:class:`DelegatedAuthorityClaim` is what a caller asserts. It is
untrusted: an issuer name and an external reference id, nothing more. It
can be built by anyone, out of request data, and it proves nothing.

:class:`DelegatedAuthorityReference`, :class:`ResolvedAuthority`,
:class:`ExecutionContext` and :class:`AuthorityRequirement` are what a
*trusted server-side provider* produces. They carry verification status,
delegate binding, organisation identity and scope — exactly the things a
client must never be able to assert about itself. They therefore require
a :class:`TrustedAuthorityConstruction` capability that cannot be
produced from request data: no deserializer, no ``**request_body``, and
no JSON document can conjure one, so there is no shape in which a normal
client self-asserts ``verification_status=verified``.

Scope is authority data, not a decision
---------------------------------------
:attr:`ResolvedAuthority.scope` is an opaque mapping handed over by the
provider for a domain policy to interpret. Core never reads a key out of
it. Core does not know what any external issuer calls its fields, and
adding such knowledge here would be the exact coupling this boundary
exists to prevent.

Failure is data, not an exception
---------------------------------
An artefact that does not verify produces a ``ResolvedAuthority`` whose
status is not ``VERIFIED`` and whose :attr:`ResolvedAuthority.issues`
carry typed codes. It does not raise. A provider that raises on routine
denial turns an expected ``BLOCK`` into a 500.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import InitVar, dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final, final

from api.core.authority._validation import (
    require_digest,
    require_identifier,
    require_optional_identifier,
    require_optional_utc,
)
from api.core.authority.errors import InvalidAuthorityConstructionError

_TRUSTED_CONSTRUCTION_SENTINEL: Final = object()


@final
class TrustedAuthorityConstruction:
    """Capability proving the caller is trusted server-side authority code.

    It has no fields, no serialised form and a constructor that refuses
    anything but a module-private sentinel. That is what makes it
    unforgeable *from data*: a request body is parsed values, and no
    parsed value is this object.
    """

    __slots__ = ()

    def __init__(self, sentinel: object = None) -> None:
        if sentinel is not _TRUSTED_CONSTRUCTION_SENTINEL:
            raise InvalidAuthorityConstructionError(
                "TrustedAuthorityConstruction cannot be constructed directly; "
                "trusted AuthorityProvider / ContextProvider implementations "
                "obtain it from trusted_authority_construction()"
            )


def trusted_authority_construction() -> TrustedAuthorityConstruction:
    """Mint the trusted-construction capability.

    Only trusted server-side ``AuthorityProvider``,
    ``ContextProvider`` and ``AuthorityRequirementResolver``
    implementations may call this. It must never be reachable from a
    request-handling path that has not already established the
    organisation and principal it is speaking for.
    """
    return TrustedAuthorityConstruction(_TRUSTED_CONSTRUCTION_SENTINEL)


def _require_trusted(construction: object, what: str) -> None:
    if not isinstance(construction, TrustedAuthorityConstruction):
        raise InvalidAuthorityConstructionError(
            f"{what} is a trusted provider output and requires a "
            "TrustedAuthorityConstruction capability; it cannot be built from "
            "caller-supplied data"
        )


class VerificationStatus(StrEnum):
    """Whether the external authority artefact was actually verified."""

    #: Nothing was verified. The default, and the only status a
    #: non-trusted caller could ever have meant.
    UNVERIFIED = "unverified"
    #: The provider verified the artefact.
    VERIFIED = "verified"
    #: Verification ran and rejected the artefact.
    FAILED = "failed"
    #: Verification could not run. Fail closed, never treat as verified.
    UNAVAILABLE = "unavailable"


class DelegateBindingStatus(StrEnum):
    """Whether the acting delegate is bound to the authority's principal."""

    UNKNOWN = "unknown"
    BOUND = "bound"
    NOT_BOUND = "not_bound"
    #: The issuer does not express delegate binding at all.
    UNSUPPORTED = "unsupported"


class AuthorityVerificationFailure(StrEnum):
    """Typed reasons an authority artefact did not resolve to usable evidence."""

    AUTHORITY_NOT_FOUND = "authority_not_found"
    AUTHORITY_ARTEFACT_INVALID = "authority_artefact_invalid"
    AUTHORITY_DIGEST_MISMATCH = "authority_digest_mismatch"
    AUTHORITY_SIGNATURE_INVALID = "authority_signature_invalid"
    AUTHORITY_NOT_YET_VALID = "authority_not_yet_valid"
    AUTHORITY_EXPIRED = "authority_expired"
    AUTHORITY_REVOKED = "authority_revoked"
    AUTHORITY_PRINCIPAL_MISMATCH = "authority_principal_mismatch"
    AUTHORITY_DELEGATE_NOT_BOUND = "authority_delegate_not_bound"
    AUTHORITY_SCOPE_UNREADABLE = "authority_scope_unreadable"
    AUTHORITY_PROVIDER_UNAVAILABLE = "authority_provider_unavailable"


@dataclass(frozen=True, slots=True)
class AuthorityVerificationIssue:
    """One typed reason, with optional human detail for operators."""

    code: AuthorityVerificationFailure
    detail: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.code, AuthorityVerificationFailure):
            raise InvalidAuthorityConstructionError(
                "code must be an AuthorityVerificationFailure, got "
                f"{type(self.code).__name__}"
            )


@dataclass(frozen=True, slots=True)
class DelegatedAuthorityClaim:
    """The caller's untrusted pointer at external delegated-authority evidence.

    This is the ``raw_authority`` input to ``AuthorityProvider.resolve``.
    It asserts nothing about verification: it names an issuer and an
    external reference and optionally carries opaque evidence material
    the provider knows how to interpret.
    """

    issuer: str
    external_reference_id: str
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_identifier(self.issuer, "issuer", error=InvalidAuthorityConstructionError)
        require_identifier(
            self.external_reference_id,
            "external_reference_id",
            error=InvalidAuthorityConstructionError,
        )
        if not isinstance(self.evidence, Mapping):
            raise InvalidAuthorityConstructionError(
                f"evidence must be a mapping, got {type(self.evidence).__name__}"
            )
        object.__setattr__(self, "evidence", MappingProxyType(dict(self.evidence)))


@dataclass(frozen=True)
class DelegatedAuthorityReference:
    """An opaque evidence reference produced by a trusted provider.

    ``artefact_digest`` pins the raw external artefact the provider
    actually inspected, so a later audit can tell whether the evidence
    changed underneath a decision.
    """

    construction: InitVar[TrustedAuthorityConstruction | None]
    issuer: str
    external_reference_id: str
    artefact_digest: str
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    verified_at: datetime | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None

    def __post_init__(self, construction: TrustedAuthorityConstruction | None) -> None:
        _require_trusted(construction, "DelegatedAuthorityReference")
        require_identifier(self.issuer, "issuer", error=InvalidAuthorityConstructionError)
        require_identifier(
            self.external_reference_id,
            "external_reference_id",
            error=InvalidAuthorityConstructionError,
        )
        require_digest(
            self.artefact_digest, "artefact_digest", error=InvalidAuthorityConstructionError
        )
        if not isinstance(self.verification_status, VerificationStatus):
            raise InvalidAuthorityConstructionError(
                "verification_status must be a VerificationStatus, got "
                f"{type(self.verification_status).__name__}"
            )
        for name in ("verified_at", "not_before", "not_after"):
            object.__setattr__(
                self,
                name,
                require_optional_utc(
                    getattr(self, name), name, error=InvalidAuthorityConstructionError
                ),
            )
        if (
            self.not_before is not None
            and self.not_after is not None
            and self.not_after <= self.not_before
        ):
            raise InvalidAuthorityConstructionError(
                "not_after must be strictly after not_before"
            )
        if (
            self.verification_status is VerificationStatus.VERIFIED
            and self.verified_at is None
        ):
            raise InvalidAuthorityConstructionError(
                "a VERIFIED reference must record verified_at"
            )

    @property
    def is_verified(self) -> bool:
        """State only. Being verified is not the same as being sufficient."""
        return self.verification_status is VerificationStatus.VERIFIED

    def is_within_validity(self, at: datetime) -> bool:
        """Whether ``at`` falls inside the artefact's own validity bounds."""
        if self.not_before is not None and at < self.not_before:
            return False
        return not (self.not_after is not None and at >= self.not_after)


@dataclass(frozen=True)
class ResolvedAuthority:
    """What a trusted ``AuthorityProvider`` concluded about a claim.

    A resolution that failed is still a valid ``ResolvedAuthority``: it
    carries the reference in a non-verified state plus the typed issues
    that explain why. That is what lets the decision path answer ``BLOCK``
    with a truthful reason instead of raising.
    """

    construction: InitVar[TrustedAuthorityConstruction | None]
    reference: DelegatedAuthorityReference
    delegate_binding_status: DelegateBindingStatus = DelegateBindingStatus.UNKNOWN
    #: Opaque provider-side handle for the delegate binding. Never parsed here.
    delegate_binding_reference: str | None = None
    #: Domain-consumable authority data. Opaque to Core.
    scope: Mapping[str, Any] = field(default_factory=dict)
    not_before: datetime | None = None
    not_after: datetime | None = None
    issues: tuple[AuthorityVerificationIssue, ...] = ()

    def __post_init__(self, construction: TrustedAuthorityConstruction | None) -> None:
        _require_trusted(construction, "ResolvedAuthority")
        if not isinstance(self.reference, DelegatedAuthorityReference):
            raise InvalidAuthorityConstructionError(
                "reference must be a DelegatedAuthorityReference, got "
                f"{type(self.reference).__name__}"
            )
        if not isinstance(self.delegate_binding_status, DelegateBindingStatus):
            raise InvalidAuthorityConstructionError(
                "delegate_binding_status must be a DelegateBindingStatus, got "
                f"{type(self.delegate_binding_status).__name__}"
            )
        require_optional_identifier(
            self.delegate_binding_reference,
            "delegate_binding_reference",
            error=InvalidAuthorityConstructionError,
        )
        if not isinstance(self.scope, Mapping):
            raise InvalidAuthorityConstructionError(
                f"scope must be a mapping, got {type(self.scope).__name__}"
            )
        object.__setattr__(self, "scope", MappingProxyType(dict(self.scope)))
        for name in ("not_before", "not_after"):
            object.__setattr__(
                self,
                name,
                require_optional_utc(
                    getattr(self, name), name, error=InvalidAuthorityConstructionError
                ),
            )
        if (
            self.not_before is not None
            and self.not_after is not None
            and self.not_after <= self.not_before
        ):
            raise InvalidAuthorityConstructionError(
                "not_after must be strictly after not_before"
            )
        issues = tuple(self.issues)
        for issue in issues:
            if not isinstance(issue, AuthorityVerificationIssue):
                raise InvalidAuthorityConstructionError(
                    "issues must be AuthorityVerificationIssue values, got "
                    f"{type(issue).__name__}"
                )
        object.__setattr__(self, "issues", issues)
        if self.reference.is_verified and issues:
            raise InvalidAuthorityConstructionError(
                "a VERIFIED reference cannot be resolved with verification issues"
            )

    @property
    def verification_status(self) -> VerificationStatus:
        return self.reference.verification_status

    @property
    def is_verified(self) -> bool:
        """State only — whether the artefact verified and no issues remain."""
        return self.reference.is_verified and not self.issues

    @property
    def failure_codes(self) -> tuple[AuthorityVerificationFailure, ...]:
        return tuple(issue.code for issue in self.issues)

    def is_within_validity(self, at: datetime) -> bool:
        """Whether ``at`` falls inside both the resolution's and the artefact's bounds."""
        if self.not_before is not None and at < self.not_before:
            return False
        if self.not_after is not None and at >= self.not_after:
            return False
        return self.reference.is_within_validity(at)


@dataclass(frozen=True)
class ExecutionContext:
    """Trusted current context for one organisation/principal pair.

    Produced by a ``ContextProvider``. ``principal_binding`` carries the
    external principal-binding data an ``AuthorityProvider`` needs in
    order to check that the authority it is verifying actually belongs to
    this principal — it is opaque here, and it is trusted precisely
    because Core never accepted it from the caller.
    """

    construction: InitVar[TrustedAuthorityConstruction | None]
    organisation_id: str
    principal_id: str
    principal_binding: Mapping[str, Any] = field(default_factory=dict)
    observed_at: datetime | None = None

    def __post_init__(self, construction: TrustedAuthorityConstruction | None) -> None:
        _require_trusted(construction, "ExecutionContext")
        require_identifier(
            self.organisation_id, "organisation_id", error=InvalidAuthorityConstructionError
        )
        require_identifier(
            self.principal_id, "principal_id", error=InvalidAuthorityConstructionError
        )
        if not isinstance(self.principal_binding, Mapping):
            raise InvalidAuthorityConstructionError(
                f"principal_binding must be a mapping, got "
                f"{type(self.principal_binding).__name__}"
            )
        object.__setattr__(
            self, "principal_binding", MappingProxyType(dict(self.principal_binding))
        )
        object.__setattr__(
            self,
            "observed_at",
            require_optional_utc(
                self.observed_at, "observed_at", error=InvalidAuthorityConstructionError
            ),
        )


@dataclass(frozen=True)
class AuthorityRequirement:
    """Whether delegated authority is required, per trusted configuration.

    Answered by an ``AuthorityRequirementResolver`` from server-side
    configuration and context — never from the request. Phase 1 defines
    the answer's shape only; no persistence and no configuration UI.

    Two rules bind later phases:

    * a resolver that cannot determine the answer MUST return
      ``required=True``; not knowing is not permission;
    * when ``required`` is ``True`` and no verified authority is present,
      the decision path MUST fail closed with
      ``DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING``.
    """

    construction: InitVar[TrustedAuthorityConstruction | None]
    organisation_id: str
    principal_id: str
    action_class: str
    required: bool = True
    #: Which trusted configuration produced this answer, for audit.
    source: str | None = None
    detail: str | None = None

    def __post_init__(self, construction: TrustedAuthorityConstruction | None) -> None:
        _require_trusted(construction, "AuthorityRequirement")
        require_identifier(
            self.organisation_id, "organisation_id", error=InvalidAuthorityConstructionError
        )
        require_identifier(
            self.principal_id, "principal_id", error=InvalidAuthorityConstructionError
        )
        require_identifier(
            self.action_class, "action_class", error=InvalidAuthorityConstructionError
        )
        if not isinstance(self.required, bool):
            raise InvalidAuthorityConstructionError(
                f"required must be a bool, got {type(self.required).__name__}"
            )
        require_optional_identifier(
            self.source, "source", error=InvalidAuthorityConstructionError
        )
