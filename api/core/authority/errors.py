"""Typed errors for the core authority boundary.

Error philosophy
----------------
There are two very different failure shapes and they must not be
conflated:

1. **Programming / construction faults.** An envelope that cannot be
   validated, a domain that is not registered, an internal authority
   object assembled outside the trusted path. These are bugs or
   integration faults, they are exceptional, and they raise.

2. **Expected denial.** An external authority artefact that does not
   verify, has expired, or is not bound to the acting delegate. This is
   the system working as designed and it MUST NOT raise. It is
   represented as a failed/unverified ``ResolvedAuthority`` carrying
   typed ``AuthorityVerificationFailure`` codes, so the decision path
   can return ``BLOCK`` with a truthful reason instead of turning a
   routine denial into a 500.

An ``AuthorityProvider`` implementation that raises on "the artefact did
not verify" is implemented incorrectly.
"""

from __future__ import annotations


class CoreAuthorityError(Exception):
    """Base class for every error raised by the core authority boundary."""


class InvalidEnvelopeError(CoreAuthorityError):
    """The proposed action could not be validated into an executable form.

    Raised for a missing or malformed identifier, a payload that cannot be
    canonicalized, or an action that expresses its target more than once.
    """


class UnknownDomainError(CoreAuthorityError):
    """No domain policy is registered for the envelope's domain."""


class InvalidAuthorityConstructionError(CoreAuthorityError):
    """An internal authority object was constructed outside the trusted path.

    ``ResolvedAuthority``, ``DelegatedAuthorityReference``,
    ``ExecutionContext`` and ``AuthorityRequirement`` are outputs of a
    trusted server-side provider. They require a
    ``TrustedAuthorityConstruction`` capability that cannot be produced
    from request data, so no client can self-assert a verified authority,
    an organisation identity, or a delegate binding.
    """


class InvalidGrantError(CoreAuthorityError):
    """Execution authority was assembled with an internally inconsistent shape.

    Raised for a grant whose validity window is empty, whose hashes are
    malformed, or which asks for multi-use semantics that v0.5 does not
    define.
    """
