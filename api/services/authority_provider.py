"""The trusted resolution of a delegated-authority claim.

Phase 7A, Gate 3. This is the component the ``AuthorityProvider`` port was
written for: it turns a caller's untrusted claim into typed evidence, or
into a truthful explanation of why it is not evidence.

The order of checks, and why it is this order
---------------------------------------------
Each step is cheaper than the one after it and can only narrow what
follows, so a hostile caller cannot make Core do expensive work by sending
rubbish:

1. **Parse under bounds** — size, depth, keys, strings, arrays, deadline.
   Nothing below runs on an unbounded document.
2. **Issuer is configured and enabled** — a signature from an issuer Core
   does not trust is not worth verifying.
3. **Signing key is known, active and in date** — a retired key may not
   authenticate *new* authority even though what it signed before stays
   verifiable for audit.
4. **Revocation** — read from the database, and fails closed. Checked
   BEFORE the signature so a revoked key never even gets verified, and so
   a revoked delegation cannot be distinguished from a valid one by timing.
5. **Signature** — Ed25519 over the RFC 8785 canonical payload.
6. **Validity window** — the artefact's own ``not_before``/``not_after``.
7. **Principal binding** — the artefact's principal claims must match the
   trusted, server-assembled ``ExecutionContext.principal_binding``. This
   is the step that stops a real delegation for principal A being used by
   principal B in the same organisation.
8. **Delegate binding** — when the issuer expresses one.
9. **Scope translation** — issuer field names to this build's neutral keys.

Failure is returned, not raised
-------------------------------
Every one of those steps can fail, and each failure is reported as a
``ResolvedAuthority`` in a non-verified state carrying typed issues. The
decision path then BLOCKs with a truthful reason. Raising is reserved for
genuine faults: a caller that handed over something structurally
impossible, or an inability to establish revocation state (which is not a
verdict about the artefact and must not be reported as one).

What "verified" does and does not mean
--------------------------------------
A VERIFIED resolution means: this issuer really signed this delegation, it
is in date, nobody has revoked it, and it names this principal. It does
NOT mean the act is permitted. Organisation policy still decides, and a
delegated scope can only narrow what policy already allows.
"""

from __future__ import annotations

import base64
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from api.core.authority.authority import (
    AuthorityVerificationFailure,
    AuthorityVerificationIssue,
    DelegateBindingStatus,
    DelegatedAuthorityClaim,
    DelegatedAuthorityReference,
    ExecutionContext,
    ResolvedAuthority,
    VerificationStatus,
    trusted_authority_construction,
)
from api.trust.artefact import (
    DEFAULT_BOUNDS,
    ArtefactBounds,
    ArtefactParseError,
    Deadline,
    DelegatedAuthorityArtefact,
    parse_authority_artefact,
)
from api.trust.issuer_registry import (
    IssuerStatus,
    KeyStatus,
    TrustedIssuer,
    TrustedIssuerRegistry,
    public_key_fingerprint,
)
from api.trust.revocations import (
    RevocationLookupUnavailable,
    RevocationSnapshot,
    RevocationSubject,
    load_revocations,
)

logger = logging.getLogger(__name__)

#: Where in the claim's ``evidence`` mapping the issuer artefact lives.
ARTEFACT_EVIDENCE_KEY: Final[str] = "artefact"

#: Digest used when no artefact could be inspected at all. A reference must
#: carry a 64-hex digest, and inventing a plausible-looking one would let a
#: failed resolution masquerade as having examined something. This constant
#: is deliberately recognisable as "nothing was inspected".
_NO_ARTEFACT_DIGEST: Final[str] = "00" * 32


class AuthorityProviderFault(RuntimeError):
    """Resolution could not be attempted, as distinct from failing.

    Raised when revocation state is unknown. "We could not check whether
    this was revoked" is not a verdict about the artefact, and reporting it
    as one would put a false statement into the audit record.
    """


def _issue(
    code: AuthorityVerificationFailure, detail: str
) -> tuple[AuthorityVerificationIssue, ...]:
    return (AuthorityVerificationIssue(code=code, detail=detail),)


def _unverified(
    *,
    issuer: str,
    external_reference_id: str,
    artefact_digest: str,
    issues: tuple[AuthorityVerificationIssue, ...],
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    delegate_binding_status: DelegateBindingStatus = DelegateBindingStatus.UNKNOWN,
) -> ResolvedAuthority:
    """A resolution that did not produce usable evidence, and says why."""
    construction = trusted_authority_construction()
    reference = DelegatedAuthorityReference(
        construction,
        issuer=issuer,
        external_reference_id=external_reference_id,
        artefact_digest=artefact_digest,
        verification_status=VerificationStatus.UNVERIFIED,
        not_before=not_before,
        not_after=not_after,
    )
    return ResolvedAuthority(
        construction,
        reference=reference,
        delegate_binding_status=delegate_binding_status,
        issues=issues,
        not_before=not_before,
        not_after=not_after,
    )


@dataclass(frozen=True, slots=True)
class _KeyCheck:
    """Outcome of locating the signing key named by an artefact."""

    verify_key: VerifyKey | None
    fingerprint: str | None
    issues: tuple[AuthorityVerificationIssue, ...]


class TrustedIssuerAuthorityProvider:
    """Resolves a claim against configured trust and live revocation state.

    Constructed per request with a revocation snapshot already loaded, so
    ``resolve`` stays synchronous and satisfies the ``AuthorityProvider``
    port: no decision path reaches for I/O part-way through deciding. Use
    :func:`build_authority_provider` to construct one.
    """

    def __init__(
        self,
        registry: TrustedIssuerRegistry,
        revocations: RevocationSnapshot,
        *,
        bounds: ArtefactBounds = DEFAULT_BOUNDS,
        now: datetime | None = None,
    ) -> None:
        self._registry = registry
        self._revocations = revocations
        self._bounds = bounds
        self._now = now

    # -- the port ---------------------------------------------------------

    def resolve(
        self,
        raw_authority: DelegatedAuthorityClaim | None,
        expected_principal_context: ExecutionContext,
    ) -> ResolvedAuthority:
        if raw_authority is None:
            # "No claim was presented" is a fact about the request, not a
            # failed verification. The caller distinguishes the two.
            raise AuthorityProviderFault(
                "resolve() was called with no claim; the absence of a claim is "
                "the caller's fact to report, not a resolution outcome"
            )

        at = self._now or datetime.now(UTC)
        deadline = Deadline(self._bounds.budget_seconds)

        # --- 1. Parse under bounds ---------------------------------------
        raw_artefact = raw_authority.evidence.get(ARTEFACT_EVIDENCE_KEY)
        if raw_artefact is None:
            return _unverified(
                issuer=raw_authority.issuer,
                external_reference_id=raw_authority.external_reference_id,
                artefact_digest=_NO_ARTEFACT_DIGEST,
                issues=_issue(
                    AuthorityVerificationFailure.AUTHORITY_NOT_FOUND,
                    f"claim carries no {ARTEFACT_EVIDENCE_KEY!r} evidence to verify",
                ),
            )
        try:
            artefact = parse_authority_artefact(
                raw_artefact, bounds=self._bounds, deadline=deadline
            )
        except ArtefactParseError as exc:
            return _unverified(
                issuer=raw_authority.issuer,
                external_reference_id=raw_authority.external_reference_id,
                artefact_digest=_NO_ARTEFACT_DIGEST,
                issues=_issue(AuthorityVerificationFailure.AUTHORITY_ARTEFACT_INVALID, str(exc)),
            )

        digest = artefact.artefact_digest

        # The claim and the artefact must agree about what they describe.
        # A mismatch means the caller is pointing at one thing and handing
        # over another, and following either would be a guess.
        if artefact.issuer != raw_authority.issuer:
            return _unverified(
                issuer=raw_authority.issuer,
                external_reference_id=raw_authority.external_reference_id,
                artefact_digest=digest,
                issues=_issue(
                    AuthorityVerificationFailure.AUTHORITY_DIGEST_MISMATCH,
                    "the claim names a different issuer from the artefact",
                ),
            )
        if artefact.authority_id != raw_authority.external_reference_id:
            return _unverified(
                issuer=raw_authority.issuer,
                external_reference_id=raw_authority.external_reference_id,
                artefact_digest=digest,
                issues=_issue(
                    AuthorityVerificationFailure.AUTHORITY_DIGEST_MISMATCH,
                    "the claim names a different authority id from the artefact",
                ),
            )

        # --- 2. Issuer is configured and enabled -------------------------
        issuer = self._registry.issuer(artefact.issuer)
        if issuer is None:
            return _unverified(
                issuer=artefact.issuer,
                external_reference_id=artefact.authority_id,
                artefact_digest=digest,
                issues=_issue(
                    AuthorityVerificationFailure.AUTHORITY_NOT_FOUND,
                    f"issuer {artefact.issuer!r} is not configured as trusted",
                ),
            )
        if issuer.status is not IssuerStatus.ACTIVE:
            return _unverified(
                issuer=artefact.issuer,
                external_reference_id=artefact.authority_id,
                artefact_digest=digest,
                issues=_issue(
                    AuthorityVerificationFailure.AUTHORITY_REVOKED,
                    f"issuer {artefact.issuer!r} is disabled in configuration",
                ),
            )

        # --- 3. Signing key is known, active and in date -----------------
        key_check = self._locate_key(issuer, artefact, at=at)
        if key_check.issues:
            return _unverified(
                issuer=artefact.issuer,
                external_reference_id=artefact.authority_id,
                artefact_digest=digest,
                issues=key_check.issues,
            )
        assert key_check.verify_key is not None  # guaranteed by the branch above
        assert key_check.fingerprint is not None

        # --- 4. Revocation, BEFORE the signature check -------------------
        revocation_issue = self._revocation_issue(
            issuer_id=artefact.issuer,
            key_fingerprint=key_check.fingerprint,
            authority_id=artefact.authority_id,
            delegate_fingerprint=self._delegate_fingerprint(issuer, artefact),
        )
        if revocation_issue is not None:
            return _unverified(
                issuer=artefact.issuer,
                external_reference_id=artefact.authority_id,
                artefact_digest=digest,
                issues=revocation_issue,
            )
        deadline.check("revocation")

        # --- 5. Signature -------------------------------------------------
        try:
            signature = base64.b64decode(artefact.signature_value_b64, validate=True)
        except (ValueError, TypeError):
            return _unverified(
                issuer=artefact.issuer,
                external_reference_id=artefact.authority_id,
                artefact_digest=digest,
                issues=_issue(
                    AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID,
                    "signature.value is not valid base64",
                ),
            )
        try:
            key_check.verify_key.verify(artefact.signed_bytes, signature)
        except (BadSignatureError, ValueError):
            return _unverified(
                issuer=artefact.issuer,
                external_reference_id=artefact.authority_id,
                artefact_digest=digest,
                issues=_issue(
                    AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID,
                    "the artefact signature does not verify under the named key",
                ),
            )
        deadline.check("signature")

        # --- 6. Validity window -------------------------------------------
        if artefact.not_before is not None and at < artefact.not_before:
            return _unverified(
                issuer=artefact.issuer,
                external_reference_id=artefact.authority_id,
                artefact_digest=digest,
                not_before=artefact.not_before,
                not_after=artefact.not_after,
                issues=_issue(
                    AuthorityVerificationFailure.AUTHORITY_NOT_YET_VALID,
                    "the delegation is not yet valid",
                ),
            )
        if artefact.not_after is not None and at >= artefact.not_after:
            return _unverified(
                issuer=artefact.issuer,
                external_reference_id=artefact.authority_id,
                artefact_digest=digest,
                not_before=artefact.not_before,
                not_after=artefact.not_after,
                issues=_issue(
                    AuthorityVerificationFailure.AUTHORITY_EXPIRED,
                    "the delegation has expired",
                ),
            )

        # --- 7. Principal binding -----------------------------------------
        principal_issue = self._principal_issue(issuer, artefact, expected_principal_context)
        if principal_issue is not None:
            return _unverified(
                issuer=artefact.issuer,
                external_reference_id=artefact.authority_id,
                artefact_digest=digest,
                not_before=artefact.not_before,
                not_after=artefact.not_after,
                issues=principal_issue,
            )

        # --- 8. Delegate binding ------------------------------------------
        binding_status, binding_reference, binding_issue = self._delegate_binding(
            issuer, artefact, expected_principal_context
        )
        if binding_issue is not None:
            return _unverified(
                issuer=artefact.issuer,
                external_reference_id=artefact.authority_id,
                artefact_digest=digest,
                not_before=artefact.not_before,
                not_after=artefact.not_after,
                delegate_binding_status=binding_status,
                issues=binding_issue,
            )

        # --- 9. Scope translation ------------------------------------------
        scope = self._translate_scope(issuer, artefact)

        construction = trusted_authority_construction()
        reference = DelegatedAuthorityReference(
            construction,
            issuer=artefact.issuer,
            external_reference_id=artefact.authority_id,
            artefact_digest=digest,
            verification_status=VerificationStatus.VERIFIED,
            verified_at=at,
            not_before=artefact.not_before,
            not_after=artefact.not_after,
        )
        return ResolvedAuthority(
            construction,
            reference=reference,
            delegate_binding_status=binding_status,
            delegate_binding_reference=binding_reference,
            scope=scope,
            not_before=artefact.not_before,
            not_after=artefact.not_after,
        )

    # -- steps ------------------------------------------------------------

    def _locate_key(
        self, issuer: TrustedIssuer, artefact: DelegatedAuthorityArtefact, *, at: datetime
    ) -> _KeyCheck:
        key = issuer.key(artefact.signature_key_id)
        if key is None:
            return _KeyCheck(
                None,
                None,
                _issue(
                    AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID,
                    f"issuer {issuer.issuer_id!r} has no configured key "
                    f"{artefact.signature_key_id!r}",
                ),
            )
        if key.status is KeyStatus.REVOKED:
            return _KeyCheck(
                None,
                None,
                _issue(
                    AuthorityVerificationFailure.AUTHORITY_REVOKED,
                    f"signing key {key.key_id!r} is revoked in configuration",
                ),
            )
        if not key.usable_for_new_authority(at):
            # RETIRED, or outside its validity window. Both mean the same
            # thing here: this key may not authenticate NEW authority. What
            # it signed while active stays verifiable for audit elsewhere.
            return _KeyCheck(
                None,
                None,
                _issue(
                    AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID,
                    f"signing key {key.key_id!r} is {key.status.value} or outside "
                    "its validity window and cannot authenticate new authority",
                ),
            )
        return _KeyCheck(VerifyKey(key.public_key), key.fingerprint, ())

    def _delegate_fingerprint(
        self, issuer: TrustedIssuer, artefact: DelegatedAuthorityArtefact
    ) -> str | None:
        """The delegate key fingerprint the artefact names, if it names one."""
        if not issuer.expresses_delegate_binding:
            return None
        value = artefact.delegate_claims.get("key_fingerprint")
        return value if isinstance(value, str) and value else None

    def _revocation_issue(
        self,
        *,
        issuer_id: str,
        key_fingerprint: str,
        authority_id: str,
        delegate_fingerprint: str | None,
    ) -> tuple[AuthorityVerificationIssue, ...] | None:
        checks: list[tuple[RevocationSubject, str, str | None, str]] = [
            (RevocationSubject.ISSUER, issuer_id, None, "issuer is revoked"),
            (
                RevocationSubject.ISSUER_KEY,
                key_fingerprint,
                issuer_id,
                "the signing key is revoked",
            ),
            (
                RevocationSubject.AUTHORITY_REFERENCE,
                authority_id,
                issuer_id,
                "this delegation is revoked",
            ),
        ]
        if delegate_fingerprint:
            checks.append(
                (
                    RevocationSubject.DELEGATE_KEY,
                    delegate_fingerprint,
                    issuer_id,
                    "the delegate key is revoked",
                )
            )
        for subject_type, subject_id, scoped_issuer, detail in checks:
            if self._revocations.is_revoked(subject_type, subject_id, issuer=scoped_issuer):
                return _issue(AuthorityVerificationFailure.AUTHORITY_REVOKED, detail)
        return None

    def _principal_issue(
        self,
        issuer: TrustedIssuer,
        artefact: DelegatedAuthorityArtefact,
        context: ExecutionContext,
    ) -> tuple[AuthorityVerificationIssue, ...] | None:
        """Every configured principal claim must match the trusted binding.

        ``context.principal_binding`` was assembled server-side from the
        organisation's own record of this principal. The caller never
        supplied it, which is the whole reason this comparison means
        anything.
        """
        for claim_name, binding_key in issuer.principal_claim_bindings.items():
            claimed = artefact.principal_claims.get(claim_name)
            expected = context.principal_binding.get(binding_key)
            if not isinstance(claimed, str) or not claimed:
                return _issue(
                    AuthorityVerificationFailure.AUTHORITY_PRINCIPAL_MISMATCH,
                    f"the delegation states no {claim_name!r} for its principal",
                )
            if not isinstance(expected, str) or not expected:
                # The principal has no such binding recorded, so there is
                # nothing to match against. Accepting the delegation anyway
                # would make it usable for any principal in the organisation.
                return _issue(
                    AuthorityVerificationFailure.AUTHORITY_PRINCIPAL_MISMATCH,
                    f"this principal has no {binding_key!r} binding recorded, so "
                    "the delegation cannot be tied to it",
                )
            if not secrets.compare_digest(claimed, expected):
                return _issue(
                    AuthorityVerificationFailure.AUTHORITY_PRINCIPAL_MISMATCH,
                    f"the delegation's {claim_name!r} does not match this principal",
                )
        return None

    def _delegate_binding(
        self,
        issuer: TrustedIssuer,
        artefact: DelegatedAuthorityArtefact,
        context: ExecutionContext,
    ) -> tuple[DelegateBindingStatus, str | None, tuple[AuthorityVerificationIssue, ...] | None]:
        if not issuer.expresses_delegate_binding:
            # UNSUPPORTED, not BOUND. The issuer makes no statement about
            # which delegate may act, and inventing one would be Core
            # asserting something its issuer did not.
            return DelegateBindingStatus.UNSUPPORTED, None, None

        claimed = artefact.delegate_claims.get("key_fingerprint")
        if not isinstance(claimed, str) or not claimed:
            return (
                DelegateBindingStatus.NOT_BOUND,
                None,
                _issue(
                    AuthorityVerificationFailure.AUTHORITY_DELEGATE_NOT_BOUND,
                    "the issuer expresses delegate binding but this delegation "
                    "names no delegate key",
                ),
            )

        binding_key = issuer.delegate_binding_key or ""
        expected = context.principal_binding.get(binding_key)
        if not isinstance(expected, str) or not expected:
            return (
                DelegateBindingStatus.NOT_BOUND,
                None,
                _issue(
                    AuthorityVerificationFailure.AUTHORITY_DELEGATE_NOT_BOUND,
                    f"this principal has no {binding_key!r} delegate binding "
                    "recorded, so the named delegate cannot be confirmed",
                ),
            )
        if not secrets.compare_digest(claimed, expected):
            return (
                DelegateBindingStatus.NOT_BOUND,
                None,
                _issue(
                    AuthorityVerificationFailure.AUTHORITY_DELEGATE_NOT_BOUND,
                    "the delegation names a delegate key that is not bound to " "this principal",
                ),
            )
        return DelegateBindingStatus.BOUND, claimed, None

    def _translate_scope(
        self, issuer: TrustedIssuer, artefact: DelegatedAuthorityArtefact
    ) -> dict[str, Any]:
        """Issuer field names to this build's neutral scope keys.

        A field with no configured mapping is carried through under its own
        name. That is deliberate: downstream, an unrecognised scope key is
        an unsupported constraint and the payment path fails closed. Dropping
        it instead would silently broaden what the issuer granted.
        """
        translated: dict[str, Any] = {}
        for field_name, value in artefact.scope_claims.items():
            neutral = issuer.scope_field_mapping.get(field_name, field_name)
            translated[neutral] = value
        return translated


async def build_authority_provider(
    database: Any,
    *,
    claim: DelegatedAuthorityClaim | None,
    registry: TrustedIssuerRegistry,
    bounds: ArtefactBounds = DEFAULT_BOUNDS,
    now: datetime | None = None,
) -> TrustedIssuerAuthorityProvider | None:
    """Load revocation state and build the provider for one resolution.

    Returns ``None`` when no claim was presented — there is nothing to
    resolve and no reason to touch the database.

    Raises :class:`AuthorityProviderFault` when revocation state cannot be
    established. That is not a verdict about the artefact and is reported
    to the decision path as provider unavailability, which fails closed.
    """
    if claim is None:
        return None

    subjects: list[tuple[RevocationSubject, str, str | None]] = [
        (RevocationSubject.ISSUER, claim.issuer, None),
        (
            RevocationSubject.AUTHORITY_REFERENCE,
            claim.external_reference_id,
            claim.issuer,
        ),
    ]
    issuer = registry.issuer(claim.issuer)
    if issuer is not None:
        # Every configured key fingerprint, plus any delegate key the claim
        # names. Asking about all of them in one read keeps the number of
        # round trips independent of which key the artefact turns out to
        # have been signed with.
        subjects.extend(
            (RevocationSubject.ISSUER_KEY, key.fingerprint, claim.issuer) for key in issuer.keys
        )
        delegate = _claimed_delegate_fingerprint(claim)
        if delegate:
            subjects.append((RevocationSubject.DELEGATE_KEY, delegate, claim.issuer))

    try:
        revocations = await load_revocations(database, subjects=subjects)
    except RevocationLookupUnavailable as exc:
        raise AuthorityProviderFault(str(exc)) from exc

    return TrustedIssuerAuthorityProvider(registry, revocations, bounds=bounds, now=now)


def _claimed_delegate_fingerprint(claim: DelegatedAuthorityClaim) -> str | None:
    """Peek at the delegate fingerprint before the artefact is parsed.

    Untrusted and used for one thing only: deciding which revocation rows
    to fetch. A caller that lies here can only cause a row it does not care
    about to be fetched; the fingerprint that is actually checked comes
    from the parsed, signature-verified artefact.
    """
    artefact = claim.evidence.get(ARTEFACT_EVIDENCE_KEY)
    if not isinstance(artefact, dict):
        return None
    payload = artefact.get("payload")
    if not isinstance(payload, dict):
        return None
    delegate = payload.get("delegate")
    if not isinstance(delegate, dict):
        return None
    fingerprint = delegate.get("key_fingerprint")
    return fingerprint if isinstance(fingerprint, str) and fingerprint else None


__all__ = [
    "ARTEFACT_EVIDENCE_KEY",
    "AuthorityProviderFault",
    "TrustedIssuerAuthorityProvider",
    "build_authority_provider",
    "public_key_fingerprint",
]
