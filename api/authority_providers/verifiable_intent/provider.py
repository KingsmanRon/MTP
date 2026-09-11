"""An ``AuthorityProvider`` over Mastercard/Google Verifiable Intent.

What this provider is for
-------------------------
It answers one question: *given this presented VI delegation, what did
the issuer actually authorise, and does it belong to the principal we are
about to act for?* It answers with a ``ResolvedAuthority`` — verified or
not — and it never decides whether the act is permitted. That decision
belongs to the organisation's own policy, which runs afterwards and is
free to refuse something VI permits.

What it verifies
----------------
Verification itself is delegated to the pinned official VI reference
implementation (:func:`verifiable_intent.verification.chain.verify_chain`).
This module does not reimplement SD-JWT, ES256 or the chain rules. Around
that call it enforces the four things a chain check alone does not:

issuer
    The L1 signing key comes from trusted server-side configuration, not
    from the presented artefact.
audience
    The L2 mandate must name this deployment, and the L3 payment mandate
    must name the network endpoint we are. A valid mandate addressed to
    somebody else is not ours to spend.
delegate
    The agent key the mandate delegates to must be the key this
    organisation has registered for this principal.
principal
    The L1 subject must be the subject this organisation has registered
    for this principal, so one organisation's delegation cannot be
    presented for another's agent.

Failure is data
---------------
Every routine denial — unknown issuer, bad signature, expired mandate,
wrong audience, unbound delegate — returns an unverified
``ResolvedAuthority`` carrying typed issues. The provider raises only on
a genuine fault, because a provider that raises on denial turns an
expected BLOCK into a 500.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from api.authority_providers.verifiable_intent.scope import (
    VerifiableIntentScopeError,
    map_payment_constraints,
)
from api.authority_providers.verifiable_intent.trust import (
    IssuerTrustStore,
    TrustedIssuer,
)
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

logger = logging.getLogger(__name__)

#: The issuer name this provider answers for on a ``DelegatedAuthorityClaim``.
VERIFIABLE_INTENT_ISSUER_KIND: Final[str] = "verifiable-intent"

#: ``vct`` of the L2 autonomous payment mandate this provider reads.
L2_PAYMENT_MANDATE_VCT: Final[str] = "mandate.payment.open.1"

#: Versioned preimage identifier for the artefact digest.
ARTEFACT_DIGEST_FORMAT: Final[str] = "inntris-vi-artefact-v1"

_Failure = AuthorityVerificationFailure


class VerifiableIntentProviderFault(RuntimeError):
    """The provider was handed something structurally impossible.

    Not raised for any artefact a caller could plausibly present: a
    malformed, expired or unverifiable delegation is reported as data.
    """


@dataclass(frozen=True, slots=True)
class PresentedDelegation:
    """The serialised VI material a caller presented, still untrusted."""

    l1: str
    l2: str
    l3_payment: str
    #: The selective L2 presentation the payment recipient was shown, when
    #: the caller routed one. Absent means the full L2 was presented.
    l2_payment: str | None = None


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint of an EC JWK.

    Only the required members take part, in lexicographic order, with no
    whitespace — so two spellings of the same key (a ``kid`` added, member
    order changed) produce one identity. Comparing whole JWK objects
    instead would let a cosmetic difference read as a different key.
    """
    try:
        kty = jwk["kty"]
    except (TypeError, KeyError) as exc:
        raise VerifiableIntentScopeError("delegate key is not a JWK") from exc
    if kty != "EC":
        raise VerifiableIntentScopeError(f"unsupported delegate key type {kty!r}")
    try:
        required = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    except KeyError as exc:
        raise VerifiableIntentScopeError(
            f"EC delegate key is missing {exc.args[0]!r}"
        ) from exc
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def artefact_digest(presented: PresentedDelegation) -> str:
    """Pin the exact material that was inspected.

    Over the serialised presentation rather than the parsed claims: what a
    later audit needs to know is whether the bytes changed, and a digest
    of our own reading of them would not show that.
    """
    preimage = "\n".join(
        (
            ARTEFACT_DIGEST_FORMAT,
            presented.l1,
            presented.l2,
            presented.l3_payment,
            presented.l2_payment or "",
        )
    )
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def read_presented_delegation(evidence: Mapping[str, Any]) -> PresentedDelegation:
    """Read the caller's evidence mapping. Structural failures raise here."""
    if not isinstance(evidence, Mapping):
        raise VerifiableIntentScopeError("evidence must be a mapping")
    fields = {}
    for name in ("l1", "l2", "l3_payment"):
        value = evidence.get(name)
        if not isinstance(value, str) or not value.strip():
            raise VerifiableIntentScopeError(
                f"evidence.{name} must be a serialised SD-JWT"
            )
        fields[name] = value
    l2_payment = evidence.get("l2_payment")
    if l2_payment is not None and (
        not isinstance(l2_payment, str) or not l2_payment.strip()
    ):
        raise VerifiableIntentScopeError(
            "evidence.l2_payment must be a serialised SD-JWT presentation or absent"
        )
    return PresentedDelegation(l2_payment=l2_payment, **fields)


class VerifiableIntentAuthorityProvider:
    """Resolve a VI delegation into neutral, trusted authority evidence.

    Constructed with the issuers this deployment trusts. Constructing one
    changes nothing on its own: it becomes live only when a deployment
    hands it to ``AuthorityEvaluationService``.
    """

    def __init__(
        self,
        trust_store: IssuerTrustStore,
        *,
        clock_skew_seconds: int = 300,
        now: Any = None,
    ) -> None:
        if not isinstance(trust_store, IssuerTrustStore):
            raise VerifiableIntentProviderFault(
                "trust_store must implement IssuerTrustStore, got "
                f"{type(trust_store).__name__}"
            )
        self._trust = trust_store
        self._clock_skew = int(clock_skew_seconds)
        #: Injected clock. Tests advance it; production leaves it alone.
        self._now = now

    # -- the port ---------------------------------------------------------

    def resolve(
        self,
        raw_authority: DelegatedAuthorityClaim | None,
        expected_principal_context: ExecutionContext,
    ) -> ResolvedAuthority:
        """Resolve ``raw_authority`` against the principal it must belong to."""
        if raw_authority is None:
            return self._unresolved(
                issuer=VERIFIABLE_INTENT_ISSUER_KIND,
                external_reference_id="absent",
                digest="0" * 64,
                status=VerificationStatus.UNVERIFIED,
                issues=(AuthorityVerificationIssue(_Failure.AUTHORITY_NOT_FOUND),),
            )

        try:
            presented = read_presented_delegation(raw_authority.evidence)
        except VerifiableIntentScopeError as exc:
            return self._unresolved(
                issuer=raw_authority.issuer,
                external_reference_id=raw_authority.external_reference_id,
                digest="0" * 64,
                status=VerificationStatus.FAILED,
                issues=(
                    AuthorityVerificationIssue(
                        _Failure.AUTHORITY_ARTEFACT_INVALID, str(exc)
                    ),
                ),
            )

        digest = artefact_digest(presented)
        trusted = self._trust.trusted_issuer(raw_authority.issuer)
        if trusted is None:
            # Not configured is not "verify it anyway against whatever key
            # came with it". It is simply not an issuer we accept.
            return self._unresolved(
                issuer=raw_authority.issuer,
                external_reference_id=raw_authority.external_reference_id,
                digest=digest,
                status=VerificationStatus.FAILED,
                issues=(
                    AuthorityVerificationIssue(
                        _Failure.AUTHORITY_NOT_FOUND,
                        "no trusted key is configured for this issuer",
                    ),
                ),
            )

        try:
            return self._resolve_verified(
                raw_authority, presented, digest, trusted, expected_principal_context
            )
        except VerifiableIntentProviderFault:
            raise
        except Exception as exc:  # pragma: no cover - defence in depth
            # The reference implementation raised on something we did not
            # anticipate. "We could not check" is not "it checks out".
            logger.warning("verifiable intent verification faulted: %s", exc)
            return self._unresolved(
                issuer=raw_authority.issuer,
                external_reference_id=raw_authority.external_reference_id,
                digest=digest,
                status=VerificationStatus.UNAVAILABLE,
                issues=(
                    AuthorityVerificationIssue(
                        _Failure.AUTHORITY_PROVIDER_UNAVAILABLE, str(exc)
                    ),
                ),
            )

    # -- verification -----------------------------------------------------

    def _resolve_verified(
        self,
        claim: DelegatedAuthorityClaim,
        presented: PresentedDelegation,
        digest: str,
        trusted: TrustedIssuer,
        context: ExecutionContext,
    ) -> ResolvedAuthority:
        from verifiable_intent.crypto.sd_jwt import decode_sd_jwt, resolve_disclosures
        from verifiable_intent.verification.chain import verify_chain

        try:
            l1 = decode_sd_jwt(presented.l1)
            l2 = decode_sd_jwt(presented.l2)
            l3_payment = decode_sd_jwt(presented.l3_payment)
        except Exception as exc:
            return self._unresolved(
                issuer=claim.issuer,
                external_reference_id=claim.external_reference_id,
                digest=digest,
                status=VerificationStatus.FAILED,
                issues=(
                    AuthorityVerificationIssue(
                        _Failure.AUTHORITY_ARTEFACT_INVALID, str(exc)
                    ),
                ),
            )

        result = verify_chain(
            l1,
            l2,
            l3_payment=l3_payment,
            issuer_public_key=trusted.public_key,
            l1_serialized=presented.l1,
            l2_serialized=presented.l2,
            l2_payment_serialized=presented.l2_payment or presented.l2,
            expected_l2_aud=trusted.l2_audience,
            expected_l3_payment_aud=trusted.l3_payment_audience,
            clock_skew_seconds=self._clock_skew,
        )
        if not result.valid:
            return self._unresolved(
                issuer=claim.issuer,
                external_reference_id=claim.external_reference_id,
                digest=digest,
                status=VerificationStatus.FAILED,
                issues=tuple(_chain_issues(result.errors)),
            )

        l1_claims = result.l1_claims or {}
        l2_claims = result.l2_claims or resolve_disclosures(l2)

        # --- the delegation must belong to THIS principal -----------------
        binding = context.principal_binding or {}
        expected_subject = binding.get("vi_subject")
        if not expected_subject:
            # Nothing server-side says this principal has a VI identity, so
            # nothing presented can be shown to be theirs.
            return self._unresolved(
                issuer=claim.issuer,
                external_reference_id=claim.external_reference_id,
                digest=digest,
                status=VerificationStatus.FAILED,
                issues=(
                    AuthorityVerificationIssue(
                        _Failure.AUTHORITY_PRINCIPAL_MISMATCH,
                        "no Verifiable Intent subject is registered for this principal",
                    ),
                ),
            )
        if l1_claims.get("sub") != expected_subject:
            return self._unresolved(
                issuer=claim.issuer,
                external_reference_id=claim.external_reference_id,
                digest=digest,
                status=VerificationStatus.FAILED,
                issues=(
                    AuthorityVerificationIssue(
                        _Failure.AUTHORITY_PRINCIPAL_MISMATCH,
                        "the credential subject is not this principal's registered subject",
                    ),
                ),
            )

        mandate = _payment_mandate(l2_claims)
        if mandate is None:
            return self._unresolved(
                issuer=claim.issuer,
                external_reference_id=claim.external_reference_id,
                digest=digest,
                status=VerificationStatus.FAILED,
                issues=(
                    AuthorityVerificationIssue(
                        _Failure.AUTHORITY_SCOPE_UNREADABLE,
                        "the presentation carries no autonomous payment mandate",
                    ),
                ),
            )

        delegate_status, delegate_reference, delegate_issue = self._delegate_binding(
            mandate, binding
        )
        if delegate_issue is not None:
            return self._unresolved(
                issuer=claim.issuer,
                external_reference_id=claim.external_reference_id,
                digest=digest,
                status=VerificationStatus.FAILED,
                issues=(delegate_issue,),
                delegate_binding_status=delegate_status,
            )

        # --- what was actually delegated ---------------------------------
        try:
            resolved_constraints = _resolve_constraint_references(
                mandate.get("constraints", ()), l2
            )
            mapped = map_payment_constraints(
                resolved_constraints,
                not_before=l2_claims.get("iat"),
                not_after=l2_claims.get("exp"),
            )
        except VerifiableIntentScopeError as exc:
            return self._unresolved(
                issuer=claim.issuer,
                external_reference_id=claim.external_reference_id,
                digest=digest,
                status=VerificationStatus.FAILED,
                issues=(
                    AuthorityVerificationIssue(
                        _Failure.AUTHORITY_SCOPE_UNREADABLE, str(exc)
                    ),
                ),
                delegate_binding_status=delegate_status,
            )

        construction = trusted_authority_construction()
        reference = DelegatedAuthorityReference(
            construction,
            issuer=claim.issuer,
            external_reference_id=claim.external_reference_id,
            artefact_digest=digest,
            verification_status=VerificationStatus.VERIFIED,
            verified_at=self._instant(),
            not_before=mapped.not_before,
            not_after=mapped.not_after,
        )
        return ResolvedAuthority(
            construction,
            reference=reference,
            delegate_binding_status=delegate_status,
            delegate_binding_reference=delegate_reference,
            scope=mapped.scope,
            not_before=mapped.not_before,
            not_after=mapped.not_after,
        )

    def _delegate_binding(
        self, mandate: Mapping[str, Any], binding: Mapping[str, Any]
    ) -> tuple[DelegateBindingStatus, str | None, AuthorityVerificationIssue | None]:
        """Is the key this mandate delegates to the key we registered?"""
        expected = binding.get("vi_delegate_jwk_thumbprint")
        confirmation = mandate.get("cnf")
        jwk = confirmation.get("jwk") if isinstance(confirmation, Mapping) else None
        if not isinstance(jwk, Mapping):
            return (
                DelegateBindingStatus.NOT_BOUND,
                None,
                AuthorityVerificationIssue(
                    _Failure.AUTHORITY_DELEGATE_NOT_BOUND,
                    "the payment mandate delegates to no key",
                ),
            )
        try:
            thumbprint = jwk_thumbprint(jwk)
        except VerifiableIntentScopeError as exc:
            return (
                DelegateBindingStatus.NOT_BOUND,
                None,
                AuthorityVerificationIssue(
                    _Failure.AUTHORITY_DELEGATE_NOT_BOUND, str(exc)
                ),
            )
        if not expected:
            return (
                DelegateBindingStatus.NOT_BOUND,
                None,
                AuthorityVerificationIssue(
                    _Failure.AUTHORITY_DELEGATE_NOT_BOUND,
                    "no delegate key is registered for this principal",
                ),
            )
        if thumbprint != expected:
            return (
                DelegateBindingStatus.NOT_BOUND,
                None,
                AuthorityVerificationIssue(
                    _Failure.AUTHORITY_DELEGATE_NOT_BOUND,
                    "the mandate delegates to a key this principal has not registered",
                ),
            )
        return DelegateBindingStatus.BOUND, f"vi-delegate:{thumbprint}", None

    # -- helpers ----------------------------------------------------------

    def _instant(self) -> datetime:
        if self._now is None:
            return datetime.now(UTC)
        value = self._now() if callable(self._now) else self._now
        return value.astimezone(UTC)

    @staticmethod
    def _unresolved(
        *,
        issuer: str,
        external_reference_id: str,
        digest: str,
        status: VerificationStatus,
        issues: Sequence[AuthorityVerificationIssue],
        delegate_binding_status: DelegateBindingStatus = DelegateBindingStatus.UNKNOWN,
    ) -> ResolvedAuthority:
        construction = trusted_authority_construction()
        reference = DelegatedAuthorityReference(
            construction,
            issuer=issuer,
            external_reference_id=external_reference_id,
            artefact_digest=digest,
            verification_status=status,
        )
        return ResolvedAuthority(
            construction,
            reference=reference,
            delegate_binding_status=delegate_binding_status,
            issues=tuple(issues)
            or (AuthorityVerificationIssue(_Failure.AUTHORITY_ARTEFACT_INVALID),),
        )


# -- reading the presentation ---------------------------------------------


def _payment_mandate(l2_claims: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """The autonomous payment mandate inside an L2 presentation."""
    delegates = l2_claims.get("delegate_payload")
    if not isinstance(delegates, Sequence):
        return None
    for delegate in delegates:
        if (
            isinstance(delegate, Mapping)
            and delegate.get("vct") == L2_PAYMENT_MANDATE_VCT
        ):
            return delegate
    return None


def _resolve_constraint_references(
    constraints: Any, l2: Any
) -> list[Mapping[str, Any]]:
    """Replace selective-disclosure references with what they disclose.

    A payee allowlist is stored as ``{"...": hash}`` references into the
    L2 disclosures. Only the disclosures actually presented resolve; one
    that was withheld stays a reference, and the scope mapper refuses it
    rather than treating an unseen payee as approved.
    """
    from verifiable_intent.crypto.disclosure import hash_disclosure

    if not isinstance(constraints, Sequence) or isinstance(constraints, (str, bytes)):
        raise VerifiableIntentScopeError("constraints must be a list")

    disclosed: dict[str, Any] = {}
    for text, value in zip(l2.disclosures, l2.disclosure_values, strict=False):
        disclosed[hash_disclosure(text)] = value[-1] if value else None

    resolved: list[Mapping[str, Any]] = []
    for constraint in constraints:
        if not isinstance(constraint, Mapping):
            raise VerifiableIntentScopeError(
                f"a constraint is not an object: {type(constraint).__name__}"
            )
        if constraint.get("type") != "mandate.payment.allowed_payees":
            resolved.append(constraint)
            continue
        allowed = constraint.get("allowed")
        if not isinstance(allowed, Sequence) or isinstance(allowed, (str, bytes)):
            raise VerifiableIntentScopeError(
                "mandate.payment.allowed_payees.allowed must be a list"
            )
        entries: list[Any] = []
        for entry in allowed:
            if isinstance(entry, Mapping) and "..." in entry:
                reference = entry["..."]
                if reference in disclosed:
                    entries.append(disclosed[reference])
                    continue
            entries.append(entry)
        resolved.append({**constraint, "allowed": entries})
    return resolved


def _chain_issues(errors: Sequence[str]) -> list[AuthorityVerificationIssue]:
    """Map the reference implementation's errors onto typed failures.

    Matched on substrings the upstream implementation emits. An error we
    do not recognise becomes ``AUTHORITY_SIGNATURE_INVALID`` rather than
    being dropped: an unmapped failure is still a failure, and losing it
    would turn a rejected chain into a silent pass.
    """
    issues: list[AuthorityVerificationIssue] = []
    for error in errors:
        text = str(error)
        lowered = text.lower()
        if "expired" in lowered:
            code = _Failure.AUTHORITY_EXPIRED
        elif "future" in lowered or "not yet" in lowered:
            code = _Failure.AUTHORITY_NOT_YET_VALID
        elif "aud" in lowered or "audience" in lowered or "nonce" in lowered:
            code = _Failure.AUTHORITY_PRINCIPAL_MISMATCH
        elif "cnf" in lowered or "delegat" in lowered or "key bind" in lowered:
            code = _Failure.AUTHORITY_DELEGATE_NOT_BOUND
        elif "sd_hash" in lowered or "digest" in lowered or "hash" in lowered:
            code = _Failure.AUTHORITY_DIGEST_MISMATCH
        elif "missing" in lowered or "invalid" in lowered or "malformed" in lowered:
            code = _Failure.AUTHORITY_ARTEFACT_INVALID
        else:
            code = _Failure.AUTHORITY_SIGNATURE_INVALID
        issues.append(AuthorityVerificationIssue(code, text))
    return issues or [
        AuthorityVerificationIssue(
            _Failure.AUTHORITY_SIGNATURE_INVALID, "the chain did not verify"
        )
    ]
