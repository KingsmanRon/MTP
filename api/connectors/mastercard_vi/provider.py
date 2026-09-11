"""The Verifiable Intent authority provider.

What this provider answers
--------------------------
Exactly one question, in four parts: is this delegation cryptographically
valid, was it intended for *this* Inntris principal, is it current, and
what scope does it delegate? It answers with a
:class:`~api.core.authority.authority.ResolvedAuthority` and nothing else.

What it never answers
---------------------
Whether the organisation permits the act. Not one organisation-policy
decision is made here, and a verified Verifiable Intent chain is never by
itself an Inntris ALLOW: the payment domain still applies the
organisation's current policy afterwards, and it can block an act this
provider verified perfectly.

The verification checklist
--------------------------
Run in this order, all of it fail-closed:

1. credential material is well-formed and carries no Layer 3;
2. the Layer 1 issuer is one this deployment trusts, and a trusted key is
   resolvable for the ``kid`` it names — no trusted key, no verification;
3. Layer 1's ES256 signature verifies under that key
   (``skip_issuer_verification`` is never used);
4. Layer 1 header ``alg``/``typ``, ``vct`` and ``_sd_alg`` are the pinned
   draft's values;
5. Layer 2's signature verifies under the user key bound by Layer 1
   ``cnf.jwk``;
6. Layer 2's ``sd_hash`` binds to the exact Layer 1 serialization
   presented;
7. Layer 1 and Layer 2 carry ``iat`` and ``exp``, and both windows are
   current within the recommended clock skew;
8. Layer 2 is autonomous mode — ``typ: kb-sd-jwt+kb`` with open mandate
   VCTs. Immediate mode delegates to no agent and is refused;
9. exactly one checkout/payment mandate pair, both disclosed, paired
   through the ``mandate.payment.reference`` constraint whose
   ``conditional_transaction_id`` hashes to the checkout disclosure;
10. Layer 2 ``aud`` is the audience this principal is provisioned under;
11. the agent key in the mandates' ``cnf.jwk`` — identical across the
    pair — has an RFC 7638 thumbprint bound to this Inntris principal by
    trusted server-side state, and is not revoked;
12. the two windows actually overlap, and the delegation's effective
    validity is that intersection — ``max(iat)`` to ``min(exp)``, with no
    clock skew added;
13. every machine-enforceable payment constraint maps into enforceable
    scope, or the delegation is refused.

Steps 3–6, 8 and 9 are performed by the pinned upstream reference
implementation rather than re-implemented here; the rest are Inntris's own
and produce Inntris's own typed failure codes.

Validity is the chain's, not one layer's
----------------------------------------
Step 12 is the one place where verification and authority deliberately
disagree. Verification may accept a credential inside a clock-skew
tolerance; the authority it yields never inherits that tolerance, and it
never outlives the shortest-lived credential in the chain. See
:func:`effective_chain_validity`.

Reuse
-----
Nothing here is stateful, and nothing treats a mandate as single-use. An
Inntris grant is single-use, but the draft does not say a mandate is, and
inventing "one grant ever per Layer 2" would deny authority the user
actually delegated. What this provider does instead is record a stable
mandate-pair reference on every resolution, so the durable decision record
always names which delegation it was made under. Cumulative-use
constraints, which would make reuse accounting necessary, fail closed in
the scope mapper.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from api.connectors.mastercard_vi.binding import (
    DelegateBindingOutcome,
    PrincipalBindingError,
    PrincipalDelegateBindingResolver,
    VerifiableIntentPrincipalBinding,
    binding_from_principal_binding,
)
from api.connectors.mastercard_vi.credential import (
    CredentialMaterialError,
    PresentedCredential,
    read_presented_credential,
)
from api.connectors.mastercard_vi.keys import (
    IssuerKeyError,
    IssuerKeyResolver,
    jwk_thumbprint,
)
from api.connectors.mastercard_vi.profile import (
    AUTHORITY_ISSUER_SCHEME,
    CONSTRAINT_REFERENCE,
    L1_VCT_MASTERCARD_CARD,
    L2_CHECKOUT_VCT_OPEN,
    L2_PAYMENT_VCT_OPEN,
    L2_TYP_AUTONOMOUS,
)
from api.connectors.mastercard_vi.reference import (
    ReferenceImplementationUnavailable,
    load_reference,
)
from api.connectors.mastercard_vi.scope import (
    MappedDelegationScope,
    ScopeMappingError,
    map_payment_mandate,
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

Failure = AuthorityVerificationFailure

#: Clock skew tolerance the draft recommends for every layer.
DEFAULT_CLOCK_SKEW_SECONDS: Final[int] = 300

#: Reference recorded when a caller presented no authority at all. It is a
#: marker, not an identifier of anything that exists.
NO_AUTHORITY_REFERENCE: Final[str] = "no-authority-presented"

#: Cap on operator-facing detail text. Details quote provider and library
#: messages that can contain caller-influenced content.
MAX_DETAIL_CHARS: Final[int] = 512

#: Maps a reference-implementation error string onto a typed failure code,
#: most specific first.
#:
#: This table is matched on substrings of another project's error messages,
#: which is brittle by nature, so nothing security-relevant rests on it:
#: every entry here is already a refusal, and an unmatched message falls
#: through to ``AUTHORITY_ARTEFACT_INVALID``. A drift upstream therefore
#: degrades the *reason* recorded, never the outcome. The checks whose
#: typed reason matters most — expiry, audience, delegate binding, scope —
#: are additionally performed by this connector itself.
_CHAIN_ERROR_CODES: Final[tuple[tuple[str, AuthorityVerificationFailure], ...]] = (
    ("signature verification failed", Failure.AUTHORITY_SIGNATURE_INVALID),
    ("sd_hash", Failure.AUTHORITY_DIGEST_MISMATCH),
    ("conditional_transaction_id", Failure.AUTHORITY_DIGEST_MISMATCH),
    ("reference binding failed", Failure.AUTHORITY_DIGEST_MISMATCH),
    ("checkout-payment binding failed", Failure.AUTHORITY_DIGEST_MISMATCH),
    ("orphaned", Failure.AUTHORITY_DIGEST_MISMATCH),
    ("pairing key collision", Failure.AUTHORITY_DIGEST_MISMATCH),
    ("mandate smuggling", Failure.AUTHORITY_DIGEST_MISMATCH),
    ("iat is in the future", Failure.AUTHORITY_NOT_YET_VALID),
    ("expired at", Failure.AUTHORITY_EXPIRED),
    ("aud mismatch", Failure.AUTHORITY_DELEGATE_NOT_BOUND),
    ("nonce mismatch", Failure.AUTHORITY_ARTEFACT_INVALID),
)


def _truncate(detail: str) -> str:
    detail = " ".join(detail.split())
    if len(detail) <= MAX_DETAIL_CHARS:
        return detail
    return detail[: MAX_DETAIL_CHARS - 1] + "…"


def _classify_chain_errors(errors: list[str]) -> tuple[AuthorityVerificationFailure, str]:
    joined = "; ".join(errors) if errors else "chain verification failed"
    lowered = joined.lower()
    for needle, code in _CHAIN_ERROR_CODES:
        if needle in lowered:
            return code, joined
    # The outcome is unchanged — this is still a refusal — but an
    # unrecognised message is the signal that the pinned reference
    # implementation's error vocabulary has moved, and the table above
    # should be revisited before the pin is bumped.
    logger.warning(
        "unclassified Verifiable Intent chain verification error; "
        "the pinned upstream error vocabulary may have changed: %s",
        _truncate(joined),
    )
    return Failure.AUTHORITY_ARTEFACT_INVALID, joined


def _artefact_digest(credential: PresentedCredential | None) -> str:
    """SHA-256 over exactly the bytes this provider inspected.

    Each part is length-prefixed so two different splits of the same
    concatenation cannot digest alike.
    """
    hasher = hashlib.sha256()
    hasher.update(b"inntris-verifiable-intent-artefact-v1")
    parts = (
        ()
        if credential is None
        else (credential.layer1_serialized, credential.layer2_serialized)
    )
    for part in parts:
        raw = part.encode("utf-8")
        hasher.update(str(len(raw)).encode("ascii"))
        hasher.update(b".")
        hasher.update(raw)
    return hasher.hexdigest()


#: Bounds on a Unix-seconds claim, so a hostile ``exp`` of ``10**20`` is a
#: refusal rather than an ``OverflowError`` out of ``datetime``. The upper
#: bound is 9999-12-31T23:59:59Z, which is the widest instant this system
#: has any reason to represent.
MIN_CLAIM_SECONDS: Final[int] = 0
MAX_CLAIM_SECONDS: Final[int] = 253_402_300_799

#: Upper bound on the mandate-pair reference read out of a credential. It
#: is a base64url SHA-256 digest in the pinned draft; this is a generous
#: ceiling that still keeps a hostile value from reaching identifier
#: validation as a construction error.
MAX_MANDATE_REFERENCE_CHARS: Final[int] = 512


def effective_chain_validity(
    layer1_payload: Mapping[str, Any], layer2_payload: Mapping[str, Any]
) -> tuple[datetime, datetime] | None:
    """The window in which the whole delegation chain is live.

    A delegation exists only while **every** credential it rests on is
    current, so the effective window is the *intersection* of the layers'
    own windows, not Layer 2's window alone::

        not_before = max(L1.iat, L2.iat)
        not_after  = min(L1.exp, L2.exp)

    Taking Layer 2 alone is the failure this function exists to prevent: a
    mandate valid until 11:00 that rests on an issuer credential expiring
    at 10:05 delegates nothing after 10:05, and authority issued against
    it must die at 10:05 too.

    No clock skew is applied. Skew is a tolerance for *reading* a
    timestamp during verification; adding it here would let a tolerance
    meant to absorb clock drift extend real authority past the moment the
    issuer said it ends.

    ``None`` when a required claim is absent or unusable, or when the two
    windows do not overlap at all — in which case there is no instant at
    which this chain ever delegated anything, and the caller fails closed.
    """
    windows: list[tuple[int, int]] = []
    for payload in (layer1_payload, layer2_payload):
        issued = _claim_seconds(payload, "iat")
        expires = _claim_seconds(payload, "exp")
        if issued is None or expires is None:
            return None
        windows.append((issued, expires))

    not_before = max(start for start, _ in windows)
    not_after = min(end for _, end in windows)
    if not_after <= not_before:
        return None
    return (
        datetime.fromtimestamp(not_before, tz=UTC),
        datetime.fromtimestamp(not_after, tz=UTC),
    )


def _claim_seconds(payload: Mapping[str, Any], name: str) -> int | None:
    """A Unix-seconds claim, or ``None`` when it is absent or unusable.

    Out-of-range values read as absent so the caller reports a missing
    required claim: a credential claiming to expire in the year 5,000,000
    has not given this system a validity window it can act on.
    """
    value = payload.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not MIN_CLAIM_SECONDS <= value <= MAX_CLAIM_SECONDS:
        return None
    return value


@dataclass(frozen=True, slots=True)
class VerifiableIntentResolution:
    """The connector's own record of one resolution, for tests and operators.

    ``ResolvedAuthority`` is deliberately narrow; this carries the
    connector-side detail — which checks the reference implementation ran,
    which checkout constraints were seen and left outside the boundary —
    that would be noise inside the neutral boundary type.
    """

    resolved: ResolvedAuthority
    mapped_scope: MappedDelegationScope | None = None
    agent_key_thumbprint: str | None = None
    mandate_pair_reference: str | None = None
    reference_checks_performed: tuple[str, ...] = ()
    reference_checks_skipped: tuple[str, ...] = ()


@dataclass
class VerifiableIntentAuthorityProvider:
    """``AuthorityProvider`` over the pinned Verifiable Intent draft.

    ``issuer_key_resolver`` and ``binding_resolver`` are the two trusted
    inputs. Neither is derived from the request being evaluated, which is
    the property that makes the answer mean anything.
    """

    issuer_key_resolver: IssuerKeyResolver
    binding_resolver: PrincipalDelegateBindingResolver | None = None
    #: Layer 1 credential types accepted. Defaults to the Mastercard
    #: reference profile; a deployment provisioning another credential
    #: provider names its VCT here.
    expected_l1_vct: str = L1_VCT_MASTERCARD_CARD
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))

    # -- the port ---------------------------------------------------------

    def resolve(
        self,
        raw_authority: DelegatedAuthorityClaim | None,
        expected_principal_context: ExecutionContext,
    ) -> ResolvedAuthority:
        """Resolve a presented Verifiable Intent delegation. Never raises on denial."""
        return self.resolve_detailed(raw_authority, expected_principal_context).resolved

    # -- the same work, with the connector-side detail kept ---------------

    def resolve_detailed(
        self,
        raw_authority: DelegatedAuthorityClaim | None,
        expected_principal_context: ExecutionContext,
    ) -> VerifiableIntentResolution:
        if raw_authority is None:
            return VerifiableIntentResolution(
                resolved=self._unresolved(
                    issuer=AUTHORITY_ISSUER_SCHEME,
                    external_reference_id=NO_AUTHORITY_REFERENCE,
                    artefact_digest=_artefact_digest(None),
                    code=Failure.AUTHORITY_NOT_FOUND,
                    detail="no delegated authority was presented",
                    status=VerificationStatus.UNVERIFIED,
                )
            )

        claim = raw_authority

        def fail(
            code: AuthorityVerificationFailure,
            detail: str,
            *,
            digest: str,
            status: VerificationStatus = VerificationStatus.FAILED,
            binding_status: DelegateBindingStatus = DelegateBindingStatus.UNKNOWN,
        ) -> VerifiableIntentResolution:
            return VerifiableIntentResolution(
                resolved=self._unresolved(
                    issuer=claim.issuer,
                    external_reference_id=claim.external_reference_id,
                    artefact_digest=digest,
                    code=code,
                    detail=detail,
                    status=status,
                    binding_status=binding_status,
                )
            )

        empty_digest = _artefact_digest(None)

        # 1. Credential material, before anything reads it as a credential.
        try:
            credential = read_presented_credential(claim.evidence)
        except CredentialMaterialError as exc:
            return fail(Failure.AUTHORITY_ARTEFACT_INVALID, str(exc), digest=empty_digest)

        digest = _artefact_digest(credential)

        # 2. The pinned reference implementation must be loadable. A verifier
        #    that cannot run its verification reports unavailability; it never
        #    reports success.
        try:
            ref = load_reference()
        except ReferenceImplementationUnavailable as exc:
            return fail(
                Failure.AUTHORITY_PROVIDER_UNAVAILABLE,
                str(exc),
                digest=digest,
                status=VerificationStatus.UNAVAILABLE,
            )

        try:
            layer1 = ref.decode_sd_jwt(credential.layer1_serialized)
            layer2 = ref.decode_sd_jwt(credential.layer2_serialized)
        except ValueError as exc:
            return fail(
                Failure.AUTHORITY_ARTEFACT_INVALID,
                f"the presented credential could not be parsed: {exc}",
                digest=digest,
            )

        if not isinstance(layer1.payload, dict) or not isinstance(layer2.payload, dict):
            return fail(
                Failure.AUTHORITY_ARTEFACT_INVALID,
                "a presented credential payload is not a JSON object",
                digest=digest,
            )

        # 3. The claim must name the issuer the credential was actually
        #    signed by. A claim that names one issuer and carries another's
        #    credential is not a labelling slip; it is the shape a confused
        #    trust decision takes.
        l1_issuer = layer1.payload.get("iss")
        if not isinstance(l1_issuer, str) or l1_issuer != claim.issuer:
            return fail(
                Failure.AUTHORITY_ARTEFACT_INVALID,
                f"the claim names issuer {claim.issuer!r} but Layer 1 was issued by "
                f"{l1_issuer!r}",
                digest=digest,
            )

        # 4. Claims the draft marks REQUIRED and the reference implementation
        #    tolerates the absence of. Recorded divergence: the normative
        #    requirement wins, and a credential without a validity window is
        #    refused rather than treated as valid forever.
        missing = self._missing_required_claims(layer1.payload, layer2.payload)
        if missing:
            return fail(
                Failure.AUTHORITY_ARTEFACT_INVALID,
                "the presented credential omits claims the draft marks REQUIRED: "
                + ", ".join(missing),
                digest=digest,
            )

        # 5. The principal this authority must belong to, from trusted state.
        try:
            binding = self._binding_for(expected_principal_context)
        except PrincipalBindingError as exc:
            return fail(
                Failure.AUTHORITY_PRINCIPAL_MISMATCH,
                f"the provisioned delegate binding is unusable: {exc}",
                digest=digest,
            )
        if binding is None:
            return fail(
                Failure.AUTHORITY_PRINCIPAL_MISMATCH,
                "no Verifiable Intent delegate binding is provisioned for "
                f"organisation {expected_principal_context.organisation_id!r} "
                f"principal {expected_principal_context.principal_id!r}; a valid "
                "credential is not evidence that it belongs to this principal",
                digest=digest,
                binding_status=DelegateBindingStatus.NOT_BOUND,
            )

        # 6. A trusted key for the issuer, located by the header kid.
        header_kid = layer1.header.get("kid") if isinstance(layer1.header, dict) else None
        if header_kid is not None and not isinstance(header_kid, str):
            header_kid = None
        try:
            issuer_key = self.issuer_key_resolver.public_key_for(l1_issuer, header_kid)
        except IssuerKeyError as exc:
            return fail(
                Failure.AUTHORITY_SIGNATURE_INVALID,
                f"the provisioned issuer keyset is unusable: {exc}",
                digest=digest,
            )
        if issuer_key is None:
            return fail(
                Failure.AUTHORITY_SIGNATURE_INVALID,
                f"no trusted signing key is provisioned for issuer {l1_issuer!r} "
                f"kid {header_kid!r}; the Layer 1 signature cannot be accepted",
                digest=digest,
            )

        # 7. The chain itself, through the pinned reference implementation.
        result = ref.verify_chain(
            layer1,
            layer2,
            issuer_public_key=issuer_key,
            l1_serialized=credential.layer1_serialized,
            l2_serialized=credential.layer2_serialized,
            expected_l2_aud=binding.expected_audience,
            expected_l1_vct=self.expected_l1_vct,
            clock_skew_seconds=self.clock_skew_seconds,
        )
        if not result.valid:
            code, detail = _classify_chain_errors(list(result.errors))
            binding_status = (
                DelegateBindingStatus.NOT_BOUND
                if code is Failure.AUTHORITY_DELEGATE_NOT_BOUND
                else DelegateBindingStatus.UNKNOWN
            )
            return fail(code, detail, digest=digest, binding_status=binding_status)

        checks_performed = tuple(result.checks_performed)
        checks_skipped = tuple(result.checks_skipped)

        # 8. Autonomous mode, one fully disclosed mandate pair.
        pair_error = self._check_mandate_pair(result, layer2)
        if pair_error is not None:
            code, detail = pair_error
            return fail(code, detail, digest=digest)

        pair = result.pair_results[0]
        checkout_mandate = dict(pair.checkout_mandate)
        payment_mandate = dict(pair.payment_mandate)

        # 9. The audience the mandate was addressed to. The reference
        #    implementation has already enforced this from
        #    ``expected_l2_aud``; repeating it here keeps the check owned by
        #    the connector, with the connector's typed reason, if that ever
        #    stops being true upstream.
        if layer2.payload.get("aud") != binding.expected_audience:
            return fail(
                Failure.AUTHORITY_DELEGATE_NOT_BOUND,
                "the Layer 2 mandate was addressed to a different agent audience "
                "than this principal is provisioned under",
                digest=digest,
                binding_status=DelegateBindingStatus.NOT_BOUND,
            )

        # 10. The delegate key, by thumbprint. A kid is a label; the
        #     thumbprint is derived from the key itself.
        agent_jwk, agent_kid = self._agent_key(checkout_mandate, payment_mandate)
        if agent_jwk is None:
            return fail(
                Failure.AUTHORITY_DELEGATE_NOT_BOUND,
                "the Layer 2 mandates carry no agent key (cnf.jwk) to delegate to",
                digest=digest,
                binding_status=DelegateBindingStatus.NOT_BOUND,
            )
        try:
            thumbprint = jwk_thumbprint(agent_jwk)
        except IssuerKeyError as exc:
            return fail(
                Failure.AUTHORITY_ARTEFACT_INVALID,
                f"the delegated agent key is malformed: {exc}",
                digest=digest,
            )

        outcome = binding.check_delegate(thumbprint, agent_kid)
        if outcome is not DelegateBindingOutcome.BOUND:
            code = (
                Failure.AUTHORITY_REVOKED
                if outcome is DelegateBindingOutcome.KEY_REVOKED
                else Failure.AUTHORITY_DELEGATE_NOT_BOUND
            )
            return fail(
                code,
                f"the delegated agent key is not bound to this principal ({outcome.value})",
                digest=digest,
                binding_status=DelegateBindingStatus.NOT_BOUND,
            )

        # 11. The mandate-pair reference, as the draft defines it.
        mandate_reference = self._mandate_pair_reference(payment_mandate)
        if mandate_reference is None:
            return fail(
                Failure.AUTHORITY_ARTEFACT_INVALID,
                "the payment mandate carries no usable mandate.payment.reference "
                "conditional_transaction_id to identify this delegation by",
                digest=digest,
            )
        if claim.external_reference_id != mandate_reference:
            return fail(
                Failure.AUTHORITY_DIGEST_MISMATCH,
                "the claim's external_reference_id is not this credential's mandate "
                "pair reference",
                digest=digest,
            )

        # 12. The effective validity window: the intersection of both
        #     credentials' own windows, never Layer 2's alone. A mandate
        #     cannot outlive the issuer credential it is bound to.
        window = effective_chain_validity(layer1.payload, layer2.payload)
        if window is None:
            return fail(
                Failure.AUTHORITY_EXPIRED,
                "the Layer 1 and Layer 2 validity windows do not overlap, so there "
                "is no instant at which this chain delegates anything",
                digest=digest,
            )
        not_before, not_after = window

        # 13. Scope, or a refusal.
        disclosure_values = self._disclosure_values(ref, layer2)
        try:
            mapped = map_payment_mandate(
                payment_mandate,
                checkout_mandate,
                disclosure_values,
                not_before=not_before,
                not_after=not_after,
            )
        except ScopeMappingError as exc:
            return fail(exc.code, exc.detail, digest=digest)

        construction = trusted_authority_construction()
        now = self._now()
        reference = DelegatedAuthorityReference(
            construction,
            issuer=claim.issuer,
            external_reference_id=mandate_reference,
            artefact_digest=digest,
            verification_status=VerificationStatus.VERIFIED,
            verified_at=now,
            not_before=not_before,
            not_after=not_after,
        )
        resolved = ResolvedAuthority(
            construction,
            reference=reference,
            delegate_binding_status=DelegateBindingStatus.BOUND,
            delegate_binding_reference=thumbprint,
            scope=dict(mapped.scope),
            not_before=not_before,
            not_after=not_after,
        )
        return VerifiableIntentResolution(
            resolved=resolved,
            mapped_scope=mapped,
            agent_key_thumbprint=thumbprint,
            mandate_pair_reference=mandate_reference,
            reference_checks_performed=checks_performed,
            reference_checks_skipped=checks_skipped,
        )

    # -- helpers ----------------------------------------------------------

    def _now(self) -> datetime:
        now = self.clock()
        if now.tzinfo is None:
            raise ValueError("the provider clock must return an aware datetime")
        return now.astimezone(UTC)

    def _unresolved(
        self,
        *,
        issuer: str,
        external_reference_id: str,
        artefact_digest: str,
        code: AuthorityVerificationFailure,
        detail: str,
        status: VerificationStatus,
        binding_status: DelegateBindingStatus = DelegateBindingStatus.UNKNOWN,
    ) -> ResolvedAuthority:
        construction = trusted_authority_construction()
        reference = DelegatedAuthorityReference(
            construction,
            issuer=issuer,
            external_reference_id=external_reference_id,
            artefact_digest=artefact_digest,
            verification_status=status,
        )
        return ResolvedAuthority(
            construction,
            reference=reference,
            delegate_binding_status=binding_status,
            issues=(AuthorityVerificationIssue(code=code, detail=_truncate(detail)),),
        )

    def _binding_for(
        self, context: ExecutionContext
    ) -> VerifiableIntentPrincipalBinding | None:
        from_context = binding_from_principal_binding(
            context.principal_binding,
            organisation_id=context.organisation_id,
            principal_id=context.principal_id,
        )
        if from_context is not None:
            return from_context
        if self.binding_resolver is None:
            return None
        return self.binding_resolver.binding_for(
            context.organisation_id, context.principal_id
        )

    @staticmethod
    def _missing_required_claims(
        l1_payload: Mapping[str, Any], l2_payload: Mapping[str, Any]
    ) -> list[str]:
        missing: list[str] = []
        for name in ("iat", "exp"):
            if _claim_seconds(l1_payload, name) is None:
                missing.append(f"layer1.{name}")
            if _claim_seconds(l2_payload, name) is None:
                missing.append(f"layer2.{name}")
        nonce = l2_payload.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            missing.append("layer2.nonce")
        return missing

    def _check_mandate_pair(
        self, result: Any, layer2: Any
    ) -> tuple[AuthorityVerificationFailure, str] | None:
        """Require autonomous mode and exactly one fully disclosed pair."""
        typ = layer2.header.get("typ") if isinstance(layer2.header, dict) else None
        if typ != L2_TYP_AUTONOMOUS:
            return (
                Failure.AUTHORITY_ARTEFACT_INVALID,
                f"Layer 2 is not an autonomous-mode credential (typ={typ!r}); a "
                "mandate that confirms final values delegates nothing to an agent",
            )
        if result.mandate_pair_count != 1:
            return (
                Failure.AUTHORITY_SCOPE_UNREADABLE,
                f"the Layer 2 credential carries {result.mandate_pair_count} mandate "
                "pairs; this release authorises one act against one pair and cannot "
                "tell which pair a proposed act falls under",
            )
        if not (result.l2_checkout_disclosed and result.l2_payment_disclosed):
            return (
                Failure.AUTHORITY_SCOPE_UNREADABLE,
                "the Layer 2 presentation withheld one of the paired mandates, so "
                "the checkout/payment pairing cannot be verified",
            )
        if "l2_reference_binding" not in result.checks_performed:
            return (
                Failure.AUTHORITY_DIGEST_MISMATCH,
                "the checkout/payment reference binding was not verified for this "
                "mandate pair",
            )
        pair = result.pair_results[0]
        checkout_vct = pair.checkout_mandate.get("vct")
        payment_vct = pair.payment_mandate.get("vct")
        if checkout_vct != L2_CHECKOUT_VCT_OPEN or payment_vct != L2_PAYMENT_VCT_OPEN:
            return (
                Failure.AUTHORITY_ARTEFACT_INVALID,
                f"the mandate pair is not autonomous (checkout vct={checkout_vct!r}, "
                f"payment vct={payment_vct!r})",
            )
        return None

    @staticmethod
    def _agent_key(
        checkout_mandate: Mapping[str, Any], payment_mandate: Mapping[str, Any]
    ) -> tuple[Mapping[str, Any] | None, str | None]:
        """The agent key both mandates delegate to, and its ``kid`` label.

        The reference implementation has already rejected a pair whose
        ``cnf.jwk`` values differ, so reading either is reading both.
        """
        for mandate in (payment_mandate, checkout_mandate):
            cnf = mandate.get("cnf")
            jwk = cnf.get("jwk") if isinstance(cnf, Mapping) else None
            if isinstance(jwk, Mapping) and jwk:
                kid = jwk.get("kid")
                return jwk, kid if isinstance(kid, str) and kid else None
        return None, None

    @staticmethod
    def _mandate_pair_reference(payment_mandate: Mapping[str, Any]) -> str | None:
        """The draft's own identifier for this mandate pair, shape-checked.

        The value is recorded on the durable decision as an identifier, so
        it is bounded and restricted to printable ASCII here. A hostile
        credential carrying control characters or a megabyte of text
        produces a refusal rather than a construction error further in.
        """
        constraints = payment_mandate.get("constraints")
        if not isinstance(constraints, list):
            return None
        for constraint in constraints:
            if not isinstance(constraint, Mapping):
                continue
            if constraint.get("type") != CONSTRAINT_REFERENCE:
                continue
            value = constraint.get("conditional_transaction_id")
            if not isinstance(value, str) or not value:
                continue
            if len(value) > MAX_MANDATE_REFERENCE_CHARS:
                continue
            if any(not ("!" <= char <= "~") for char in value):
                continue
            return value
        return None

    @staticmethod
    def _disclosure_values(ref: Any, layer2: Any) -> dict[str, Any]:
        """Index the Layer 2 disclosures the holder chose to reveal, by hash."""
        values: dict[str, Any] = {}
        for disclosure, decoded in zip(
            layer2.disclosures, layer2.disclosure_values, strict=False
        ):
            if not isinstance(decoded, list) or not decoded:
                continue
            values[ref.hash_disclosure(disclosure)] = decoded[-1]
        return values
