"""Phase 5 — the Verifiable Intent authority provider.

Every credential in this module is minted by the pinned upstream reference
implementation from test-only P-256 keys derived from fixed seeds, so the
fixtures are reproducible and no production key material exists anywhere
near them.

The adversarial catalogue lives in
``tests/fixtures/mastercard_vi/cases.json`` and every case in it must fail
**for the reason recorded there**, not merely fail. A verifier that
refuses everything is trivially safe and useless; what has to hold is that
each refusal names the thing that was actually wrong.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import itertools
import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from api.adapters.verify_envelope import build_action_envelope
from api.connectors.mastercard_vi import (
    PRINCIPAL_BINDING_CONTEXT_KEY,
    DelegateBindingOutcome,
    PrincipalBindingError,
    StaticIssuerKeyResolver,
    StaticPrincipalDelegateBindingResolver,
    TrustedIssuerKeyset,
    VerifiableIntentAuthorityProvider,
    VerifiableIntentPrincipalBinding,
    jwk_thumbprint,
)
from api.connectors.mastercard_vi import profile as vi_profile
from api.connectors.mastercard_vi import provider as vi_provider
from api.connectors.mastercard_vi.reference import ReferenceImplementationUnavailable
from api.core.authority.authority import (
    AuthorityVerificationFailure,
    DelegateBindingStatus,
    DelegatedAuthorityClaim,
    ExecutionContext,
    VerificationStatus,
    trusted_authority_construction,
)
from api.core.authority.decision import Decision, DecisionReason
from api.domains.payment.binding import ExecutionDestination, PayeeBinding
from api.domains.payment.delegation import KNOWN_SCOPE_KEYS, parse_delegation_constraints
from api.domains.payment.policy import PaymentDomainPolicy
from api.models import AgentRecord, AgentStatus

# In CI the reference implementation is installed by an explicit step, so a
# skip there does not mean "optional dependency absent" — it means that step
# silently did not run, and the connector's whole test surface would vanish
# without anything going red. Fail loudly instead.
if importlib.util.find_spec("verifiable_intent") is None and os.environ.get("CI"):
    raise RuntimeError(
        "the pinned verifiable-intent reference implementation is missing in CI; "
        "the 'install the pinned Verifiable Intent reference implementation' step "
        "must run before pytest"
    )

vi = pytest.importorskip(
    "verifiable_intent",
    reason=(
        "the pinned verifiable-intent reference implementation is an optional "
        "extra; install with pip install -e '.[mastercard-vi]'"
    ),
)

from verifiable_intent.crypto import disclosure as vi_disclosure  # noqa: E402
from verifiable_intent.crypto.disclosure import hash_bytes  # noqa: E402
from verifiable_intent.crypto.sd_jwt import decode_sd_jwt, resolve_disclosures  # noqa: E402
from verifiable_intent.crypto.signing import public_key_to_jwk  # noqa: E402
from verifiable_intent.issuance.issuer import create_layer1  # noqa: E402
from verifiable_intent.issuance.user import (  # noqa: E402
    create_layer2_autonomous,
    create_layer2_immediate,
)
from verifiable_intent.models.constraints import (  # noqa: E402
    AgentRecurrenceConstraint,
    AllowedMerchantConstraint,
    AllowedPayeeConstraint,
    CheckoutLineItemsConstraint,
    Constraint,
    PaymentAmountConstraint,
    PaymentBudgetConstraint,
    ReferenceConstraint,
)
from verifiable_intent.models.issuer_credential import IssuerCredential  # noqa: E402
from verifiable_intent.models.user_mandate import (  # noqa: E402
    CheckoutMandate,
    MandateMode,
    PaymentMandate,
    UserMandate,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "mastercard_vi"

ISSUER = "https://issuer.mastercard.com"
ISSUER_KID = "mastercard-issuer-key-1"
WALLET = "https://wallet.example"
AGENT_AUDIENCE = "https://agents.inntris.example/vi"
AGENT_KID = "inntris-agent-key-1"
USER_KID = "user-device-key-1"

ORGANISATION_ID = "org-vi-fixture"
PRINCIPAL_ID = "agent-vi-fixture"

SUPPLIER_A = {
    "id": "supplier-a",
    "name": "Supplier A",
    "website": "https://supplier-a.example",
}
SUPPLIER_B = {
    "id": "supplier-b",
    "name": "Supplier B",
    "website": "https://supplier-b.example",
}
ACCEPTABLE_ITEMS = [
    {"id": "SKU-RACK-1U", "title": "Datacentre rack unit, 1U"},
    {"id": "SKU-PSU-750", "title": "Redundant power supply, 750W"},
]
PAYMENT_INSTRUMENT = {
    "type": "mastercard.srcDigitalCard",
    "id": "card-vi-fixture-0001",
    "description": "Mastercard **** 4242",
}

#: USD 20,000.00, as the draft expresses it: integer minor units.
MAX_MINOR_UNITS = 2_000_000

CHAIN = "eip155:8453"
BOUND_ACCOUNT = "0x1111111111111111111111111111111111111111"

DAY = 86_400
P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)


# ---------------------------------------------------------------------------
# Deterministic test-only key material and salts
# ---------------------------------------------------------------------------


def deterministic_key(label: str) -> ec.EllipticCurvePrivateKey:
    """A reproducible P-256 test key, derived rather than embedded.

    Deriving from a labelled seed keeps the fixtures byte-reproducible
    without a literal private scalar sitting in the repository for a secret
    scanner — or a reader — to mistake for something real.
    """
    seed = hashlib.sha256(f"inntris-verifiable-intent-fixture:{label}".encode()).digest()
    value = (int.from_bytes(seed, "big") % (P256_ORDER - 1)) + 1
    return ec.derive_private_key(value, ec.SECP256R1())


ISSUER_KEY = deterministic_key("issuer")
OTHER_ISSUER_KEY = deterministic_key("issuer-impostor")
USER_KEY = deterministic_key("user")
AGENT_KEY = deterministic_key("agent")
OTHER_AGENT_KEY = deterministic_key("agent-other")


@contextmanager
def deterministic_salts(label: str):
    """Make SD-JWT disclosure salts reproducible for the duration of a build."""
    counter = itertools.count()

    def _salt() -> str:
        raw = hashlib.sha256(f"{label}:{next(counter)}".encode()).digest()[:16]
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    original = vi_disclosure._generate_salt
    vi_disclosure._generate_salt = _salt
    try:
        yield
    finally:
        vi_disclosure._generate_salt = original


# ---------------------------------------------------------------------------
# Chain construction
# ---------------------------------------------------------------------------

_UNSET = object()


@dataclass(frozen=True)
class Chain:
    """One built credential chain plus what a caller would present with it."""

    layer1_serialized: str
    layer2_serialized: str
    mandate_pair_reference: str

    def evidence(self) -> dict[str, str]:
        return {"layer1": self.layer1_serialized, "layer2": self.layer2_serialized}

    def claim(self, *, issuer: str = ISSUER, reference: str | None = None):
        return DelegatedAuthorityClaim(
            issuer=issuer,
            external_reference_id=reference or self.mandate_pair_reference,
            evidence=self.evidence(),
        )


def build_layer1(
    *,
    now: int,
    signing_key: ec.EllipticCurvePrivateKey = ISSUER_KEY,
    user_key: ec.EllipticCurvePrivateKey = USER_KEY,
    iat_offset: int = -DAY,
    exp_offset: int = 300 * DAY,
    issuer: str = ISSUER,
    sub: str = "user-vi-fixture-001",
    label: str = "layer1",
):
    credential = IssuerCredential(
        iss=issuer,
        sub=sub,
        iat=now + iat_offset,
        exp=now + exp_offset,
        vct=vi_profile.L1_VCT_MASTERCARD_CARD,
        aud=WALLET,
        cnf_jwk=public_key_to_jwk(user_key),
        pan_last_four="4242",
        scheme="mastercard",
        card_id=PAYMENT_INSTRUMENT["id"],
        email="procurement@buyer.example",
    )
    with deterministic_salts(label):
        return create_layer1(credential, signing_key, kid=ISSUER_KID)


def default_payment_constraints() -> list[Constraint]:
    return [
        PaymentAmountConstraint(currency="USD", max=MAX_MINOR_UNITS),
        AllowedPayeeConstraint(allowed=[SUPPLIER_A, SUPPLIER_B]),
    ]


def default_checkout_constraints() -> list[Constraint]:
    return [
        AllowedMerchantConstraint(allowed=[SUPPLIER_A, SUPPLIER_B]),
        CheckoutLineItemsConstraint(
            items=[
                {
                    "id": "line-1",
                    "acceptable_items": list(ACCEPTABLE_ITEMS),
                    "quantity": 4,
                }
            ]
        ),
    ]


def build_chain(
    *,
    now: int | None = None,
    layer1=None,
    sd_hash_over=None,
    aud: str = AGENT_AUDIENCE,
    agent_key: ec.EllipticCurvePrivateKey = AGENT_KEY,
    agent_kid: str = AGENT_KID,
    user_key: ec.EllipticCurvePrivateKey = USER_KEY,
    l2_iat_offset: int = -60,
    l2_exp: Any = _UNSET,
    l2_exp_offset: int = 30 * DAY,
    payment_constraints: list[Constraint] | None = None,
    checkout_constraints: list[Constraint] | None = None,
    disclose_payees: bool = True,
    label: str = "layer2",
) -> Chain:
    """Build an autonomous L1+L2 chain, with one knob per adversarial case."""
    now = int(time.time()) if now is None else now
    layer1 = build_layer1(now=now) if layer1 is None else layer1
    layer1_serialized = layer1.serialize()
    binding_source = layer1_serialized if sd_hash_over is None else sd_hash_over

    mandate = UserMandate(
        nonce="4f0a2b7c9d1e3f5a",
        aud=aud,
        iat=now + l2_iat_offset,
        iss=WALLET,
        exp=(now + l2_exp_offset) if l2_exp is _UNSET else l2_exp,
        mode=MandateMode.AUTONOMOUS,
        sd_hash=hash_bytes(binding_source.encode("ascii")),
        prompt_summary="Restock approved datacentre suppliers",
        checkout_mandate=CheckoutMandate(
            vct=vi_profile.L2_CHECKOUT_VCT_OPEN,
            cnf_jwk=public_key_to_jwk(agent_key),
            cnf_kid=agent_kid,
            constraints=(
                default_checkout_constraints()
                if checkout_constraints is None
                else checkout_constraints
            ),
        ),
        payment_mandate=PaymentMandate(
            vct=vi_profile.L2_PAYMENT_VCT_OPEN,
            cnf_jwk=public_key_to_jwk(agent_key),
            cnf_kid=agent_kid,
            payment_instrument=PAYMENT_INSTRUMENT,
            constraints=(
                default_payment_constraints()
                if payment_constraints is None
                else payment_constraints
            ),
        ),
        merchants=[SUPPLIER_A, SUPPLIER_B],
        acceptable_items=list(ACCEPTABLE_ITEMS),
    )
    with deterministic_salts(label):
        layer2 = create_layer2_autonomous(mandate, user_key, kid=USER_KID)

    if disclose_payees:
        layer2_serialized = layer2.serialize()
    else:
        layer2_serialized = layer2.serialize(
            include_disclosures=mandate_disclosure_indices(layer2)
        )

    return Chain(
        layer1_serialized=layer1_serialized,
        layer2_serialized=layer2_serialized,
        mandate_pair_reference=mandate_pair_reference(layer2),
    )


def mandate_disclosure_indices(layer2) -> list[int]:
    """Indices of the two mandate disclosures, withholding everything else."""
    wanted = {vi_profile.L2_CHECKOUT_VCT_OPEN, vi_profile.L2_PAYMENT_VCT_OPEN}
    indices = []
    for index, value in enumerate(layer2.disclosure_values):
        payload = value[-1] if value else None
        if isinstance(payload, dict) and payload.get("vct") in wanted:
            indices.append(index)
    return indices


def mandate_pair_reference(layer2) -> str:
    claims = resolve_disclosures(layer2)
    for delegate in claims.get("delegate_payload", []):
        if not isinstance(delegate, dict):
            continue
        if delegate.get("vct") != vi_profile.L2_PAYMENT_VCT_OPEN:
            continue
        for constraint in delegate.get("constraints", []):
            if constraint.get("type") == vi_profile.CONSTRAINT_REFERENCE:
                return str(constraint.get("conditional_transaction_id", ""))
    return ""


def build_immediate_chain(*, now: int | None = None) -> Chain:
    now = int(time.time()) if now is None else now
    layer1 = build_layer1(now=now)
    mandate = UserMandate(
        nonce="7a1b2c3d4e5f6071",
        aud=AGENT_AUDIENCE,
        iat=now - 60,
        iss=WALLET,
        exp=now + 900,
        mode=MandateMode.IMMEDIATE,
        sd_hash=hash_bytes(layer1.serialize().encode("ascii")),
        checkout_mandate=CheckoutMandate(
            vct=vi_profile.L2_CHECKOUT_VCT_FINAL,
            checkout_jwt="eyJhbGciOiJFUzI1NiJ9.e30.signature-placeholder",
        ),
        payment_mandate=PaymentMandate(
            vct=vi_profile.L2_PAYMENT_VCT_FINAL,
            payment_instrument=PAYMENT_INSTRUMENT,
            payee=SUPPLIER_A,
            currency="USD",
            amount=5_000,
        ),
    )
    with deterministic_salts("immediate"):
        result = create_layer2_immediate(mandate, USER_KEY, kid=USER_KID)
    return Chain(
        layer1_serialized=layer1.serialize(),
        layer2_serialized=result.serialize(),
        mandate_pair_reference="immediate-mode-has-no-mandate-pair-reference",
    )


# ---------------------------------------------------------------------------
# Trusted server-side state
# ---------------------------------------------------------------------------

AGENT_THUMBPRINT = jwk_thumbprint(public_key_to_jwk(AGENT_KEY))
OTHER_AGENT_THUMBPRINT = jwk_thumbprint(public_key_to_jwk(OTHER_AGENT_KEY))


def issuer_keys(*, key: ec.EllipticCurvePrivateKey = ISSUER_KEY, issuer: str = ISSUER):
    return StaticIssuerKeyResolver(
        [TrustedIssuerKeyset(issuer=issuer, keys={ISSUER_KID: public_key_to_jwk(key)})]
    )


def principal_binding(
    *,
    thumbprints=(AGENT_THUMBPRINT,),
    revoked=(),
    audience: str = AGENT_AUDIENCE,
    key_ids=None,
) -> VerifiableIntentPrincipalBinding:
    return VerifiableIntentPrincipalBinding(
        organisation_id=ORGANISATION_ID,
        principal_id=PRINCIPAL_ID,
        expected_audience=audience,
        agent_key_thumbprints=frozenset(thumbprints),
        revoked_agent_key_thumbprints=frozenset(revoked),
        agent_key_ids=None if key_ids is None else frozenset(key_ids),
        source="test-provisioning",
    )


def provider(
    *,
    binding: VerifiableIntentPrincipalBinding | None = None,
    keys=None,
    with_binding: bool = True,
) -> VerifiableIntentAuthorityProvider:
    resolver = None
    if with_binding:
        resolver = StaticPrincipalDelegateBindingResolver.from_bindings(
            [binding or principal_binding()]
        )
    return VerifiableIntentAuthorityProvider(
        issuer_key_resolver=keys or issuer_keys(),
        binding_resolver=resolver,
    )


def context(principal_binding_payload=None) -> ExecutionContext:
    return ExecutionContext(
        trusted_authority_construction(),
        organisation_id=ORGANISATION_ID,
        principal_id=PRINCIPAL_ID,
        principal_binding=principal_binding_payload or {},
    )


def codes(resolved) -> set[str]:
    return {code.value for code in resolved.failure_codes}


def only_code(resolved) -> str:
    assert len(resolved.issues) == 1, resolved.issues
    return resolved.issues[0].code.value


# ---------------------------------------------------------------------------
# The pin
# ---------------------------------------------------------------------------


class TestUpstreamPin:
    """The connector must agree with the recorded upstream revision."""

    def test_the_pinned_revision_matches_the_recorded_fixture(self) -> None:
        pin = json.loads((FIXTURE_DIR / "upstream_pin.json").read_text())
        assert pin["commit"] == vi_profile.UPSTREAM_COMMIT
        assert pin["package_version"] == vi_profile.UPSTREAM_PACKAGE_VERSION
        assert pin["repository"] == vi_profile.UPSTREAM_REPOSITORY
        assert pin["site"] == vi_profile.UPSTREAM_SITE
        assert pin["spec_revision"] == vi_profile.SPEC_REVISION
        assert pin["spec_date"] == vi_profile.SPEC_DATE

    def test_the_installed_reference_implementation_is_the_pinned_version(self) -> None:
        assert vi.__version__ == vi_profile.UPSTREAM_PACKAGE_VERSION

    def test_a_different_installed_version_refuses_to_load(self, monkeypatch) -> None:
        from api.connectors.mastercard_vi import reference

        reference.load_reference.cache_clear()
        monkeypatch.setattr(vi, "__version__", "9.9.9")
        try:
            with pytest.raises(ReferenceImplementationUnavailable, match="pinned"):
                reference.load_reference()
        finally:
            reference.load_reference.cache_clear()


# ---------------------------------------------------------------------------
# The main fixture
# ---------------------------------------------------------------------------


class TestValidAutonomousDelegation:
    def test_valid_autonomous_delegation(self) -> None:
        chain = build_chain()
        detail = provider().resolve_detailed(chain.claim(), context())
        resolved = detail.resolved

        assert resolved.is_verified, resolved.issues
        assert resolved.verification_status is VerificationStatus.VERIFIED
        assert resolved.delegate_binding_status is DelegateBindingStatus.BOUND
        assert resolved.delegate_binding_reference == AGENT_THUMBPRINT
        assert resolved.reference.external_reference_id == chain.mandate_pair_reference

    def test_the_scope_matches_the_golden_mapping(self) -> None:
        golden = json.loads((FIXTURE_DIR / "golden_scope.json").read_text())
        detail = provider().resolve_detailed(build_chain().claim(), context())
        scope = dict(detail.resolved.scope)

        for key, expected in golden["scope"].items():
            assert scope[key] == expected, key
        assert set(scope) == set(golden["scope"]) | set(
            golden["scope_keys_derived_from_layer2_validity"]
        )

    def test_twenty_thousand_dollars_maps_through_minor_units_losslessly(self) -> None:
        detail = provider().resolve_detailed(build_chain().claim(), context())
        constraints = parse_delegation_constraints(detail.resolved.scope)

        assert constraints.max_amount is not None
        assert constraints.max_amount.currency == "USD"
        assert constraints.max_amount.minor_units == MAX_MINOR_UNITS
        assert constraints.max_amount.as_decimal() == Decimal("20000.00")

    def test_the_mapped_scope_is_fully_enforceable_by_the_payment_domain(self) -> None:
        detail = provider().resolve_detailed(build_chain().claim(), context())
        constraints = parse_delegation_constraints(detail.resolved.scope)

        assert constraints.is_fully_enforceable
        assert constraints.unsupported_constraints == ()
        assert constraints.allowed_payees == frozenset(
            {"payee:id:supplier-a", "payee:id:supplier-b"}
        )

    def test_the_validity_window_comes_from_the_mandate(self) -> None:
        now = int(time.time())
        chain = build_chain(now=now)
        resolved = provider().resolve(chain.claim(), context())

        assert resolved.not_before == datetime.fromtimestamp(now - 60, tz=UTC)
        assert resolved.not_after == datetime.fromtimestamp(now + 30 * DAY, tz=UTC)
        assert resolved.is_within_validity(datetime.now(UTC))

    def test_the_checkout_constraints_are_recorded_rather_than_silently_dropped(
        self,
    ) -> None:
        detail = provider().resolve_detailed(build_chain().claim(), context())
        assert detail.mapped_scope is not None
        assert set(detail.mapped_scope.checkout_constraint_types) == {
            vi_profile.CONSTRAINT_ALLOWED_MERCHANTS,
            vi_profile.CONSTRAINT_LINE_ITEMS,
        }
        assert detail.mapped_scope.structural_constraint_types == (
            vi_profile.CONSTRAINT_REFERENCE,
        )

    def test_the_reference_implementation_actually_verified_the_pairing(self) -> None:
        detail = provider().resolve_detailed(build_chain().claim(), context())
        assert "l2_reference_binding" in detail.reference_checks_performed
        assert "l2_aud" in detail.reference_checks_performed
        assert "l1_card_id_cross_check" in detail.reference_checks_performed

    def test_resolving_the_same_mandate_twice_is_not_refused(self) -> None:
        """An Inntris grant is single-use; the draft does not say a mandate is."""
        chain = build_chain()
        subject = provider()
        first = subject.resolve(chain.claim(), context())
        second = subject.resolve(chain.claim(), context())

        assert first.is_verified and second.is_verified
        assert (
            first.reference.external_reference_id
            == second.reference.external_reference_id
        )

    def test_the_binding_can_come_from_trusted_context_instead_of_a_resolver(
        self,
    ) -> None:
        subject = VerifiableIntentAuthorityProvider(
            issuer_key_resolver=issuer_keys(), binding_resolver=None
        )
        resolved = subject.resolve(
            build_chain().claim(),
            context(
                {
                    PRINCIPAL_BINDING_CONTEXT_KEY: {
                        "expected_audience": AGENT_AUDIENCE,
                        "agent_key_thumbprints": [AGENT_THUMBPRINT],
                        "source": "agent-metadata",
                    }
                }
            ),
        )
        assert resolved.is_verified, resolved.issues

    def test_a_matching_key_id_is_accepted_as_a_secondary_check(self) -> None:
        resolved = provider(
            binding=principal_binding(key_ids=[AGENT_KID])
        ).resolve(build_chain().claim(), context())
        assert resolved.is_verified, resolved.issues


# ---------------------------------------------------------------------------
# The adversarial catalogue
# ---------------------------------------------------------------------------


class TestAdversarialCases:
    """Each case fails, and each fails for the recorded reason."""

    def test_expired_layer1(self) -> None:
        now = int(time.time())
        chain = build_chain(
            now=now,
            layer1=build_layer1(now=now, iat_offset=-400 * DAY, exp_offset=-DAY),
        )
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_expired"

    def test_expired_layer2(self) -> None:
        chain = build_chain(l2_iat_offset=-2 * DAY, l2_exp_offset=-DAY)
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_expired"

    def test_layer2_issued_in_the_future(self) -> None:
        chain = build_chain(l2_iat_offset=2 * DAY, l2_exp_offset=3 * DAY)
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_not_yet_valid"

    def test_untrusted_issuer_key(self) -> None:
        now = int(time.time())
        chain = build_chain(
            now=now, layer1=build_layer1(now=now, signing_key=OTHER_ISSUER_KEY)
        )
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_signature_invalid"

    def test_unknown_issuer(self) -> None:
        chain = build_chain()
        subject = provider(keys=issuer_keys(issuer="https://issuer.elsewhere.example"))
        resolved = subject.resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_signature_invalid"
        assert "no trusted signing key" in (resolved.issues[0].detail or "")

    def test_claim_names_a_different_issuer(self) -> None:
        chain = build_chain()
        resolved = provider().resolve(
            chain.claim(issuer="https://issuer.elsewhere.example"), context()
        )
        assert only_code(resolved) == "authority_artefact_invalid"

    def test_wrong_layer2_audience(self) -> None:
        chain = build_chain(aud="https://agents.someone-else.example/vi")
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_delegate_not_bound"

    def test_agent_key_not_bound_to_principal(self) -> None:
        chain = build_chain(agent_key=OTHER_AGENT_KEY)
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_delegate_not_bound"
        assert resolved.delegate_binding_status is DelegateBindingStatus.NOT_BOUND

    def test_agent_key_revoked_for_principal(self) -> None:
        subject = provider(
            binding=principal_binding(
                thumbprints=(AGENT_THUMBPRINT,), revoked=(AGENT_THUMBPRINT,)
            )
        )
        resolved = subject.resolve(build_chain().claim(), context())
        assert only_code(resolved) == "authority_revoked"

    def test_no_binding_provisioned(self) -> None:
        subject = provider(with_binding=False)
        resolved = subject.resolve(build_chain().claim(), context())
        assert only_code(resolved) == "authority_principal_mismatch"

    def test_broken_sd_hash_binding(self) -> None:
        now = int(time.time())
        decoy = build_layer1(now=now, sub="user-vi-fixture-002", label="decoy")
        chain = build_chain(now=now, sd_hash_over=decoy.serialize())
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_digest_mismatch"

    def test_broken_reference_binding(self) -> None:
        constraints = [
            ReferenceConstraint(conditional_transaction_id="not-the-checkout-disclosure"),
            *default_payment_constraints(),
        ]
        chain = build_chain(payment_constraints=constraints)
        resolved = provider().resolve(
            chain.claim(reference="not-the-checkout-disclosure"), context()
        )
        assert only_code(resolved) == "authority_digest_mismatch"

    def test_claim_reference_is_not_the_mandate_pair(self) -> None:
        chain = build_chain()
        resolved = provider().resolve(
            chain.claim(reference="some-other-delegation"), context()
        )
        assert only_code(resolved) == "authority_digest_mismatch"

    def test_malformed_credential(self) -> None:
        claim = DelegatedAuthorityClaim(
            issuer=ISSUER,
            external_reference_id="ref",
            evidence={"layer1": "not~a~credential", "layer2": "also~not~one"},
        )
        resolved = provider().resolve(claim, context())
        assert only_code(resolved) == "authority_artefact_invalid"

    def test_layer3_presented(self) -> None:
        chain = build_chain()
        evidence = chain.evidence()
        evidence["layer3a"] = "eyJhbGciOiJFUzI1NiJ9.e30.sig~"
        claim = DelegatedAuthorityClaim(
            issuer=ISSUER,
            external_reference_id=chain.mandate_pair_reference,
            evidence=evidence,
        )
        resolved = provider().resolve(claim, context())
        assert only_code(resolved) == "authority_artefact_invalid"
        assert "Layer 3" in (resolved.issues[0].detail or "")

    def test_immediate_mode_credential(self) -> None:
        chain = build_immediate_chain()
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_artefact_invalid"
        assert "autonomous" in (resolved.issues[0].detail or "")

    def test_layer2_without_expiry(self) -> None:
        chain = build_chain(l2_exp=None)
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_artefact_invalid"
        assert "layer2.exp" in (resolved.issues[0].detail or "")

    def test_insufficient_disclosure_for_payee_check(self) -> None:
        chain = build_chain(disclose_payees=False)
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_scope_unreadable"
        assert "disclosed no payees" in (resolved.issues[0].detail or "")

    def test_unsupported_budget_constraint(self) -> None:
        constraints = [
            *default_payment_constraints(),
            PaymentBudgetConstraint(currency="USD", max=5_000_000),
        ]
        chain = build_chain(payment_constraints=constraints)
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_scope_unreadable"
        assert vi_profile.CONSTRAINT_BUDGET in (resolved.issues[0].detail or "")

    def test_unsupported_agent_recurrence_constraint(self) -> None:
        constraints = [
            *default_payment_constraints(),
            AgentRecurrenceConstraint(
                frequency="ON_DEMAND",
                start_date="2026-01-01",
                end_date="2026-12-31",
                max_occurrences=10,
            ),
        ]
        chain = build_chain(payment_constraints=constraints)
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_scope_unreadable"

    def test_unknown_constraint_type(self) -> None:
        constraints = [
            *default_payment_constraints(),
            Constraint(
                type="urn:example:velocity-per-hour", extra_fields={"max_per_hour": 3}
            ),
        ]
        chain = build_chain(payment_constraints=constraints)
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_scope_unreadable"

    def test_unsupported_currency(self) -> None:
        constraints = [
            PaymentAmountConstraint(currency="EUR", max=MAX_MINOR_UNITS),
            AllowedPayeeConstraint(allowed=[SUPPLIER_A, SUPPLIER_B]),
        ]
        chain = build_chain(payment_constraints=constraints)
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_scope_unreadable"
        assert "EUR" in (resolved.issues[0].detail or "")

    def test_positive_amount_minimum(self) -> None:
        constraints = [
            PaymentAmountConstraint(currency="USD", min=1_000, max=MAX_MINOR_UNITS),
            AllowedPayeeConstraint(allowed=[SUPPLIER_A, SUPPLIER_B]),
        ]
        chain = build_chain(payment_constraints=constraints)
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_scope_unreadable"
        assert "min" in (resolved.issues[0].detail or "")

    def test_reference_implementation_unavailable(self, monkeypatch) -> None:
        def _unavailable():
            raise ReferenceImplementationUnavailable("not installed")

        monkeypatch.setattr(vi_provider, "load_reference", _unavailable)
        resolved = provider().resolve(build_chain().claim(), context())
        assert only_code(resolved) == "authority_provider_unavailable"
        assert resolved.verification_status is VerificationStatus.UNAVAILABLE

    def test_no_authority_presented(self) -> None:
        resolved = provider().resolve(None, context())
        assert only_code(resolved) == "authority_not_found"
        assert resolved.verification_status is VerificationStatus.UNVERIFIED

    def test_every_recorded_case_is_exercised_here(self) -> None:
        """The catalogue and the implemented cases must be the same set.

        Each case id in ``cases.json`` is carried by a test method named
        ``test_<id>`` somewhere in this module, so a case cannot be recorded
        without being tested or renamed without being noticed.
        """
        catalogue = json.loads((FIXTURE_DIR / "cases.json").read_text())
        recorded = {f"test_{case['id']}" for case in catalogue["cases"]}
        implemented = {
            name
            for value in list(globals().values())
            if isinstance(value, type) and value.__name__.startswith("Test")
            for name in vars(value)
            if name.startswith("test_")
        }
        assert recorded <= implemented, (
            "cases recorded in cases.json with no test of the same name: "
            f"{sorted(recorded - implemented)}"
        )

    def test_every_recorded_failure_code_is_a_real_one(self) -> None:
        catalogue = json.loads((FIXTURE_DIR / "cases.json").read_text())
        known = {code.value for code in AuthorityVerificationFailure}
        for case in catalogue["cases"]:
            expected = case["expected_failure_code"]
            assert expected is None or expected in known, case["id"]

    @pytest.mark.parametrize(
        ("label", "evidence"),
        [
            ("non-ascii serialization", {"layer1": "abc~é~", "layer2": "def~"}),
            ("non-string key", {"layer1": "a~", "layer2": "b~", 7: "c~"}),
            ("a list where a string belongs", {"layer1": ["a~"], "layer2": "b~"}),
            ("no separator", {"layer1": "aaaa", "layer2": "bbbb"}),
            ("padded with whitespace", {"layer1": " a~ ", "layer2": "b~"}),
            ("oversized", {"layer1": "a" + "~b" * 40_000, "layer2": "b~"}),
        ],
    )
    def test_hostile_evidence_is_refused_not_raised(
        self,
        label: str,  # noqa: ARG002
        evidence: dict,
    ) -> None:
        claim = DelegatedAuthorityClaim(
            issuer=ISSUER, external_reference_id="ref", evidence=evidence
        )
        resolved = provider().resolve(claim, context())
        assert only_code(resolved) == "authority_artefact_invalid"

    @pytest.mark.parametrize(
        ("label", "exp"),
        [
            ("beyond the representable range", 10**20),
            ("negative", -1),
            ("not a number", "soon"),
            ("a boolean", True),
        ],
    )
    def test_an_unusable_expiry_is_refused_not_raised(self, label: str, exp: Any) -> None:  # noqa: ARG002
        chain = build_chain(l2_exp=exp)
        resolved = provider().resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_artefact_invalid"
        assert "layer2.exp" in (resolved.issues[0].detail or "")

    @pytest.mark.parametrize(
        "value",
        [
            "with\x01control",
            " leading-space",
            "trailing-space ",
            "x" * 513,
            "",
            None,
            42,
            ["not", "a", "string"],
        ],
    )
    def test_an_unusable_mandate_reference_is_never_returned(self, value: Any) -> None:
        """Nothing that would fail identifier validation may reach it.

        The reference is recorded on the durable decision as an identifier,
        so a hostile credential carrying a control character, whitespace or
        a kilobyte of text must read as "no usable reference" rather than
        blow up when the trusted reference object is constructed.
        """
        mandate = {
            "vct": vi_profile.L2_PAYMENT_VCT_OPEN,
            "constraints": [
                {
                    "type": vi_profile.CONSTRAINT_REFERENCE,
                    "conditional_transaction_id": value,
                }
            ],
        }
        assert (
            VerifiableIntentAuthorityProvider._mandate_pair_reference(mandate) is None
        )

    def test_a_well_formed_mandate_reference_is_returned(self) -> None:
        mandate = {
            "vct": vi_profile.L2_PAYMENT_VCT_OPEN,
            "constraints": [
                {
                    "type": vi_profile.CONSTRAINT_REFERENCE,
                    "conditional_transaction_id": "FtD9HpwqyNCe8lzgn6ta_KahWdS9ElHPFSLbosVV1OY",
                }
            ],
        }
        assert VerifiableIntentAuthorityProvider._mandate_pair_reference(mandate) == (
            "FtD9HpwqyNCe8lzgn6ta_KahWdS9ElHPFSLbosVV1OY"
        )

    def test_an_unresolvable_payee_disclosure_reference_is_refused_not_raised(
        self,
    ) -> None:
        from api.connectors.mastercard_vi.scope import ScopeMappingError, map_payment_mandate

        constraint = {
            "type": vi_profile.CONSTRAINT_ALLOWED_PAYEES,
            "allowed": [{"...": ["not", "a", "hash"]}],
        }
        with pytest.raises(ScopeMappingError):
            map_payment_mandate(
                {
                    "vct": vi_profile.L2_PAYMENT_VCT_OPEN,
                    "constraints": [constraint],
                },
                {"vct": vi_profile.L2_CHECKOUT_VCT_OPEN, "constraints": []},
                {},
                not_before=datetime.now(UTC),
                not_after=datetime.now(UTC),
            )

    def test_no_adversarial_case_ever_raises(self) -> None:
        """Expected denial is data. A provider that raises turns BLOCK into 500."""
        subject = provider()
        broken = [
            DelegatedAuthorityClaim(issuer=ISSUER, external_reference_id="r", evidence={}),
            DelegatedAuthorityClaim(
                issuer=ISSUER, external_reference_id="r", evidence={"layer1": "~"}
            ),
            DelegatedAuthorityClaim(
                issuer=ISSUER,
                external_reference_id="r",
                evidence={"layer1": "a~", "layer2": "b~", "extra": "c~"},
            ),
        ]
        for claim in broken:
            resolved = subject.resolve(claim, context())
            assert not resolved.is_verified
            assert resolved.issues


# ---------------------------------------------------------------------------
# Verified is not permitted
# ---------------------------------------------------------------------------


def agent_record(**overrides) -> AgentRecord:
    fields: dict[str, Any] = {
        "id": uuid4(),
        "org_id": uuid4(),
        "name": "vi-agent",
        "public_key": b"\x00" * 32,
        "public_key_fingerprint": "a" * 64,
        "trust_score": 80,
        "status": AgentStatus.ACTIVE,
        "daily_limit_usd": Decimal("100000"),
        "per_action_limit_usd": Decimal("100"),
        "allowed_actions": ["wallet_transaction"],
        "blocked_actions": [],
        "rate_limit_per_minute": 60,
        "last_action_at": None,
        "total_actions_count": 0,
        "total_blocked_count": 0,
        "metadata": {},
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    fields.update(overrides)
    return AgentRecord(**fields)


class StubPayeeBindings:
    def __init__(self, bindings: dict[str, PayeeBinding]) -> None:
        self._bindings = bindings

    def binding_for(self, organisation_id: str, payee_reference: str):  # noqa: ARG002
        return self._bindings.get(payee_reference)


def supplier_a_bindings() -> StubPayeeBindings:
    return StubPayeeBindings(
        {
            "payee:id:supplier-a": PayeeBinding(
                payee_reference="payee:id:supplier-a",
                destination=ExecutionDestination(
                    network=CHAIN, account=BOUND_ACCOUNT, asset="USD"
                ),
                source="organisation-supplier-register",
            )
        }
    )


class TestOrganisationPolicyStillDecides:
    """A valid Verifiable Intent chain is necessary here, never sufficient."""

    @staticmethod
    def _decide(subject, amount: str, resolved, now: datetime):
        envelope = build_action_envelope(
            agent=subject,
            action_type="wallet_transaction",
            payload={
                "amount": amount,
                "currency": "USD",
                "chain": CHAIN,
                "recipient": BOUND_ACCOUNT,
            },
            timestamp=now,
        )
        return PaymentDomainPolicy(
            agent=subject, payee_binding_resolver=supplier_a_bindings()
        ).evaluate(envelope, resolved, at=now)

    def test_scope_wider_than_organisation_policy(self) -> None:
        resolved = provider().resolve(build_chain().claim(), context())
        assert resolved.is_verified

        subject = agent_record(per_action_limit_usd=Decimal("100"))
        decision = self._decide(subject, "500.00", resolved, datetime.now(UTC))

        assert decision.decision is Decision.BLOCK
        assert DecisionReason.PER_ACTION_LIMIT_EXCEEDED in decision.reasons

    def test_within_both_the_delegation_and_the_policy_is_allowed(self) -> None:
        resolved = provider().resolve(build_chain().claim(), context())
        subject = agent_record(per_action_limit_usd=Decimal("1000"))
        decision = self._decide(subject, "500.00", resolved, datetime.now(UTC))

        assert decision.decision is Decision.ALLOW

    def test_the_delegated_cap_narrows_what_policy_alone_would_allow(self) -> None:
        resolved = provider().resolve(build_chain().claim(), context())
        subject = agent_record(per_action_limit_usd=Decimal("50000"))
        decision = self._decide(subject, "25000.00", resolved, datetime.now(UTC))

        assert decision.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_SCOPE_EXCEEDED in decision.reasons

    def test_an_unbound_payee_destination_still_fails_closed(self) -> None:
        resolved = provider().resolve(build_chain().claim(), context())
        subject = agent_record(per_action_limit_usd=Decimal("1000"))
        envelope = build_action_envelope(
            agent=subject,
            action_type="wallet_transaction",
            payload={
                "amount": "100.00",
                "currency": "USD",
                "chain": CHAIN,
                "recipient": "0x9999999999999999999999999999999999999999",
            },
            timestamp=datetime.now(UTC),
        )
        decision = PaymentDomainPolicy(
            agent=subject, payee_binding_resolver=supplier_a_bindings()
        ).evaluate(envelope, resolved, at=datetime.now(UTC))

        assert decision.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_SCOPE_EXCEEDED in decision.reasons


# ---------------------------------------------------------------------------
# Boundary invariants
# ---------------------------------------------------------------------------

VENDOR_TOKENS = (
    "mastercard",
    "verifiable_intent",
    "verifiable-intent",
    "verifiableintent",
    "sd-jwt",
    "sd_hash",
    "kb-sd-jwt",
    "mandate.payment",
    "mandate.checkout",
    "vct",
)


class TestNoVendorVocabularyCrossesTheBoundary:
    def test_core_authority_names_no_vendor(self) -> None:
        root = Path(__file__).resolve().parents[1] / "api" / "core" / "authority"
        offenders = []
        for path in sorted(root.rglob("*.py")):
            text = path.read_text().lower()
            offenders.extend(
                f"{path.name}:{token}" for token in VENDOR_TOKENS if token in text
            )
        assert offenders == []

    def test_the_payment_domain_names_no_vendor(self) -> None:
        root = Path(__file__).resolve().parents[1] / "api" / "domains" / "payment"
        offenders = []
        for path in sorted(root.rglob("*.py")):
            text = path.read_text().lower()
            offenders.extend(
                f"{path.name}:{token}" for token in VENDOR_TOKENS if token in text
            )
        assert offenders == []

    def test_the_scope_carries_only_neutral_keys(self) -> None:
        resolved = provider().resolve(build_chain().claim(), context())
        assert set(resolved.scope) <= KNOWN_SCOPE_KEYS

    def test_no_scope_value_carries_vendor_vocabulary(self) -> None:
        resolved = provider().resolve(build_chain().claim(), context())
        serialised = json.dumps(dict(resolved.scope)).lower()
        for token in VENDOR_TOKENS:
            assert token not in serialised, token


# ---------------------------------------------------------------------------
# Binding and key identity
# ---------------------------------------------------------------------------


class TestDelegateIdentity:
    def test_a_kid_alone_never_binds_a_delegate(self) -> None:
        """The impostor copies the kid; only the key material differs."""
        chain = build_chain(agent_key=OTHER_AGENT_KEY, agent_kid=AGENT_KID)
        subject = provider(binding=principal_binding(key_ids=[AGENT_KID]))
        resolved = subject.resolve(chain.claim(), context())
        assert only_code(resolved) == "authority_delegate_not_bound"

    def test_a_mismatched_kid_fails_even_with_a_bound_thumbprint(self) -> None:
        subject = provider(binding=principal_binding(key_ids=["some-other-kid"]))
        resolved = subject.resolve(build_chain().claim(), context())
        assert only_code(resolved) == "authority_delegate_not_bound"

    def test_rotation_accepts_either_provisioned_key(self) -> None:
        subject = provider(
            binding=principal_binding(
                thumbprints=(AGENT_THUMBPRINT, OTHER_AGENT_THUMBPRINT)
            )
        )
        for key in (AGENT_KEY, OTHER_AGENT_KEY):
            resolved = subject.resolve(build_chain(agent_key=key).claim(), context())
            assert resolved.is_verified, resolved.issues

    def test_revocation_wins_over_a_stale_active_entry(self) -> None:
        binding = principal_binding(
            thumbprints=(AGENT_THUMBPRINT,), revoked=(AGENT_THUMBPRINT,)
        )
        assert (
            binding.check_delegate(AGENT_THUMBPRINT, AGENT_KID)
            is DelegateBindingOutcome.KEY_REVOKED
        )

    def test_a_binding_with_no_keys_cannot_be_provisioned(self) -> None:
        with pytest.raises(PrincipalBindingError, match="at least one delegate key"):
            principal_binding(thumbprints=())

    def test_a_thumbprint_ignores_non_defining_members(self) -> None:
        jwk = public_key_to_jwk(AGENT_KEY)
        decorated = {**jwk, "kid": "anything", "use": "sig", "alg": "ES256"}
        assert jwk_thumbprint(decorated) == jwk_thumbprint(jwk)

    def test_a_malformed_context_binding_does_not_fall_through_to_the_resolver(
        self,
    ) -> None:
        subject = provider()
        resolved = subject.resolve(
            build_chain().claim(),
            context({PRINCIPAL_BINDING_CONTEXT_KEY: "not-a-mapping"}),
        )
        assert only_code(resolved) == "authority_principal_mismatch"


class TestArtefactDigest:
    def test_the_digest_covers_exactly_what_was_inspected(self) -> None:
        chain = build_chain()
        first = provider().resolve(chain.claim(), context())
        second = provider().resolve(chain.claim(), context())
        assert first.reference.artefact_digest == second.reference.artefact_digest

    def test_a_different_presentation_digests_differently(self) -> None:
        full = provider().resolve(build_chain().claim(), context())
        partial_chain = build_chain(disclose_payees=False)
        partial = provider().resolve(partial_chain.claim(), context())
        assert full.reference.artefact_digest != partial.reference.artefact_digest

    def test_the_digest_is_a_sha256_hex_string(self) -> None:
        resolved = provider().resolve(build_chain().claim(), context())
        digest = resolved.reference.artefact_digest
        assert len(digest) == 64
        assert set(digest) <= set("0123456789abcdef")


class TestDecodedFixtureShape:
    """Guard rails on the fixtures themselves, so a broken fixture is visible."""

    def test_the_main_fixture_delegates_two_suppliers_and_twenty_thousand_usd(
        self,
    ) -> None:
        chain = build_chain()
        claims = resolve_disclosures(decode_sd_jwt(chain.layer2_serialized))
        payment = next(
            delegate
            for delegate in claims["delegate_payload"]
            if delegate.get("vct") == vi_profile.L2_PAYMENT_VCT_OPEN
        )
        amounts = [
            c
            for c in payment["constraints"]
            if c["type"] == vi_profile.CONSTRAINT_AMOUNT_RANGE
        ]
        payees = [
            c
            for c in payment["constraints"]
            if c["type"] == vi_profile.CONSTRAINT_ALLOWED_PAYEES
        ]
        assert amounts == [
            {"type": vi_profile.CONSTRAINT_AMOUNT_RANGE, "currency": "USD", "max": 2_000_000}
        ]
        assert len(payees[0]["allowed"]) == 2
        assert all("..." in entry for entry in payees[0]["allowed"])

    def test_the_fixture_builder_is_deterministic(self) -> None:
        """The credential content is reproducible; two things cannot be.

        ECDSA draws a fresh nonce per signature, so signing the same bytes
        twice yields different signatures by design — and because Layer 2's
        ``sd_hash`` binds to the serialized Layer 1, that randomness
        necessarily reaches one Layer 2 claim too. Everything a reviewer
        would want to diff — keys, salts, disclosures, claim content — is
        fixed.
        """
        now = int(time.time())
        first = build_chain(now=now)
        second = build_chain(now=now)

        for left, right in (
            (first.layer1_serialized, second.layer1_serialized),
            (first.layer2_serialized, second.layer2_serialized),
        ):
            left_jwt, *left_disclosures = left.split("~")
            right_jwt, *right_disclosures = right.split("~")
            assert left_disclosures == right_disclosures
            assert left_jwt.split(".")[0] == right_jwt.split(".")[0]

            def payload(segment: str) -> dict:
                raw = segment.split(".")[1]
                raw += "=" * (-len(raw) % 4)
                claims = json.loads(base64.urlsafe_b64decode(raw))
                claims.pop("sd_hash", None)
                return claims

            assert payload(left_jwt) == payload(right_jwt)

        assert first.mandate_pair_reference == second.mandate_pair_reference
