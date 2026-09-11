"""The one Verifiable Intent delegation the proof is built on.

Signed in-process on every run by the pinned upstream reference
implementation, through the same loader the connector uses — so a version
drift that would make the connector refuse also makes the fixture refuse,
rather than the proof quietly signing with one build and verifying with
another.

Layer 1 and Layer 2 only
------------------------
The connector refuses Layer 3 outright, and the fixture therefore never
builds one. Inntris decides whether to authorise an act *before* it
happens; Layer 3 is the agent's record of an act already committed to a
payment network and a merchant, so at evaluation time none exists.
Presenting one would invite the reading that Inntris verified a completed
Verifiable Intent transaction. It has not, and this proof must not look
as though it did.

On determinism
--------------
Keys are derived from labelled seeds and disclosure salts are made
reproducible for the duration of a build, both following the technique
Phase 5's own fixtures use. What is *not* reproducible is the ES256
signature: ECDSA carries a random nonce, so the serialisation — and
therefore the artefact digest — differs between runs. Pinning that would
mean patching the reference implementation's cryptography, which is
precisely what a proof of cryptographic behaviour may not do. Outcomes
are deterministic; digests are recorded per run.

Every private key here is derived from a published label. Nothing in this
file is secret, and it is written this way so nobody can mistake it for
something that is.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import time
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Final

from cryptography.hazmat.primitives.asymmetric import ec

from api.connectors.mastercard_vi import profile as vi_profile
from api.connectors.mastercard_vi.keys import jwk_thumbprint
from api.connectors.mastercard_vi.reference import load_reference

# --- identities ------------------------------------------------------------

#: The credential provider this proof trusts. The string is Verifiable
#: Intent's own reference-profile issuer namespace; it asserts nothing
#: about any relationship with Mastercard. See the README.
ISSUER: Final[str] = "https://issuer.mastercard.com"
ISSUER_KID: Final[str] = "mastercard-issuer-key-1"
USER_KID: Final[str] = "user-device-key-1"

#: Where the user's wallet issued the mandate from, and who it is addressed
#: to. The audience is half the principal binding: a mandate addressed to
#: somebody else is not this deployment's to spend.
WALLET: Final[str] = "https://wallet.example"
AGENT_AUDIENCE: Final[str] = "https://agents.inntris.example/vi"
AGENT_KID: Final[str] = "inntris-agent-key-1"

#: The Layer 1 credential subject this organisation registers for its agent.
CREDENTIAL_SUBJECT: Final[str] = "user-vi-proof-001"

P256_ORDER: Final[int] = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)

DAY: Final[int] = 86_400


def deterministic_key(label: str) -> ec.EllipticCurvePrivateKey:
    """A reproducible P-256 proof key, derived rather than embedded.

    Deriving from a labelled seed keeps the fixture reproducible without a
    literal private scalar sitting in the repository for a secret scanner,
    or a reader, to mistake for something real.
    """
    seed = hashlib.sha256(f"inntris-mastercard-vi-proof:{label}".encode()).digest()
    return ec.derive_private_key((int.from_bytes(seed, "big") % (P256_ORDER - 1)) + 1,
                                 ec.SECP256R1())


ISSUER_KEY: Final = deterministic_key("issuer")
USER_KEY: Final = deterministic_key("user")
AGENT_KEY: Final = deterministic_key("agent")
#: A second agent key, for proving a mandate delegated elsewhere is refused.
OTHER_AGENT_KEY: Final = deterministic_key("agent-unregistered")
#: An issuer this deployment has not provisioned a key for.
IMPOSTOR_ISSUER_KEY: Final = deterministic_key("issuer-impostor")


@contextmanager
def deterministic_salts(label: str):
    """Make SD-JWT disclosure salts reproducible for one build."""
    from verifiable_intent.crypto import disclosure as vi_disclosure

    counter = itertools.count()

    def _salt() -> str:
        raw = hashlib.sha256(f"{label}:{next(counter)}".encode()).digest()[:16]
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    original = vi_disclosure._generate_salt  # noqa: SLF001
    vi_disclosure._generate_salt = _salt  # noqa: SLF001
    try:
        yield
    finally:
        vi_disclosure._generate_salt = original  # noqa: SLF001


# --- what the delegation permits -------------------------------------------

SUPPLIER_A: Final[dict[str, str]] = {
    "id": "supplier-a",
    "name": "Supplier A",
    "website": "https://supplier-a.example",
}
SUPPLIER_B: Final[dict[str, str]] = {
    "id": "supplier-b",
    "name": "Supplier B",
    "website": "https://supplier-b.example",
}

#: The neutral payee references the connector maps these to. Recomputed
#: from the connector rather than hard-coded, so a change to its reference
#: format shows up here instead of drifting silently.
SUPPLIER_A_REFERENCE: Final[str] = "payee:id:supplier-a"
SUPPLIER_B_REFERENCE: Final[str] = "payee:id:supplier-b"

#: Verifiable Intent permits USD up to this, per transaction. Inntris
#: organisation policy is deliberately narrower; that gap is the proof.
VI_MAX_AMOUNT: Final[Decimal] = Decimal("20000.00")
VI_MAX_MINOR_UNITS: Final[int] = 2_000_000
VI_CURRENCY: Final[str] = "USD"

PAYMENT_INSTRUMENT: Final[dict[str, str]] = {
    "type": "mastercard.srcDigitalCard",
    "id": "00000000-0000-4000-8000-000000000001",
    "description": "Proof instrument **** 4242",
}

_ACCEPTABLE_ITEMS: Final[list[dict[str, str]]] = [
    {"id": "PROOF-ITEM-1", "title": "Proof line item"}
]


@dataclass(frozen=True)
class Delegation:
    """One signed Layer 1 + Layer 2 chain, as a caller would present it."""

    layer1_serialized: str
    layer2_serialized: str
    mandate_pair_reference: str

    def evidence(self) -> dict[str, str]:
        """Exactly the two keys the connector accepts. No Layer 3."""
        return {
            "layer1": self.layer1_serialized,
            "layer2": self.layer2_serialized,
        }

    def claim(self, *, issuer: str = ISSUER, reference_id: str | None = None) -> Any:
        """The untrusted claim a caller presents.

        ``issuer`` is the credential provider the caller says issued
        Layer 1, and the connector refuses the claim when it does not
        match Layer 1's own ``iss``. It is not the connector's issuer
        scheme, which names the format rather than the issuer.
        """
        from api.core.authority.authority import DelegatedAuthorityClaim

        return DelegatedAuthorityClaim(
            issuer=issuer,
            external_reference_id=reference_id or self.mandate_pair_reference,
            evidence=self.evidence(),
        )


def agent_thumbprint(key: ec.EllipticCurvePrivateKey = AGENT_KEY) -> str:
    """The RFC 7638 thumbprint an operator provisions as the delegate key."""
    from verifiable_intent.crypto.signing import public_key_to_jwk

    return jwk_thumbprint(public_key_to_jwk(key))


def issuer_jwk(key: ec.EllipticCurvePrivateKey = ISSUER_KEY) -> dict[str, Any]:
    from verifiable_intent.crypto.signing import public_key_to_jwk

    return public_key_to_jwk(key)


def build_delegation(
    *,
    now: int | None = None,
    issuer_key: ec.EllipticCurvePrivateKey = ISSUER_KEY,
    agent_key: ec.EllipticCurvePrivateKey = AGENT_KEY,
    audience: str = AGENT_AUDIENCE,
    subject: str = CREDENTIAL_SUBJECT,
    max_minor_units: int | None = VI_MAX_MINOR_UNITS,
    extra_payment_constraints: list[Any] | None = None,
    l1_exp_offset: int = 300 * DAY,
    l2_exp_offset: int = 30 * DAY,
    label: str = "proof",
) -> Delegation:
    """Sign the proof delegation with the pinned reference implementation.

    The defaults are the fixture the seven cases use: both suppliers
    permitted, USD up to 20,000.00 per transaction, delegated to the proof
    agent key. The keyword arguments exist so an acceptance case can vary
    exactly one thing without a second, divergent fixture.
    """
    from verifiable_intent.crypto.signing import public_key_to_jwk
    from verifiable_intent.issuance.issuer import create_layer1
    from verifiable_intent.issuance.user import create_layer2_autonomous
    from verifiable_intent.models.constraints import (
        AllowedMerchantConstraint,
        AllowedPayeeConstraint,
        CheckoutLineItemsConstraint,
        PaymentAmountConstraint,
    )
    from verifiable_intent.models.issuer_credential import IssuerCredential
    from verifiable_intent.models.user_mandate import (
        CheckoutMandate,
        MandateMode,
        PaymentMandate,
        UserMandate,
    )

    # Loaded through the connector's own loader so the fixture cannot sign
    # with a build the connector would refuse to verify against.
    reference = load_reference()
    issued_at = int(time.time()) if now is None else int(now)

    with deterministic_salts(f"{label}:layer1"):
        layer1 = create_layer1(
            IssuerCredential(
                iss=ISSUER,
                sub=subject,
                iat=issued_at - DAY,
                exp=issued_at + l1_exp_offset,
                vct=vi_profile.L1_VCT_MASTERCARD_CARD,
                aud=WALLET,
                cnf_jwk=public_key_to_jwk(USER_KEY),
                pan_last_four="4242",
                scheme="mastercard",
                card_id=PAYMENT_INSTRUMENT["id"],
                email="procurement@proof.example",
            ),
            issuer_key,
            kid=ISSUER_KID,
        )
    layer1_serialized = layer1.serialize()

    payment_constraints: list[Any] = []
    if max_minor_units is not None:
        payment_constraints.append(
            PaymentAmountConstraint(currency=VI_CURRENCY, max=max_minor_units)
        )
    payment_constraints.append(AllowedPayeeConstraint(allowed=[SUPPLIER_A, SUPPLIER_B]))
    payment_constraints.extend(extra_payment_constraints or ())

    agent_jwk = public_key_to_jwk(agent_key)
    mandate = UserMandate(
        nonce="9c1f4a6b2e8d0537",
        aud=audience,
        iat=issued_at - 60,
        iss=WALLET,
        exp=issued_at + l2_exp_offset,
        mode=MandateMode.AUTONOMOUS,
        # Binds Layer 2 to the exact Layer 1 serialisation the signer saw.
        sd_hash=reference.hash_bytes(layer1_serialized.encode("ascii")),
        prompt_summary="Pay approved suppliers in USD up to 20,000.00",
        checkout_mandate=CheckoutMandate(
            vct=vi_profile.L2_CHECKOUT_VCT_OPEN,
            cnf_jwk=agent_jwk,
            cnf_kid=AGENT_KID,
            constraints=[
                AllowedMerchantConstraint(allowed=[SUPPLIER_A, SUPPLIER_B]),
                CheckoutLineItemsConstraint(
                    items=[
                        {
                            "id": "line-1",
                            "acceptable_items": list(_ACCEPTABLE_ITEMS),
                            "quantity": 1,
                        }
                    ]
                ),
            ],
        ),
        payment_mandate=PaymentMandate(
            vct=vi_profile.L2_PAYMENT_VCT_OPEN,
            cnf_jwk=agent_jwk,
            cnf_kid=AGENT_KID,
            payment_instrument=PAYMENT_INSTRUMENT,
            constraints=payment_constraints,
        ),
        merchants=[SUPPLIER_A, SUPPLIER_B],
        acceptable_items=list(_ACCEPTABLE_ITEMS),
    )
    with deterministic_salts(f"{label}:layer2"):
        layer2 = create_layer2_autonomous(mandate, USER_KEY, kid=USER_KID)

    layer2_serialized = layer2.serialize()
    return Delegation(
        layer1_serialized=layer1_serialized,
        layer2_serialized=layer2_serialized,
        mandate_pair_reference=_mandate_pair_reference(layer2, reference),
    )


def _mandate_pair_reference(layer2: Any, reference: Any) -> str:
    """The connector's own external reference for this mandate pair.

    Derived the same way the provider derives it, so a claim the proof
    builds names the delegation the provider will say it resolved.
    """
    from api.connectors.mastercard_vi.provider import (
        VerifiableIntentAuthorityProvider,
    )

    claims = reference.resolve_disclosures(layer2)
    for delegate in claims.get("delegate_payload", []):
        if (
            isinstance(delegate, dict)
            and delegate.get("vct") == vi_profile.L2_PAYMENT_VCT_OPEN
        ):
            derived = VerifiableIntentAuthorityProvider._mandate_pair_reference(delegate)  # noqa: SLF001
            if derived:
                return derived
    raise RuntimeError("the signed Layer 2 carries no autonomous payment mandate")
