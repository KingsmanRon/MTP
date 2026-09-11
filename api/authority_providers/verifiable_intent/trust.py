"""Which Verifiable Intent issuers this deployment will trust, and on what key.

The issuer's public key is the root of the whole chain: L1 is signed by
it, L1 binds the user's key, the user's key signs L2, and L2 binds the
agent's key. Get the issuer key from the presented artefact and the chain
verifies against whatever key the presenter chose, which is no
verification at all.

So the key comes from here — trusted server-side configuration — and
never from the claim. A claim naming an issuer this deployment has not
configured resolves to ``AUTHORITY_NOT_FOUND`` rather than being verified
against an improvised key.

Production issuer-key discovery is deliberately NOT implemented
------------------------------------------------------------------
There is no JWKS fetch, no ``/.well-known`` lookup and no key rotation
protocol in this module. A deployment configures the keys it accepts, out
of band. Anything more would be a network dependency inside a decision
path, and this release has not specified what it should do when that
network call fails.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class IssuerTrustError(ValueError):
    """A trust entry was configured with something unusable as a key."""


@dataclass(frozen=True, slots=True)
class TrustedIssuer:
    """One issuer this deployment accepts L1 credentials from.

    ``audience`` is the audience value an L2 mandate must name for this
    deployment to be its intended recipient. A mandate addressed to
    somebody else is not ours to spend, even when every signature on it
    is valid.
    """

    issuer_id: str
    public_key: ec.EllipticCurvePublicKey
    #: Expected ``aud`` on L2. ``None`` means this deployment does not
    #: constrain it, which is only appropriate in a test.
    l2_audience: str | None = None
    #: Expected ``aud`` on the L3 payment mandate — the network endpoint
    #: the agent addressed its fulfilment to.
    l3_payment_audience: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.issuer_id, str) or not self.issuer_id.strip():
            raise IssuerTrustError("issuer_id must be a non-empty string")
        if not isinstance(self.public_key, ec.EllipticCurvePublicKey):
            raise IssuerTrustError(
                "public_key must be an elliptic-curve public key, got "
                f"{type(self.public_key).__name__}"
            )


@runtime_checkable
class IssuerTrustStore(Protocol):
    """Answers "do we trust this issuer, and on which key"."""

    def trusted_issuer(self, issuer_id: str) -> TrustedIssuer | None:
        """Return the trust entry for ``issuer_id``, or ``None``.

        ``None`` means not configured. It is never an error and never a
        reason to fall back to an unverified chain.
        """
        ...


class StaticIssuerTrustStore:
    """Trust configured up front, from PEM material or live key objects."""

    def __init__(self, issuers: Iterable[TrustedIssuer] = ()) -> None:
        entries: dict[str, TrustedIssuer] = {}
        for entry in issuers:
            if not isinstance(entry, TrustedIssuer):
                raise IssuerTrustError(
                    f"issuers must be TrustedIssuer values, got {type(entry).__name__}"
                )
            entries[entry.issuer_id] = entry
        self._issuers = entries

    @classmethod
    def from_pem(cls, issuers: Mapping[str, Mapping[str, str]]) -> StaticIssuerTrustStore:
        """Build from ``{issuer_id: {"public_key_pem": ..., "l2_audience": ...}}``."""
        built: list[TrustedIssuer] = []
        for issuer_id, config in issuers.items():
            pem = config.get("public_key_pem")
            if not isinstance(pem, str) or not pem.strip():
                raise IssuerTrustError(f"issuer {issuer_id!r} has no public_key_pem")
            key = load_pem_public_key(pem.encode("utf-8"))
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise IssuerTrustError(
                    f"issuer {issuer_id!r} public_key_pem is not an EC public key"
                )
            built.append(
                TrustedIssuer(
                    issuer_id=issuer_id,
                    public_key=key,
                    l2_audience=config.get("l2_audience"),
                    l3_payment_audience=config.get("l3_payment_audience"),
                )
            )
        return cls(built)

    def trusted_issuer(self, issuer_id: str) -> TrustedIssuer | None:
        return self._issuers.get(str(issuer_id))
