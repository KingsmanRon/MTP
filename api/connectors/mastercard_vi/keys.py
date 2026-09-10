"""Issuer key resolution and key identity, kept apart from key *names*.

Two different things are easy to confuse and must not be:

``kid``
    A hint that helps locate a key inside some issuer's keyset. It is a
    label. It is chosen by whoever wrote the credential, it is not
    globally unique, and matching one proves nothing at all.

JWK thumbprint
    The RFC 7638 hash of the key's own defining parameters. Two keys with
    the same thumbprint are the same key. It is derived from key material
    rather than asserted next to it, so it is usable as identity.

Every trust decision in this connector is made on thumbprints or on an
actual signature check. ``kid`` is used only to select a candidate key,
and — where an operator has registered expected values — as a secondary
consistency check layered on top of a thumbprint match, never instead of
one.

Issuer key discovery over the network (JWKS fetch, caching, rotation
polling) is deliberately not implemented here. The resolver is an
interface with an offline implementation; a production discovery strategy
is a later phase.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric import ec


class IssuerKeyError(ValueError):
    """A key or keyset was configured with an unusable shape."""


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_to_int(value: str) -> int:
    padding = "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(value + padding), "big")


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint of an EC public JWK, base64url-encoded.

    Only the required members participate, in lexicographic order and with
    no whitespace, so a key carrying an extra ``kid``, ``use`` or ``alg``
    hashes to the same value as the same key without them. That is the
    property that makes a thumbprint stable across re-provisioning.
    """
    if not isinstance(jwk, Mapping):
        raise IssuerKeyError(f"jwk must be a mapping, got {type(jwk).__name__}")
    kty = jwk.get("kty")
    if kty != "EC":
        raise IssuerKeyError(f"only EC keys are supported, got kty={kty!r}")
    required = {}
    for member in ("crv", "x", "y"):
        value = jwk.get(member)
        if not isinstance(value, str) or not value:
            raise IssuerKeyError(f"EC jwk is missing required member '{member}'")
        required[member] = value
    canonical = json.dumps(
        {"crv": required["crv"], "kty": "EC", "x": required["x"], "y": required["y"]},
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
    )
    return _b64url_no_pad(hashlib.sha256(canonical.encode("ascii")).digest())


def public_key_from_jwk(jwk: Mapping[str, Any]) -> ec.EllipticCurvePublicKey:
    """Build a P-256 public key from a JWK, rejecting anything else.

    Verifiable Intent v0.1 mandates ES256 at every layer, so a key on any
    other curve is not a key this connector can be handed by mistake.
    """
    if not isinstance(jwk, Mapping):
        raise IssuerKeyError(f"jwk must be a mapping, got {type(jwk).__name__}")
    if jwk.get("kty") != "EC":
        raise IssuerKeyError(f"only EC keys are supported, got kty={jwk.get('kty')!r}")
    if jwk.get("crv") != "P-256":
        raise IssuerKeyError(
            f"only the P-256 curve is supported (ES256), got crv={jwk.get('crv')!r}"
        )
    try:
        x = _b64url_to_int(str(jwk["x"]))
        y = _b64url_to_int(str(jwk["y"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise IssuerKeyError(f"EC jwk coordinates are malformed: {exc}") from exc
    try:
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError as exc:
        raise IssuerKeyError(f"EC jwk is not a point on P-256: {exc}") from exc


@runtime_checkable
class IssuerKeyResolver(Protocol):
    """Supplies the public key an issuer signed a Layer 1 credential with."""

    def public_key_for(
        self, issuer: str, kid: str | None
    ) -> ec.EllipticCurvePublicKey | None:
        """Return the trusted key for ``issuer``/``kid``, or ``None``.

        ``None`` means "no trusted key could be resolved", which is a
        fail-closed condition: the caller reports the authority as
        unverified rather than skipping the signature check. Returning a
        key means the implementation asserts this key is trusted for this
        issuer — resolution and trust are the same decision here, and an
        implementation that resolves untrusted keys has none.
        """
        ...


@dataclass(frozen=True, slots=True)
class TrustedIssuerKeyset:
    """One issuer's keys, as provisioned into Inntris.

    ``keys`` maps ``kid`` to the public JWK. ``revoked_thumbprints`` names
    keys that must never verify again even if a stale ``kid`` still points
    at them — revocation is expressed on key identity, not on the label.
    """

    issuer: str
    keys: Mapping[str, Mapping[str, Any]]
    revoked_thumbprints: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.issuer, str) or not self.issuer.strip():
            raise IssuerKeyError("issuer must be a non-empty string")
        if not isinstance(self.keys, Mapping) or not self.keys:
            raise IssuerKeyError(f"issuer {self.issuer!r} was configured with no keys")
        for kid, jwk in self.keys.items():
            if not isinstance(kid, str) or not kid:
                raise IssuerKeyError(f"issuer {self.issuer!r} has a non-string kid")
            # Validate eagerly: a keyset that cannot be parsed should fail at
            # provisioning time, not silently at the first verification.
            public_key_from_jwk(jwk)


class StaticIssuerKeyResolver:
    """An offline resolver over explicitly provisioned issuer keysets.

    This is the implementation used in tests and in any deployment that
    provisions issuer keys out of band. It performs no network I/O, so a
    verification result never depends on whether an issuer's JWKS endpoint
    happened to be reachable.
    """

    def __init__(self, keysets: Iterable[TrustedIssuerKeyset]) -> None:
        self._by_issuer: dict[str, TrustedIssuerKeyset] = {}
        for keyset in keysets:
            if keyset.issuer in self._by_issuer:
                raise IssuerKeyError(f"duplicate keyset for issuer {keyset.issuer!r}")
            self._by_issuer[keyset.issuer] = keyset

    @classmethod
    def from_mapping(
        cls, mapping: Mapping[str, Mapping[str, Mapping[str, Any]]]
    ) -> StaticIssuerKeyResolver:
        """Build from ``{issuer: {kid: jwk}}``, the shape config carries."""
        return cls(
            TrustedIssuerKeyset(issuer=issuer, keys=dict(keys))
            for issuer, keys in mapping.items()
        )

    def public_key_for(
        self, issuer: str, kid: str | None
    ) -> ec.EllipticCurvePublicKey | None:
        keyset = self._by_issuer.get(issuer)
        if keyset is None:
            return None
        if kid is None:
            # No locator was supplied. Guessing a key from a single-key
            # issuer would work today and break silently the day that issuer
            # rotates, so the answer is "not resolvable".
            return None
        jwk = keyset.keys.get(kid)
        if jwk is None:
            return None
        if jwk_thumbprint(jwk) in keyset.revoked_thumbprints:
            return None
        return public_key_from_jwk(jwk)
