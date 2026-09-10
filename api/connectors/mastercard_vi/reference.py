"""The pinned reference implementation, loaded as the compatibility oracle.

Verifiable Intent publishes a Python reference implementation alongside
the specification. This connector calls it rather than re-implementing
SD-JWT parsing, KB-SD-JWT chain binding or ES256 verification: a
hand-rolled second implementation of a draft that is still moving is a
guarantee of divergence, and divergence in a verifier is a security bug,
not a compatibility annoyance.

Loading rules
-------------
* the package is imported lazily, so a deployment that does not use this
  connector does not need the dependency installed at all;
* ``verifiable_intent.__version__`` must equal the version pinned in
  :mod:`api.connectors.mastercard_vi.profile`. A different version is
  refused rather than assumed compatible — the whole point of pinning a
  draft is that "close enough" is not a verification result;
* every failure to load raises :class:`ReferenceImplementationUnavailable`,
  which the provider turns into ``AUTHORITY_PROVIDER_UNAVAILABLE``. A
  verifier that cannot run its verification never reports success.

``skip_issuer_verification`` is deliberately not exposed. The reference
implementation offers it for its own unit tests; reaching it from here
would mean accepting an L1 whose issuer signature was never checked.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from api.connectors.mastercard_vi.profile import UPSTREAM_COMMIT, UPSTREAM_PACKAGE_VERSION


class ReferenceImplementationUnavailable(RuntimeError):
    """The pinned Verifiable Intent reference implementation cannot be used."""


@dataclass(frozen=True, slots=True)
class ReferenceImplementation:
    """The subset of the pinned package this connector depends on."""

    version: str
    decode_sd_jwt: Any
    resolve_disclosures: Any
    hash_disclosure: Any
    hash_bytes: Any
    verify_chain: Any
    check_constraints: Any
    strictness_mode: Any


@lru_cache(maxsize=1)
def load_reference() -> ReferenceImplementation:
    """Import and version-check the pinned reference implementation."""
    try:
        import verifiable_intent as vi
        from verifiable_intent.crypto.disclosure import hash_bytes, hash_disclosure
        from verifiable_intent.crypto.sd_jwt import decode_sd_jwt, resolve_disclosures
        from verifiable_intent.verification.chain import verify_chain
        from verifiable_intent.verification.constraint_checker import (
            StrictnessMode,
            check_constraints,
        )
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise ReferenceImplementationUnavailable(
            "the verifiable-intent reference implementation is not installed; "
            f"install it pinned to {UPSTREAM_COMMIT}"
        ) from exc

    version = getattr(vi, "__version__", None)
    if version != UPSTREAM_PACKAGE_VERSION:
        raise ReferenceImplementationUnavailable(
            f"verifiable-intent {version!r} is installed but this connector is "
            f"pinned to {UPSTREAM_PACKAGE_VERSION!r} (commit {UPSTREAM_COMMIT}); "
            "verification is refused rather than assumed compatible"
        )

    return ReferenceImplementation(
        version=version,
        decode_sd_jwt=decode_sd_jwt,
        resolve_disclosures=resolve_disclosures,
        hash_disclosure=hash_disclosure,
        hash_bytes=hash_bytes,
        verify_chain=verify_chain,
        check_constraints=check_constraints,
        strictness_mode=StrictnessMode,
    )
