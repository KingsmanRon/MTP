"""Trusted external-issuer configuration for delegated authority.

Nothing in this package accepts a conclusion from a caller. It holds the
explicitly configured public trust material, parses an issuer's artefact
under hard bounds, and answers whether that artefact verifies — which is
the only thing that turns an untrusted claim into usable evidence.
"""

from api.trust.artefact import (
    ArtefactBounds,
    ArtefactParseError,
    DelegatedAuthorityArtefact,
    parse_authority_artefact,
)
from api.trust.issuer_registry import (
    IssuerKey,
    IssuerTrustConfigError,
    KeyStatus,
    TrustedIssuer,
    TrustedIssuerRegistry,
    load_registry_from_environment,
)

__all__ = [
    "ArtefactBounds",
    "ArtefactParseError",
    "DelegatedAuthorityArtefact",
    "IssuerKey",
    "IssuerTrustConfigError",
    "KeyStatus",
    "TrustedIssuer",
    "TrustedIssuerRegistry",
    "load_registry_from_environment",
    "parse_authority_artefact",
]
