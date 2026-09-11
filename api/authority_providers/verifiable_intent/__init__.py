"""Verifiable Intent as an authority input to Inntris policy.

VI is the *input*. It says what an issuer and a user delegated. It never
says whether this organisation permits the act — that is Inntris policy,
which runs afterwards and may refuse something VI plainly allows.

The supported constraint set is small and explicit; see
:mod:`api.authority_providers.verifiable_intent.scope`. A delegation
carrying anything outside it fails closed rather than being enforced in
part.
"""

from __future__ import annotations

from api.authority_providers.verifiable_intent.provider import (
    ARTEFACT_DIGEST_FORMAT,
    L2_PAYMENT_MANDATE_VCT,
    VERIFIABLE_INTENT_ISSUER_KIND,
    PresentedDelegation,
    VerifiableIntentAuthorityProvider,
    VerifiableIntentProviderFault,
    artefact_digest,
    jwk_thumbprint,
    read_presented_delegation,
)
from api.authority_providers.verifiable_intent.scope import (
    CHAIN_ENFORCED_CONSTRAINT_TYPES,
    KNOWN_UNSUPPORTED_CONSTRAINT_TYPES,
    SUPPORTED_CONSTRAINT_TYPES,
    UNSUPPORTED_KEY_PREFIX,
    MappedScope,
    VerifiableIntentScopeError,
    map_payment_constraints,
)
from api.authority_providers.verifiable_intent.trust import (
    IssuerTrustError,
    IssuerTrustStore,
    StaticIssuerTrustStore,
    TrustedIssuer,
)

__all__ = [
    "ARTEFACT_DIGEST_FORMAT",
    "CHAIN_ENFORCED_CONSTRAINT_TYPES",
    "KNOWN_UNSUPPORTED_CONSTRAINT_TYPES",
    "L2_PAYMENT_MANDATE_VCT",
    "SUPPORTED_CONSTRAINT_TYPES",
    "UNSUPPORTED_KEY_PREFIX",
    "VERIFIABLE_INTENT_ISSUER_KIND",
    "IssuerTrustError",
    "IssuerTrustStore",
    "MappedScope",
    "PresentedDelegation",
    "StaticIssuerTrustStore",
    "TrustedIssuer",
    "VerifiableIntentAuthorityProvider",
    "VerifiableIntentProviderFault",
    "VerifiableIntentScopeError",
    "artefact_digest",
    "jwk_thumbprint",
    "map_payment_constraints",
    "read_presented_delegation",
]
