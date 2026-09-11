"""Verifiable Intent as one Inntris ``AuthorityProvider``.

Verifiable Intent (https://verifiableintent.dev/) is a public draft that
defines a layered SD-JWT credential chain binding an agent's commercial
actions to a user's stated purchase intent. This connector treats a
verified chain as *delegated-authority input*: evidence of what a user
delegated to an agent, and to which agent.

It is one input, never a conclusion. Inntris applies the organisation's
current policy independently afterwards, and that policy can block an act
whose Verifiable Intent chain verified perfectly. The reverse never
happens: nothing here can widen an organisation limit, and no valid
external credential produces an ALLOW on its own.

Scope of this release
---------------------
Layer 1 and Layer 2 (autonomous mode) are verified against the pinned
upstream reference implementation. Layer 3 — the agent's final commitment
to a payment network and a merchant — is **not** verified and is refused
if presented: Inntris decides before an act, and no Layer 3 exists then.
Nothing here is a Mastercard Agent Pay call, an AP4M execution, a
settlement, or any claim of partnership, certification or conformance.

See ``docs/integrations/mastercard-vi-profile.md`` for the pinned commit,
the field-by-field mapping, and everything deliberately left out.
"""

from __future__ import annotations

from api.connectors.mastercard_vi.binding import (
    PRINCIPAL_BINDING_CONTEXT_KEY,
    DelegateBindingOutcome,
    PrincipalBindingError,
    PrincipalDelegateBindingResolver,
    StaticPrincipalDelegateBindingResolver,
    VerifiableIntentPrincipalBinding,
    binding_from_principal_binding,
)
from api.connectors.mastercard_vi.credential import (
    CredentialMaterialError,
    PresentedCredential,
    UnsupportedCredentialLayerError,
    read_presented_credential,
)
from api.connectors.mastercard_vi.keys import (
    IssuerKeyError,
    IssuerKeyResolver,
    StaticIssuerKeyResolver,
    TrustedIssuerKeyset,
    jwk_thumbprint,
    public_key_from_jwk,
)
from api.connectors.mastercard_vi.profile import (
    AUTHORITY_ISSUER_SCHEME,
    L1_VCT_MASTERCARD_CARD,
    MAPPED_PAYMENT_CONSTRAINT_TYPES,
    REGISTERED_CONSTRAINT_TYPES,
    SPEC_REVISION,
    UPSTREAM_COMMIT,
    UPSTREAM_PACKAGE_VERSION,
    UPSTREAM_REPOSITORY,
    UPSTREAM_SITE,
    USAGE_ACCOUNTING_CONSTRAINT_TYPES,
)
from api.connectors.mastercard_vi.provider import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    VerifiableIntentAuthorityProvider,
    VerifiableIntentResolution,
    effective_chain_validity,
)
from api.connectors.mastercard_vi.reference import (
    ReferenceImplementationUnavailable,
    load_reference,
)
from api.connectors.mastercard_vi.scope import (
    MappedDelegationScope,
    ScopeMappingError,
    map_payment_mandate,
    minor_units_to_major_string,
    payee_reference,
)

__all__ = [
    "AUTHORITY_ISSUER_SCHEME",
    "DEFAULT_CLOCK_SKEW_SECONDS",
    "L1_VCT_MASTERCARD_CARD",
    "MAPPED_PAYMENT_CONSTRAINT_TYPES",
    "PRINCIPAL_BINDING_CONTEXT_KEY",
    "REGISTERED_CONSTRAINT_TYPES",
    "SPEC_REVISION",
    "UPSTREAM_COMMIT",
    "UPSTREAM_PACKAGE_VERSION",
    "UPSTREAM_REPOSITORY",
    "UPSTREAM_SITE",
    "USAGE_ACCOUNTING_CONSTRAINT_TYPES",
    "CredentialMaterialError",
    "DelegateBindingOutcome",
    "IssuerKeyError",
    "IssuerKeyResolver",
    "MappedDelegationScope",
    "PresentedCredential",
    "PrincipalBindingError",
    "PrincipalDelegateBindingResolver",
    "ReferenceImplementationUnavailable",
    "ScopeMappingError",
    "StaticIssuerKeyResolver",
    "StaticPrincipalDelegateBindingResolver",
    "TrustedIssuerKeyset",
    "UnsupportedCredentialLayerError",
    "VerifiableIntentAuthorityProvider",
    "VerifiableIntentPrincipalBinding",
    "VerifiableIntentResolution",
    "binding_from_principal_binding",
    "effective_chain_validity",
    "jwk_thumbprint",
    "load_reference",
    "map_payment_mandate",
    "minor_units_to_major_string",
    "payee_reference",
    "public_key_from_jwk",
    "read_presented_credential",
]
