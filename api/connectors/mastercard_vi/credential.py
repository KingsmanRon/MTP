"""Reading the credential material a caller presented, before trusting any of it.

The evidence mapping on a :class:`DelegatedAuthorityClaim` is caller data.
Everything here treats it that way: it is shape-checked and bounded before
a single byte reaches the reference implementation, and nothing it says
about itself is believed.

Presented shape
---------------
::

    {"layer1": "<serialized L1 SD-JWT>", "layer2": "<serialized L2 SD-JWT>"}

Both are the full SD-JWT serializations — base JWT, ``~``, disclosures,
trailing ``~`` — exactly as the holder received them. The L2 ``sd_hash``
binds to the L1 *serialization the L2 signer saw*, so re-serializing or
trimming disclosures in transit breaks the chain, which is the intended
behaviour rather than something to work around.

Layer 3 is not accepted
-----------------------
Layer 3 is the agent's final commitment to concrete values, produced for a
payment network and a merchant. Inntris is neither: it decides whether to
issue execution authority *before* the act, so at evaluation time no L3
exists. Presenting one here would invite the reading that Inntris verified
a completed Verifiable Intent transaction, which it has not. Any L3 key is
therefore rejected outright rather than ignored.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

#: Upper bound on a single presented credential string. A Verifiable Intent
#: L1/L2 pair is a few kilobytes; this leaves a wide margin while keeping a
#: hostile caller from pushing megabytes through parsing and hashing.
MAX_CREDENTIAL_CHARS: Final[int] = 64 * 1024

LAYER1_KEY: Final[str] = "layer1"
LAYER2_KEY: Final[str] = "layer2"

#: Keys accepted on the evidence mapping. Anything else is refused rather
#: than ignored: an unread key is a claim the caller believes it made.
ACCEPTED_EVIDENCE_KEYS: Final[frozenset[str]] = frozenset({LAYER1_KEY, LAYER2_KEY})

#: Keys that name material this release deliberately does not verify.
#: Called out separately so the refusal explains itself.
REJECTED_LAYER3_KEYS: Final[frozenset[str]] = frozenset(
    {"layer3", "layer3a", "layer3b", "l3", "l3a", "l3b", "layer3_payment", "layer3_checkout"}
)


class CredentialMaterialError(ValueError):
    """The presented credential material is not usable as presented."""


class UnsupportedCredentialLayerError(CredentialMaterialError):
    """The caller presented a credential layer this release does not verify."""


@dataclass(frozen=True, slots=True)
class PresentedCredential:
    """The exact serialized Layer 1 and Layer 2 strings the caller handed over."""

    layer1_serialized: str
    layer2_serialized: str


def _require_credential_string(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise CredentialMaterialError(
            f"evidence.{field} must be a string, got {type(value).__name__}"
        )
    if not value.strip():
        raise CredentialMaterialError(f"evidence.{field} must not be empty")
    if len(value) > MAX_CREDENTIAL_CHARS:
        raise CredentialMaterialError(
            f"evidence.{field} exceeds the maximum of {MAX_CREDENTIAL_CHARS} characters"
        )
    if value.strip() != value:
        raise CredentialMaterialError(
            f"evidence.{field} must not have leading or trailing whitespace; the "
            "serialization is hashed exactly as presented"
        )
    if "~" not in value:
        raise CredentialMaterialError(
            f"evidence.{field} is not an SD-JWT serialization (no '~' separator)"
        )
    if not value.isascii():
        # An SD-JWT serialization is base64url segments joined by '~', so it
        # is ASCII by construction — and the chain bindings hash it as ASCII.
        # Rejecting here keeps a non-ASCII byte from reaching an ``ascii``
        # encode deep inside verification, where it would raise instead of
        # producing a refusal.
        raise CredentialMaterialError(
            f"evidence.{field} contains non-ASCII characters; an SD-JWT "
            "serialization is base64url and '~' only"
        )
    return value


def read_presented_credential(evidence: Mapping[str, Any] | None) -> PresentedCredential:
    """Validate the evidence mapping into the two strings this connector reads."""
    if not isinstance(evidence, Mapping):
        raise CredentialMaterialError(
            f"evidence must be a mapping, got {type(evidence).__name__}"
        )

    # Evidence is caller data, so its keys are not assumed to be strings.
    keys = [key for key in evidence if isinstance(key, str)]
    if len(keys) != len(evidence):
        raise CredentialMaterialError("evidence keys must all be strings")

    presented_l3 = sorted(key for key in keys if key.lower() in REJECTED_LAYER3_KEYS)
    if presented_l3:
        raise UnsupportedCredentialLayerError(
            "Layer 3 credential material was presented "
            f"({', '.join(presented_l3)}), and this release does not verify it. "
            "Inntris authorises an act before it happens; Layer 3 is the agent's "
            "record of an act already committed to a network and a merchant. "
            "Accepting it here would imply a verification that did not occur."
        )

    unknown = sorted(key for key in keys if key not in ACCEPTED_EVIDENCE_KEYS)
    if unknown:
        raise CredentialMaterialError(
            f"evidence carries unrecognised keys ({', '.join(unknown)}); this "
            "connector reads only "
            f"{', '.join(sorted(ACCEPTED_EVIDENCE_KEYS))}"
        )

    for required in (LAYER1_KEY, LAYER2_KEY):
        if required not in evidence:
            raise CredentialMaterialError(f"evidence.{required} is required")

    return PresentedCredential(
        layer1_serialized=_require_credential_string(evidence[LAYER1_KEY], LAYER1_KEY),
        layer2_serialized=_require_credential_string(evidence[LAYER2_KEY], LAYER2_KEY),
    )
