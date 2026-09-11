"""The explicitly configured trust roots for delegated authority.

Phase 7A, Gate 3. Until now a delegation could not be resolved at all:
``AuthorityEvaluationService`` raised ``AUTHORITY_PROVIDER_UNAVAILABLE``
because no provider was configured. That is a safe default and a useless
one. This module supplies the missing half — *which issuers Core trusts,
under which public keys* — in a form an operator can review, rotate and
revoke.

No network key discovery
------------------------
Issuer keys are resolved from explicitly configured trust material and
from nowhere else. There is deliberately no online discovery client here.

That is a deliberate scope decision, not an omission: this build does not
claim that any card scheme or issuer operates a key-discovery endpoint for
this purpose, and implementing one would mean either inventing an endpoint
or fetching from a URL an operator typed. Both are worse than configured
trust, and the second adds a network dependency on the authorisation path
whose failure modes then have to be reasoned about.

The consequence is that the questions Gate 3 asks about network resolution
have a short answer: there is no cache, because there is nothing to cache;
there is no refresh interval, because trust material changes only when a
deployment changes it; and a network outage cannot change the answer,
because no answer depends on the network.

What DOES depend on the database is revocation (see
``api.trust.revocations``), and that read fails closed: if Core cannot
establish that an issuer, key or delegation is still live, no new
delegated authority is accepted.

No private material, ever
-------------------------
This configuration holds public keys and nothing else. Core verifies
issuer signatures; it never produces one, so it has no legitimate use for
an issuer private key. A configuration carrying anything shaped like
private key material is REFUSED rather than ignored — a config that
silently tolerates a leaked secret trains people to leave it there.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

logger = logging.getLogger(__name__)

#: Path to a JSON trust configuration file.
TRUST_FILE_ENV: Final[str] = "INNTRIS_AUTHORITY_TRUST_FILE"
#: Inline JSON trust configuration, for deployments that inject config as
#: environment rather than as files.
TRUST_INLINE_ENV: Final[str] = "INNTRIS_AUTHORITY_TRUST"

#: Ed25519 raw public keys are exactly 32 bytes.
_ED25519_PUBLIC_KEY_BYTES: Final[int] = 32

#: Keys whose presence means somebody pasted a secret into trust config.
#: Checked against the whole document, at any depth.
_FORBIDDEN_KEYS: Final[frozenset[str]] = frozenset(
    {
        "private_key",
        "privatekey",
        "secret",
        "secret_key",
        "seed",
        "signing_key",
        "d",  # the JWK private scalar
        "k",  # the JWK symmetric key
    }
)

#: Markers of PEM-encoded private material appearing in any string value.
_FORBIDDEN_MARKERS: Final[tuple[str, ...]] = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
)


class IssuerTrustConfigError(ValueError):
    """The trust configuration is unusable.

    Always fatal at load time rather than tolerated at request time. Trust
    material that half-loads is the worst of both worlds: some issuers work
    and nobody notices the ones that silently do not.
    """


class KeyStatus(StrEnum):
    """Where a key sits in its lifecycle.

    ``RETIRED`` and ``REVOKED`` are deliberately different. A retired key
    signed things legitimately and simply must not sign new ones —
    historical artefacts it signed stay verifiable for audit. A revoked key
    is one whose signatures were never trustworthy, or are no longer to be
    treated as such, and nothing it signed is accepted at any time.
    """

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class IssuerStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class IssuerKey:
    """One public key an issuer signs delegations with."""

    key_id: str
    public_key: bytes
    fingerprint: str
    status: KeyStatus
    not_before: datetime | None = None
    not_after: datetime | None = None

    def usable_for_new_authority(self, at: datetime) -> bool:
        """Whether this key may authenticate a delegation being resolved now."""
        if self.status is not KeyStatus.ACTIVE:
            return False
        if self.not_before is not None and at < self.not_before:
            return False
        return not (self.not_after is not None and at >= self.not_after)


@dataclass(frozen=True)
class TrustedIssuer:
    """One issuer Core will accept delegated authority from."""

    issuer_id: str
    display_name: str
    status: IssuerStatus
    keys: tuple[IssuerKey, ...]
    #: Which principal claim in the artefact must match which server-side
    #: binding key, e.g. ``{"account_reference": "issuer_account_reference"}``
    #: reads ``payload.principal.account_reference`` and compares it to the
    #: trusted ``ExecutionContext.principal_binding["issuer_account_reference"]``.
    #: Empty means this issuer names no principal Core can check — which is
    #: refused at load time, because an unbindable delegation would be usable
    #: against any principal in the organisation.
    principal_claim_bindings: Mapping[str, str] = field(default_factory=dict)
    #: Whether this issuer expresses delegate binding at all. When False the
    #: resolution reports ``DelegateBindingStatus.UNSUPPORTED`` rather than
    #: inventing a binding the issuer never made.
    expresses_delegate_binding: bool = False
    #: Which server-side binding key holds the delegate key fingerprint the
    #: artefact must name. Required when ``expresses_delegate_binding``.
    delegate_binding_key: str | None = None
    #: Issuer scope field -> neutral scope key understood by the payment
    #: domain. An issuer field with no mapping is carried through unchanged,
    #: which makes it an unknown key downstream and therefore fails closed.
    scope_field_mapping: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "principal_claim_bindings",
            MappingProxyType(dict(self.principal_claim_bindings)),
        )
        object.__setattr__(
            self, "scope_field_mapping", MappingProxyType(dict(self.scope_field_mapping))
        )

    def key(self, key_id: str) -> IssuerKey | None:
        for candidate in self.keys:
            if candidate.key_id == key_id:
                return candidate
        return None

    def key_by_fingerprint(self, fingerprint: str) -> IssuerKey | None:
        for candidate in self.keys:
            if candidate.fingerprint == fingerprint:
                return candidate
        return None


def _reject_private_material(node: Any, path: str = "$") -> None:
    """Refuse a configuration that carries anything shaped like a secret."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key.strip().lower() in _FORBIDDEN_KEYS:
                raise IssuerTrustConfigError(
                    f"trust configuration carries a forbidden key {key!r} at "
                    f"{path}; this file holds public verification material "
                    "only and must never contain private key material"
                )
            _reject_private_material(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _reject_private_material(value, f"{path}[{index}]")
    elif isinstance(node, str):
        for marker in _FORBIDDEN_MARKERS:
            if marker in node:
                raise IssuerTrustConfigError(
                    f"trust configuration contains PEM private key material at "
                    f"{path}; rotate that key immediately and remove it from "
                    "configuration"
                )


def _decode_public_key(raw: Any, *, where: str) -> bytes:
    """Accept hex or standard base64; require exactly 32 raw bytes."""
    if not isinstance(raw, str) or not raw.strip():
        raise IssuerTrustConfigError(f"{where}: public_key must be a non-empty string")
    text = raw.strip()
    decoded: bytes | None = None
    if len(text) == _ED25519_PUBLIC_KEY_BYTES * 2:
        try:
            decoded = bytes.fromhex(text)
        except ValueError:
            decoded = None
    if decoded is None:
        try:
            decoded = base64.b64decode(text, validate=True)
        except (ValueError, TypeError) as exc:
            raise IssuerTrustConfigError(
                f"{where}: public_key must be hex or base64"
            ) from exc
    if len(decoded) != _ED25519_PUBLIC_KEY_BYTES:
        raise IssuerTrustConfigError(
            f"{where}: public_key must decode to {_ED25519_PUBLIC_KEY_BYTES} "
            f"bytes, got {len(decoded)}"
        )
    if decoded == bytes(_ED25519_PUBLIC_KEY_BYTES):
        # The all-zero point is not a usable Ed25519 key and is what an
        # uninitialised template leaves behind.
        raise IssuerTrustConfigError(f"{where}: public_key must not be all zeroes")
    return decoded


def _instant(raw: Any, *, where: str) -> datetime | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise IssuerTrustConfigError(f"{where} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IssuerTrustConfigError(f"{where} is not an ISO-8601 instant") from exc
    if parsed.tzinfo is None:
        raise IssuerTrustConfigError(f"{where} must carry an explicit UTC offset")
    return parsed.astimezone(UTC)


def public_key_fingerprint(public_key: bytes) -> str:
    """SHA-256 over the raw 32-byte key.

    Same construction the evidence-pack key mirror already publishes, so
    an operator comparing a fingerprint across the two is comparing like
    with like.
    """
    return hashlib.sha256(public_key).hexdigest()


def _build_key(raw: Any, *, issuer_id: str) -> IssuerKey:
    if not isinstance(raw, dict):
        raise IssuerTrustConfigError(f"issuer {issuer_id}: each key must be an object")
    key_id = raw.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise IssuerTrustConfigError(f"issuer {issuer_id}: key_id is required")
    where = f"issuer {issuer_id} key {key_id}"

    public_key = _decode_public_key(raw.get("public_key"), where=where)
    computed = public_key_fingerprint(public_key)

    declared = raw.get("fingerprint")
    if declared is not None and (
        not isinstance(declared, str) or declared.strip().lower() != computed
    ):
        # The fingerprint is what an operator reads out loud during a
        # rotation. A config whose stated fingerprint disagrees with its own
        # key is not a typo to tolerate: one of the two is wrong and there is
        # no way to tell which.
        raise IssuerTrustConfigError(
            f"{where}: declared fingerprint does not match the public key "
            f"(computed {computed})"
        )

    status_raw = raw.get("status", KeyStatus.ACTIVE.value)
    try:
        status = KeyStatus(str(status_raw))
    except ValueError as exc:
        raise IssuerTrustConfigError(
            f"{where}: status must be one of "
            f"{', '.join(s.value for s in KeyStatus)}"
        ) from exc

    not_before = _instant(raw.get("not_before"), where=f"{where}.not_before")
    not_after = _instant(raw.get("not_after"), where=f"{where}.not_after")
    if not_before is not None and not_after is not None and not_after <= not_before:
        raise IssuerTrustConfigError(f"{where}: not_after must be after not_before")

    return IssuerKey(
        key_id=key_id,
        public_key=public_key,
        fingerprint=computed,
        status=status,
        not_before=not_before,
        not_after=not_after,
    )


def _build_issuer(raw: Any) -> TrustedIssuer:
    if not isinstance(raw, dict):
        raise IssuerTrustConfigError("each issuer must be an object")
    issuer_id = raw.get("issuer_id")
    if not isinstance(issuer_id, str) or not issuer_id.strip():
        raise IssuerTrustConfigError("issuer_id is required")

    try:
        status = IssuerStatus(str(raw.get("status", IssuerStatus.ACTIVE.value)))
    except ValueError as exc:
        raise IssuerTrustConfigError(
            f"issuer {issuer_id}: status must be active or disabled"
        ) from exc

    keys_raw = raw.get("keys")
    if not isinstance(keys_raw, list) or not keys_raw:
        raise IssuerTrustConfigError(f"issuer {issuer_id}: at least one key is required")
    keys = tuple(_build_key(entry, issuer_id=issuer_id) for entry in keys_raw)

    seen_ids = [key.key_id for key in keys]
    if len(set(seen_ids)) != len(seen_ids):
        raise IssuerTrustConfigError(f"issuer {issuer_id}: duplicate key_id")
    seen_fingerprints = [key.fingerprint for key in keys]
    if len(set(seen_fingerprints)) != len(seen_fingerprints):
        raise IssuerTrustConfigError(
            f"issuer {issuer_id}: two key entries carry the same public key"
        )

    bindings = raw.get("principal_claim_bindings")
    if not isinstance(bindings, dict) or not bindings:
        # Without this, a delegation naming principal X would be accepted for
        # principal Y in the same organisation: the artefact would verify and
        # nothing would tie it to the agent actually acting.
        raise IssuerTrustConfigError(
            f"issuer {issuer_id}: principal_claim_bindings is required; an "
            "issuer whose delegations cannot be tied to a specific principal "
            "would be usable against any principal in the organisation"
        )
    for claim, binding in bindings.items():
        if not isinstance(claim, str) or not isinstance(binding, str):
            raise IssuerTrustConfigError(
                f"issuer {issuer_id}: principal_claim_bindings must map strings "
                "to strings"
            )

    expresses_delegate_binding = bool(raw.get("expresses_delegate_binding", False))
    delegate_binding_key = raw.get("delegate_binding_key")
    if expresses_delegate_binding:
        if not isinstance(delegate_binding_key, str) or not delegate_binding_key.strip():
            raise IssuerTrustConfigError(
                f"issuer {issuer_id}: delegate_binding_key is required when the "
                "issuer expresses delegate binding"
            )
    elif delegate_binding_key is not None:
        raise IssuerTrustConfigError(
            f"issuer {issuer_id}: delegate_binding_key is set but "
            "expresses_delegate_binding is false; one of the two is wrong"
        )

    scope_mapping = raw.get("scope_field_mapping", {})
    if not isinstance(scope_mapping, dict):
        raise IssuerTrustConfigError(
            f"issuer {issuer_id}: scope_field_mapping must be an object"
        )

    return TrustedIssuer(
        issuer_id=issuer_id,
        display_name=str(raw.get("display_name") or issuer_id),
        status=status,
        keys=keys,
        principal_claim_bindings=bindings,
        expresses_delegate_binding=expresses_delegate_binding,
        delegate_binding_key=delegate_binding_key,
        scope_field_mapping=scope_mapping,
    )


@dataclass(frozen=True)
class TrustedIssuerRegistry:
    """Every issuer Core trusts, and under which keys."""

    issuers: Mapping[str, TrustedIssuer]

    def __post_init__(self) -> None:
        object.__setattr__(self, "issuers", MappingProxyType(dict(self.issuers)))

    def __bool__(self) -> bool:
        return bool(self.issuers)

    def issuer(self, issuer_id: str) -> TrustedIssuer | None:
        return self.issuers.get(issuer_id)

    def fingerprints(self) -> dict[str, list[str]]:
        """issuer -> fingerprints, for the release evidence record."""
        return {
            issuer_id: [
                f"{key.key_id}:{key.fingerprint}:{key.status.value}"
                for key in issuer.keys
            ]
            for issuer_id, issuer in sorted(self.issuers.items())
        }

    @classmethod
    def from_document(cls, document: Any) -> TrustedIssuerRegistry:
        _reject_private_material(document)
        if not isinstance(document, dict):
            raise IssuerTrustConfigError("trust configuration must be a JSON object")
        version = document.get("version")
        if version != 1:
            raise IssuerTrustConfigError(
                f"unsupported trust configuration version {version!r}; expected 1"
            )
        issuers_raw = document.get("issuers")
        if not isinstance(issuers_raw, list):
            raise IssuerTrustConfigError("trust configuration needs an issuers array")

        issuers: dict[str, TrustedIssuer] = {}
        for entry in issuers_raw:
            issuer = _build_issuer(entry)
            if issuer.issuer_id in issuers:
                raise IssuerTrustConfigError(
                    f"duplicate issuer_id {issuer.issuer_id!r}"
                )
            issuers[issuer.issuer_id] = issuer
        return cls(issuers=issuers)

    @classmethod
    def empty(cls) -> TrustedIssuerRegistry:
        """No issuer is trusted. Every delegation fails closed."""
        return cls(issuers={})


def load_registry_from_environment(
    environ: Mapping[str, str] | None = None,
) -> TrustedIssuerRegistry:
    """Build the registry from configuration, or return an empty one.

    An empty registry is a valid and safe state: it means no issuer is
    trusted, so every presented delegation resolves unverified and blocks.
    It is NOT the same as a broken configuration, which raises — a
    deployment with a malformed trust file must fail to start rather than
    come up quietly trusting nobody and refusing traffic it should serve.
    """
    env = environ if environ is not None else os.environ

    inline = (env.get(TRUST_INLINE_ENV) or "").strip()
    path_value = (env.get(TRUST_FILE_ENV) or "").strip()
    if inline and path_value:
        raise IssuerTrustConfigError(
            f"set exactly one of {TRUST_INLINE_ENV} and {TRUST_FILE_ENV}"
        )

    if inline:
        try:
            document = json.loads(inline)
        except json.JSONDecodeError as exc:
            raise IssuerTrustConfigError(
                f"{TRUST_INLINE_ENV} is not valid JSON"
            ) from exc
    elif path_value:
        path = Path(path_value)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise IssuerTrustConfigError(
                f"{TRUST_FILE_ENV} points at {path} which cannot be read"
            ) from exc
        except json.JSONDecodeError as exc:
            raise IssuerTrustConfigError(f"{path} is not valid JSON") from exc
    else:
        logger.info(
            "no delegated-authority trust configuration; every presented "
            "delegation will fail closed"
        )
        return TrustedIssuerRegistry.empty()

    registry = TrustedIssuerRegistry.from_document(document)
    logger.info(
        "loaded delegated-authority trust for %d issuer(s): %s",
        len(registry.issuers),
        ", ".join(sorted(registry.issuers)),
    )
    return registry


__all__ = [
    "IssuerKey",
    "IssuerStatus",
    "IssuerTrustConfigError",
    "KeyStatus",
    "TRUST_FILE_ENV",
    "TRUST_INLINE_ENV",
    "TrustedIssuer",
    "TrustedIssuerRegistry",
    "load_registry_from_environment",
    "public_key_fingerprint",
]
