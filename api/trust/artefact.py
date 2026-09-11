"""Parsing an issuer's delegated-authority artefact, under hard bounds.

Phase 7A, Gate 3. This module reads bytes that came from outside. It is
written on the assumption that they are hostile, so every dimension a
parser can be attacked along is bounded before any of it is interpreted:
total size, nesting depth, key count, string length, array length, and the
wall-clock budget for the whole operation.

Why the artefact is re-canonicalised
------------------------------------
The signature covers the RFC 8785 canonical form of the payload, not the
bytes as they arrived. So an attacker cannot smuggle a second meaning past
verification by re-ordering keys, changing number formatting, or adding
whitespace: every form of the same payload hashes identically, and any
payload that canonicalises differently is a different payload with a
different signature.

Duplicate keys are refused outright rather than resolved. JSON parsers
disagree about which duplicate wins, and a payload whose meaning depends
on that disagreement must never reach a policy decision.

What this module does NOT do
----------------------------
It does not verify a signature, know an issuer, or decide anything. It
turns bytes into a structurally valid :class:`DelegatedAuthorityArtefact`
or raises. Verification lives in ``api.services.authority_provider``,
which owns the trust decision.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Final

from api import jcs

#: Versioned artefact identifier. An artefact that does not say this is not
#: one of ours, and is refused rather than guessed at.
ARTEFACT_FORMAT: Final[str] = "inntris-delegated-authority-v1"

#: The signature algorithm this build verifies. An artefact naming anything
#: else is refused: silently accepting an unknown algorithm name and then
#: not checking it would be worse than refusing.
SUPPORTED_ALGORITHM: Final[str] = "ed25519"


class ArtefactParseError(ValueError):
    """The artefact is structurally unusable or exceeds a bound.

    Deliberately one error type for "malformed" and "too big". Both mean
    the same thing to the decision path — no usable evidence — and giving
    a caller a finer-grained oracle about which bound it hit only helps
    somebody probing the limits.
    """


@dataclass(frozen=True, slots=True)
class ArtefactBounds:
    """Every limit applied to an artefact, in one place.

    The defaults are far above any legitimate delegation (a real one is a
    few hundred bytes) and far below anything that could occupy a worker
    for a noticeable time.
    """

    #: Total serialised size of the artefact.
    max_bytes: int = 16 * 1024
    #: JSON nesting depth. A delegation is flat; 8 is generous.
    max_depth: int = 8
    #: Total number of object keys anywhere in the document.
    max_keys: int = 256
    #: Longest single string value.
    max_string_length: int = 2048
    #: Longest array.
    max_array_length: int = 64
    #: Wall-clock budget for parse plus verification, in seconds. Enforced
    #: by deadline checks rather than by a thread, because the work is
    #: bounded CPU and a cancelled thread mid-verification is worse than a
    #: refusal.
    budget_seconds: float = 2.0

    def __post_init__(self) -> None:
        for name in (
            "max_bytes",
            "max_depth",
            "max_keys",
            "max_string_length",
            "max_array_length",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not isinstance(self.budget_seconds, (int, float)) or (
            self.budget_seconds <= 0
        ):
            raise ValueError("budget_seconds must be positive")


DEFAULT_BOUNDS: Final[ArtefactBounds] = ArtefactBounds()


class Deadline:
    """A monotonic budget checked between stages.

    ``time.monotonic`` rather than wall time: a clock adjustment must not
    be able to extend or collapse the budget.
    """

    __slots__ = ("_expires_at", "_budget")

    def __init__(self, budget_seconds: float) -> None:
        self._budget = budget_seconds
        self._expires_at = time.monotonic() + budget_seconds

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self._expires_at

    def check(self, stage: str) -> None:
        if self.expired:
            raise ArtefactParseError(
                f"authority resolution exceeded its {self._budget}s budget at "
                f"stage {stage!r}"
            )


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ArtefactParseError(
                f"duplicate key {key!r}; a payload whose meaning depends on "
                "which duplicate a parser prefers cannot reach a decision"
            )
        seen[key] = value
    return seen


def _walk(value: Any, bounds: ArtefactBounds, depth: int, counter: list[int]) -> None:
    """Enforce depth, key count, string and array bounds over the tree."""
    if depth > bounds.max_depth:
        raise ArtefactParseError("artefact exceeds the permitted nesting depth")
    if isinstance(value, dict):
        counter[0] += len(value)
        if counter[0] > bounds.max_keys:
            raise ArtefactParseError("artefact exceeds the permitted key count")
        for key, child in value.items():
            if len(key) > bounds.max_string_length:
                raise ArtefactParseError("artefact contains an over-long key")
            _walk(child, bounds, depth + 1, counter)
    elif isinstance(value, list):
        if len(value) > bounds.max_array_length:
            raise ArtefactParseError("artefact exceeds the permitted array length")
        for child in value:
            _walk(child, bounds, depth + 1, counter)
    elif isinstance(value, str):
        if len(value) > bounds.max_string_length:
            raise ArtefactParseError("artefact contains an over-long string")
    elif isinstance(value, float):
        # Floats do not round-trip through canonicalisation identically on
        # every producer, and money must never be one. Amounts are strings.
        raise ArtefactParseError(
            "artefact contains a floating-point number; amounts and limits "
            "must be strings so they canonicalise identically everywhere"
        )


def _require_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ArtefactParseError(f"{field_name} must be an object")
    return value


def _require_text(value: Any, field_name: str, *, bounds: ArtefactBounds) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ArtefactParseError(f"{field_name} must be a non-empty string")
    if len(value) > bounds.max_string_length:
        raise ArtefactParseError(f"{field_name} is over-long")
    return value


def _optional_instant(value: Any, field_name: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ArtefactParseError(f"{field_name} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ArtefactParseError(f"{field_name} is not an ISO-8601 instant") from exc
    if parsed.tzinfo is None:
        raise ArtefactParseError(
            f"{field_name} must carry an explicit UTC offset; a naive instant "
            "is ambiguous and cannot be checked for validity"
        )
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class DelegatedAuthorityArtefact:
    """A structurally valid, not-yet-verified issuer artefact.

    Holding one of these means the bytes parsed and fit inside every
    bound. It means nothing whatsoever about whether the signature is
    good, the issuer is trusted, or the delegation is still live.
    """

    #: The issuer identifier as the artefact states it. Compared against
    #: the claim's issuer AND looked up in the registry; both must agree.
    issuer: str
    #: The issuer's own identifier for this delegation.
    authority_id: str
    #: SHA-256 over the canonical bytes actually inspected. This is what a
    #: later audit compares to tell whether evidence changed underneath a
    #: decision.
    artefact_digest: str
    #: The canonical signed bytes, kept so verification signs exactly what
    #: was hashed and nothing re-serialises in between.
    signed_bytes: bytes
    #: Issuer-side identity of the principal this delegation belongs to.
    principal_claims: Mapping[str, Any]
    #: Issuer-side identity of the delegate permitted to act, when the
    #: issuer expresses delegate binding at all.
    delegate_claims: Mapping[str, Any]
    #: The issuer's scope, in the issuer's own vocabulary. Translated to
    #: neutral keys by the provider, never read as neutral here.
    scope_claims: Mapping[str, Any]
    not_before: datetime | None
    not_after: datetime | None
    signature_algorithm: str
    signature_key_id: str
    signature_value_b64: str
    #: Present only when the issuer binds a delegate key cryptographically.
    delegate_proof: Mapping[str, Any] | None = field(default=None)

    def __post_init__(self) -> None:
        for name in ("principal_claims", "delegate_claims", "scope_claims"):
            object.__setattr__(
                self, name, MappingProxyType(dict(getattr(self, name)))
            )
        if self.delegate_proof is not None:
            object.__setattr__(
                self, "delegate_proof", MappingProxyType(dict(self.delegate_proof))
            )


def parse_authority_artefact(
    raw: bytes | str | Mapping[str, Any],
    *,
    bounds: ArtefactBounds = DEFAULT_BOUNDS,
    deadline: Deadline | None = None,
) -> DelegatedAuthorityArtefact:
    """Parse and bound-check an issuer artefact. Verifies nothing.

    ``raw`` may be bytes, text, or an already-decoded mapping (the HTTP
    surface receives evidence as a JSON object). A mapping is re-encoded
    before the size bound is applied, so the limit means the same thing
    whichever door the artefact came through.
    """
    deadline = deadline or Deadline(bounds.budget_seconds)

    if isinstance(raw, Mapping):
        # Re-encode compactly so max_bytes bounds the same quantity
        # regardless of how the caller delivered it.
        try:
            payload_bytes = json.dumps(dict(raw), separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ArtefactParseError("artefact is not JSON-encodable") from exc
    elif isinstance(raw, str):
        payload_bytes = raw.encode("utf-8")
    elif isinstance(raw, (bytes, bytearray)):
        payload_bytes = bytes(raw)
    else:
        raise ArtefactParseError(
            f"artefact must be bytes, text or a mapping, got {type(raw).__name__}"
        )

    # Size FIRST, before any parse. Everything downstream is bounded by it.
    if len(payload_bytes) > bounds.max_bytes:
        raise ArtefactParseError(
            f"artefact exceeds the {bounds.max_bytes}-byte limit"
        )
    deadline.check("size")

    try:
        document = json.loads(
            payload_bytes.decode("utf-8"), object_pairs_hook=_no_duplicate_keys
        )
    except UnicodeDecodeError as exc:
        raise ArtefactParseError("artefact is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ArtefactParseError("artefact is not valid JSON") from exc
    deadline.check("decode")

    if not isinstance(document, dict):
        raise ArtefactParseError("artefact must be a JSON object")
    _walk(document, bounds, depth=1, counter=[0])
    deadline.check("bounds")

    payload = _require_mapping(document.get("payload"), "payload")
    signature = _require_mapping(document.get("signature"), "signature")

    declared_format = _require_text(payload.get("format"), "payload.format", bounds=bounds)
    if declared_format != ARTEFACT_FORMAT:
        raise ArtefactParseError(
            f"unknown artefact format {declared_format!r}; expected {ARTEFACT_FORMAT!r}"
        )

    algorithm = _require_text(
        signature.get("algorithm"), "signature.algorithm", bounds=bounds
    )
    if algorithm != SUPPORTED_ALGORITHM:
        raise ArtefactParseError(
            f"unsupported signature algorithm {algorithm!r}; this build "
            f"verifies {SUPPORTED_ALGORITHM!r} only"
        )

    issuer = _require_text(payload.get("issuer"), "payload.issuer", bounds=bounds)
    authority_id = _require_text(
        payload.get("authority_id"), "payload.authority_id", bounds=bounds
    )

    principal_claims = _require_mapping(payload.get("principal"), "payload.principal")
    delegate_claims = (
        _require_mapping(payload.get("delegate"), "payload.delegate")
        if payload.get("delegate") is not None
        else {}
    )
    scope_claims = _require_mapping(payload.get("scope"), "payload.scope")

    not_before = _optional_instant(payload.get("not_before"), "payload.not_before")
    not_after = _optional_instant(payload.get("not_after"), "payload.not_after")
    if not_before is not None and not_after is not None and not_after <= not_before:
        raise ArtefactParseError("payload.not_after must be strictly after not_before")

    # The signature covers the CANONICAL payload, so re-canonicalise here
    # and carry those exact bytes forward. Nothing between this line and
    # the signature check may re-serialise.
    try:
        signed_bytes = jcs.canonicalize(payload)
    except (TypeError, ValueError) as exc:
        raise ArtefactParseError(
            f"payload cannot be canonicalised: {exc}"
        ) from exc
    deadline.check("canonicalise")

    delegate_proof = (
        _require_mapping(document.get("delegate_proof"), "delegate_proof")
        if document.get("delegate_proof") is not None
        else None
    )

    return DelegatedAuthorityArtefact(
        issuer=issuer,
        authority_id=authority_id,
        artefact_digest=jcs.sha256_hex(payload),
        signed_bytes=signed_bytes,
        principal_claims=principal_claims,
        delegate_claims=delegate_claims,
        scope_claims=scope_claims,
        not_before=not_before,
        not_after=not_after,
        signature_algorithm=algorithm,
        signature_key_id=_require_text(
            signature.get("key_id"), "signature.key_id", bounds=bounds
        ),
        signature_value_b64=_require_text(
            signature.get("value"), "signature.value", bounds=bounds
        ),
        delegate_proof=delegate_proof,
    )


__all__ = [
    "ARTEFACT_FORMAT",
    "ArtefactBounds",
    "ArtefactParseError",
    "DEFAULT_BOUNDS",
    "Deadline",
    "DelegatedAuthorityArtefact",
    "SUPPORTED_ALGORITHM",
    "parse_authority_artefact",
]
