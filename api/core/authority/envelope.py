"""The validated executable representation of a proposed action.

Why there is exactly one representation
---------------------------------------
The failure mode this module exists to prevent is a system that reads the
recipient of an act from one place while hashing, policy-checking or
executing a *different* recipient read from somewhere else. So there is
one validated object — :class:`ExecutableAction` — and policy
evaluation, execution hashing and later executor handoff all derive from
it. :class:`ActionEnvelope` carries that object plus the decision and
provenance context that surrounds it; it never carries a second,
independently parsed copy of the act.

An action expresses its target **once**, in :attr:`ExecutableAction.target`.
A payload that also carries a target-designating key (``recipient``,
``resource_id``, ``destination``, …) is rejected, even when the two
representations happen to agree, because "they agree" is a judgement that
would have to be re-made identically by every layer. Adapters that accept
a legacy wire payload are responsible for lifting the target out of the
payload into ``target`` before building an ``ExecutableAction``.

The execution action hash
-------------------------
``execution_action_hash`` is a **new, separately versioned** hash. It is
deliberately not called ``action_hash``: that name already has deployed
meaning in Inntris (the client-signed request hash produced by
``api.crypto.CryptoService.compute_action_hash`` and carried in receipts,
approval tokens and anchors). Nothing here redefines or touches it. An
envelope may carry both — :attr:`ActionEnvelope.signed_action_hash` for
the existing signed request hash, and the execution action hash for the
semantic act.

Format identifier: ``inntris-execution-action-v1``.

**Preimage.** A JSON object canonicalized with the repository's RFC 8785
implementation (``api.jcs``) and hashed with SHA-256:

    {
      "format":        "inntris-execution-action-v1",   (required)
      "principal":     <principal_id>,                  (required)
      "organisation":  <organisation_id>,               (required)
      "domain":        <domain>,                        (required)
      "action_type":   <action_type>,                   (required)
      "target":        {"resource_type": …, "resource_id": …},  (optional)
      "payload":       <payload object>                 (required, may be {})
    }

**Omitted vs null.** At the top level of the preimage there are no null
values. ``target`` is the only optional member: when an action has no
target the key is *omitted entirely*, it is never emitted as ``null``.
So "absent" and "null" are the same thing for ``target``, and only one of
them is representable. Inside ``payload`` the rule is the opposite:
``payload`` is opaque application data, so a JSON ``null`` is a real
value that is preserved verbatim — ``{"memo": null}`` and ``{}`` are
different acts and hash differently.

**Strings.** Identifiers must be non-empty, single-line, free of control
characters and already Unicode NFC-normalised; non-NFC input is rejected
rather than normalised, so this layer never rewrites caller identity
behind its back. Payload strings are opaque and are canonicalized
verbatim with no normalisation of any kind.

**Permitted payload values.** ``str``, ``bool``, ``int``, finite
``float``, ``None``, arrays, and objects with string keys, nested no
deeper than :data:`MAX_PAYLOAD_DEPTH`. Everything else is rejected at
construction: ``Decimal`` (encode money as a string, as the executor
binding guide already does), ``datetime``, ``bytes``, ``set``, arbitrary
objects, non-string object keys, ``NaN`` and ``Infinity``. Rejection
happens before hashing, so a payload that cannot be canonicalized can
never reach a decision.

**What is deliberately absent.** The hash covers the semantic act an
executor would perform and nothing else. It does not include
``policy_hash``, the delegated-authority reference, the consequence
classification, a grant id, the request nonce or timestamp, or any
executor binding. Those are decision, provenance and binding context —
they belong to the grant, not to the act. It follows that two identical
acts hash identically; separate authorisations of the same act are
distinguished by grant id and consumption state, not by this hash.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Final

from api import jcs
from api.core.authority._validation import (
    require_identifier,
    require_optional_digest,
    require_optional_identifier,
    require_optional_utc,
)
from api.core.authority.authority import DelegatedAuthorityClaim
from api.core.authority.decision import ConsequenceClass
from api.core.authority.errors import InvalidEnvelopeError

# The versioned semantic-preimage identifier. It is a module constant, not
# an envelope field: no caller can choose the format string, so no caller
# can steer one act's preimage into another version's hash space. Because
# "format" is a required member of the canonical object, any future
# version string produces a different canonical form and therefore a
# different digest — versions cannot accidentally collide.
EXECUTION_ACTION_HASH_FORMAT: Final[str] = "inntris-execution-action-v1"

# Bound on payload nesting. Deep structures are rejected rather than
# recursed into.
MAX_PAYLOAD_DEPTH: Final[int] = 32

# Payload keys that would express the action's target a second time. An
# action names its target exactly once, in ``ExecutableAction.target``.
RESERVED_TARGET_PAYLOAD_KEYS: Final[frozenset[str]] = frozenset(
    {
        "counterparty",
        "counterparty_id",
        "destination",
        "destination_id",
        "payee",
        "payee_id",
        "recipient",
        "recipient_id",
        "resource",
        "resource_id",
        "resource_type",
        "target",
        "target_id",
        "target_type",
    }
)


def _freeze(value: Any, *, path: str, depth: int) -> Any:
    """Deep-freeze a payload value, rejecting anything JCS cannot encode."""
    if depth > MAX_PAYLOAD_DEPTH:
        raise InvalidEnvelopeError(
            f"payload nesting at {path} exceeds the maximum depth of {MAX_PAYLOAD_DEPTH}"
        )
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InvalidEnvelopeError(
                f"payload value at {path} is NaN or Infinity, which cannot be "
                "canonicalized; encode it as a string or omit the field"
            )
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidEnvelopeError(
                    f"payload object keys must be strings; {path} has a "
                    f"{type(key).__name__} key"
                )
            frozen[key] = _freeze(item, path=f"{path}.{key}", depth=depth + 1)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        # Only list and tuple are arrays. Other sequences are rejected on
        # purpose: bytes would otherwise iterate into an array of integers
        # and hash as one, silently turning binary data into a different act.
        return tuple(
            _freeze(item, path=f"{path}[{index}]", depth=depth + 1)
            for index, item in enumerate(value)
        )
    raise InvalidEnvelopeError(
        f"payload value at {path} has unsupported type {type(value).__name__}; "
        "permitted types are string, bool, int, finite float, null, array and "
        "object (encode decimals, timestamps and binary data as strings)"
    )


def _thaw(value: Any) -> Any:
    """Rebuild plain JSON types from a frozen payload for canonicalization."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class ResourceReference:
    """A neutral reference to the thing an action acts upon.

    Deliberately two opaque strings. Core does not know what a resource
    type means in any particular domain; it only needs a stable pair to
    hash and to hand to a domain policy.
    """

    resource_type: str
    resource_id: str

    def __post_init__(self) -> None:
        require_identifier(self.resource_type, "resource_type", error=InvalidEnvelopeError)
        require_identifier(self.resource_id, "resource_id", error=InvalidEnvelopeError)

    def as_preimage_member(self) -> dict[str, str]:
        """The canonical object this reference contributes to the preimage."""
        return {"resource_type": self.resource_type, "resource_id": self.resource_id}


@dataclass(frozen=True, slots=True)
class ExecutableAction:
    """The one validated representation of the act an executor would perform.

    Every downstream reading of "what is being done" — policy evaluation,
    execution hashing, executor handoff — derives from this object. There
    is no second parse of the payload anywhere in the boundary.
    """

    principal_id: str
    organisation_id: str
    domain: str
    action_type: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    target: ResourceReference | None = None
    execution_action_hash: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        require_identifier(self.principal_id, "principal_id", error=InvalidEnvelopeError)
        require_identifier(self.organisation_id, "organisation_id", error=InvalidEnvelopeError)
        require_identifier(self.domain, "domain", error=InvalidEnvelopeError)
        require_identifier(self.action_type, "action_type", error=InvalidEnvelopeError)

        if self.target is not None and not isinstance(self.target, ResourceReference):
            raise InvalidEnvelopeError(
                "target must be a ResourceReference or None, got "
                f"{type(self.target).__name__}"
            )
        if not isinstance(self.payload, Mapping):
            raise InvalidEnvelopeError(
                f"payload must be a mapping, got {type(self.payload).__name__}"
            )

        duplicated = sorted(RESERVED_TARGET_PAYLOAD_KEYS.intersection(self.payload))
        if duplicated:
            raise InvalidEnvelopeError(
                "an action expresses its target exactly once, in 'target'; the "
                f"payload also carries target-designating key(s) {duplicated}. "
                "Lift the target into ResourceReference before building the "
                "action — two representations of one recipient are rejected "
                "before hashing even when they happen to agree."
            )

        frozen_payload = _freeze(dict(self.payload), path="payload", depth=1)
        object.__setattr__(self, "payload", frozen_payload)
        object.__setattr__(self, "execution_action_hash", self._compute_hash())

    def preimage(self) -> dict[str, Any]:
        """The exact ``inntris-execution-action-v1`` object that gets hashed.

        Exposed so a verifier can reproduce the digest without re-deriving
        the field set from prose.
        """
        preimage: dict[str, Any] = {
            "format": EXECUTION_ACTION_HASH_FORMAT,
            "principal": self.principal_id,
            "organisation": self.organisation_id,
            "domain": self.domain,
            "action_type": self.action_type,
            "payload": _thaw(self.payload),
        }
        if self.target is not None:
            # Omitted, never null, when the action has no target.
            preimage["target"] = self.target.as_preimage_member()
        return preimage

    def _compute_hash(self) -> str:
        try:
            return jcs.sha256_hex(self.preimage())
        except jcs.JCSError as exc:  # pragma: no cover - guarded by _freeze
            raise InvalidEnvelopeError(
                f"action could not be canonicalized: {exc}"
            ) from exc


@dataclass(frozen=True, slots=True)
class ActionEnvelope:
    """Everything Core needs to reason about one proposed consequential action.

    The act itself lives in :attr:`action`. The remaining fields are
    decision context and request provenance that surround the act without
    being part of it: none of them participate in
    :attr:`execution_action_hash`.
    """

    action: ExecutableAction

    # The existing Inntris client-signed request hash, when the caller
    # produced one. Carried for continuity of evidence; never recomputed,
    # never redefined, and never mixed into the execution action hash.
    signed_action_hash: str | None = None

    # The caller's untrusted pointer at external delegated-authority
    # evidence. A claim is not a DelegatedAuthorityReference: only a
    # trusted AuthorityProvider can turn this into one.
    delegated_authority_reference: DelegatedAuthorityClaim | None = None

    # How bad it is if this act happens without authority. Advisory input
    # to the decision path, not a decision.
    consequence_class: ConsequenceClass | None = None

    # Request provenance. These identify the *request*, not the act, so a
    # replayed request describing the same act still hashes the same.
    occurred_at: datetime | None = None
    nonce: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.action, ExecutableAction):
            raise InvalidEnvelopeError(
                f"action must be an ExecutableAction, got {type(self.action).__name__}"
            )
        object.__setattr__(
            self,
            "signed_action_hash",
            require_optional_digest(
                self.signed_action_hash, "signed_action_hash", error=InvalidEnvelopeError
            ),
        )
        if self.delegated_authority_reference is not None and not isinstance(
            self.delegated_authority_reference, DelegatedAuthorityClaim
        ):
            raise InvalidEnvelopeError(
                "delegated_authority_reference must be a DelegatedAuthorityClaim or "
                "None. A claim is untrusted by construction: only a trusted "
                "AuthorityProvider can turn it into a DelegatedAuthorityReference. "
                f"Got {type(self.delegated_authority_reference).__name__}"
            )
        if self.consequence_class is not None and not isinstance(
            self.consequence_class, ConsequenceClass
        ):
            raise InvalidEnvelopeError(
                "consequence_class must be a ConsequenceClass or None, got "
                f"{type(self.consequence_class).__name__}"
            )
        object.__setattr__(
            self,
            "occurred_at",
            require_optional_utc(self.occurred_at, "occurred_at", error=InvalidEnvelopeError),
        )
        object.__setattr__(
            self,
            "nonce",
            require_optional_identifier(self.nonce, "nonce", error=InvalidEnvelopeError),
        )

    @property
    def execution_action_hash(self) -> str:
        """The act's ``inntris-execution-action-v1`` digest."""
        return self.action.execution_action_hash

    @property
    def principal_id(self) -> str:
        return self.action.principal_id

    @property
    def organisation_id(self) -> str:
        return self.action.organisation_id

    @property
    def domain(self) -> str:
        return self.action.domain

    @property
    def action_type(self) -> str:
        return self.action.action_type
