"""Tying an Inntris principal to the delegate a Verifiable Intent mandate names.

The failure this module exists to prevent: a Verifiable Intent chain that
verifies perfectly proves that *some* user delegated authority to *some*
agent key. It says nothing about whether that agent is the authenticated
Inntris principal making the request. Accepting "cryptographically valid"
as "belongs to this agent" would let any holder of any valid credential
spend under someone else's delegation.

So the connector requires an explicit, trusted binding between the
Inntris principal and the Verifiable Intent delegate, on two independent
dimensions:

``expected_audience``
    The L2 ``aud`` claim names the party the user delegated to
    (credential-format.md §4.3). The mandate must have been addressed to
    *this* agent platform, not merely be well-formed.

``agent_key_thumbprints``
    The RFC 7638 thumbprint of the agent key carried in the L2 mandates'
    ``cnf.jwk``. This is proof of which key the user delegated to, derived
    from the key itself rather than from a label beside it.

Different credentials, one principal
------------------------------------
Inntris principals sign requests with Ed25519. Verifiable Intent agents
sign Layer 3 with ES256 over P-256. These are different keys for the same
actor and there is no arithmetic that relates them, so nothing here
compares one to the other. The link is an operator-provisioned fact
recorded in trusted server-side state, and it is the only link accepted.

Rotation and revocation
-----------------------
``agent_key_thumbprints`` may hold more than one value, so an operator can
provision a replacement key before retiring the old one. A thumbprint
moved into ``revoked_agent_key_thumbprints`` is refused outright, and it
is refused even if it is also still listed as active — a revocation that
could be cancelled by forgetting to remove the old entry is not a
revocation.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

#: The key under ``ExecutionContext.principal_binding`` this connector reads.
#: Namespaced so several connectors can carry binding data on one context
#: without colliding.
PRINCIPAL_BINDING_CONTEXT_KEY = "mastercard_vi"


class PrincipalBindingError(ValueError):
    """A principal binding was configured with an unusable shape."""


class DelegateBindingOutcome(StrEnum):
    """Why a Verifiable Intent delegate is, or is not, this principal's."""

    BOUND = "bound"
    #: No binding is provisioned for this organisation/principal at all.
    NO_BINDING = "no_binding"
    #: The delegate key is not one this principal is bound to.
    KEY_NOT_BOUND = "key_not_bound"
    #: The delegate key was explicitly revoked for this principal.
    KEY_REVOKED = "key_revoked"
    #: The key matched but the credential's key identifier did not. The
    #: thumbprint is what proves identity; this is a consistency check on
    #: top of it, and a mismatch still fails closed.
    KEY_ID_MISMATCH = "key_id_mismatch"


def _require_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PrincipalBindingError(f"{name} must be a non-empty string")
    return value


def _frozen_text_set(values: object, name: str) -> frozenset[str]:
    if values is None:
        return frozenset()
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise PrincipalBindingError(f"{name} must be a collection of strings")
    out: set[str] = set()
    for entry in values:
        out.add(_require_text(entry, f"{name} entry"))
    return frozenset(out)


@dataclass(frozen=True, slots=True)
class VerifiableIntentPrincipalBinding:
    """A trusted statement that this principal is that Verifiable Intent delegate.

    ``source`` records which trusted system asserted the binding, so an
    audit can tell provisioned state from a test double.
    """

    organisation_id: str
    principal_id: str
    expected_audience: str
    agent_key_thumbprints: frozenset[str]
    source: str
    revoked_agent_key_thumbprints: frozenset[str] = frozenset()
    #: Optional expected ``cnf.jwk.kid`` values. A locator consistency
    #: check only — never a substitute for the thumbprint match.
    agent_key_ids: frozenset[str] | None = None
    bound_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_text(self.organisation_id, "organisation_id")
        _require_text(self.principal_id, "principal_id")
        _require_text(self.expected_audience, "expected_audience")
        _require_text(self.source, "source")
        object.__setattr__(
            self,
            "agent_key_thumbprints",
            _frozen_text_set(self.agent_key_thumbprints, "agent_key_thumbprints"),
        )
        object.__setattr__(
            self,
            "revoked_agent_key_thumbprints",
            _frozen_text_set(
                self.revoked_agent_key_thumbprints, "revoked_agent_key_thumbprints"
            ),
        )
        if not self.agent_key_thumbprints:
            raise PrincipalBindingError(
                "agent_key_thumbprints must name at least one delegate key; an "
                "empty binding grants nothing and must not be provisioned as if "
                "it did"
            )
        if self.agent_key_ids is not None:
            object.__setattr__(
                self, "agent_key_ids", _frozen_text_set(self.agent_key_ids, "agent_key_ids")
            )
            if not self.agent_key_ids:
                raise PrincipalBindingError(
                    "agent_key_ids must be omitted entirely rather than left empty"
                )
        if self.bound_at is not None and (
            not isinstance(self.bound_at, datetime) or self.bound_at.tzinfo is None
        ):
            raise PrincipalBindingError(
                "bound_at must be a timezone-aware datetime or None"
            )

    def check_delegate(
        self, agent_key_thumbprint: str, agent_key_id: str | None
    ) -> DelegateBindingOutcome:
        """Decide whether this delegate key is the one bound to the principal."""
        if agent_key_thumbprint in self.revoked_agent_key_thumbprints:
            return DelegateBindingOutcome.KEY_REVOKED
        if agent_key_thumbprint not in self.agent_key_thumbprints:
            return DelegateBindingOutcome.KEY_NOT_BOUND
        if self.agent_key_ids is not None and agent_key_id not in self.agent_key_ids:
            return DelegateBindingOutcome.KEY_ID_MISMATCH
        return DelegateBindingOutcome.BOUND


@runtime_checkable
class PrincipalDelegateBindingResolver(Protocol):
    """Supplies principal/delegate bindings from trusted server-side state."""

    def binding_for(
        self, organisation_id: str, principal_id: str
    ) -> VerifiableIntentPrincipalBinding | None:
        """Return the binding for this pair, or ``None`` when none exists.

        ``None`` is not permission. The provider reports the authority as
        unresolved rather than treating an unbound principal as bound to
        whatever delegate the credential happens to name.
        """
        ...


@dataclass
class StaticPrincipalDelegateBindingResolver:
    """A resolver over explicitly provisioned bindings, keyed by pair."""

    bindings: dict[tuple[str, str], VerifiableIntentPrincipalBinding] = field(
        default_factory=dict
    )

    @classmethod
    def from_bindings(
        cls, bindings: Iterable[VerifiableIntentPrincipalBinding]
    ) -> StaticPrincipalDelegateBindingResolver:
        indexed: dict[tuple[str, str], VerifiableIntentPrincipalBinding] = {}
        for binding in bindings:
            key = (binding.organisation_id, binding.principal_id)
            if key in indexed:
                raise PrincipalBindingError(
                    f"duplicate binding for organisation {key[0]!r} principal {key[1]!r}"
                )
            indexed[key] = binding
        return cls(bindings=indexed)

    def binding_for(
        self, organisation_id: str, principal_id: str
    ) -> VerifiableIntentPrincipalBinding | None:
        return self.bindings.get((organisation_id, principal_id))


def binding_from_principal_binding(
    principal_binding: Mapping[str, Any] | None,
    *,
    organisation_id: str,
    principal_id: str,
) -> VerifiableIntentPrincipalBinding | None:
    """Read this connector's binding out of a trusted ``ExecutionContext``.

    ``None`` means the context carried no binding for this connector, which
    leaves the provider's injected resolver to answer. A context that
    carries the key but cannot be read raises: a malformed trusted record
    is an integration fault, and quietly falling through to a different
    source would hide it.
    """
    if not isinstance(principal_binding, Mapping):
        return None
    raw = principal_binding.get(PRINCIPAL_BINDING_CONTEXT_KEY)
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise PrincipalBindingError(
            f"principal_binding[{PRINCIPAL_BINDING_CONTEXT_KEY!r}] must be a mapping, "
            f"got {type(raw).__name__}"
        )
    key_ids = raw.get("agent_key_ids")
    return VerifiableIntentPrincipalBinding(
        organisation_id=organisation_id,
        principal_id=principal_id,
        expected_audience=raw.get("expected_audience"),
        agent_key_thumbprints=_frozen_text_set(
            raw.get("agent_key_thumbprints"), "agent_key_thumbprints"
        ),
        revoked_agent_key_thumbprints=_frozen_text_set(
            raw.get("revoked_agent_key_thumbprints"), "revoked_agent_key_thumbprints"
        ),
        agent_key_ids=None if key_ids is None else _frozen_text_set(key_ids, "agent_key_ids"),
        source=raw.get("source") or "execution_context.principal_binding",
    )
