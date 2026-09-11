"""Binding an approved payee to the destination the executor will use.

The failure this module exists to prevent: a delegated payee identity — a
supplier name, a registered business, a website — is **not** proof that a
particular wallet, account or instrument belongs to that payee. An
authority that says "you may pay Supplier A" plus a request that sends to
an unrelated recipient is not an authorised payment, and approving it
because the payee name matched would be the whole system failing at once.

So policy evaluation binds the approved payee to the concrete execution
destination: network, account and asset. The mapping comes from a trusted
server-side ``PayeeBindingResolver``, never from the request. A request
that names a payee with no binding, or whose destination does not match
the binding, fails closed.

Vendor-neutral throughout: ``network`` is an opaque rail or chain
identifier, ``account`` an opaque destination identifier, ``asset`` the
currency or asset code.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from api.domains.payment.wallet import recipient_in_allowlist


class PayeeBindingError(ValueError):
    """A payee binding was constructed with an unusable shape."""


class DestinationMismatch(StrEnum):
    """Why a proposed destination is not the one the payee is bound to."""

    NETWORK_MISMATCH = "network_mismatch"
    ACCOUNT_MISMATCH = "account_mismatch"
    ASSET_MISMATCH = "asset_mismatch"


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PayeeBindingError(f"{field} must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class ExecutionDestination:
    """Where value actually goes, in the dimensions the domain must bind.

    All three dimensions matter. Binding only the account would let an
    authority for a stablecoin on one network authorise a native-token
    transfer on another to the same address.
    """

    network: str
    account: str
    asset: str

    def __post_init__(self) -> None:
        _require_text(self.network, "network")
        _require_text(self.account, "account")
        _require_text(self.asset, "asset")

    def matches(self, other: ExecutionDestination) -> DestinationMismatch | None:
        """Compare against another destination, most-specific reason first.

        Account comparison reuses the existing allowlist rule exactly:
        case-insensitive on EVM networks, because checksum casing is
        presentational, and exact everywhere else. Nothing is rewritten,
        trimmed or checksummed.
        """
        if self.network != other.network:
            return DestinationMismatch.NETWORK_MISMATCH
        if not recipient_in_allowlist(self.network, other.account, [self.account]):
            return DestinationMismatch.ACCOUNT_MISMATCH
        if self.asset.upper() != other.asset.upper():
            return DestinationMismatch.ASSET_MISMATCH
        return None


@dataclass(frozen=True, slots=True)
class PayeeBinding:
    """A trusted mapping from a delegated payee identity to a destination.

    ``payee_reference`` is the identity the external authority names.
    ``destination`` is where this organisation has established that payee
    actually receives value. ``source`` records which trusted system
    asserted the binding, for audit.
    """

    payee_reference: str
    destination: ExecutionDestination
    source: str
    bound_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_text(self.payee_reference, "payee_reference")
        _require_text(self.source, "source")
        if not isinstance(self.destination, ExecutionDestination):
            raise PayeeBindingError(
                "destination must be an ExecutionDestination, got "
                f"{type(self.destination).__name__}"
            )
        if self.bound_at is not None and (
            not isinstance(self.bound_at, datetime) or self.bound_at.tzinfo is None
        ):
            raise PayeeBindingError("bound_at must be a timezone-aware datetime or None")

    def mismatch_against(self, proposed: ExecutionDestination) -> DestinationMismatch | None:
        """``None`` when ``proposed`` is the destination this payee is bound to."""
        if not isinstance(proposed, ExecutionDestination):
            raise PayeeBindingError(
                "proposed destination must be an ExecutionDestination, got "
                f"{type(proposed).__name__}"
            )
        return self.destination.matches(proposed)


@runtime_checkable
class PayeeBindingResolver(Protocol):
    """Supplies payee bindings from trusted server-side state."""

    def binding_for(self, organisation_id: str, payee_reference: str) -> PayeeBinding | None:
        """Return this organisation's binding for ``payee_reference``.

        ``None`` means no binding is established. That is not permission:
        the payment path fails closed on an unbound payee rather than
        trusting the payee identity to imply a destination.

        Implementations read trusted server-side state only. A resolver
        that derives a binding from the request it is evaluating provides
        no assurance at all.
        """
        ...
