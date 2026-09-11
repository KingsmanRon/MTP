"""Delegated payment scope, expressed in this domain's own vocabulary.

An external authority may say what was delegated. It never says what is
permitted here. The effective permission is an intersection:

    organisation policy AND delegated authority scope

A delegated scope can only narrow. It can never widen an organisation
limit, re-enable a blocked action, or authorise a destination the
organisation's own policy refuses. Every check in this module runs
*after* organisation policy has already allowed the act.

Unsupported constraints fail closed
-----------------------------------
A scope may carry a machine-enforceable constraint this build cannot
safely interpret — a limit in an unsupported currency, a velocity rule, a
condition named in a key we do not know. Ignoring it would silently
broaden the authority the issuer granted. So every key that is not
explicitly understood is collected into
:attr:`PaymentDelegationConstraints.unsupported_constraints`, and the
payment path blocks rather than proceeding on a partial reading.

Nothing here names a vendor. ``scope`` arrives as an opaque mapping from
``ResolvedAuthority.scope``; the provider that produced it is responsible
for translating its issuer's field names into these neutral keys.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from api.domains.payment.money import SUPPORTED_CURRENCIES, Money, MoneyError

#: Scope keys this build understands and enforces.
KNOWN_SCOPE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "max_amount",
        "currency",
        "allowed_payees",
        "not_before",
        "not_after",
    }
)


class DelegationScopeError(ValueError):
    """The scope is structurally unusable — not merely unsupported.

    A scope whose ``max_amount`` is a list, or whose ``not_after`` is not
    a timestamp, cannot be read at all. That is a provider fault and it
    raises. A scope this build simply does not know how to enforce is not
    an error: it is recorded as unsupported and blocks the decision.
    """


def _parse_instant(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        instant = value
    elif isinstance(value, str):
        try:
            instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise DelegationScopeError(f"scope.{field} is not an ISO-8601 instant") from exc
    else:
        raise DelegationScopeError(
            f"scope.{field} must be a datetime or ISO-8601 string, got " f"{type(value).__name__}"
        )
    if instant.tzinfo is None:
        raise DelegationScopeError(f"scope.{field} must be timezone-aware")
    return instant.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class PaymentDelegationConstraints:
    """The subset of an external payment authority this domain can enforce."""

    max_amount: Money | None = None
    #: The currency the authority is denominated in, when the scope names one.
    #: Independent of ``max_amount``: a scope may restrict the currency without
    #: capping the amount, and that restriction is enforced on its own.
    currency: str | None = None
    allowed_payees: frozenset[str] | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    #: Keys present in the scope that this build cannot enforce. Non-empty
    #: means the payment path must fail closed.
    unsupported_constraints: tuple[str, ...] = ()

    @property
    def is_fully_enforceable(self) -> bool:
        """Whether every constraint in the source scope is enforced here."""
        return not self.unsupported_constraints

    def is_within_validity(self, at: datetime) -> bool:
        """Whether ``at`` falls inside the scope's own validity window."""
        if self.not_before is not None and at < self.not_before:
            return False
        return not (self.not_after is not None and at >= self.not_after)


def parse_delegation_constraints(scope: Mapping[str, Any] | None) -> PaymentDelegationConstraints:
    """Read an opaque authority scope into enforceable payment constraints.

    An empty or absent scope yields constraints that narrow nothing — the
    caller still decides whether authority was *required*, which is a
    separate question this function does not answer.
    """
    if scope is None:
        return PaymentDelegationConstraints()
    if not isinstance(scope, Mapping):
        raise DelegationScopeError(f"scope must be a mapping, got {type(scope).__name__}")

    unenforceable = {key for key in scope if key not in KNOWN_SCOPE_KEYS}

    # Currency is parsed whenever it is present. It is a constraint in its own
    # right: a scope naming a currency this build cannot handle grants authority
    # that cannot be enforced, and treating it as "no constraint" would let a
    # payment in a different currency through untouched.
    currency: str | None = None
    raw_currency = scope.get("currency")
    if raw_currency is not None:
        if not isinstance(raw_currency, str) or not raw_currency.strip():
            raise DelegationScopeError("scope.currency must be a non-empty ISO 4217 code")
        code = raw_currency.strip().upper()
        if code in SUPPORTED_CURRENCIES:
            currency = code
        else:
            # Not a provider fault — the issuer granted authority in a currency
            # this release does not support. Record it so the decision path
            # fails closed rather than silently ignoring the restriction.
            unenforceable.add("currency")

    max_amount: Money | None = None
    raw_amount = scope.get("max_amount")
    if raw_amount is not None:
        if raw_currency is None:
            raise DelegationScopeError(
                "scope.max_amount requires scope.currency; an amount without a "
                "currency cannot be compared against anything"
            )
        if currency is None:
            # The limit is denominated in the currency constraint that could not
            # be enforced, so the limit cannot be enforced either.
            unenforceable.add("max_amount")
        else:
            try:
                max_amount = Money.from_decimal(raw_amount, currency)
            except MoneyError:
                unenforceable.add("max_amount")
                max_amount = None

    allowed_payees: frozenset[str] | None = None
    raw_payees = scope.get("allowed_payees")
    if raw_payees is not None:
        if isinstance(raw_payees, (str, bytes)) or not isinstance(
            raw_payees, (list, tuple, set, frozenset)
        ):
            raise DelegationScopeError("scope.allowed_payees must be a list of payee references")
        payees = set()
        for entry in raw_payees:
            if not isinstance(entry, str) or not entry.strip():
                raise DelegationScopeError("scope.allowed_payees entries must be non-empty strings")
            payees.add(entry)
        if not payees:
            raise DelegationScopeError("scope.allowed_payees must not be empty when present")
        allowed_payees = frozenset(payees)

    not_before = (
        _parse_instant(scope["not_before"], "not_before")
        if scope.get("not_before") is not None
        else None
    )
    not_after = (
        _parse_instant(scope["not_after"], "not_after")
        if scope.get("not_after") is not None
        else None
    )
    if not_before is not None and not_after is not None and not_after <= not_before:
        raise DelegationScopeError("scope.not_after must be strictly after scope.not_before")

    return PaymentDelegationConstraints(
        max_amount=max_amount,
        currency=currency,
        allowed_payees=allowed_payees,
        not_before=not_before,
        not_after=not_after,
        unsupported_constraints=tuple(sorted(unenforceable)),
    )
