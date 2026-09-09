"""One validated money representation for delegated payment authority.

Legacy ``/verify`` money handling is untouched: it stays in
``api.domains.payment.amounts`` and keeps its "first recognised field
wins" reading. This module is the *new* representation, used only on the
delegated-authority path, and it is deliberately stricter:

* currency is explicit, never assumed;
* the value is an integer count of minor units, so no float or trailing
  decimal ambiguity survives into a decision;
* conversion from ``Decimal`` is exact — excess precision is rejected,
  never rounded, because rounding money silently changes what was
  authorised;
* a payload carrying more than one amount or currency representation is
  normalised once and rejected on conflict, rather than one layer reading
  ``amount`` while another reads ``value``.

Only USD is supported initially. An unsupported currency is rejected
explicitly rather than treated as USD.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Final

from api.domains.payment.amounts import AMOUNT_FIELDS

#: ISO 4217 code -> number of decimal digits in its minor unit.
#: The initial proof supports USD only. Adding a currency means adding its
#: exponent here deliberately, not inferring one.
SUPPORTED_CURRENCIES: Final[dict[str, int]] = {"USD": 2}

#: Payload fields that may name the currency, in priority order.
CURRENCY_FIELDS: Final[tuple[str, ...]] = ("currency", "currency_code")

#: Amount fields whose name already fixes the currency.
IMPLIED_CURRENCY_FIELDS: Final[dict[str, str]] = {"amount_usd": "USD"}


class MoneyError(ValueError):
    """Base class for every money-representation failure."""


class UnsupportedCurrencyError(MoneyError):
    """The currency is not one this build knows how to reason about."""


class AmountPrecisionError(MoneyError):
    """The amount carries more precision than the currency's minor unit."""


class ConflictingAmountError(MoneyError):
    """The payload expresses the amount or currency more than one way."""


def _require_supported_currency(currency: object) -> str:
    if not isinstance(currency, str) or not currency.strip():
        raise UnsupportedCurrencyError("currency must be a non-empty ISO 4217 code")
    code = currency.strip().upper()
    if code not in SUPPORTED_CURRENCIES:
        raise UnsupportedCurrencyError(
            f"Currency '{code}' is not supported. Supported: "
            f"{', '.join(sorted(SUPPORTED_CURRENCIES))}."
        )
    return code


@dataclass(frozen=True, slots=True)
class Money:
    """An exact amount in one currency, counted in integer minor units."""

    currency: str
    minor_units: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "currency", _require_supported_currency(self.currency))
        if isinstance(self.minor_units, bool) or not isinstance(self.minor_units, int):
            raise MoneyError(
                f"minor_units must be an int, got {type(self.minor_units).__name__}"
            )
        if self.minor_units < 0:
            raise MoneyError("minor_units must not be negative")

    @property
    def exponent(self) -> int:
        """Digits after the decimal point for this currency's minor unit."""
        return SUPPORTED_CURRENCIES[self.currency]

    @classmethod
    def from_decimal(cls, value: Decimal | int | str, currency: str) -> Money:
        """Convert an exact decimal amount into minor units.

        Excess precision is a rejection, never a rounding: an operator who
        wrote ``10.005`` in a two-decimal currency meant something this
        layer cannot represent, and silently choosing 10.00 or 10.01
        changes what gets authorised.
        """
        code = _require_supported_currency(currency)
        if isinstance(value, bool):
            raise MoneyError("amount must be a number, not a boolean")
        if isinstance(value, float):
            raise MoneyError(
                "amount must be a Decimal, int or string; a float cannot represent "
                "money exactly"
            )
        try:
            amount = value if isinstance(value, Decimal) else Decimal(str(value))
        except (InvalidOperation, ValueError, TypeError, ArithmeticError):
            raise MoneyError(f"amount {value!r} is not a valid decimal")
        if not amount.is_finite():
            raise MoneyError(f"amount must be finite (got {value!r})")
        if amount < 0:
            raise MoneyError(f"amount must not be negative (got {amount})")

        exponent = SUPPORTED_CURRENCIES[code]
        scaled = amount.scaleb(exponent)
        if scaled != scaled.to_integral_value():
            raise AmountPrecisionError(
                f"amount {amount} has more precision than {code} minor units "
                f"({exponent} decimal places); it cannot be represented exactly"
            )
        return cls(currency=code, minor_units=int(scaled))

    def as_decimal(self) -> Decimal:
        """The exact major-unit value."""
        return Decimal(self.minor_units).scaleb(-self.exponent)

    def _require_same_currency(self, other: Money) -> None:
        if self.currency != other.currency:
            raise MoneyError(
                f"cannot compare {self.currency} with {other.currency}; "
                "amounts in different currencies are not ordered"
            )

    def __le__(self, other: Money) -> bool:
        self._require_same_currency(other)
        return self.minor_units <= other.minor_units

    def __lt__(self, other: Money) -> bool:
        self._require_same_currency(other)
        return self.minor_units < other.minor_units

    def __str__(self) -> str:
        return f"{self.as_decimal()} {self.currency}"


def _distinct_amount_representations(payload: dict[str, Any]) -> dict[str, Decimal]:
    present: dict[str, Decimal] = {}
    for field in AMOUNT_FIELDS:
        if field not in payload:
            continue
        raw = payload[field]
        if isinstance(raw, bool):
            raise MoneyError(f"Field '{field}' must be a number, not a boolean.")
        if isinstance(raw, float):
            raise MoneyError(
                f"Field '{field}' must be a string or integer; a float cannot "
                "represent money exactly."
            )
        try:
            value = Decimal(str(raw))
        except (InvalidOperation, ValueError, TypeError, ArithmeticError):
            raise MoneyError(f"Field '{field}' is not a valid decimal amount.")
        if not value.is_finite():
            raise MoneyError(f"Field '{field}' must be a finite amount (got {raw!r}).")
        if value < 0:
            raise MoneyError(f"Field '{field}' must not be negative (got {value}).")
        present[field] = value
    return present


def _resolve_currency(payload: dict[str, Any], amount_fields: dict[str, Decimal]) -> str:
    declared: dict[str, str] = {}
    for field in CURRENCY_FIELDS:
        if field in payload:
            declared[field] = _require_supported_currency(payload[field])
    for field in amount_fields:
        implied = IMPLIED_CURRENCY_FIELDS.get(field)
        if implied is not None:
            declared[field] = implied

    if not declared:
        raise ConflictingAmountError(
            "the delegated payment path requires an explicit currency; add a "
            f"'{CURRENCY_FIELDS[0]}' field"
        )
    distinct = set(declared.values())
    if len(distinct) > 1:
        pairs = ", ".join(f"{field}={code}" for field, code in sorted(declared.items()))
        raise ConflictingAmountError(
            f"the payload names more than one currency ({pairs}); normalise it to one"
        )
    return distinct.pop()


def normalise_payment_money(payload: dict[str, Any]) -> Money | None:
    """Read the one amount this payload expresses, or ``None`` if it has none.

    Unlike the legacy reader this does not stop at the first recognised
    field. Every amount field is parsed, and two fields disagreeing is a
    rejection: that shape is exactly how one layer ends up authorising a
    different number than another layer executes.
    """
    if not isinstance(payload, dict):
        raise MoneyError(f"payload must be a mapping, got {type(payload).__name__}")

    amounts = _distinct_amount_representations(payload)
    if not amounts:
        return None

    distinct = set(amounts.values())
    if len(distinct) > 1:
        pairs = ", ".join(f"{field}={value}" for field, value in sorted(amounts.items()))
        raise ConflictingAmountError(
            f"the payload expresses more than one amount ({pairs}); normalise it to one"
        )

    currency = _resolve_currency(payload, amounts)
    return Money.from_decimal(distinct.pop(), currency)
