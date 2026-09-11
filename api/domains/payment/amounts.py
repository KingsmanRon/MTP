"""Legacy amount extraction.

Moved verbatim from ``api/policy.py``. This is the *legacy* reading of a
payload amount and its behaviour is frozen: first recognised field wins,
later fields are not examined, and a malformed value fails closed.

The new delegated-payment path does not use this. It uses
``api.domains.payment.money``, which normalises once and rejects
conflicting representations. Keeping the two separate is deliberate:
legacy ``/verify`` traffic must behave exactly as it did before this
refactor.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

# Action types that MUST carry a parseable spend amount. A financial
# action with no recognized amount field fails closed (BLOCKED) rather
# than being silently treated as a $0 transaction that bypasses the
# daily/per-action caps entirely.
AMOUNT_REQUIRED_ACTIONS: frozenset = frozenset(
    {
        "financial_transaction",
    }
)

# Payload fields that may carry a transaction amount, in priority order.
# The first field present wins; if it is malformed the request is blocked
# rather than falling through to a later field.
AMOUNT_FIELDS: tuple = ("amount", "amount_usd", "value", "total")


class AmountError(ValueError):
    """Raised when a payload amount field is present but malformed.

    Distinct from "no amount field at all": a malformed amount (non-numeric,
    boolean, NaN, infinite, or negative) is a fail-closed signal, whereas an
    absent amount is only fatal for action types that require one.
    """


def extract_amount(payload: dict[str, Any]) -> Decimal | None:
    """Extract and validate a transaction amount from the payload.

    Returns the amount from the first recognized field (priority order in
    ``AMOUNT_FIELDS``), or ``None`` when no amount field is present.

    Raises ``AmountError`` when an amount field is present but malformed —
    non-numeric, boolean, NaN, infinite, or negative. The previous
    implementation silently skipped unparseable values, which let a
    compromised agent bypass spend limits two ways: send ``{"amount":
    "NaN"}`` (NaN compares False against every limit, so the check passes)
    or omit the recognized field so ``None`` short-circuits the check
    entirely. Both now fail closed.
    """
    for field in AMOUNT_FIELDS:
        if field not in payload:
            continue
        raw = payload[field]
        # bool is an int subclass; reject it explicitly so True/False
        # cannot be coerced into 1/0 spend.
        if isinstance(raw, bool):
            raise AmountError(f"Field '{field}' must be a number, not a boolean.")
        try:
            value = Decimal(str(raw))
        except (ValueError, TypeError, ArithmeticError):
            raise AmountError(f"Field '{field}' is not a valid decimal amount.")
        if not value.is_finite():
            raise AmountError(f"Field '{field}' must be a finite amount (got {raw!r}).")
        if value < 0:
            raise AmountError(f"Field '{field}' must not be negative (got {value}).")
        return value
    return None
