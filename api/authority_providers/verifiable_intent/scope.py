"""Translating Verifiable Intent constraints into the neutral payment scope.

The payment domain speaks five scope keys — ``max_amount``, ``currency``,
``allowed_payees``, ``not_before``, ``not_after`` — and treats every other
key as a constraint it cannot enforce. That is the mechanism this module
is built on, not a mechanism it works around.

The supported set is deliberately small
---------------------------------------
Two VI payment constraints map onto something this build can actually
enforce:

``mandate.payment.amount_range``
    A **per-transaction** bound. Its ``max`` becomes ``max_amount`` and
    its ``currency`` becomes ``currency``. It is not a budget: nothing
    here accumulates across transactions, and nothing here may be read as
    doing so.

``mandate.payment.allowed_payees``
    An allowlist of payee identities, which becomes ``allowed_payees``.
    A payee identity is not a destination; binding it to one is the
    payment domain's job and it fails closed without a trusted binding.

One more is enforced before this module runs. ``mandate.payment.reference``
binds an autonomous payment mandate to the checkout mandate it is
conditional on, and the reference implementation's chain verification both
*requires* it and checks that its ``conditional_transaction_id`` hashes to
the presented checkout disclosure. By the time constraints are mapped the
chain has already verified, so the constraint is satisfied, carries no
payment-scope semantics for this domain to intersect, and is passed over
rather than reported as unenforceable.

Everything else — ``mandate.payment.budget`` (a cumulative cap this build
does not track), ``mandate.payment.recurrence`` and
``mandate.payment.agent_recurrence`` (network-enforced recurrence terms),
and any constraint type published after this release — is emitted into
the scope under a ``vi.``-prefixed key
that the payment domain does not recognise. The effect is that the
decision fails closed with ``AUTHORITY_SCOPE_UNSUPPORTED`` instead of
enforcing the subset it happens to understand, which would be broader
authority than the issuer granted.

The ``min`` of an amount range is treated the same way. A floor the
issuer set and we ignore would let through a transaction below the range
the user authorised — a smaller payment is still a payment outside the
mandate.

Only JSON types go into the scope
---------------------------------
The scope mapping is canonicalised with JCS and digested, and that digest
is what binds an issued grant to the exact delegation it rested on. So
every value here is a JSON primitive: an amount is a decimal *string*,
an instant is an ISO-8601 *string*. The payment domain parses both back,
and the provider keeps the parsed instants alongside the scope for the
fields that need real datetimes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Final

#: VI constraint types this build maps onto enforceable scope keys.
SUPPORTED_CONSTRAINT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "mandate.payment.amount_range",
        "mandate.payment.allowed_payees",
    }
)

#: VI constraint types already checked by the reference implementation's
#: chain verification, which has necessarily run and passed before any
#: constraint is mapped. They bind the chain together; they say nothing
#: about what this domain may pay, so there is nothing here to intersect.
CHAIN_ENFORCED_CONSTRAINT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "mandate.payment.reference",
    }
)

#: VI constraint types this build knows about and deliberately cannot
#: enforce. Listed by name so an operator reading a refusal sees a
#: recognised constraint rather than "unknown key".
KNOWN_UNSUPPORTED_CONSTRAINT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "mandate.payment.budget",
        "mandate.payment.recurrence",
        "mandate.payment.agent_recurrence",
    }
)

#: Prefix under which an unenforceable constraint is reported. The payment
#: domain does not recognise it, which is exactly the point.
UNSUPPORTED_KEY_PREFIX: Final[str] = "vi."


class VerifiableIntentScopeError(ValueError):
    """A constraint is structurally unreadable, not merely unsupported.

    An ``amount_range`` whose ``max`` is a list cannot be read at all.
    That is a malformed artefact and the provider reports it as such,
    rather than pretending the mandate simply carried a constraint we do
    not support.
    """


def _minor_units_to_decimal(value: Any, field: str) -> Decimal:
    """Read an integer minor-unit amount as a major-unit decimal.

    VI denominates amounts in integer minor units. A non-integer here is
    not a rounding question, it is a malformed artefact: silently
    truncating ``1050.7`` would authorise a different number than the one
    the user signed.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise VerifiableIntentScopeError(
            f"{field} must be an integer number of minor units, got "
            f"{type(value).__name__}"
        )
    if value < 0:
        raise VerifiableIntentScopeError(f"{field} must not be negative")
    return (Decimal(value) / Decimal(100)).quantize(Decimal("0.01"))


def _payee_references(allowed: Any) -> list[str]:
    """The payee identities an ``allowed_payees`` constraint names.

    Entries arrive either already resolved (a payee object) or as a
    selective-disclosure reference the caller has resolved for us. An
    entry that is still an unresolved ``{"...": hash}`` reference names a
    payee whose identity we were not shown, and a payee we cannot see is
    not a payee we can check.
    """
    if isinstance(allowed, (str, bytes)) or not isinstance(allowed, Sequence):
        raise VerifiableIntentScopeError(
            "mandate.payment.allowed_payees.allowed must be a list"
        )
    references: list[str] = []
    for entry in allowed:
        if isinstance(entry, Mapping):
            if "..." in entry:
                raise VerifiableIntentScopeError(
                    "an allowed payee is an undisclosed selective-disclosure "
                    "reference; its identity was not presented"
                )
            identity = entry.get("id")
            if not isinstance(identity, str) or not identity.strip():
                raise VerifiableIntentScopeError(
                    "an allowed payee carries no usable 'id'"
                )
            references.append(identity)
        elif isinstance(entry, str) and entry.strip():
            references.append(entry)
        else:
            raise VerifiableIntentScopeError(
                f"an allowed payee entry is unreadable: {type(entry).__name__}"
            )
    if not references:
        raise VerifiableIntentScopeError(
            "mandate.payment.allowed_payees.allowed must not be empty"
        )
    return references


def _instant(value: Any, name: str) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise VerifiableIntentScopeError(f"{name} must be a NumericDate")
    return datetime.fromtimestamp(int(value), tz=UTC)


@dataclass(frozen=True, slots=True)
class MappedScope:
    """The neutral scope, plus the instants in already-parsed form.

    ``scope`` is JSON-only so it can be canonicalised and digested.
    ``not_before`` / ``not_after`` repeat two of its values as datetimes,
    for the ``ResolvedAuthority`` fields that are typed that way — one
    source, two representations, rather than two parses that could drift.
    """

    scope: dict[str, Any] = field(default_factory=dict)
    not_before: datetime | None = None
    not_after: datetime | None = None


def map_payment_constraints(
    constraints: Sequence[Any],
    *,
    not_before: Any = None,
    not_after: Any = None,
) -> MappedScope:
    """Map an L2 payment mandate's constraints onto a neutral scope.

    ``not_before`` / ``not_after`` are the mandate's own ``iat`` / ``exp``
    as NumericDates. They bound the authority independently of any
    constraint, so they are carried even when the mandate lists none.
    """
    scope: dict[str, Any] = {}

    issued = _instant(not_before, "iat")
    expires = _instant(not_after, "exp")
    if issued is not None:
        scope["not_before"] = issued.isoformat()
    if expires is not None:
        scope["not_after"] = expires.isoformat()

    if not isinstance(constraints, Sequence) or isinstance(constraints, (str, bytes)):
        raise VerifiableIntentScopeError("constraints must be a list")

    for constraint in constraints:
        if not isinstance(constraint, Mapping):
            raise VerifiableIntentScopeError(
                f"a constraint is not an object: {type(constraint).__name__}"
            )
        ctype = constraint.get("type")
        if not isinstance(ctype, str) or not ctype.strip():
            raise VerifiableIntentScopeError("a constraint carries no type")

        if ctype == "mandate.payment.amount_range":
            _map_amount_range(constraint, scope)
        elif ctype == "mandate.payment.allowed_payees":
            scope["allowed_payees"] = _payee_references(constraint.get("allowed"))
        elif ctype in CHAIN_ENFORCED_CONSTRAINT_TYPES:
            continue
        else:
            # Known-but-unenforceable and entirely unknown are the same
            # answer: report it under a key the payment domain does not
            # recognise, so the decision fails closed.
            scope[f"{UNSUPPORTED_KEY_PREFIX}{ctype}"] = _describe(constraint)

    return MappedScope(scope=scope, not_before=issued, not_after=expires)


def _map_amount_range(constraint: Mapping[str, Any], scope: dict[str, Any]) -> None:
    currency = constraint.get("currency")
    if not isinstance(currency, str) or not currency.strip():
        raise VerifiableIntentScopeError(
            "mandate.payment.amount_range must name a currency"
        )
    scope["currency"] = currency.strip().upper()

    maximum = constraint.get("max")
    if maximum is not None:
        scope["max_amount"] = str(
            _minor_units_to_decimal(maximum, "mandate.payment.amount_range.max")
        )

    minimum = constraint.get("min")
    if minimum is not None and _minor_units_to_decimal(
        minimum, "mandate.payment.amount_range.min"
    ) > Decimal("0"):
        # A per-transaction floor. Nothing in the neutral vocabulary
        # expresses one, and ignoring it would authorise payments the
        # mandate placed below its range.
        scope[f"{UNSUPPORTED_KEY_PREFIX}mandate.payment.amount_range.min"] = minimum

    if maximum is None and minimum is None:
        raise VerifiableIntentScopeError(
            "mandate.payment.amount_range bounds nothing; it must carry min or max"
        )


def _describe(constraint: Mapping[str, Any]) -> str:
    """A short, stable description of a constraint we will not enforce."""
    ctype = str(constraint.get("type"))
    if ctype in KNOWN_UNSUPPORTED_CONSTRAINT_TYPES:
        return "recognised VI constraint this build does not enforce"
    return "VI constraint type unknown to this build"
