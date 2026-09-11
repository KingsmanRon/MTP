"""Mapping a Verifiable Intent mandate into vendor-neutral delegated scope.

This module is the translation layer, and the translation runs one way
only: Verifiable Intent's vocabulary comes in, and the neutral scope keys
:mod:`api.domains.payment` already understands go out. Nothing downstream
of here learns that Verifiable Intent exists.

What is mapped
--------------
``mandate.payment.amount_range``
    ``max`` and ``currency`` become ``max_amount`` and ``currency``. The
    draft expresses amounts as integer minor units per ISO 4217
    (constraints.md §4.4); Inntris's canonical money type is built from an
    exact major-unit decimal. The conversion happens once, here, by digit
    placement rather than float arithmetic, so nothing is rounded on the
    way in. ``amount_range`` is a **per-transaction** bound, not a
    cumulative budget, and it is mapped as one.

``mandate.payment.allowed_payees``
    Each disclosed payee becomes a stable neutral payee reference. The
    reference is only an *identity*; binding it to a concrete execution
    destination is the payment domain's job, through the Phase 2
    ``PayeeBindingResolver``. A payee identity on its own authorises
    nothing.

L2 ``iat`` / ``exp``
    Become ``not_before`` / ``not_after``.

What fails closed
-----------------
Every other constraint in the **payment** mandate. Cumulative budgets and
recurrence constraints require a per-mandate spend and occurrence ledger
that this release does not keep, so it cannot enforce them; a constraint
type outside the pinned draft's registry cannot be evaluated at all, and
the draft itself requires open mandates to reject those (constraints.md
§5.4). In both cases the delegation is reported unusable rather than
enforced in part and described as satisfied.

The checkout mandate's boundary
-------------------------------
``mandate.checkout.*`` constraints bound the agent's *merchant checkout* —
which items, from which merchants. Inntris does not perform a merchant
checkout and issues no execution authority for one, so those constraints
are outside what this provider authorises rather than something it
silently drops. The checkout mandate is still verified in full for chain
integrity, pairing and delegate identity, its constraint types are
recorded on the mapping result, and an unregistered constraint type
anywhere in the disclosed Layer 2 still fails closed. What Inntris will
not do is issue authority for the checkout leg and imply it checked it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from api.connectors.mastercard_vi.profile import (
    CONSTRAINT_ALLOWED_PAYEES,
    CONSTRAINT_AMOUNT_RANGE,
    MAPPED_PAYMENT_CONSTRAINT_TYPES,
    REGISTERED_CONSTRAINT_TYPES,
    STRUCTURAL_PAYMENT_CONSTRAINT_TYPES,
    USAGE_ACCOUNTING_CONSTRAINT_TYPES,
)
from api.core.authority.authority import AuthorityVerificationFailure
from api.domains.payment.money import SUPPORTED_CURRENCIES

#: Prefix on every payee reference this connector emits, so an operator
#: provisioning a ``PayeeBinding`` can tell a delegated payee identity from
#: an internally chosen one at a glance.
PAYEE_REFERENCE_PREFIX = "payee"


class ScopeMappingError(Exception):
    """A mandate could not be mapped into enforceable scope.

    Carries the typed authority-failure code the provider reports, so the
    reason a delegation was refused survives all the way to the decision
    record instead of collapsing into a generic failure.
    """

    def __init__(self, code: AuthorityVerificationFailure, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class MappedDelegationScope:
    """The neutral scope, plus what the mapper saw on the way to it."""

    #: The mapping handed to ``ResolvedAuthority.scope``. Neutral keys only.
    scope: Mapping[str, Any]
    #: Payee references in the scope, in the order they were disclosed.
    payee_references: tuple[str, ...] = ()
    #: The Verifiable Intent payee objects that were actually disclosed.
    #: Kept for differential testing against the reference constraint
    #: checker; never handed inward.
    disclosed_payees: tuple[Mapping[str, Any], ...] = ()
    #: Approved payees whose identity was withheld from this verifier.
    #: Inntris enforces only the disclosed subset, which is strictly
    #: narrower than what was delegated.
    undisclosed_payee_count: int = 0
    #: Checkout-mandate constraint types seen, recorded rather than mapped.
    checkout_constraint_types: tuple[str, ...] = ()
    #: Payment-mandate constraint types verified structurally elsewhere.
    structural_constraint_types: tuple[str, ...] = ()
    #: The per-transaction bound as the mandate expressed it, in integer
    #: minor units, for differential comparison against the reference
    #: implementation.
    amount_range_minor_units: Mapping[str, Any] = field(default_factory=dict)


def minor_units_to_major_string(minor_units: int, currency: str) -> str:
    """Convert ISO 4217 minor units to an exact major-unit decimal string.

    Done by digit placement, not by float or decimal-context arithmetic,
    so the result is exact for any integer and cannot be quietly rounded
    by a precision setting somewhere.
    """
    exponent = SUPPORTED_CURRENCIES[currency]
    sign = "-" if minor_units < 0 else ""
    digits = str(abs(minor_units))
    if exponent == 0:
        return f"{sign}{digits}"
    digits = digits.rjust(exponent + 1, "0")
    return f"{sign}{digits[:-exponent]}.{digits[-exponent:]}"


def _escape_reference_component(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def payee_reference(payee: Mapping[str, Any]) -> str:
    """A stable neutral reference for one Verifiable Intent payee object.

    The key mirrors the draft's own matching rule (constraints.md §4.3):
    ``id`` is the primary key when present, and ``name`` + ``website`` is
    the identity the user actually saw and approved when it is not. Both
    fallback components are escaped so a separator inside a merchant name
    cannot make two different payees collapse to one reference.

    Comparisons are exact. The draft forbids substring or case-insensitive
    payee matching (§7.3), so nothing here trims, lowercases or otherwise
    normalises what the user signed.
    """
    if not isinstance(payee, Mapping):
        raise ScopeMappingError(
            AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
            f"a disclosed payee is not an object (got {type(payee).__name__})",
        )
    payee_id = payee.get("id")
    if isinstance(payee_id, str) and payee_id.strip():
        return f"{PAYEE_REFERENCE_PREFIX}:id:{payee_id}"
    name = payee.get("name")
    website = payee.get("website")
    if (
        isinstance(name, str)
        and name.strip()
        and isinstance(website, str)
        and website.strip()
    ):
        return (
            f"{PAYEE_REFERENCE_PREFIX}:name-website:"
            f"{_escape_reference_component(name)}|{_escape_reference_component(website)}"
        )
    raise ScopeMappingError(
        AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
        "a disclosed payee carries neither an 'id' nor the required "
        "'name' and 'website' pair, so it cannot be identified",
    )


def _is_disclosure_reference(entry: Any) -> bool:
    return isinstance(entry, Mapping) and "..." in entry


def _constraints_of(mandate: Mapping[str, Any], label: str) -> list[Mapping[str, Any]]:
    raw = mandate.get("constraints")
    if raw is None:
        return []
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ScopeMappingError(
            AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
            f"the {label} mandate's constraints must be an array",
        )
    out: list[Mapping[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            raise ScopeMappingError(
                AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
                f"a {label} mandate constraint is not an object",
            )
        ctype = entry.get("type")
        if not isinstance(ctype, str) or not ctype:
            raise ScopeMappingError(
                AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
                f"a {label} mandate constraint has no 'type'",
            )
        out.append(entry)
    return out


def _require_integer(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScopeMappingError(
            AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
            f"{what} must be an integer in minor units, got {type(value).__name__}",
        )
    return value


def _map_amount_range(constraint: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return ``(scope_fragment, minor_unit_record)`` for one amount range."""
    currency = constraint.get("currency")
    if not isinstance(currency, str) or not currency.strip():
        raise ScopeMappingError(
            AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
            "mandate.payment.amount_range is missing its required 'currency'",
        )
    code = currency.strip().upper()
    if code not in SUPPORTED_CURRENCIES:
        raise ScopeMappingError(
            AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
            f"the delegation is denominated in {code}, which this release cannot "
            "enforce; refusing rather than treating the limit as unset",
        )

    minimum = constraint.get("min")
    if minimum is not None:
        minimum = _require_integer(minimum, "mandate.payment.amount_range.min")
        if minimum < 0:
            raise ScopeMappingError(
                AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
                "mandate.payment.amount_range.min must not be negative",
            )
        if minimum > 0:
            # A positive floor is a machine-enforceable bound, and Inntris's
            # neutral scope has no lower bound to carry it into. Enforcing the
            # ceiling alone would authorise transactions the user's mandate
            # excluded.
            raise ScopeMappingError(
                AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
                "mandate.payment.amount_range carries a positive 'min'; this "
                "release enforces no lower bound and will not enforce half of a "
                "constraint",
            )

    scope_fragment: dict[str, Any] = {"currency": code}
    record: dict[str, Any] = {"currency": code, "min": minimum}

    maximum = constraint.get("max")
    if maximum is not None:
        maximum = _require_integer(maximum, "mandate.payment.amount_range.max")
        if maximum < 0:
            raise ScopeMappingError(
                AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
                "mandate.payment.amount_range.max must not be negative",
            )
        scope_fragment["max_amount"] = minor_units_to_major_string(maximum, code)
    record["max"] = maximum
    return scope_fragment, record


def _resolve_allowed_payees(
    constraint: Mapping[str, Any],
    disclosure_values_by_hash: Mapping[str, Any],
) -> tuple[list[Mapping[str, Any]], int]:
    allowed = constraint.get("allowed")
    if not isinstance(allowed, Sequence) or isinstance(allowed, (str, bytes)):
        raise ScopeMappingError(
            AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
            "mandate.payment.allowed_payees 'allowed' must be an array",
        )
    if not allowed:
        # constraints.md §5: an empty allowlist is unsatisfiable and MUST NOT
        # be read as "unrestricted".
        raise ScopeMappingError(
            AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
            "mandate.payment.allowed_payees is empty, which is unsatisfiable",
        )

    disclosed: list[Mapping[str, Any]] = []
    withheld = 0
    for entry in allowed:
        if _is_disclosure_reference(entry):
            ref = entry["..."]
            # A disclosure reference is a base64url hash. Anything else is
            # not a reference this verifier can resolve, and looking an
            # unhashable value up in a dict would raise rather than refuse.
            resolved = disclosure_values_by_hash.get(ref) if isinstance(ref, str) else None
            if resolved is None:
                withheld += 1
                continue
            if not isinstance(resolved, Mapping):
                raise ScopeMappingError(
                    AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
                    "a disclosed payee resolved to something that is not an object",
                )
            disclosed.append(resolved)
        elif isinstance(entry, Mapping):
            disclosed.append(entry)
        else:
            raise ScopeMappingError(
                AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
                "mandate.payment.allowed_payees contains an entry that is neither "
                "a payee object nor a disclosure reference",
            )

    if not disclosed:
        # Selective disclosure withheld every approved payee. Inntris cannot
        # show that any payee satisfies the allowlist, so it will not issue
        # execution authority. This is a deliberately conservative verifier
        # posture: the reference implementation skips an allowlist it cannot
        # see, and skipping is not something an authority issuer may do.
        raise ScopeMappingError(
            AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
            "mandate.payment.allowed_payees disclosed no payees, so no proposed "
            "payee can be shown to satisfy it",
        )
    return disclosed, withheld


def map_payment_mandate(
    payment_mandate: Mapping[str, Any],
    checkout_mandate: Mapping[str, Any],
    disclosure_values_by_hash: Mapping[str, Any],
    *,
    not_before: datetime,
    not_after: datetime,
) -> MappedDelegationScope:
    """Map a verified autonomous mandate pair into neutral delegated scope.

    The caller must already have verified the chain: this reads mandate
    content and translates it, and it is not a second place where trust is
    established.
    """
    checkout_types: list[str] = []
    for constraint in _constraints_of(checkout_mandate, "checkout"):
        ctype = str(constraint["type"])
        if ctype not in REGISTERED_CONSTRAINT_TYPES:
            # The draft requires open mandates to reject unknown constraint
            # types outright: an unevaluable constraint leaves the agent's
            # authority unbounded, whichever mandate carries it.
            raise ScopeMappingError(
                AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
                f"the checkout mandate carries an unregistered constraint type "
                f"'{ctype}', which cannot be evaluated",
            )
        checkout_types.append(ctype)

    scope: dict[str, Any] = {}
    payee_references: tuple[str, ...] = ()
    disclosed_payees: tuple[Mapping[str, Any], ...] = ()
    undisclosed = 0
    structural: list[str] = []
    amount_record: dict[str, Any] = {}
    seen_mapped: set[str] = set()

    for constraint in _constraints_of(payment_mandate, "payment"):
        ctype = str(constraint["type"])

        if ctype in STRUCTURAL_PAYMENT_CONSTRAINT_TYPES:
            structural.append(ctype)
            continue

        if ctype in USAGE_ACCOUNTING_CONSTRAINT_TYPES:
            raise ScopeMappingError(
                AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
                f"the payment mandate carries '{ctype}', which bounds cumulative "
                "or recurring use. This release keeps no per-mandate spend or "
                "occurrence ledger, so it cannot enforce that bound and will not "
                "issue authority as though it had",
            )

        if ctype not in MAPPED_PAYMENT_CONSTRAINT_TYPES:
            raise ScopeMappingError(
                AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
                f"the payment mandate carries '{ctype}', which this release does "
                "not enforce",
            )

        if ctype in seen_mapped:
            # The draft permits repeated constraints of one type, each
            # validated independently. Combining two into one neutral scope
            # would mean choosing an intersection rule the draft does not
            # define, so this refuses instead of guessing one.
            raise ScopeMappingError(
                AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE,
                f"the payment mandate carries more than one '{ctype}' constraint; "
                "this release maps a single instance of each",
            )
        seen_mapped.add(ctype)

        if ctype == CONSTRAINT_AMOUNT_RANGE:
            fragment, amount_record = _map_amount_range(constraint)
            scope.update(fragment)
        elif ctype == CONSTRAINT_ALLOWED_PAYEES:
            resolved, undisclosed = _resolve_allowed_payees(
                constraint, disclosure_values_by_hash
            )
            disclosed_payees = tuple(resolved)
            payee_references = tuple(payee_reference(payee) for payee in resolved)
            scope["allowed_payees"] = sorted(set(payee_references))

    scope["not_before"] = not_before.isoformat()
    scope["not_after"] = not_after.isoformat()

    return MappedDelegationScope(
        scope=scope,
        payee_references=payee_references,
        disclosed_payees=disclosed_payees,
        undisclosed_payee_count=undisclosed,
        checkout_constraint_types=tuple(checkout_types),
        structural_constraint_types=tuple(structural),
        amount_range_minor_units=amount_record,
    )
