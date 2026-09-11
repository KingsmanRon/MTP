"""Phase 5 — the Verifiable Intent scope mapper, differentially tested.

The mapper is where Inntris decides what a mandate *means*. A mapping bug
here does not look like a crash; it looks like a payment that was allowed
because a constraint was read a little too generously. So the two mapped
constraint types are checked against the pinned upstream reference
constraint checker rather than against this repository's own idea of what
they should do.

The property being asserted is not "identical", it is:

* **agreement** wherever the two implementations are answering the same
  question, and
* **Inntris is never the more permissive one** everywhere else.

That asymmetry is deliberate and is recorded in
``docs/integrations/mastercard-vi-profile.md``.
"""

from __future__ import annotations

import importlib.util
import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from api.connectors.mastercard_vi import profile as vi_profile
from api.connectors.mastercard_vi.scope import (
    ScopeMappingError,
    map_payment_mandate,
    minor_units_to_major_string,
    payee_reference,
)
from api.core.authority.authority import AuthorityVerificationFailure
from api.domains.payment.delegation import parse_delegation_constraints
from api.domains.payment.money import Money

# In CI the reference implementation is installed by an explicit step, so a
# skip there does not mean "optional dependency absent" — it means that step
# silently did not run, and the connector's whole test surface would vanish
# without anything going red. Fail loudly instead.
if importlib.util.find_spec("verifiable_intent") is None and os.environ.get("CI"):
    raise RuntimeError(
        "the pinned verifiable-intent reference implementation is missing in CI; "
        "the 'install the pinned Verifiable Intent reference implementation' step "
        "must run before pytest"
    )

pytest.importorskip(
    "verifiable_intent",
    reason=(
        "the pinned verifiable-intent reference implementation is an optional "
        "extra; install with pip install -e '.[mastercard-vi]'"
    ),
)

from verifiable_intent.verification.constraint_checker import (  # noqa: E402
    StrictnessMode,
    check_constraints,
)

NOT_BEFORE = datetime(2026, 5, 1, tzinfo=UTC)
NOT_AFTER = NOT_BEFORE + timedelta(days=30)

SUPPLIER_A = {
    "id": "supplier-a",
    "name": "Supplier A",
    "website": "https://supplier-a.example",
}
SUPPLIER_B = {
    "id": "supplier-b",
    "name": "Supplier B",
    "website": "https://supplier-b.example",
}
#: The same two suppliers as the draft allows them to be expressed: no
#: opaque id, identified by the pair the user actually saw.
SUPPLIER_A_NO_ID = {"name": "Supplier A", "website": "https://supplier-a.example"}
SUPPLIER_B_NO_ID = {"name": "Supplier B", "website": "https://supplier-b.example"}
IMPOSTOR = {
    "id": "supplier-z",
    "name": "Supplier A",
    "website": "https://supplier-a.example.attacker.test",
}


def checkout_mandate(constraints=None) -> dict:
    return {
        "vct": vi_profile.L2_CHECKOUT_VCT_OPEN,
        "constraints": constraints if constraints is not None else [],
    }


def payment_mandate(*constraints) -> dict:
    return {
        "vct": vi_profile.L2_PAYMENT_VCT_OPEN,
        "constraints": [
            {
                "type": vi_profile.CONSTRAINT_REFERENCE,
                "conditional_transaction_id": "checkout-disclosure-hash",
            },
            *constraints,
        ],
    }


def amount_range(currency="USD", minimum=None, maximum=None) -> dict:
    constraint = {"type": vi_profile.CONSTRAINT_AMOUNT_RANGE, "currency": currency}
    if minimum is not None:
        constraint["min"] = minimum
    if maximum is not None:
        constraint["max"] = maximum
    return constraint


def allowed_payees(*payees) -> dict:
    return {"type": vi_profile.CONSTRAINT_ALLOWED_PAYEES, "allowed": list(payees)}


def mapped(*constraints, checkout=None):
    return map_payment_mandate(
        payment_mandate(*constraints),
        checkout_mandate(checkout),
        {},
        not_before=NOT_BEFORE,
        not_after=NOT_AFTER,
    )


def reference_accepts_amount(constraint: dict, currency: str, amount: int) -> bool:
    """What the pinned reference constraint checker says about one amount."""
    result = check_constraints(
        [constraint],
        {"payment_amount": {"currency": currency, "amount": amount}},
        mode=StrictnessMode.STRICT,
        is_open_mandate=True,
    )
    return result.satisfied


def reference_accepts_payee(constraint: dict, payee: dict) -> bool:
    result = check_constraints(
        [constraint],
        {"payee": payee},
        mode=StrictnessMode.STRICT,
        is_open_mandate=True,
    )
    return result.satisfied


def inntris_accepts_amount(constraint: dict, currency: str, amount: int) -> bool:
    """What Inntris's mapped constraints say about the same amount."""
    try:
        scope = mapped(constraint).scope
    except ScopeMappingError:
        return False
    constraints = parse_delegation_constraints(scope)
    if not constraints.is_fully_enforceable:
        return False
    if constraints.currency is not None and constraints.currency != currency:
        return False
    if constraints.max_amount is None:
        return True
    try:
        money = Money(currency=currency, minor_units=amount)
    except ValueError:
        return False
    return money <= constraints.max_amount


def inntris_accepts_payee(constraint: dict, payee: dict) -> bool:
    try:
        scope = mapped(constraint).scope
    except ScopeMappingError:
        return False
    constraints = parse_delegation_constraints(scope)
    if constraints.allowed_payees is None:
        return True
    try:
        reference = payee_reference(payee)
    except ScopeMappingError:
        return False
    return reference in constraints.allowed_payees


# ---------------------------------------------------------------------------
# Amount range
# ---------------------------------------------------------------------------

AMOUNT_CASES = [
    ("at the cap", 2_000_000),
    ("one minor unit under the cap", 1_999_999),
    ("one minor unit over the cap", 2_000_001),
    ("far under", 1),
    ("zero", 0),
    ("far over", 100_000_000),
]


class TestAmountRangeAgreesWithTheReferenceChecker:
    @pytest.mark.parametrize(("label", "amount"), AMOUNT_CASES, ids=[c[0] for c in AMOUNT_CASES])
    def test_capped_range(self, label: str, amount: int) -> None:  # noqa: ARG002
        constraint = amount_range(currency="USD", maximum=2_000_000)
        assert inntris_accepts_amount(constraint, "USD", amount) is (
            reference_accepts_amount(constraint, "USD", amount)
        )

    @pytest.mark.parametrize(("label", "amount"), AMOUNT_CASES, ids=[c[0] for c in AMOUNT_CASES])
    def test_zero_minimum_is_the_same_as_no_minimum(self, label: str, amount: int) -> None:  # noqa: ARG002
        constraint = amount_range(currency="USD", minimum=0, maximum=2_000_000)
        assert inntris_accepts_amount(constraint, "USD", amount) is (
            reference_accepts_amount(constraint, "USD", amount)
        )

    @pytest.mark.parametrize(("label", "amount"), AMOUNT_CASES, ids=[c[0] for c in AMOUNT_CASES])
    def test_an_uncapped_range(self, label: str, amount: int) -> None:  # noqa: ARG002
        constraint = amount_range(currency="USD")
        assert inntris_accepts_amount(constraint, "USD", amount) is (
            reference_accepts_amount(constraint, "USD", amount)
        )

    def test_a_currency_mismatch_is_refused_by_both(self) -> None:
        constraint = amount_range(currency="USD", maximum=2_000_000)
        assert reference_accepts_amount(constraint, "GBP", 1_000) is False
        assert inntris_accepts_amount(constraint, "GBP", 1_000) is False

    def test_inntris_is_never_more_permissive_on_amounts(self) -> None:
        constraint = amount_range(currency="USD", minimum=1_000, maximum=2_000_000)
        for _label, amount in AMOUNT_CASES:
            if inntris_accepts_amount(constraint, "USD", amount):
                assert reference_accepts_amount(constraint, "USD", amount), amount

    def test_a_positive_minimum_is_refused_rather_than_half_enforced(self) -> None:
        """The reference checker enforces the floor; Inntris has nowhere to."""
        constraint = amount_range(currency="USD", minimum=1_000, maximum=2_000_000)
        assert reference_accepts_amount(constraint, "USD", 500) is False
        with pytest.raises(ScopeMappingError) as caught:
            mapped(constraint)
        assert caught.value.code is AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE


# ---------------------------------------------------------------------------
# Allowed payees
# ---------------------------------------------------------------------------

PAYEE_CANDIDATES = [
    ("approved, by id", SUPPLIER_A),
    ("the other approved supplier", SUPPLIER_B),
    ("an unapproved supplier", {"id": "supplier-z", "name": "Z", "website": "https://z.example"}),
    ("an impostor sharing a display name", IMPOSTOR),
]


class TestAllowedPayeesAgreesWithTheReferenceChecker:
    @pytest.mark.parametrize(
        ("label", "payee"), PAYEE_CANDIDATES, ids=[c[0] for c in PAYEE_CANDIDATES]
    )
    def test_identified_payees(self, label: str, payee: dict) -> None:  # noqa: ARG002
        constraint = allowed_payees(SUPPLIER_A, SUPPLIER_B)
        assert inntris_accepts_payee(constraint, payee) is (
            reference_accepts_payee(constraint, payee)
        )

    @pytest.mark.parametrize(
        ("label", "payee"),
        [
            ("approved, by name and website", SUPPLIER_A_NO_ID),
            ("the other approved supplier", SUPPLIER_B_NO_ID),
            ("same name, different website", {"name": "Supplier A", "website": "https://a.test"}),
            ("same website, different name", {"name": "Other", "website": SUPPLIER_A["website"]}),
        ],
    )
    def test_payees_identified_by_name_and_website(self, label: str, payee: dict) -> None:  # noqa: ARG002
        constraint = allowed_payees(SUPPLIER_A_NO_ID, SUPPLIER_B_NO_ID)
        assert inntris_accepts_payee(constraint, payee) is (
            reference_accepts_payee(constraint, payee)
        )

    @pytest.mark.parametrize(
        ("allowlist", "payee"),
        [
            # The draft's matcher falls back to name+website whenever either
            # side lacks an id; Inntris keys each side independently. These
            # are the cases where the two therefore differ.
            ((SUPPLIER_A,), SUPPLIER_A_NO_ID),
            ((SUPPLIER_A_NO_ID,), SUPPLIER_A),
        ],
    )
    def test_inntris_is_the_stricter_one_on_mixed_identification(
        self, allowlist: tuple, payee: dict
    ) -> None:
        constraint = allowed_payees(*allowlist)
        assert reference_accepts_payee(constraint, payee) is True
        assert inntris_accepts_payee(constraint, payee) is False

    def test_inntris_never_accepts_a_payee_the_reference_rejects(self) -> None:
        allowlists = [
            (SUPPLIER_A, SUPPLIER_B),
            (SUPPLIER_A_NO_ID, SUPPLIER_B_NO_ID),
            (SUPPLIER_A, SUPPLIER_B_NO_ID),
        ]
        candidates = [
            SUPPLIER_A,
            SUPPLIER_B,
            SUPPLIER_A_NO_ID,
            SUPPLIER_B_NO_ID,
            IMPOSTOR,
            {"id": "supplier-z", "name": "Z", "website": "https://z.example"},
        ]
        for allowlist in allowlists:
            constraint = allowed_payees(*allowlist)
            for payee in candidates:
                if inntris_accepts_payee(constraint, payee):
                    assert reference_accepts_payee(constraint, payee), (allowlist, payee)

    def test_an_empty_allowlist_is_unsatisfiable_for_both(self) -> None:
        constraint = allowed_payees()
        assert reference_accepts_payee(constraint, SUPPLIER_A) is False
        with pytest.raises(ScopeMappingError):
            mapped(constraint)


# ---------------------------------------------------------------------------
# The mapper's own rules
# ---------------------------------------------------------------------------


class TestMinorUnitConversion:
    @pytest.mark.parametrize(
        ("minor", "major"),
        [
            (0, "0.00"),
            (1, "0.01"),
            (99, "0.99"),
            (100, "1.00"),
            (27_999, "279.99"),
            (2_000_000, "20000.00"),
            (10**18, "10000000000000000.00"),
        ],
    )
    def test_conversion_is_exact(self, minor: int, major: str) -> None:
        assert minor_units_to_major_string(minor, "USD") == major
        assert Money.from_decimal(Decimal(major), "USD").minor_units == minor

    def test_a_very_large_amount_survives_the_round_trip(self) -> None:
        """No decimal context, no float: digit placement only."""
        minor = 12_345_678_901_234_567_890_123_456_789
        major = minor_units_to_major_string(minor, "USD")
        assert Money.from_decimal(Decimal(major), "USD").minor_units == minor


class TestPayeeReferences:
    def test_an_id_is_the_primary_key(self) -> None:
        assert payee_reference(SUPPLIER_A) == "payee:id:supplier-a"

    def test_name_and_website_identify_a_payee_without_an_id(self) -> None:
        assert payee_reference(SUPPLIER_A_NO_ID) == (
            "payee:name-website:Supplier A|https://supplier-a.example"
        )

    def test_a_separator_in_a_name_cannot_collapse_two_payees(self) -> None:
        first = payee_reference({"name": "A|B", "website": "https://c.example"})
        second = payee_reference({"name": "A", "website": "B|https://c.example"})
        assert first != second

    def test_a_payee_with_no_usable_identity_is_refused(self) -> None:
        with pytest.raises(ScopeMappingError) as caught:
            payee_reference({"name": "Nameless only"})
        assert caught.value.code is AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE

    def test_comparison_is_exact_not_normalised(self) -> None:
        """The draft forbids case-insensitive and substring payee matching."""
        assert payee_reference({"name": "supplier a", "website": "https://x"}) != (
            payee_reference({"name": "Supplier A", "website": "https://x"})
        )


class TestPartialDisclosureNarrowsRatherThanWidens:
    def test_only_the_disclosed_payees_are_enforced(self) -> None:
        constraint = {
            "type": vi_profile.CONSTRAINT_ALLOWED_PAYEES,
            "allowed": [SUPPLIER_A, {"...": "withheld-payee-hash"}],
        }
        result = map_payment_mandate(
            payment_mandate(constraint),
            checkout_mandate(),
            {},
            not_before=NOT_BEFORE,
            not_after=NOT_AFTER,
        )
        assert result.scope["allowed_payees"] == ["payee:id:supplier-a"]
        assert result.undisclosed_payee_count == 1

    def test_a_withheld_payee_can_be_resolved_from_its_disclosure(self) -> None:
        constraint = {
            "type": vi_profile.CONSTRAINT_ALLOWED_PAYEES,
            "allowed": [{"...": "hash-a"}, {"...": "hash-b"}],
        }
        result = map_payment_mandate(
            payment_mandate(constraint),
            checkout_mandate(),
            {"hash-a": SUPPLIER_A, "hash-b": SUPPLIER_B},
            not_before=NOT_BEFORE,
            not_after=NOT_AFTER,
        )
        assert result.scope["allowed_payees"] == [
            "payee:id:supplier-a",
            "payee:id:supplier-b",
        ]
        assert result.undisclosed_payee_count == 0

    def test_withholding_every_payee_fails_closed(self) -> None:
        constraint = {
            "type": vi_profile.CONSTRAINT_ALLOWED_PAYEES,
            "allowed": [{"...": "hash-a"}, {"...": "hash-b"}],
        }
        with pytest.raises(ScopeMappingError) as caught:
            map_payment_mandate(
                payment_mandate(constraint),
                checkout_mandate(),
                {},
                not_before=NOT_BEFORE,
                not_after=NOT_AFTER,
            )
        assert caught.value.code is AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE


class TestUnsupportedConstraintsFailClosed:
    @pytest.mark.parametrize(
        "constraint",
        [
            {"type": vi_profile.CONSTRAINT_BUDGET, "currency": "USD", "max": 5_000_000},
            {
                "type": vi_profile.CONSTRAINT_RECURRENCE,
                "frequency": "MNTH",
                "start_date": "2026-05-01",
            },
            {
                "type": vi_profile.CONSTRAINT_AGENT_RECURRENCE,
                "frequency": "ON_DEMAND",
                "start_date": "2026-05-01",
                "end_date": "2026-06-01",
            },
            {"type": "urn:example:velocity", "max_per_hour": 3},
            {"type": "mandate.payment.something_new", "value": 1},
        ],
    )
    def test_an_unmapped_payment_constraint_refuses_the_delegation(
        self, constraint: dict
    ) -> None:
        with pytest.raises(ScopeMappingError) as caught:
            mapped(amount_range(maximum=1000), allowed_payees(SUPPLIER_A), constraint)
        assert caught.value.code is AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE

    def test_an_unregistered_checkout_constraint_also_refuses(self) -> None:
        with pytest.raises(ScopeMappingError) as caught:
            mapped(
                amount_range(maximum=1000),
                allowed_payees(SUPPLIER_A),
                checkout=[{"type": "urn:example:delivery-window", "before": "2026-06-01"}],
            )
        assert caught.value.code is AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE

    def test_registered_checkout_constraints_are_recorded_not_mapped(self) -> None:
        result = mapped(
            amount_range(maximum=1000),
            allowed_payees(SUPPLIER_A),
            checkout=[
                {"type": vi_profile.CONSTRAINT_ALLOWED_MERCHANTS, "allowed": [SUPPLIER_A]},
                {"type": vi_profile.CONSTRAINT_LINE_ITEMS, "items": []},
            ],
        )
        assert result.checkout_constraint_types == (
            vi_profile.CONSTRAINT_ALLOWED_MERCHANTS,
            vi_profile.CONSTRAINT_LINE_ITEMS,
        )
        assert "line_items" not in result.scope
        assert "allowed_merchants" not in result.scope

    def test_a_repeated_mapped_constraint_refuses_rather_than_guessing(self) -> None:
        with pytest.raises(ScopeMappingError, match="more than one"):
            mapped(amount_range(maximum=1000), amount_range(maximum=2000))

    def test_an_unsupported_currency_refuses(self) -> None:
        with pytest.raises(ScopeMappingError, match="GBP"):
            mapped(amount_range(currency="GBP", maximum=1000))


class TestMappedScopeShape:
    def test_the_scope_carries_the_mandate_validity_window(self) -> None:
        result = mapped(amount_range(maximum=1000), allowed_payees(SUPPLIER_A))
        constraints = parse_delegation_constraints(result.scope)
        assert constraints.not_before == NOT_BEFORE
        assert constraints.not_after == NOT_AFTER

    def test_an_amount_range_is_a_per_transaction_bound(self) -> None:
        """Two acts of 1000 each are both within a 1000 cap; it is not a budget."""
        result = mapped(amount_range(maximum=1000), allowed_payees(SUPPLIER_A))
        constraints = parse_delegation_constraints(result.scope)
        one = Money(currency="USD", minor_units=1000)
        assert one <= constraints.max_amount
        assert result.amount_range_minor_units == {
            "currency": "USD",
            "min": None,
            "max": 1000,
        }
