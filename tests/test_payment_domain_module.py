"""Phase 2 — the payment domain module.

Covers the money representation, the payee-to-destination binding, the
versioned authority policy snapshot, and the one rule the whole delegated
path rests on: the effective permission is organisation policy AND
delegated scope, and the intersection can only ever narrow.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest

from api.adapters.verify_envelope import build_action_envelope
from api.core.authority.authority import (
    AuthorityVerificationFailure,
    AuthorityVerificationIssue,
    DelegatedAuthorityReference,
    ExecutionContext,
    ResolvedAuthority,
    VerificationStatus,
    trusted_authority_construction,
)
from api.core.authority.decision import Decision, DecisionReason
from api.core.authority.errors import UnknownDomainError
from api.domains.payment.binding import (
    DestinationMismatch,
    ExecutionDestination,
    PayeeBinding,
    PayeeBindingError,
)
from api.domains.payment.delegation import (
    KNOWN_SCOPE_KEYS,
    DelegationScopeError,
    parse_delegation_constraints,
)
from api.domains.payment.money import (
    SUPPORTED_CURRENCIES,
    AmountPrecisionError,
    ConflictingAmountError,
    Money,
    MoneyError,
    UnsupportedCurrencyError,
    normalise_payment_money,
)
from api.domains.payment.policy import PaymentDomainPolicy, payment_destination
from api.domains.payment.snapshot import (
    PAYMENT_AUTHORITY_POLICY_FORMAT,
    build_payment_authority_policy_snapshot,
)
from api.models import AgentRecord, AgentStatus

NOW = datetime(2026, 4, 17, 12, 0, 0, tzinfo=UTC)
CHAIN = "eip155:8453"
SUPPLIER_A = "supplier-a"
SUPPLIER_B = "supplier-b"
BOUND_ACCOUNT = "0x1111111111111111111111111111111111111111"
UNRELATED_ACCOUNT = "0x9999999999999999999999999999999999999999"


def agent(metadata=None, **overrides) -> AgentRecord:
    fields = {
        "id": uuid4(),
        "org_id": uuid4(),
        "name": "payment-agent",
        "public_key": b"\x00" * 32,
        "public_key_fingerprint": "a" * 64,
        "trust_score": 80,
        "status": AgentStatus.ACTIVE,
        "daily_limit_usd": Decimal("1000"),
        "per_action_limit_usd": Decimal("100"),
        "allowed_actions": ["financial_transaction", "wallet_transaction"],
        "blocked_actions": [],
        "rate_limit_per_minute": 60,
        "last_action_at": None,
        "total_actions_count": 0,
        "total_blocked_count": 0,
        "metadata": metadata if metadata is not None else {},
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    fields.update(overrides)
    return AgentRecord(**fields)


def envelope(subject, amount="10.00", account=BOUND_ACCOUNT, action_type="wallet_transaction"):
    payload = {"amount": amount, "currency": "USD", "chain": CHAIN, "recipient": account}
    return build_action_envelope(
        agent=subject, action_type=action_type, payload=payload, timestamp=NOW
    )


def resolved(scope=None, *, verified=True, issues=(), not_before=None, not_after=None):
    token = trusted_authority_construction()
    reference = DelegatedAuthorityReference(
        token,
        issuer="external-issuer",
        external_reference_id="ref-1",
        artefact_digest="a" * 64,
        verification_status=(
            VerificationStatus.VERIFIED if verified else VerificationStatus.FAILED
        ),
        verified_at=NOW if verified else None,
    )
    return ResolvedAuthority(
        token,
        reference=reference,
        scope=scope or {},
        issues=issues,
        not_before=not_before,
        not_after=not_after,
    )


class StubBindingResolver:
    """Trusted server-side payee bindings, as a later phase would supply."""

    def __init__(self, bindings: dict[str, PayeeBinding]) -> None:
        self._bindings = bindings

    def binding_for(self, organisation_id: str, payee_reference: str):  # noqa: ARG002
        return self._bindings.get(payee_reference)


class StubRequirementResolver:
    def __init__(self, required: bool) -> None:
        self._required = required

    def requirement(self, organisation_id: str, principal_id: str, action_class: str):
        from api.core.authority.authority import AuthorityRequirement

        return AuthorityRequirement(
            trusted_authority_construction(),
            organisation_id=organisation_id,
            principal_id=principal_id,
            action_class=action_class,
            required=self._required,
        )


def supplier_a_binding(account=BOUND_ACCOUNT) -> StubBindingResolver:
    return StubBindingResolver(
        {
            SUPPLIER_A: PayeeBinding(
                payee_reference=SUPPLIER_A,
                destination=ExecutionDestination(
                    network=CHAIN, account=account, asset="USD"
                ),
                source="organisation-supplier-register",
            )
        }
    )


class TestMoney:
    def test_only_usd_is_supported_initially(self) -> None:
        assert set(SUPPORTED_CURRENCIES) == {"USD"}

    def test_an_unsupported_currency_is_rejected_not_treated_as_usd(self) -> None:
        with pytest.raises(UnsupportedCurrencyError, match="EUR"):
            Money.from_decimal(Decimal("10.00"), "EUR")

    def test_decimal_conversion_is_exact(self) -> None:
        assert Money.from_decimal(Decimal("10.00"), "USD").minor_units == 1000
        assert Money.from_decimal(Decimal("0.01"), "USD").minor_units == 1
        assert Money.from_decimal(Decimal("10"), "USD").minor_units == 1000

    def test_excess_precision_is_rejected_never_rounded(self) -> None:
        with pytest.raises(AmountPrecisionError, match="more precision"):
            Money.from_decimal(Decimal("10.005"), "USD")

    def test_a_float_amount_is_rejected(self) -> None:
        with pytest.raises(MoneyError, match="float"):
            Money.from_decimal(10.01, "USD")  # type: ignore[arg-type]

    def test_a_boolean_amount_is_rejected(self) -> None:
        with pytest.raises(MoneyError, match="boolean"):
            Money.from_decimal(True, "USD")  # type: ignore[arg-type]

    def test_a_negative_amount_is_rejected(self) -> None:
        with pytest.raises(MoneyError, match="negative"):
            Money.from_decimal(Decimal("-1.00"), "USD")

    def test_round_trips_back_to_the_same_decimal(self) -> None:
        assert Money.from_decimal(Decimal("12.34"), "USD").as_decimal() == Decimal("12.34")

    def test_currency_case_is_normalised(self) -> None:
        assert Money.from_decimal(Decimal("1.00"), "usd").currency == "USD"

    def test_amounts_in_different_currencies_are_not_ordered(self) -> None:
        usd = Money("USD", 100)
        other = Money("USD", 200)
        assert usd < other
        assert usd <= other


class TestMoneyNormalisation:
    def test_a_single_representation_normalises(self) -> None:
        money = normalise_payment_money({"amount": "10.00", "currency": "USD"})
        assert money == Money("USD", 1000)

    def test_no_amount_reads_as_none(self) -> None:
        assert normalise_payment_money({"currency": "USD"}) is None

    def test_two_agreeing_representations_are_accepted(self) -> None:
        money = normalise_payment_money(
            {"amount": "10.00", "value": "10.00", "currency": "USD"}
        )
        assert money == Money("USD", 1000)

    def test_two_conflicting_amounts_are_rejected(self) -> None:
        with pytest.raises(ConflictingAmountError, match="more than one amount"):
            normalise_payment_money({"amount": "10.00", "value": "10000.00", "currency": "USD"})

    def test_an_unsupported_currency_is_rejected_rather_than_assumed(self) -> None:
        with pytest.raises(UnsupportedCurrencyError, match="EUR"):
            normalise_payment_money({"amount": "10.00", "currency": "EUR"})

    def test_two_conflicting_currencies_are_rejected(self, monkeypatch) -> None:
        """Reachable only once a second currency is supported, so simulate one.

        With USD alone, an explicit non-USD currency is refused before any
        conflict can be observed. The conflict rule still has to hold the
        day a second currency is added.
        """
        monkeypatch.setitem(SUPPORTED_CURRENCIES, "EUR", 2)
        with pytest.raises(ConflictingAmountError, match="more than one currency"):
            normalise_payment_money({"amount_usd": "10.00", "amount": "10.00", "currency": "EUR"})

    def test_amount_usd_implies_its_currency(self) -> None:
        assert normalise_payment_money({"amount_usd": "10.00"}) == Money("USD", 1000)

    def test_an_amount_with_no_currency_is_rejected_on_the_delegated_path(self) -> None:
        with pytest.raises(ConflictingAmountError, match="explicit currency"):
            normalise_payment_money({"amount": "10.00"})

    def test_the_legacy_reader_is_untouched_by_these_rules(self) -> None:
        """Legacy /verify keeps first-field-wins with no currency requirement."""
        from api.domains.payment.amounts import extract_amount

        assert extract_amount({"amount": "10.00", "value": "10000.00"}) == Decimal("10.00")
        assert extract_amount({"amount": "10.00"}) == Decimal("10.00")


class TestPayeeBinding:
    def test_a_matching_destination_has_no_mismatch(self) -> None:
        binding = supplier_a_binding()._bindings[SUPPLIER_A]
        assert binding.mismatch_against(
            ExecutionDestination(network=CHAIN, account=BOUND_ACCOUNT, asset="USD")
        ) is None

    def test_an_unrelated_account_is_an_account_mismatch(self) -> None:
        binding = supplier_a_binding()._bindings[SUPPLIER_A]
        assert (
            binding.mismatch_against(
                ExecutionDestination(network=CHAIN, account=UNRELATED_ACCOUNT, asset="USD")
            )
            is DestinationMismatch.ACCOUNT_MISMATCH
        )

    def test_a_different_network_is_a_network_mismatch(self) -> None:
        binding = supplier_a_binding()._bindings[SUPPLIER_A]
        assert (
            binding.mismatch_against(
                ExecutionDestination(network="eip155:1", account=BOUND_ACCOUNT, asset="USD")
            )
            is DestinationMismatch.NETWORK_MISMATCH
        )

    def test_a_different_asset_is_an_asset_mismatch(self) -> None:
        binding = supplier_a_binding()._bindings[SUPPLIER_A]
        assert (
            binding.mismatch_against(
                ExecutionDestination(network=CHAIN, account=BOUND_ACCOUNT, asset="XYZ")
            )
            is DestinationMismatch.ASSET_MISMATCH
        )

    def test_evm_account_matching_keeps_the_existing_case_rule(self) -> None:
        binding = supplier_a_binding()._bindings[SUPPLIER_A]
        assert binding.mismatch_against(
            ExecutionDestination(network=CHAIN, account=BOUND_ACCOUNT.upper(), asset="USD")
        ) is None

    def test_a_binding_needs_a_real_destination(self) -> None:
        with pytest.raises(PayeeBindingError, match="ExecutionDestination"):
            PayeeBinding(
                payee_reference=SUPPLIER_A,
                destination={"account": BOUND_ACCOUNT},  # type: ignore[arg-type]
                source="register",
            )


class TestDelegationScope:
    def test_an_absent_scope_narrows_nothing(self) -> None:
        constraints = parse_delegation_constraints(None)
        assert constraints.max_amount is None
        assert constraints.allowed_payees is None
        assert constraints.is_fully_enforceable

    def test_a_known_scope_parses(self) -> None:
        constraints = parse_delegation_constraints(
            {"max_amount": "50.00", "currency": "USD", "allowed_payees": [SUPPLIER_A]}
        )
        assert constraints.max_amount == Money("USD", 5000)
        assert constraints.allowed_payees == frozenset({SUPPLIER_A})
        assert constraints.is_fully_enforceable

    def test_an_unknown_key_is_recorded_not_ignored(self) -> None:
        constraints = parse_delegation_constraints({"velocity_per_hour": 3})
        assert constraints.unsupported_constraints == ("velocity_per_hour",)
        assert not constraints.is_fully_enforceable

    def test_an_unsupported_currency_limit_is_recorded_as_unenforceable(self) -> None:
        constraints = parse_delegation_constraints({"max_amount": "50.00", "currency": "EUR"})
        assert "max_amount" in constraints.unsupported_constraints
        assert not constraints.is_fully_enforceable

    def test_an_amount_without_a_currency_is_a_provider_fault(self) -> None:
        with pytest.raises(DelegationScopeError, match="requires scope.currency"):
            parse_delegation_constraints({"max_amount": "50.00"})

    def test_a_malformed_payee_list_is_a_provider_fault(self) -> None:
        with pytest.raises(DelegationScopeError, match="allowed_payees"):
            parse_delegation_constraints({"allowed_payees": SUPPLIER_A})

    def test_the_enforceable_key_set_is_explicit(self) -> None:
        assert set(KNOWN_SCOPE_KEYS) == {
            "max_amount",
            "currency",
            "allowed_payees",
            "not_before",
            "not_after",
        }


class TestAuthorityPolicySnapshot:
    def test_it_is_deterministic(self) -> None:
        subject = agent()
        first = build_payment_authority_policy_snapshot(
            subject, "financial_transaction", trust_threshold=30, captured_at=NOW
        )
        second = build_payment_authority_policy_snapshot(
            subject, "financial_transaction", trust_threshold=30, captured_at=NOW
        )
        assert first.digest == second.digest

    def test_it_is_explicitly_versioned(self) -> None:
        snapshot = build_payment_authority_policy_snapshot(
            agent(), "financial_transaction", trust_threshold=30, captured_at=NOW
        )
        assert snapshot.preimage["format"] == PAYMENT_AUTHORITY_POLICY_FORMAT
        assert snapshot.as_policy_snapshot().source == PAYMENT_AUTHORITY_POLICY_FORMAT

    def test_it_covers_the_wallet_policy_the_legacy_hash_omits(self) -> None:
        without = build_payment_authority_policy_snapshot(
            agent(), "wallet_transaction", trust_threshold=30, captured_at=NOW
        )
        with_policy = build_payment_authority_policy_snapshot(
            agent(
                metadata={
                    "wallet_policy": {
                        "allowed_chains": [CHAIN],
                        "allowed_recipients": {CHAIN: [BOUND_ACCOUNT]},
                    }
                }
            ),
            "wallet_transaction",
            trust_threshold=30,
            captured_at=NOW,
        )
        assert with_policy.digest != without.digest
        assert with_policy.preimage["wallet_policy"]["allowed_recipients"] == {
            CHAIN: [BOUND_ACCOUNT]
        }

    def test_a_limit_change_changes_the_digest(self) -> None:
        baseline = build_payment_authority_policy_snapshot(
            agent(), "financial_transaction", trust_threshold=30, captured_at=NOW
        )
        raised = build_payment_authority_policy_snapshot(
            agent(per_action_limit_usd=Decimal("500")),
            "financial_transaction",
            trust_threshold=30,
            captured_at=NOW,
        )
        assert raised.digest != baseline.digest

    def test_an_unreadable_wallet_policy_is_recorded_not_dropped(self) -> None:
        snapshot = build_payment_authority_policy_snapshot(
            agent(metadata={"wallet_policy": {"allowed_chains": []}}),
            "wallet_transaction",
            trust_threshold=30,
            captured_at=NOW,
        )
        assert snapshot.preimage["wallet_policy"] == {"configured": True, "state": "invalid"}

    def test_it_carries_revision_metadata_for_change_detection(self) -> None:
        snapshot = build_payment_authority_policy_snapshot(
            agent(), "financial_transaction", trust_threshold=30, captured_at=NOW
        )
        assert PAYMENT_AUTHORITY_POLICY_FORMAT in snapshot.revision
        assert "2026-01-01T00:00:00Z" in snapshot.revision
        assert snapshot.preimage["principal"]["key_version"] == 1

    def test_it_contains_no_secrets(self) -> None:
        import json

        subject = agent(metadata={"api_key": "super-secret", "webhook_secret": "s3cr3t"})
        snapshot = build_payment_authority_policy_snapshot(
            subject, "financial_transaction", trust_threshold=30, captured_at=NOW
        )
        rendered = json.dumps(snapshot.preimage)
        assert "super-secret" not in rendered
        assert "s3cr3t" not in rendered
        assert subject.public_key.hex() not in rendered

    def test_it_does_not_redefine_the_legacy_effective_policy_hash(self) -> None:
        from api.legacy_main import _effective_policy_hash

        subject = agent()
        snapshot = build_payment_authority_policy_snapshot(
            subject, "financial_transaction", trust_threshold=30, captured_at=NOW
        )
        assert snapshot.digest != _effective_policy_hash(subject)


class TestOrganisationPolicyDecidesFirst:
    def test_an_allowed_payment_with_no_delegation_is_allowed(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(envelope(subject), at=NOW)
        assert decision.decision is Decision.ALLOW
        assert decision.authorises_execution

    def test_over_the_per_action_limit_blocks(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject, amount="500.00"), at=NOW
        )
        assert decision.decision is Decision.BLOCK
        assert DecisionReason.PER_ACTION_LIMIT_EXCEEDED in decision.reasons

    def test_over_the_daily_limit_blocks(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject, daily_spend=Decimal("995")).evaluate(
            envelope(subject), at=NOW
        )
        assert DecisionReason.DAILY_LIMIT_EXCEEDED in decision.reasons

    def test_the_wallet_allowlist_still_applies(self) -> None:
        subject = agent(
            metadata={
                "wallet_policy": {
                    "allowed_chains": [CHAIN],
                    "allowed_recipients": {CHAIN: [BOUND_ACCOUNT]},
                }
            }
        )
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject, account=UNRELATED_ACCOUNT), at=NOW
        )
        assert DecisionReason.WALLET_RECIPIENT_NOT_ALLOWED in decision.reasons

    def test_a_non_payment_action_is_refused_by_this_domain(self) -> None:
        subject = agent()
        general = build_action_envelope(
            agent=subject, action_type="api_call", payload={"operation": "read"}, timestamp=NOW
        )
        with pytest.raises(UnknownDomainError):
            PaymentDomainPolicy(agent=subject).evaluate(general, at=NOW)

    def test_the_decision_records_the_policy_snapshot_it_was_made_under(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(envelope(subject), at=NOW)
        assert decision.policy_snapshot.source == PAYMENT_AUTHORITY_POLICY_FORMAT
        assert len(decision.policy_snapshot.policy_hash) == 64


class TestDelegatedScopeOnlyNarrows:
    def test_a_delegated_cap_narrows_an_otherwise_allowed_payment(self) -> None:
        subject = agent()
        allowed_without = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject, amount="50.00"), at=NOW
        )
        assert allowed_without.decision is Decision.ALLOW

        narrowed = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject, amount="50.00"),
            resolved({"max_amount": "20.00", "currency": "USD"}),
            at=NOW,
        )
        assert narrowed.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_SCOPE_EXCEEDED in narrowed.reasons

    def test_a_delegated_cap_within_the_organisation_limit_still_allows(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject, amount="10.00"),
            resolved({"max_amount": "20.00", "currency": "USD"}),
            at=NOW,
        )
        assert decision.decision is Decision.ALLOW

    def test_a_generous_delegated_cap_cannot_widen_an_organisation_denial(self) -> None:
        """The whole security property, in one test."""
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject, amount="500.00"),
            resolved({"max_amount": "100000.00", "currency": "USD"}),
            at=NOW,
        )
        assert decision.decision is Decision.BLOCK
        assert DecisionReason.PER_ACTION_LIMIT_EXCEEDED in decision.reasons
        assert DecisionReason.AUTHORITY_SCOPE_EXCEEDED not in decision.reasons

    def test_delegation_cannot_re_enable_a_blocked_wallet_recipient(self) -> None:
        subject = agent(
            metadata={
                "wallet_policy": {
                    "allowed_chains": [CHAIN],
                    "allowed_recipients": {CHAIN: [BOUND_ACCOUNT]},
                }
            }
        )
        decision = PaymentDomainPolicy(
            agent=subject, payee_binding_resolver=supplier_a_binding(UNRELATED_ACCOUNT)
        ).evaluate(
            envelope(subject, account=UNRELATED_ACCOUNT),
            resolved({"allowed_payees": [SUPPLIER_A]}),
            at=NOW,
        )
        assert decision.decision is Decision.BLOCK
        assert DecisionReason.WALLET_RECIPIENT_NOT_ALLOWED in decision.reasons

    def test_an_expired_delegated_window_blocks(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject),
            resolved({"not_after": (NOW - timedelta(hours=1)).isoformat()}),
            at=NOW,
        )
        assert DecisionReason.AUTHORITY_EXPIRED in decision.reasons

    def test_a_not_yet_valid_delegated_window_blocks(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject),
            resolved({"not_before": (NOW + timedelta(hours=1)).isoformat()}),
            at=NOW,
        )
        assert DecisionReason.AUTHORITY_NOT_YET_VALID in decision.reasons

    def test_an_unverified_authority_blocks_with_its_typed_reason(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject),
            resolved(
                verified=False,
                issues=(
                    AuthorityVerificationIssue(
                        AuthorityVerificationFailure.AUTHORITY_REVOKED
                    ),
                ),
            ),
            at=NOW,
        )
        assert decision.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_REVOKED in decision.reasons


class TestUnsupportedDelegatedConstraintFailsClosed:
    def test_an_unknown_machine_constraint_blocks(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject),
            resolved({"velocity_per_hour": 3}),
            at=NOW,
        )
        assert decision.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_SCOPE_UNSUPPORTED in decision.reasons

    def test_a_limit_in_an_unsupported_currency_blocks(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject),
            resolved({"max_amount": "50.00", "currency": "EUR"}),
            at=NOW,
        )
        assert DecisionReason.AUTHORITY_SCOPE_UNSUPPORTED in decision.reasons

    def test_a_payee_restriction_with_no_resolver_blocks(self) -> None:
        """Cannot bind the payee, so cannot honour the constraint."""
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject),
            resolved({"allowed_payees": [SUPPLIER_A]}),
            at=NOW,
        )
        assert DecisionReason.AUTHORITY_SCOPE_UNSUPPORTED in decision.reasons

    def test_an_unreadable_scope_blocks(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject),
            resolved({"allowed_payees": "not-a-list"}),
            at=NOW,
        )
        assert DecisionReason.AUTHORITY_SCOPE_UNSUPPORTED in decision.reasons


class TestPayeeIsBoundToTheExecutionDestination:
    def test_a_bound_payee_and_matching_destination_allows(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(
            agent=subject, payee_binding_resolver=supplier_a_binding()
        ).evaluate(
            envelope(subject, account=BOUND_ACCOUNT),
            resolved({"allowed_payees": [SUPPLIER_A]}),
            at=NOW,
        )
        assert decision.decision is Decision.ALLOW

    def test_naming_supplier_a_while_sending_elsewhere_fails_closed(self) -> None:
        """A payee identity is not proof that an account belongs to that payee."""
        subject = agent()
        decision = PaymentDomainPolicy(
            agent=subject, payee_binding_resolver=supplier_a_binding()
        ).evaluate(
            envelope(subject, account=UNRELATED_ACCOUNT),
            resolved({"allowed_payees": [SUPPLIER_A]}),
            at=NOW,
        )
        assert decision.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_SCOPE_EXCEEDED in decision.reasons

    def test_an_unbound_payee_fails_closed(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(
            agent=subject, payee_binding_resolver=supplier_a_binding()
        ).evaluate(
            envelope(subject),
            resolved({"allowed_payees": [SUPPLIER_B]}),
            at=NOW,
        )
        assert DecisionReason.AUTHORITY_SCOPE_EXCEEDED in decision.reasons

    def test_an_undeterminable_destination_fails_closed(self) -> None:
        subject = agent()
        targetless = build_action_envelope(
            agent=subject,
            action_type="financial_transaction",
            payload={"amount": "10.00", "currency": "USD"},
            timestamp=NOW,
        )
        assert payment_destination(targetless, None) is None
        decision = PaymentDomainPolicy(
            agent=subject, payee_binding_resolver=supplier_a_binding()
        ).evaluate(targetless, resolved({"allowed_payees": [SUPPLIER_A]}), at=NOW)
        assert DecisionReason.AUTHORITY_SCOPE_EXCEEDED in decision.reasons


class TestAuthorityRequirementDoesNotFallThrough:
    def test_no_resolver_means_current_behaviour(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(envelope(subject), at=NOW)
        assert decision.decision is Decision.ALLOW

    def test_a_resolver_saying_not_required_means_current_behaviour(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(
            agent=subject, authority_requirement_resolver=StubRequirementResolver(False)
        ).evaluate(envelope(subject), at=NOW)
        assert decision.decision is Decision.ALLOW

    def test_required_but_absent_cannot_take_the_non_delegated_path(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(
            agent=subject, authority_requirement_resolver=StubRequirementResolver(True)
        ).evaluate(envelope(subject), at=NOW)
        assert decision.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING in decision.reasons

    def test_required_and_unverified_blocks_with_the_verification_reason(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(
            agent=subject, authority_requirement_resolver=StubRequirementResolver(True)
        ).evaluate(
            envelope(subject),
            resolved(
                verified=False,
                issues=(
                    AuthorityVerificationIssue(
                        AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID
                    ),
                ),
            ),
            at=NOW,
        )
        assert DecisionReason.AUTHORITY_VERIFICATION_FAILED in decision.reasons

    def test_required_and_verified_proceeds_to_the_intersection(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(
            agent=subject, authority_requirement_resolver=StubRequirementResolver(True)
        ).evaluate(
            envelope(subject),
            resolved({"max_amount": "20.00", "currency": "USD"}),
            at=NOW,
        )
        assert decision.decision is Decision.ALLOW


class TestTrustedContextMustAgree:
    def _context(self, organisation_id: str, principal_id: str) -> ExecutionContext:
        return ExecutionContext(
            trusted_authority_construction(),
            organisation_id=organisation_id,
            principal_id=principal_id,
        )

    def test_a_matching_context_allows(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject),
            None,
            self._context(str(subject.org_id), str(subject.id)),
            at=NOW,
        )
        assert decision.decision is Decision.ALLOW

    def test_a_context_naming_another_principal_blocks(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject),
            None,
            self._context(str(subject.org_id), str(uuid4())),
            at=NOW,
        )
        assert DecisionReason.AUTHORITY_PRINCIPAL_MISMATCH in decision.reasons

    def test_a_context_naming_another_organisation_blocks(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject),
            None,
            self._context(str(uuid4()), str(subject.id)),
            at=NOW,
        )
        assert DecisionReason.AUTHORITY_PRINCIPAL_MISMATCH in decision.reasons


def envelope_without_currency(subject, amount=None, account=BOUND_ACCOUNT):
    """A wallet transaction whose currency cannot be determined.

    ``wallet_transaction`` does not require an amount, so with no amount and
    no currency field the normalised money is ``None`` — the case a currency
    constraint must still fail closed on.
    """
    payload = {"chain": CHAIN, "recipient": account}
    if amount is not None:
        payload["amount"] = amount
    return build_action_envelope(
        agent=subject, action_type="wallet_transaction", payload=payload, timestamp=NOW
    )


class TestDelegatedCurrencyIsParsedIndependently:
    """Regression: ``currency`` was only read when ``max_amount`` was present.

    A verified scope of ``{"currency": "EUR"}`` therefore parsed to a fully
    enforceable constraint set that constrained nothing, and a USD payment
    proceeded — a scope that restricted the authority was read as a scope
    that restricted nothing.
    """

    def test_currency_is_retained_without_a_max_amount(self) -> None:
        constraints = parse_delegation_constraints({"currency": "USD"})
        assert constraints.currency == "USD"
        assert constraints.max_amount is None
        assert constraints.is_fully_enforceable

    def test_an_unsupported_currency_alone_is_not_fully_enforceable(self) -> None:
        constraints = parse_delegation_constraints({"currency": "EUR"})
        assert constraints.currency is None
        assert constraints.unsupported_constraints == ("currency",)
        assert not constraints.is_fully_enforceable

    def test_currency_case_is_normalised(self) -> None:
        assert parse_delegation_constraints({"currency": "usd"}).currency == "USD"

    def test_a_malformed_currency_is_a_provider_fault(self) -> None:
        with pytest.raises(DelegationScopeError, match="scope.currency"):
            parse_delegation_constraints({"currency": 840})
        with pytest.raises(DelegationScopeError, match="scope.currency"):
            parse_delegation_constraints({"currency": "  "})

    def test_a_max_amount_uses_the_same_parsed_currency(self) -> None:
        constraints = parse_delegation_constraints(
            {"max_amount": "20.00", "currency": "usd"}
        )
        assert constraints.currency == "USD"
        assert constraints.max_amount == Money("USD", 2000)
        assert constraints.max_amount.currency == constraints.currency

    def test_an_unsupported_currency_makes_its_limit_unenforceable_too(self) -> None:
        constraints = parse_delegation_constraints(
            {"max_amount": "20.00", "currency": "EUR"}
        )
        assert constraints.currency is None
        assert constraints.max_amount is None
        assert set(constraints.unsupported_constraints) == {"currency", "max_amount"}
        assert not constraints.is_fully_enforceable

    def test_a_max_amount_still_requires_a_currency(self) -> None:
        with pytest.raises(DelegationScopeError, match="requires scope.currency"):
            parse_delegation_constraints({"max_amount": "20.00"})

    def test_an_absent_currency_constrains_nothing(self) -> None:
        constraints = parse_delegation_constraints({"allowed_payees": [SUPPLIER_A]})
        assert constraints.currency is None
        assert constraints.is_fully_enforceable


class TestDelegatedCurrencyIsEnforcedIndependently:
    """The parsed currency constraint must actually decide something."""

    def test_a_matching_currency_may_continue(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject, amount="10.00"), resolved({"currency": "USD"}), at=NOW
        )
        assert decision.decision is Decision.ALLOW

    def test_an_unsupported_scope_currency_fails_closed(self) -> None:
        """The reported fail-open, pinned shut."""
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject, amount="10.00"), resolved({"currency": "EUR"}), at=NOW
        )
        assert decision.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_SCOPE_UNSUPPORTED in decision.reasons

    def test_an_undeterminable_action_currency_blocks(self) -> None:
        subject = agent()
        payment = envelope_without_currency(subject)
        assert normalise_payment_money(dict(payment.action.payload)) is None
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            payment, resolved({"currency": "USD"}), at=NOW
        )
        assert decision.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_SCOPE_EXCEEDED in decision.reasons

    def test_an_amount_with_no_currency_still_fails_closed(self) -> None:
        """A different route to the same refusal: unreadable money blocks first."""
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope_without_currency(subject, amount="10.00"),
            resolved({"currency": "USD"}),
            at=NOW,
        )
        assert decision.decision is Decision.BLOCK
        assert DecisionReason.AMOUNT_INVALID in decision.reasons

    def test_a_currency_constraint_does_not_disturb_an_unscoped_payment(self) -> None:
        """No currency in the scope means the currency is not constrained."""
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope_without_currency(subject), resolved({}), at=NOW
        )
        assert decision.decision is Decision.ALLOW

    def test_a_cap_with_a_matching_currency_behaves_as_before(self) -> None:
        subject = agent()
        within = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject, amount="10.00"),
            resolved({"max_amount": "20.00", "currency": "USD"}),
            at=NOW,
        )
        assert within.decision is Decision.ALLOW

        over = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject, amount="50.00"),
            resolved({"max_amount": "20.00", "currency": "USD"}),
            at=NOW,
        )
        assert over.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_SCOPE_EXCEEDED in over.reasons

    def test_a_cap_in_an_unsupported_currency_still_blocks(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject, amount="10.00"),
            resolved({"max_amount": "20.00", "currency": "EUR"}),
            at=NOW,
        )
        assert decision.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_SCOPE_UNSUPPORTED in decision.reasons

    def test_a_currency_scope_still_cannot_widen_an_organisation_denial(self) -> None:
        subject = agent()
        decision = PaymentDomainPolicy(agent=subject).evaluate(
            envelope(subject, amount="500.00"), resolved({"currency": "USD"}), at=NOW
        )
        assert decision.decision is Decision.BLOCK
        assert DecisionReason.PER_ACTION_LIMIT_EXCEEDED in decision.reasons

    def test_every_declared_known_scope_key_actually_constrains_something(self) -> None:
        """The invariant the regression violated.

        A key listed in ``KNOWN_SCOPE_KEYS`` claims this build enforces it. A
        key that parses to no retained constraint and no unenforceable marker
        is a silent fail-open, which is how this bug reached the branch.
        """
        samples: dict[str, dict] = {
            "currency": {"currency": "USD"},
            "max_amount": {"max_amount": "20.00", "currency": "USD"},
            "allowed_payees": {"allowed_payees": [SUPPLIER_A]},
            "not_before": {"not_before": (NOW - timedelta(hours=1)).isoformat()},
            "not_after": {"not_after": (NOW + timedelta(hours=1)).isoformat()},
        }
        assert set(samples) == set(KNOWN_SCOPE_KEYS)
        for key, scope in samples.items():
            constraints = parse_delegation_constraints(scope)
            retained = {
                "currency": constraints.currency,
                "max_amount": constraints.max_amount,
                "allowed_payees": constraints.allowed_payees,
                "not_before": constraints.not_before,
                "not_after": constraints.not_after,
            }
            assert retained[key] is not None, (
                f"scope key {key!r} is declared enforceable but parses to no "
                "retained constraint"
            )
