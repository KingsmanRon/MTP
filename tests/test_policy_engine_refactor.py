"""Phase 2 — the payment split must not move any existing behaviour.

Amount extraction, spend limits and the wallet allowlists moved out of
``api/policy.py`` into ``api/domains/payment/``. The engine still runs
them at the same points in the same order, so every one of these
assertions describes behaviour that predates the split. If one fails, the
refactor is wrong — not the test.
"""

from __future__ import annotations

import ast
import inspect
from collections import Counter
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest

import api.policy as policy_module
from api.models import ActionVerdict, AgentRecord, AgentStatus
from api.policy import (
    AMOUNT_FIELDS,
    AMOUNT_REQUIRED_ACTIONS,
    AmountError,
    PolicyEngine,
    PolicyResult,
    PolicyViolation,
    WalletPolicyError,
    recipient_in_allowlist,
    validate_wallet_policy,
)

CHAIN = "eip155:8453"
OTHER_CHAIN = "eip155:1"
APPROVED_RECIPIENT = "0x1111111111111111111111111111111111111111"
UNKNOWN_RECIPIENT = "0x9999999999999999999999999999999999999999"

ALL_ACTIONS = [
    "financial_transaction",
    "wallet_transaction",
    "wallet_signature",
    "email_send",
    "api_call",
    "tool_call",
    "data_export",
    "admin_action",
]


def agent(metadata=None, trust_score=80, **overrides) -> AgentRecord:
    fields = {
        "id": uuid4(),
        "org_id": uuid4(),
        "name": "refactor-agent",
        "public_key": b"\x00" * 32,
        "public_key_fingerprint": "a" * 64,
        "trust_score": trust_score,
        "status": AgentStatus.ACTIVE,
        "daily_limit_usd": Decimal("1000"),
        "per_action_limit_usd": Decimal("100"),
        "allowed_actions": ALL_ACTIONS,
        "blocked_actions": [],
        "rate_limit_per_minute": 60,
        "last_action_at": None,
        "total_actions_count": 0,
        "total_blocked_count": 0,
        "metadata": metadata if metadata is not None else {},
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    fields.update(overrides)
    return AgentRecord(**fields)


def evaluate(subject, action_type, payload, **engine_kwargs) -> PolicyResult:
    return PolicyEngine(**engine_kwargs).evaluate(
        agent=subject,
        action_type=action_type,
        payload=payload,
        timestamp=datetime.now(UTC),
    )


class TestMovedSymbolsStillImportFromPolicy:
    """Every symbol that moved is still reachable from its old home."""

    @pytest.mark.parametrize(
        "name",
        [
            "AMOUNT_FIELDS",
            "AMOUNT_REQUIRED_ACTIONS",
            "AmountError",
            "PolicyResult",
            "PolicyViolation",
            "WALLET_ACTION_TYPES",
            "WALLET_ALLOWLIST_ACTION_TYPES",
            "WalletPolicyError",
            "recipient_in_allowlist",
            "validate_wallet_policy",
        ],
    )
    def test_symbol_is_re_exported(self, name: str) -> None:
        assert hasattr(policy_module, name)

    def test_re_exports_are_the_same_objects_as_the_new_home(self) -> None:
        from api.domains.payment import amounts, wallet

        assert policy_module.AmountError is amounts.AmountError
        assert policy_module.AMOUNT_FIELDS is amounts.AMOUNT_FIELDS
        assert policy_module.AMOUNT_REQUIRED_ACTIONS is amounts.AMOUNT_REQUIRED_ACTIONS
        assert policy_module.WalletPolicyError is wallet.WalletPolicyError
        assert policy_module.validate_wallet_policy is wallet.validate_wallet_policy
        assert policy_module.recipient_in_allowlist is wallet.recipient_in_allowlist

    def test_engine_class_attributes_still_expose_the_amount_tables(self) -> None:
        assert PolicyEngine.AMOUNT_FIELDS == ("amount", "amount_usd", "value", "total")
        assert set(PolicyEngine.AMOUNT_REQUIRED_ACTIONS) == {"financial_transaction"}
        assert PolicyEngine.AMOUNT_FIELDS is AMOUNT_FIELDS
        assert PolicyEngine.AMOUNT_REQUIRED_ACTIONS is AMOUNT_REQUIRED_ACTIONS

    def test_the_amount_experiment_membership_is_unchanged(self) -> None:
        """Widening this set would change behaviour for live action types."""
        assert set(AMOUNT_REQUIRED_ACTIONS) == {"financial_transaction"}

    def test_extract_amount_is_still_callable_as_an_engine_method(self) -> None:
        """api/legacy_main.py computes its reservation amount through this."""
        assert PolicyEngine()._extract_amount({"amount": "12.50"}) == Decimal("12.50")
        assert PolicyEngine()._extract_amount({}) is None
        with pytest.raises(AmountError):
            PolicyEngine()._extract_amount({"amount": "NaN"})

    def test_violation_codes_are_unchanged(self) -> None:
        assert {violation.value for violation in PolicyViolation} == {
            "agent_not_active",
            "action_not_allowed",
            "action_blocked",
            "daily_limit_exceeded",
            "per_action_limit_exceeded",
            "rate_limit_exceeded",
            "trust_score_too_low",
            "timestamp_invalid",
            "amount_invalid",
            "policy_hash_mismatch",
            "action_type_downgrade",
            "action_type_unknown",
            "wallet_chain_not_allowed",
            "wallet_recipient_not_allowed",
            "wallet_recipient_required",
            "wallet_policy_invalid",
        }


class TestEngineHasNoDuplicateCheckMethods:
    """This repo has previously suffered a silent Python method override.

    A second ``def _check_x`` in the same class body replaces the first
    with no error and no warning, so a check can stop running while every
    call site still reads as if it does.
    """

    def _class_body(self, cls: type) -> ast.ClassDef:
        source = Path(inspect.getfile(cls)).read_text(encoding="utf-8")
        for node in ast.parse(source).body:
            if isinstance(node, ast.ClassDef) and node.name == cls.__name__:
                return node
        raise AssertionError(f"{cls.__name__} not found in its own module")

    def test_policy_engine_defines_each_method_once(self) -> None:
        names = [
            node.name
            for node in self._class_body(PolicyEngine).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        duplicates = [name for name, count in Counter(names).items() if count > 1]
        assert not duplicates, f"PolicyEngine defines these more than once: {duplicates}"

    def test_policy_engine_still_defines_every_check_it_dispatches(self) -> None:
        names = {
            node.name
            for node in self._class_body(PolicyEngine).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert {
            "_check_agent_status",
            "_check_action_allowed",
            "_check_action_registered",
            "_check_policy_binding",
            "_check_trust_score",
            "_check_wallet_policy",
            "_check_timestamp",
            "_check_rate_limits",
            "_check_spending_limits",
            "_extract_amount",
            "_compute_limits_remaining",
        } <= names

    def test_the_payment_domain_defines_each_function_once(self) -> None:
        from api.domains.payment import policy as payment_policy

        source = Path(inspect.getfile(payment_policy)).read_text(encoding="utf-8")
        names = [
            node.name
            for node in ast.parse(source).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        duplicates = [name for name, count in Counter(names).items() if count > 1]
        assert not duplicates, f"payment domain defines these more than once: {duplicates}"


class TestVerifyCompatibilityApproved:
    """Representative approved requests, unchanged by the split."""

    def test_a_financial_transaction_within_limits_is_approved(self) -> None:
        result = evaluate(agent(), "financial_transaction", {"amount": "10.00"})
        assert result.allowed is True
        assert result.verdict == ActionVerdict.APPROVED
        assert result.violation is None

    def test_an_approved_result_still_carries_limits_remaining(self) -> None:
        result = evaluate(agent(), "financial_transaction", {"amount": "10.00"})
        assert result.limits_remaining == {
            "daily_limit_usd": "1000",
            "daily_spent_usd": "10.00",
            "daily_remaining_usd": "990.00",
            "per_action_limit_usd": "100",
            "rate_limit_per_minute": 60,
            "rate_limit_used_this_minute": 1,
        }

    def test_an_amountless_api_call_is_approved(self) -> None:
        result = evaluate(agent(), "api_call", {"operation": "read"})
        assert result.allowed is True
        assert result.verdict == ActionVerdict.APPROVED

    def test_a_wallet_transaction_with_no_wallet_policy_is_approved(self) -> None:
        result = evaluate(
            agent(), "wallet_transaction", {"chain": CHAIN, "recipient": UNKNOWN_RECIPIENT}
        )
        assert result.allowed is True


class TestVerifyCompatibilityDenied:
    """Representative denied requests: verdict, code and reason all pinned."""

    def test_per_action_limit_reason_string_is_unchanged(self) -> None:
        result = evaluate(agent(), "financial_transaction", {"amount": "500.00"})
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation is PolicyViolation.PER_ACTION_LIMIT_EXCEEDED
        assert result.reason == "Amount $500.00 exceeds per-action limit of $100."

    def test_daily_limit_reason_string_is_unchanged(self) -> None:
        result = evaluate(
            agent(),
            "financial_transaction",
            {"amount": "50.00"},
            daily_spend=Decimal("980"),
        )
        assert result.violation is PolicyViolation.DAILY_LIMIT_EXCEEDED
        assert result.reason == "Amount $50.00 would exceed daily limit. Remaining: $20."

    def test_a_financial_transaction_without_an_amount_fails_closed(self) -> None:
        result = evaluate(agent(), "financial_transaction", {"note": "no amount"})
        assert result.violation is PolicyViolation.AMOUNT_INVALID
        assert result.reason == (
            "Action 'financial_transaction' requires a numeric spend amount "
            "(one of: amount, amount_usd, value, total)."
        )

    def test_a_malformed_amount_reason_string_is_unchanged(self) -> None:
        result = evaluate(agent(), "financial_transaction", {"amount": "NaN"})
        assert result.violation is PolicyViolation.AMOUNT_INVALID
        assert result.reason == "Field 'amount' must be a finite amount (got 'NaN')."

    def test_an_unregistered_action_type_still_denies(self) -> None:
        result = evaluate(
            agent(allowed_actions=["wallet_transactions"]),
            "wallet_transactions",
            {},
        )
        assert result.violation is PolicyViolation.ACTION_TYPE_UNKNOWN

    def test_a_blocked_action_still_denies(self) -> None:
        result = evaluate(
            agent(blocked_actions=["financial_transaction"]),
            "financial_transaction",
            {"amount": "1.00"},
        )
        assert result.violation is PolicyViolation.ACTION_BLOCKED

    def test_a_low_trust_score_still_denies(self) -> None:
        result = evaluate(agent(trust_score=5), "financial_transaction", {"amount": "1.00"})
        assert result.violation is PolicyViolation.TRUST_SCORE_TOO_LOW

    def test_wallet_recipient_reason_string_is_unchanged(self) -> None:
        subject = agent(
            metadata={
                "wallet_policy": {
                    "allowed_chains": [CHAIN],
                    "allowed_recipients": {CHAIN: [APPROVED_RECIPIENT]},
                }
            }
        )
        result = evaluate(
            subject, "wallet_transaction", {"chain": CHAIN, "recipient": UNKNOWN_RECIPIENT}
        )
        assert result.violation is PolicyViolation.WALLET_RECIPIENT_NOT_ALLOWED
        assert result.reason == (
            f"Recipient '{UNKNOWN_RECIPIENT}' is not in the allowlist configured for "
            f"chain '{CHAIN}'."
        )

    def test_an_invalid_wallet_policy_still_blocks_every_wallet_action(self) -> None:
        subject = agent(metadata={"wallet_policy": {"allowed_chains": []}})
        for action_type in ("wallet_transaction", "wallet_signature"):
            result = evaluate(subject, action_type, {"chain": CHAIN})
            assert result.violation is PolicyViolation.WALLET_POLICY_INVALID


class TestAllowedRecipientsProvisioningTrap:
    """Documented, deliberately preserved. Not a bug to be tidied away.

    ``allowed_recipients`` is keyed by chain. A key configured for one
    chain imposes no recipient restriction on a different chain — only
    ``allowed_chains`` decides whether that other chain may be used at
    all. An operator who assumes otherwise has not restricted what they
    think they restricted.
    """

    def test_a_chain_key_does_not_restrict_a_different_chain(self) -> None:
        subject = agent(
            metadata={
                "wallet_policy": {
                    "allowed_chains": [CHAIN, OTHER_CHAIN],
                    # Recipients constrained on CHAIN only.
                    "allowed_recipients": {CHAIN: [APPROVED_RECIPIENT]},
                }
            }
        )
        constrained = evaluate(
            subject, "wallet_transaction", {"chain": CHAIN, "recipient": UNKNOWN_RECIPIENT}
        )
        assert constrained.violation is PolicyViolation.WALLET_RECIPIENT_NOT_ALLOWED

        # THE TRAP: the same unknown recipient is permitted on the other
        # chain, because no allowlist is keyed for it.
        unconstrained = evaluate(
            subject,
            "wallet_transaction",
            {"chain": OTHER_CHAIN, "recipient": UNKNOWN_RECIPIENT},
        )
        assert unconstrained.allowed is True

    def test_the_helper_reports_no_allowlist_for_an_unkeyed_chain(self) -> None:
        from api.domains.payment.wallet import chain_allowlist_for

        allowed_recipients = {CHAIN: [APPROVED_RECIPIENT]}
        assert chain_allowlist_for(allowed_recipients, CHAIN) == [APPROVED_RECIPIENT]
        assert chain_allowlist_for(allowed_recipients, OTHER_CHAIN) is None

    def test_evm_recipient_matching_is_still_case_insensitive(self) -> None:
        assert recipient_in_allowlist(CHAIN, APPROVED_RECIPIENT.upper(), [APPROVED_RECIPIENT])
        assert recipient_in_allowlist(CHAIN, APPROVED_RECIPIENT, [APPROVED_RECIPIENT.upper()])

    def test_non_evm_recipient_matching_is_still_exact(self) -> None:
        assert recipient_in_allowlist("solana:mainnet", "AbCd", ["AbCd"]) is True
        assert recipient_in_allowlist("solana:mainnet", "abcd", ["AbCd"]) is False

    def test_the_wallet_policy_validator_still_rejects_the_same_shapes(self) -> None:
        assert validate_wallet_policy({"allowed_chains": [CHAIN]}) == ([CHAIN], None)
        with pytest.raises(WalletPolicyError):
            validate_wallet_policy({"allowed_chains": {}})
        with pytest.raises(WalletPolicyError):
            validate_wallet_policy({"allowed_recipients": {CHAIN: "not-a-list"}})


class TestSpendLimitsStillApplyBeyondPayment:
    """The trap this refactor could most easily have walked into.

    Spend limits are not payment-only. Any action type carrying an amount
    was subject to the organisation's caps before the split. Moving the
    implementation into the payment domain must not narrow *when* it runs.
    """

    @pytest.mark.parametrize(
        "action_type", ["email_send", "api_call", "tool_call", "data_export", "admin_action"]
    )
    def test_a_non_payment_action_with_an_amount_is_still_capped(self, action_type: str) -> None:
        result = evaluate(agent(), action_type, {"amount": "500.00"})
        assert result.violation is PolicyViolation.PER_ACTION_LIMIT_EXCEEDED

    @pytest.mark.parametrize("action_type", ["email_send", "api_call", "data_export"])
    def test_a_non_payment_action_still_hits_the_daily_cap(self, action_type: str) -> None:
        result = evaluate(agent(), action_type, {"amount": "50.00"}, daily_spend=Decimal("980"))
        assert result.violation is PolicyViolation.DAILY_LIMIT_EXCEEDED

    @pytest.mark.parametrize("action_type", ["email_send", "api_call", "tool_call"])
    def test_a_malformed_amount_still_fails_closed_outside_payment(self, action_type: str) -> None:
        result = evaluate(agent(), action_type, {"amount": "-1"})
        assert result.violation is PolicyViolation.AMOUNT_INVALID

    def test_a_non_payment_action_without_an_amount_is_still_not_required_to_have_one(
        self,
    ) -> None:
        assert evaluate(agent(), "email_send", {"to": "x@example.com"}).allowed is True

    def test_the_engine_dispatches_spend_without_consulting_the_domain_table(self) -> None:
        """The dispatch is not gated on the action type being a payment one."""
        from api.domains.payment.policy import PAYMENT_ACTION_TYPES

        assert "email_send" not in PAYMENT_ACTION_TYPES
        assert evaluate(agent(), "email_send", {"amount": "500.00"}).allowed is False


class TestEngineKeepsGeneralConcerns:
    def test_trust_thresholds_are_unchanged(self) -> None:
        assert PolicyEngine.TRUST_THRESHOLDS == {
            "financial_transaction": 30,
            "wallet_transaction": 30,
            "wallet_signature": 30,
            "email_send": 20,
            "api_call": 10,
            "tool_call": 10,
            "data_export": 40,
            "admin_action": 70,
            "ci_workflow_change": 80,
            "protected_branch_merge": 80,
            "production_deployment": 80,
        }

    def test_attestation_actions_are_unchanged(self) -> None:
        assert set(PolicyEngine.ATTESTATION_ACTIONS) == {"promptfoo_eval", "repo_change"}

    def test_registration_gate_and_thresholds_stay_on_the_engine(self) -> None:
        engine_source = Path(inspect.getfile(PolicyEngine)).read_text(encoding="utf-8")
        assert "KNOWN_ACTION_TYPES" in engine_source
        assert "TRUST_THRESHOLDS" in engine_source

    def test_payment_rules_no_longer_live_in_the_engine_module(self) -> None:
        engine_source = Path(inspect.getfile(PolicyEngine)).read_text(encoding="utf-8")
        assert "def validate_wallet_policy" not in engine_source
        assert "def recipient_in_allowlist" not in engine_source
        assert "class AmountError" not in engine_source
