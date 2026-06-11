"""Tests for strict, fail-closed amount extraction in the policy engine.

Regression for the spend-limit bypass: a financial action whose amount field
was missing, malformed, NaN, infinite, or negative previously slipped through
the spend checks (returning None → no check, or NaN → every comparison False).
"""
from datetime import datetime, timezone
from decimal import Decimal
from uuid import uuid4

import pytest

from api.models import ActionVerdict, AgentRecord, AgentStatus
from api.policy import AmountError, PolicyEngine, PolicyViolation


def _agent(trust_score=50, daily=Decimal("1000"), per_action=Decimal("100")):
    return AgentRecord(
        id=uuid4(),
        org_id=uuid4(),
        name="test",
        public_key=b"\x00" * 32,
        public_key_fingerprint="a" * 64,
        trust_score=trust_score,
        status=AgentStatus.ACTIVE,
        daily_limit_usd=daily,
        per_action_limit_usd=per_action,
        allowed_actions=["financial_transaction", "email_send", "api_call"],
        blocked_actions=[],
        rate_limit_per_minute=60,
        last_action_at=None,
        total_actions_count=0,
        total_blocked_count=0,
        metadata={},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def _evaluate(payload, action_type="financial_transaction", **agent_kwargs):
    engine = PolicyEngine()
    return engine.evaluate(
        agent=_agent(**agent_kwargs),
        action_type=action_type,
        payload=payload,
        timestamp=datetime.now(timezone.utc),
    )


class TestExtractAmount:
    def test_valid_amount_returns_decimal(self):
        assert PolicyEngine()._extract_amount({"amount": "50.00"}) == Decimal("50.00")

    def test_priority_order_first_field_wins(self):
        # amount beats value/total
        assert PolicyEngine()._extract_amount(
            {"value": 999, "amount": 5}
        ) == Decimal("5")

    def test_missing_amount_returns_none(self):
        assert PolicyEngine()._extract_amount({"description": "no money here"}) is None

    @pytest.mark.parametrize("bad", ["NaN", "Infinity", "-Infinity"])
    def test_non_finite_raises(self, bad):
        with pytest.raises(AmountError):
            PolicyEngine()._extract_amount({"amount": bad})

    def test_negative_raises(self):
        with pytest.raises(AmountError):
            PolicyEngine()._extract_amount({"amount": "-1"})

    def test_unparseable_raises(self):
        with pytest.raises(AmountError):
            PolicyEngine()._extract_amount({"amount": "fifty bucks"})

    def test_boolean_raises(self):
        with pytest.raises(AmountError):
            PolicyEngine()._extract_amount({"amount": True})


class TestEvaluateFailsClosed:
    def test_financial_without_amount_is_blocked(self):
        result = _evaluate({"description": "pay someone"})
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.AMOUNT_INVALID

    def test_financial_with_nan_is_blocked(self):
        result = _evaluate({"amount": "NaN"})
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.AMOUNT_INVALID

    def test_financial_with_negative_is_blocked(self):
        result = _evaluate({"amount": -500})
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.AMOUNT_INVALID

    def test_unrecognized_amount_field_does_not_bypass(self):
        # "amt" is not a recognized field → financial_transaction has no
        # parseable amount → fail closed (previously this returned APPROVED
        # with zero spend accounting).
        result = _evaluate({"amt": 50000})
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.AMOUNT_INVALID

    def test_valid_financial_within_limits_approved(self):
        result = _evaluate({"amount": "50"})
        assert result.verdict == ActionVerdict.APPROVED

    def test_over_per_action_limit_blocked(self):
        result = _evaluate({"amount": "150"}, per_action=Decimal("100"))
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.PER_ACTION_LIMIT_EXCEEDED

    def test_non_financial_action_without_amount_is_fine(self):
        # email_send carries no amount and does not require one.
        result = _evaluate({"recipient": "a@b.com"}, action_type="email_send")
        assert result.verdict == ActionVerdict.APPROVED
