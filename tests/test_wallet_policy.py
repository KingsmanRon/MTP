"""Wallet transaction policy: recipient allowlisting, enforced at /verify.

``_check_wallet_policy`` is invoked from ``PolicyEngine.evaluate()`` alongside
the other checks, and ``evaluate()`` is what ``verify_action`` calls
(api/main.py:1987) — so the check sits on the ``/verify`` path by construction
rather than being defined and never reached.

Absence is denial throughout: no ``metadata.wallet_policy``, no recipient in
the payload, and an empty allowlist all block. There is no configuration of
this feature under which an unrecognised recipient is approved.
"""
from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

from api.models import ActionVerdict, AgentRecord, AgentStatus
from api.policy import PolicyEngine, PolicyViolation

GOOD_RECIPIENT = "0x1111111111111111111111111111111111111111"
BAD_RECIPIENT = "0x2222222222222222222222222222222222222222"


def _wallet_agent(trust_score=50, metadata=None):
    return AgentRecord(
        id=uuid4(),
        org_id=uuid4(),
        name="wallet-agent",
        public_key=b"\x00" * 32,
        public_key_fingerprint="a" * 64,
        trust_score=trust_score,
        status=AgentStatus.ACTIVE,
        daily_limit_usd=Decimal("1000"),
        per_action_limit_usd=Decimal("100"),
        allowed_actions=["wallet_transaction"],
        blocked_actions=[],
        rate_limit_per_minute=60,
        last_action_at=None,
        total_actions_count=0,
        total_blocked_count=0,
        metadata=metadata if metadata is not None else {},
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _evaluate(agent, payload):
    return PolicyEngine().evaluate(
        agent=agent,
        action_type="wallet_transaction",
        payload=payload,
        timestamp=datetime.now(UTC),
    )


class TestWalletPolicyRequired:
    """Test 3: the one that matters most — absence must deny."""

    def test_missing_wallet_policy_denies_rather_than_approves(self):
        """No metadata.wallet_policy at all → BLOCKED, never APPROVED."""
        agent = _wallet_agent(metadata={})

        result = _evaluate(agent, {"recipient": GOOD_RECIPIENT, "amount": "1.00"})

        assert result.verdict == ActionVerdict.BLOCKED, (
            f"Missing wallet_policy fell through to approval: {result.reason}"
        )
        assert result.allowed is False
        assert result.violation == PolicyViolation.WALLET_POLICY_MISSING

    def test_wallet_policy_without_allowlist_denies(self):
        """A wallet_policy that names no recipients approves nobody."""
        agent = _wallet_agent(metadata={"wallet_policy": {}})

        result = _evaluate(agent, {"recipient": GOOD_RECIPIENT, "amount": "1.00"})

        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_POLICY_MISSING

    def test_empty_allowlist_denies(self):
        agent = _wallet_agent(
            metadata={"wallet_policy": {"allowed_recipients": []}}
        )

        result = _evaluate(agent, {"recipient": GOOD_RECIPIENT, "amount": "1.00"})

        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_RECIPIENT_NOT_ALLOWED

    def test_missing_recipient_in_payload_denies(self):
        """A wallet transaction with no recipient field cannot be allowlisted."""
        agent = _wallet_agent(
            metadata={"wallet_policy": {"allowed_recipients": [GOOD_RECIPIENT]}}
        )

        result = _evaluate(agent, {"amount": "1.00"})

        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_RECIPIENT_NOT_ALLOWED


class TestRecipientAllowlist:
    """Tests 4 and 5, and Gate 1 as written."""

    def test_non_allowlisted_recipient_denied(self):
        """Test 4 / Gate 1: the violation is wallet_recipient_not_allowed."""
        agent = _wallet_agent(
            metadata={"wallet_policy": {"allowed_recipients": [GOOD_RECIPIENT]}}
        )

        result = _evaluate(agent, {"recipient": BAD_RECIPIENT, "amount": "1.00"})

        assert result.verdict == ActionVerdict.BLOCKED, (
            f"Non-allowlisted recipient approved: {result.reason}"
        )
        assert result.violation == PolicyViolation.WALLET_RECIPIENT_NOT_ALLOWED
        assert result.violation.value == "wallet_recipient_not_allowed", (
            "Gate 1 checks the wire string, not just the enum member"
        )

    def test_allowlisted_recipient_approved(self):
        """Test 5: the happy path still works once everything is in place."""
        agent = _wallet_agent(
            metadata={
                "wallet_policy": {
                    "allowed_recipients": [BAD_RECIPIENT, GOOD_RECIPIENT]
                }
            }
        )

        result = _evaluate(agent, {"recipient": GOOD_RECIPIENT, "amount": "1.00"})

        assert result.verdict == ActionVerdict.APPROVED, (
            f"Allowlisted recipient denied: {result.reason}"
        )
        assert result.allowed is True


class TestTrustThresholdIsReused:
    """trust_score >= 30 comes from TRUST_THRESHOLDS, not a second copy."""

    def test_wallet_transaction_threshold_is_registered_as_30(self):
        assert PolicyEngine.TRUST_THRESHOLDS["wallet_transaction"] == 30

    def test_trust_29_denied_by_the_shared_trust_check(self):
        agent = _wallet_agent(
            trust_score=29,
            metadata={"wallet_policy": {"allowed_recipients": [GOOD_RECIPIENT]}},
        )

        result = _evaluate(agent, {"recipient": GOOD_RECIPIENT, "amount": "1.00"})

        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.TRUST_SCORE_TOO_LOW, (
            "The wallet path must reuse _check_trust_score, not reimplement it"
        )
