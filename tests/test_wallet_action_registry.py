"""The seam between the action-type registry and the wallet policy layer.

Two independently-developed changes meet here: the class fail-open fix, which
denies any action type absent from ``KNOWN_ACTION_TYPES``, and the WalletConnect
CWP wallet policy, which adds two such types. Neither change tests the other,
so the interaction between them is covered here rather than in either
inherited file.

The property that matters: the wallet action types are registered *derivatively*
— ``KNOWN_ACTION_TYPES`` is built from ``TRUST_THRESHOLDS | ATTESTATION_ACTIONS``,
so declaring a threshold is what registers an action. A future wallet action
added to the threshold table is registered by construction, and one added to
neither table is denied by construction. There is no third list to keep in sync.
"""
from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from api.models import (
    ActionVerdict,
    AgentRecord,
    AgentStatus,
    RegisterAgentRequest,
    UpdateAgentRequest,
)
from api.policy import KNOWN_ACTION_TYPES, PolicyEngine, PolicyViolation

CHAIN = "eip155:8453"
ALLOWED_RECIPIENT = "0x1111111111111111111111111111111111111111"
BLOCKED_RECIPIENT = "0x9999999999999999999999999999999999999999"

WALLET_POLICY = {
    "wallet_policy": {
        "allowed_chains": [CHAIN],
        "allowed_recipients": {CHAIN: [ALLOWED_RECIPIENT]},
    }
}


def _agent(metadata=None, allowed_actions=None, trust_score=60):
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
        allowed_actions=(
            allowed_actions
            if allowed_actions is not None
            else ["wallet_transaction", "wallet_signature"]
        ),
        blocked_actions=[],
        rate_limit_per_minute=60,
        last_action_at=None,
        total_actions_count=0,
        total_blocked_count=0,
        metadata=metadata if metadata is not None else {},
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _evaluate(agent, action_type="wallet_transaction", payload=None):
    return PolicyEngine().evaluate(
        agent=agent,
        action_type=action_type,
        payload=(
            payload
            if payload is not None
            else {"chain": CHAIN, "recipient": ALLOWED_RECIPIENT}
        ),
        timestamp=datetime.now(UTC),
    )


class TestWalletActionsAreRegistered:
    """Both wallet action types must survive the registry gate."""

    @pytest.mark.parametrize("action_type", ["wallet_transaction", "wallet_signature"])
    def test_wallet_action_is_a_known_action_type(self, action_type):
        assert action_type in KNOWN_ACTION_TYPES

    @pytest.mark.parametrize("action_type", ["wallet_transaction", "wallet_signature"])
    def test_registration_is_derived_from_the_threshold_table(self, action_type):
        # Not a hand-maintained third list: declaring a trust threshold is what
        # registers an action type. This is why adding wallet_signature to
        # TRUST_THRESHOLDS was sufficient to register it.
        assert action_type in PolicyEngine.TRUST_THRESHOLDS
        assert (
            frozenset(PolicyEngine.TRUST_THRESHOLDS) | PolicyEngine.ATTESTATION_ACTIONS
        ) == KNOWN_ACTION_TYPES

    @pytest.mark.parametrize("action_type", ["wallet_transaction", "wallet_signature"])
    def test_registered_wallet_action_passes_the_registry_gate(self, action_type):
        # The gate the class fix added must not deny a legitimate wallet action.
        assert (
            PolicyEngine()._check_action_registered(action_type).verdict
            == ActionVerdict.APPROVED
        )


class TestWalletTypoStillFailsClosed:
    """The defect the class fix exists for, on the wallet rail specifically."""

    def test_plural_typo_is_not_registered(self):
        assert "wallet_transactions" not in KNOWN_ACTION_TYPES

    def test_plural_typo_is_denied_even_when_the_agent_allows_it(self):
        # An agent created through database.create_agent bypasses the request
        # models, so allowed_actions can still carry a typo. The engine's
        # registry check is what catches it. Without the class fix this
        # approved at an invented threshold of 20 with no spend check.
        agent = _agent(
            metadata=WALLET_POLICY, allowed_actions=["wallet_transactions"]
        )

        result = _evaluate(agent, action_type="wallet_transactions")

        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.ACTION_TYPE_UNKNOWN

    def test_registry_gate_precedes_the_wallet_check(self):
        # An unregistered type must be rejected before the wallet layer is
        # consulted, so an unknown action can never be answered with a
        # wallet-shaped verdict that implies the engine understood it.
        agent = _agent(
            metadata=WALLET_POLICY, allowed_actions=["wallet_transactions"]
        )

        result = _evaluate(
            agent,
            action_type="wallet_transactions",
            payload={"chain": CHAIN, "recipient": BLOCKED_RECIPIENT},
        )

        assert result.violation == PolicyViolation.ACTION_TYPE_UNKNOWN, (
            "an unregistered action type must not reach the recipient allowlist"
        )


class TestAdmissionAcceptsWalletActions:
    """The write-path registry validator must admit the wallet action types."""

    def test_update_request_accepts_both_wallet_actions(self):
        request = UpdateAgentRequest(
            allowed_actions=["wallet_transaction", "wallet_signature"]
        )
        assert request.allowed_actions == ["wallet_transaction", "wallet_signature"]

    def test_register_request_accepts_both_wallet_actions(self):
        request = RegisterAgentRequest(
            org_id=uuid4(),
            name="wallet-agent",
            public_key="A" * 43 + "=",
            allowed_actions=["wallet_transaction", "wallet_signature"],
        )
        assert request.allowed_actions == ["wallet_transaction", "wallet_signature"]

    def test_update_request_rejects_the_plural_typo(self):
        with pytest.raises(ValueError, match="wallet_transactions"):
            UpdateAgentRequest(allowed_actions=["wallet_transactions"])

    def test_wallet_policy_and_allowed_actions_validate_together(self):
        # Both validators run on the same request: the registry check on
        # allowed_actions and the structural check on metadata.wallet_policy.
        request = UpdateAgentRequest(
            allowed_actions=["wallet_transaction"], metadata=WALLET_POLICY
        )
        assert request.metadata == WALLET_POLICY

    def test_a_malformed_wallet_policy_is_rejected_alongside_valid_actions(self):
        with pytest.raises(ValueError, match="allowed_chains"):
            UpdateAgentRequest(
                allowed_actions=["wallet_transaction"],
                metadata={"wallet_policy": {"allowed_chains": "eip155:8453"}},
            )


class TestOptInSurvivesTheClassFix:
    """The one behaviour the two changes disagreed on.

    The class fix denied a wallet_transaction with no configured wallet policy;
    the wallet layer approves it. The wallet layer's opt-in semantics are the
    ones that must hold after the merge — an agent with no wallet_policy is
    still subject to every generic check, but not to a chain or recipient
    restriction that was never configured.
    """

    def test_absent_wallet_policy_approves(self):
        assert _evaluate(_agent({})).verdict == ActionVerdict.APPROVED

    def test_absent_wallet_policy_still_enforces_trust(self):
        result = _evaluate(_agent({}, trust_score=29))
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.TRUST_SCORE_TOO_LOW

    def test_the_superseded_missing_policy_violation_is_gone(self):
        # WALLET_POLICY_MISSING named the fail-closed-on-absent behaviour that
        # opt-in semantics replace. A violation code that can never be emitted
        # would reach the wire as a documented verdict the engine never
        # returns, so it is removed rather than left dead.
        assert not hasattr(PolicyViolation, "WALLET_POLICY_MISSING")

    def test_configured_policy_still_blocks_a_non_allowlisted_recipient(self):
        result = _evaluate(
            _agent(WALLET_POLICY),
            payload={"chain": CHAIN, "recipient": BLOCKED_RECIPIENT},
        )
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_RECIPIENT_NOT_ALLOWED
        assert result.violation.value == "wallet_recipient_not_allowed", (
            "Gate 1 checks the wire string, not the enum member"
        )


class TestSpendCounterCoversWalletActions:
    """The class fix's observability counter meets the new action types."""

    @pytest.mark.parametrize("action_type", ["wallet_transaction", "wallet_signature"])
    def test_wallet_action_without_an_amount_is_counted_not_blocked(self, action_type):
        # Wallet actions carry no USD amount by design, so they land in the
        # set the counter measures. Counting must not become blocking:
        # AMOUNT_REQUIRED_ACTIONS is deliberately unchanged.
        assert action_type not in PolicyEngine.AMOUNT_REQUIRED_ACTIONS
        assert _evaluate(_agent(WALLET_POLICY), action_type).verdict == (
            ActionVerdict.APPROVED
        )
