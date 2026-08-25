"""G1.3: unknown action types must fail closed.

The defect these tests pin is not wallet-shaped. ``TRUST_THRESHOLDS`` is keyed
by exact action-type string and was read with a permissive fallback::

    threshold = self.TRUST_THRESHOLDS.get(action_type, 20)

so any string absent from the table was gated at 20 — *lower* than every
runtime action the table actually names except ``api_call``/``tool_call``.
Combined with ``allowed_actions`` being an unvalidated ``list[str]``, a single
admin typo (``wallet_transactions``, plural) minted a live action type that
approved at trust 20 with no spend check, because ``AMOUNT_REQUIRED_ACTIONS``
names only ``financial_transaction``.

An unregistered action type must now be denied outright rather than defaulted.
"""
from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest
from pydantic import ValidationError

from api.models import ActionVerdict, AgentRecord, AgentStatus
from api.policy import KNOWN_ACTION_TYPES, PolicyEngine, PolicyViolation


def _agent(allowed_actions, trust_score=50, metadata=None):
    return AgentRecord(
        id=uuid4(),
        org_id=uuid4(),
        name="test",
        public_key=b"\x00" * 32,
        public_key_fingerprint="a" * 64,
        trust_score=trust_score,
        status=AgentStatus.ACTIVE,
        daily_limit_usd=Decimal("1000"),
        per_action_limit_usd=Decimal("100"),
        allowed_actions=allowed_actions,
        blocked_actions=[],
        rate_limit_per_minute=60,
        last_action_at=None,
        total_actions_count=0,
        total_blocked_count=0,
        metadata=metadata if metadata is not None else {},
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


class TestUnknownActionTypeFailsClosed:
    """Test 1 and 2 of the gate: the class fix."""

    def test_unknown_action_type_denied_even_when_allowlisted(self):
        """Test 1: an invented action type must never approve by default.

        The agent is allowlisted for it and carries trust 50 — comfortably
        over the old permissive fallback of 20 — so the only thing that can
        deny this is the registry check itself.
        """
        engine = PolicyEngine()
        agent = _agent(allowed_actions=["totally_unknown_action"], trust_score=50)

        result = engine.evaluate(
            agent=agent,
            action_type="totally_unknown_action",
            payload={},
            timestamp=datetime.now(UTC),
        )

        assert result.verdict == ActionVerdict.BLOCKED, (
            f"Unregistered action type approved: {result.reason}"
        )
        assert result.allowed is False
        assert result.violation == PolicyViolation.ACTION_TYPE_UNKNOWN

    def test_admin_typo_plural_wallet_transactions_denied(self):
        """Test 2: registered but absent from TRUST_THRESHOLDS → denied.

        This is the production condition in full: a plural typo, maximum trust,
        and no amount field — which under the old code skipped
        ``_check_spending_limits`` entirely and landed on APPROVED.
        """
        engine = PolicyEngine()
        agent = _agent(allowed_actions=["wallet_transactions"], trust_score=100)

        result = engine.evaluate(
            agent=agent,
            action_type="wallet_transactions",
            payload={"recipient": "0xattacker", "amount": "999999"},
            timestamp=datetime.now(UTC),
        )

        assert result.verdict == ActionVerdict.BLOCKED, (
            f"Admin typo minted a live approving action type: {result.reason}"
        )
        assert result.violation == PolicyViolation.ACTION_TYPE_UNKNOWN, (
            "Typo'd action must be rejected as unregistered, not merely "
            f"gated at the old default of 20 (got {result.violation})"
        )


class TestKnownActionTypesStillWork:
    """Guards: flipping the default must not deny traffic that works today."""

    @pytest.mark.parametrize("action_type", sorted(PolicyEngine.ATTESTATION_ACTIONS))
    def test_attestation_actions_still_pass_through(self, action_type):
        """Attestation actions are absent from TRUST_THRESHOLDS by design."""
        engine = PolicyEngine()
        agent = _agent(allowed_actions=[action_type], trust_score=0)

        result = engine.evaluate(
            agent=agent,
            action_type=action_type,
            payload={},
            timestamp=datetime.now(UTC),
        )

        assert result.verdict == ActionVerdict.APPROVED, (
            f"Attestation action {action_type} regressed: {result.reason}"
        )

    @pytest.mark.parametrize(
        "action_type",
        sorted(set(PolicyEngine.TRUST_THRESHOLDS) - {"wallet_transaction"}),
    )
    def test_registered_runtime_actions_still_approve_at_full_trust(self, action_type):
        """Every named runtime action still approves for a maxed-trust agent."""
        engine = PolicyEngine()
        agent = _agent(allowed_actions=[action_type], trust_score=100)

        result = engine.evaluate(
            agent=agent,
            action_type=action_type,
            payload={"amount": "1.00"},
            timestamp=datetime.now(UTC),
        )

        assert result.verdict == ActionVerdict.APPROVED, (
            f"Registered action {action_type} regressed: {result.reason}"
        )


class TestRegistryInvariant:
    """KNOWN_ACTION_TYPES is what the admin schema validates against."""

    def test_registry_is_exactly_the_two_policy_tables(self):
        from_tables = (
            frozenset(PolicyEngine.TRUST_THRESHOLDS)
            | PolicyEngine.ATTESTATION_ACTIONS
        )
        assert from_tables == KNOWN_ACTION_TYPES, (
            "A new action type was added to a policy table without reaching "
            "KNOWN_ACTION_TYPES, or vice versa. Both must move together or "
            "the schema layer and the engine disagree about what is real."
        )


class TestSchemaLayerRejectsUnknownActions:
    """The write path must not admit an action type the engine cannot govern.

    Validation lives on the request models in ``api/models.py``, not on the
    response models in ``api/schemas/admin.py`` — validating a read model would
    make existing rows carrying a stale action type unreadable.
    """

    def test_register_rejects_unknown_action(self):
        from api.models import RegisterAgentRequest

        with pytest.raises(ValidationError, match="unknown action types"):
            RegisterAgentRequest(
                org_id=uuid4(),
                name="typo-agent",
                public_key="0" * 64,
                allowed_actions=["wallet_transactions"],
            )

    def test_update_rejects_unknown_action(self):
        from api.models import UpdateAgentRequest

        with pytest.raises(ValidationError, match="unknown action types"):
            UpdateAgentRequest(allowed_actions=["wallet_transactions"])

    def test_register_accepts_registered_actions(self):
        from api.models import RegisterAgentRequest

        request = RegisterAgentRequest(
            org_id=uuid4(),
            name="wallet-agent",
            public_key="0" * 64,
            allowed_actions=["wallet_transaction", "financial_transaction"],
        )
        assert request.allowed_actions == [
            "wallet_transaction",
            "financial_transaction",
        ]

    def test_update_normalizes_case_and_whitespace(self):
        from api.models import UpdateAgentRequest

        request = UpdateAgentRequest(allowed_actions=["  Wallet_Transaction  "])
        assert request.allowed_actions == ["wallet_transaction"]

    def test_blocked_actions_may_name_unregistered_types(self):
        """Blocklisting a string the engine doesn't know is harmless."""
        from api.models import UpdateAgentRequest

        request = UpdateAgentRequest(blocked_actions=["some_future_action"])
        assert request.blocked_actions == ["some_future_action"]
