"""Tests for F7: attestation vs runtime action type semantics."""
from datetime import datetime, timezone
from decimal import Decimal
from uuid import uuid4

from api.models import ActionVerdict, AgentRecord, AgentStatus
from api.policy import PolicyEngine


def _agent(allowed_actions=None, trust_score=50, status=AgentStatus.ACTIVE):
    return AgentRecord(
        id=uuid4(),
        org_id=uuid4(),
        name="test",
        public_key=b"\x00" * 32,
        public_key_fingerprint="a" * 64,
        trust_score=trust_score,
        status=status,
        daily_limit_usd=Decimal("1000"),
        per_action_limit_usd=Decimal("100"),
        allowed_actions=allowed_actions or [
            "tool_call", "promptfoo_eval", "repo_change",
            "data_export", "admin_action", "financial_transaction",
            "email_send", "api_call",
        ],
        blocked_actions=[],
        rate_limit_per_minute=60,
        last_action_at=None,
        total_actions_count=0,
        total_blocked_count=0,
        metadata={},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


class TestAttestationActions:
    def test_promptfoo_eval_approved_regardless_of_trust_score(self):
        """Attestation actions pass through even with trust_score=0."""
        engine = PolicyEngine()
        agent = _agent(trust_score=0)
        result = engine.evaluate(
            agent=agent,
            action_type="promptfoo_eval",
            payload={},
            timestamp=datetime.now(timezone.utc),
        )
        assert result.verdict == ActionVerdict.APPROVED, (
            f"Expected APPROVED, got {result.verdict}: {result.reason}"
        )

    def test_repo_change_approved_regardless_of_trust_score(self):
        engine = PolicyEngine()
        agent = _agent(trust_score=0)
        result = engine.evaluate(
            agent=agent,
            action_type="repo_change",
            payload={},
            timestamp=datetime.now(timezone.utc),
        )
        assert result.verdict == ActionVerdict.APPROVED


class TestRuntimeActions:
    def test_tool_call_threshold_is_10(self):
        """tool_call needs trust_score >= 10."""
        engine = PolicyEngine()
        agent_low = _agent(trust_score=5)
        result = engine.evaluate(
            agent=agent_low,
            action_type="tool_call",
            payload={},
            timestamp=datetime.now(timezone.utc),
        )
        assert result.verdict == ActionVerdict.BLOCKED

        agent_ok = _agent(trust_score=10)
        result = engine.evaluate(
            agent=agent_ok,
            action_type="tool_call",
            payload={},
            timestamp=datetime.now(timezone.utc),
        )
        assert result.verdict == ActionVerdict.APPROVED

    def test_admin_action_threshold_is_70(self):
        """admin_action needs trust_score >= 70."""
        engine = PolicyEngine()
        agent_low = _agent(trust_score=50)
        result = engine.evaluate(
            agent=agent_low,
            action_type="admin_action",
            payload={},
            timestamp=datetime.now(timezone.utc),
        )
        assert result.verdict == ActionVerdict.BLOCKED

        agent_ok = _agent(trust_score=70)
        result = engine.evaluate(
            agent=agent_ok,
            action_type="admin_action",
            payload={},
            timestamp=datetime.now(timezone.utc),
        )
        assert result.verdict == ActionVerdict.APPROVED

    def test_data_export_threshold_is_40(self):
        """data_export is a runtime action — threshold remains 40."""
        engine = PolicyEngine()
        agent = _agent(trust_score=10)
        result = engine.evaluate(
            agent=agent,
            action_type="data_export",
            payload={},
            timestamp=datetime.now(timezone.utc),
        )
        assert result.verdict == ActionVerdict.BLOCKED
