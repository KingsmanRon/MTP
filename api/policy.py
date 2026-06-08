"""
Policy Engine for the Inntris Core API.

Evaluates agent actions against configured rules and limits.
"Zero Trust" - Every action is verified against all applicable policies.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Optional

from api.models import AgentRecord, AgentStatus, ActionVerdict

logger = logging.getLogger(__name__)


class PolicyViolation(Enum):
    """Types of policy violations."""
    AGENT_NOT_ACTIVE = "agent_not_active"
    ACTION_NOT_ALLOWED = "action_not_allowed"
    ACTION_BLOCKED = "action_blocked"
    DAILY_LIMIT_EXCEEDED = "daily_limit_exceeded"
    PER_ACTION_LIMIT_EXCEEDED = "per_action_limit_exceeded"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    TRUST_SCORE_TOO_LOW = "trust_score_too_low"
    TIMESTAMP_INVALID = "timestamp_invalid"


@dataclass
class PolicyResult:
    """Result of policy evaluation."""
    allowed: bool
    verdict: ActionVerdict
    violation: Optional[PolicyViolation] = None
    reason: Optional[str] = None
    limits_remaining: Optional[dict[str, Any]] = None


class PolicyEngine:
    """
    Evaluates actions against security policies.

    Philosophy: "Fail Closed" - If any policy check fails or errors,
    the action is blocked.
    """

    # Attestation actions: pass-through semantics.
    # These are logged for auditing but do NOT gate on trust score.
    # They record that something happened (eval, push, export receipt),
    # not that the system is authorizing a live operation.
    ATTESTATION_ACTIONS: frozenset = frozenset({
        "promptfoo_eval",
        "repo_change",
    })

    # Runtime actions: PASS/BLOCK/ESCALATE semantics.
    # The caller is asking the system to authorize a live operation.
    TRUST_THRESHOLDS = {
        "financial_transaction": 30,
        "email_send": 20,
        "api_call": 10,
        "tool_call": 10,
        "data_export": 40,
        "admin_action": 70,
        "ci_workflow_change": 80,
        "protected_branch_merge": 80,
        "production_deployment": 80,
    }

    # Maximum clock skew allowed (seconds)
    MAX_CLOCK_SKEW = 300  # 5 minutes

    def __init__(
        self,
        daily_spend: Decimal = Decimal("0"),
        minute_request_count: int = 0,
    ):
        """
        Initialize policy engine with current limits state.

        Args:
            daily_spend: Current daily spend for the agent.
            minute_request_count: Requests made in the current minute.
        """
        self.daily_spend = daily_spend
        self.minute_request_count = minute_request_count

    def evaluate(
        self,
        agent: AgentRecord,
        action_type: str,
        payload: dict[str, Any],
        timestamp: datetime,
    ) -> PolicyResult:
        """
        Evaluate an action against all applicable policies.

        SECURITY: Policies are evaluated in order of severity.
        The first violation stops evaluation (fail fast).

        Args:
            agent: The agent record from database.
            action_type: Type of action being performed.
            payload: Action payload with details.
            timestamp: Client-provided timestamp.

        Returns:
            PolicyResult with verdict and details.
        """
        # 1. Check agent status (highest priority)
        status_result = self._check_agent_status(agent)
        if not status_result.allowed:
            return status_result

        # 2. Check action is allowed for this agent
        action_result = self._check_action_allowed(agent, action_type)
        if not action_result.allowed:
            return action_result

        # 3. Check trust score threshold
        trust_result = self._check_trust_score(agent, action_type)
        if not trust_result.allowed:
            return trust_result

        # 4. Check timestamp validity
        timestamp_result = self._check_timestamp(timestamp)
        if not timestamp_result.allowed:
            return timestamp_result

        # 5. Check rate limits
        rate_result = self._check_rate_limits(agent)
        if not rate_result.allowed:
            return rate_result

        # 6. Check spending limits (for financial transactions)
        amount = self._extract_amount(payload)
        if amount is not None:
            spend_result = self._check_spending_limits(agent, amount)
            if not spend_result.allowed:
                return spend_result

        # All checks passed
        return PolicyResult(
            allowed=True,
            verdict=ActionVerdict.APPROVED,
            limits_remaining=self._compute_limits_remaining(agent, amount),
        )

    def _check_agent_status(self, agent: AgentRecord) -> PolicyResult:
        """Verify agent is in active status."""
        if agent.status != AgentStatus.ACTIVE:
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.BLOCKED,
                violation=PolicyViolation.AGENT_NOT_ACTIVE,
                reason=f"Agent status is '{agent.status.value}'. Only 'active' agents can perform actions.",
            )
        return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)

    def _check_action_allowed(
        self,
        agent: AgentRecord,
        action_type: str,
    ) -> PolicyResult:
        """Check if action type is allowed for the agent."""
        # Check blocklist first (explicit blocks take precedence)
        if action_type in agent.blocked_actions:
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.BLOCKED,
                violation=PolicyViolation.ACTION_BLOCKED,
                reason=f"Action type '{action_type}' is explicitly blocked for this agent.",
            )

        # Check allowlist
        if action_type not in agent.allowed_actions:
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.BLOCKED,
                violation=PolicyViolation.ACTION_NOT_ALLOWED,
                reason=f"Action type '{action_type}' is not in the allowed list. Allowed: {agent.allowed_actions}",
            )

        return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)

    def _check_trust_score(
        self,
        agent: AgentRecord,
        action_type: str,
    ) -> PolicyResult:
        """Check if agent's trust score meets threshold for action.

        Attestation actions (``ATTESTATION_ACTIONS``) are pass-through —
        they record facts rather than gate live operations, so no trust
        threshold is enforced.
        """
        # Attestation actions are exempt from trust-score gating
        if action_type in self.ATTESTATION_ACTIONS:
            return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)

        threshold = self.TRUST_THRESHOLDS.get(action_type, 20)

        if agent.trust_score < threshold:
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.BLOCKED,
                violation=PolicyViolation.TRUST_SCORE_TOO_LOW,
                reason=f"Trust score {agent.trust_score} is below threshold {threshold} for action '{action_type}'.",
            )

        return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)

    def _check_timestamp(self, timestamp: datetime) -> PolicyResult:
        """Check if timestamp is within acceptable range."""
        now = datetime.now(timezone.utc)
        ts = timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp

        diff = abs((now - ts).total_seconds())

        if diff > self.MAX_CLOCK_SKEW:
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.BLOCKED,
                violation=PolicyViolation.TIMESTAMP_INVALID,
                reason=f"Timestamp skew of {int(diff)}s exceeds maximum of {self.MAX_CLOCK_SKEW}s.",
            )

        return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)

    def _check_rate_limits(self, agent: AgentRecord) -> PolicyResult:
        """Check if rate limits are exceeded."""
        if self.minute_request_count >= agent.rate_limit_per_minute:
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.RATE_LIMITED,
                violation=PolicyViolation.RATE_LIMIT_EXCEEDED,
                reason=f"Rate limit of {agent.rate_limit_per_minute} requests/minute exceeded.",
            )

        return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)

    def _check_spending_limits(
        self,
        agent: AgentRecord,
        amount: Decimal,
    ) -> PolicyResult:
        """Check spending limits for financial transactions."""
        # Check per-action limit
        if amount > agent.per_action_limit_usd:
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.BLOCKED,
                violation=PolicyViolation.PER_ACTION_LIMIT_EXCEEDED,
                reason=f"Amount ${amount} exceeds per-action limit of ${agent.per_action_limit_usd}.",
            )

        # Check daily limit
        projected_daily = self.daily_spend + amount
        if projected_daily > agent.daily_limit_usd:
            remaining = agent.daily_limit_usd - self.daily_spend
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.BLOCKED,
                violation=PolicyViolation.DAILY_LIMIT_EXCEEDED,
                reason=f"Amount ${amount} would exceed daily limit. Remaining: ${remaining}.",
            )

        return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)

    def _extract_amount(self, payload: dict[str, Any]) -> Optional[Decimal]:
        """Extract transaction amount from payload if present."""
        # Look for common amount field names
        for field in ["amount", "amount_usd", "value", "total"]:
            if field in payload:
                try:
                    return Decimal(str(payload[field]))
                except (ValueError, TypeError):
                    continue
        return None

    def _compute_limits_remaining(
        self,
        agent: AgentRecord,
        amount: Optional[Decimal],
    ) -> dict[str, Any]:
        """Compute remaining limits for the agent."""
        new_daily_spend = self.daily_spend
        if amount:
            new_daily_spend += amount

        return {
            "daily_limit_usd": str(agent.daily_limit_usd),
            "daily_spent_usd": str(new_daily_spend),
            "daily_remaining_usd": str(agent.daily_limit_usd - new_daily_spend),
            "per_action_limit_usd": str(agent.per_action_limit_usd),
            "rate_limit_per_minute": agent.rate_limit_per_minute,
            "rate_limit_used_this_minute": self.minute_request_count + 1,
        }


class TrustScorer:
    """
    Calculates and updates agent trust scores.

    Trust score is a 0-100 value that represents the reliability
    and safety of an agent based on its historical behavior.
    """

    # Base score for new agents
    BASE_SCORE = 50

    # Score adjustments for different events
    ADJUSTMENTS = {
        "action_approved": +0.1,
        "action_blocked_policy": -1,
        "action_blocked_rate_limit": -0.5,
        "signature_invalid": -20,  # Severe penalty
        "consecutive_successes_10": +2,
        "consecutive_successes_100": +5,
        "first_violation_after_good_streak": -3,
    }

    # Decay rate (score moves toward BASE_SCORE over time)
    DAILY_DECAY_RATE = 0.01

    @staticmethod
    def calculate_adjustment(
        current_score: int,
        event_type: str,
        consecutive_successes: int = 0,
    ) -> int:
        """
        Calculate the new trust score after an event.

        Args:
            current_score: Current trust score.
            event_type: Type of event that occurred.
            consecutive_successes: Number of consecutive successful actions.

        Returns:
            New trust score (clamped to 0-100).
        """
        adjustment = TrustScorer.ADJUSTMENTS.get(event_type, 0)

        # Bonus for streaks
        if consecutive_successes >= 100:
            adjustment += TrustScorer.ADJUSTMENTS["consecutive_successes_100"]
        elif consecutive_successes >= 10:
            adjustment += TrustScorer.ADJUSTMENTS["consecutive_successes_10"]

        new_score = current_score + adjustment

        # Clamp to valid range
        return max(0, min(100, int(new_score)))

    @staticmethod
    def apply_daily_decay(current_score: int) -> int:
        """
        Apply daily decay to move score toward baseline.

        Scores above BASE_SCORE decay down, scores below decay up.
        """
        if current_score == TrustScorer.BASE_SCORE:
            return current_score

        direction = 1 if current_score < TrustScorer.BASE_SCORE else -1
        decay = abs(current_score - TrustScorer.BASE_SCORE) * TrustScorer.DAILY_DECAY_RATE

        new_score = current_score + (direction * decay)

        return max(0, min(100, int(new_score)))
