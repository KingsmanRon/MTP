"""Shared policy decision contracts.

``PolicyViolation`` and ``PolicyResult`` were defined in ``api/policy.py``
until the payment domain was split out. They live here now so the domain
modules and the general engine can both speak the same result vocabulary
without importing each other. ``api.policy`` re-exports both, so every
existing import site keeps working unchanged.

The violation codes are a wire-visible contract: they appear in receipts,
audit rows and client-facing reasons. Values are never renamed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from api.models import ActionVerdict


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
    AMOUNT_INVALID = "amount_invalid"
    POLICY_HASH_MISMATCH = "policy_hash_mismatch"
    ACTION_TYPE_DOWNGRADE = "action_type_downgrade"
    ACTION_TYPE_UNKNOWN = "action_type_unknown"
    # WalletConnect CWP rail (Track A). These apply only to the wallet_* action
    # types and only when the agent has an opt-in wallet_policy configured.
    WALLET_CHAIN_NOT_ALLOWED = "wallet_chain_not_allowed"
    WALLET_RECIPIENT_NOT_ALLOWED = "wallet_recipient_not_allowed"
    WALLET_RECIPIENT_REQUIRED = "wallet_recipient_required"
    WALLET_POLICY_INVALID = "wallet_policy_invalid"


@dataclass
class PolicyResult:
    """Result of policy evaluation."""

    allowed: bool
    verdict: ActionVerdict
    violation: PolicyViolation | None = None
    reason: str | None = None
    limits_remaining: dict[str, Any] | None = None
