"""
Policy Engine for the Inntris Core API.

Evaluates agent actions against configured rules and limits.
"Zero Trust" - Every action is verified against all applicable policies.
"""

import hashlib
import json
import logging
import re
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from api.domains.payment.amounts import (
    AMOUNT_FIELDS,
    AMOUNT_REQUIRED_ACTIONS,
    AmountError,
    extract_amount,
)
from api.domains.payment.policy import check_spending_limits, check_wallet_policy
from api.domains.payment.wallet import (
    WALLET_ACTION_TYPES,
    WALLET_ALLOWLIST_ACTION_TYPES,
    WalletPolicyError,
    recipient_in_allowlist,
    validate_wallet_policy,
)
from api.models import ActionVerdict, AgentRecord, AgentStatus, RegisteredPolicy
from api.observability import spend_check_skipped_total
from api.policy_contracts import PolicyResult, PolicyViolation

# Re-exported for backwards compatibility. These symbols were defined in this
# module before the payment domain was split out into api/domains/payment/ and
# the shared decision contracts into api/policy_contracts.py. Every existing
# import site — the API, the models validator, the SDKs and the test suite —
# keeps importing them from here.
__all__ = [
    "AMOUNT_FIELDS",
    "AMOUNT_REQUIRED_ACTIONS",
    "CI_GUARD_ACTIONS",
    "KNOWN_ACTION_TYPES",
    "RISK_RANK",
    "WALLET_ACTION_TYPES",
    "WALLET_ALLOWLIST_ACTION_TYPES",
    "AmountError",
    "PolicyEngine",
    "PolicyResult",
    "PolicyViolation",
    "TrustScorer",
    "WalletPolicyError",
    "canonical_policy_hash",
    "extract_amount",
    "glob_to_regex",
    "match_protected_branch",
    "recipient_in_allowlist",
    "strongest_required_action_type",
    "validate_wallet_policy",
]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Server-side change classification (Tier A defense in depth)
# ---------------------------------------------------------------------------
# This is the Python mirror of the JS action's classifier (github-action/
# index.js). The two MUST agree; the shared golden vectors in
# tests/fixtures/classification/vectors.json pin them together. The server uses
# the *registered* mapping (its own trusted copy), not the client's, so a
# caller cannot lower the risk class of a change by asserting a weaker
# action_type.

# Strongest wins. Keep in sync with the action's ACTION_PRIORITY.
RISK_RANK = {
    "repo_change": 0,
    "ci_workflow_change": 1,
    "protected_branch_merge": 2,
    "production_deployment": 3,
}

# The action types governed by .inntris.yml. Other action types (financial,
# email, ...) are not classified from changed files and skip policy binding.
CI_GUARD_ACTIONS = frozenset(RISK_RANK.keys())


def canonical_policy_hash(
    mapping: dict[str, list[str]] | None,
    protected_branches: Any,
) -> str:
    """Canonical hash of a policy's enforced content (mapping + branches).

    Formatting-independent: comments, whitespace, and line endings in the
    source ``.inntris.yml`` do not change it, so a cosmetic edit does not cause
    a spurious POLICY_HASH_MISMATCH. Must match ``canonicalPolicyHash`` in
    github-action/index.js, which hashes the same two fields.
    """
    canonical = json.dumps(
        {
            "mapping": mapping or {},
            "protected_branches": list(protected_branches or []),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_GLOB_SPECIAL = set(".+^${}()|[]\\/")


def glob_to_regex(glob: str) -> "re.Pattern[str]":
    """Translate a minimatch-style glob into an anchored regex.

    Mirrors ``globToRegExp`` in github-action/index.js: ``**`` crosses ``/``,
    ``*`` does not, ``**/`` matches zero or more leading path segments.
    """
    out: list[str] = []
    i = 0
    n = len(glob)
    while i < n:
        c = glob[i]
        if c == "*":
            if i + 1 < n and glob[i + 1] == "*":
                if i + 2 < n and glob[i + 2] == "/":
                    out.append("(?:.*/)?")
                    i += 3
                    continue
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c in _GLOB_SPECIAL:
            out.append("\\" + c)
        else:
            out.append(c)
        i += 1
    return re.compile("^" + "".join(out) + "$")


def match_protected_branch(branch: str | None, patterns: Any) -> str | None:
    """Return the matching protected-branch pattern, or None."""
    if not branch or not isinstance(patterns, (list, tuple)):
        return None
    for pattern in patterns:
        if glob_to_regex(str(pattern)).search(branch):
            return pattern
    return None


def strongest_required_action_type(
    changed_files: Any,
    base_ref: str | None,
    mapping: dict[str, list[str]] | None,
    protected_branches: Any,
) -> str:
    """The minimum action type a change requires under the given policy.

    Combines path mapping with the branch dimension (#3): a base_ref matching a
    protected branch contributes ``protected_branch_merge``. Returns the
    strongest matched type, defaulting to ``repo_change``.
    """
    present: set[str] = set()
    compiled = {
        atype: [glob_to_regex(g) for g in (globs or [])] for atype, globs in (mapping or {}).items()
    }
    for path in changed_files or []:
        for atype, regexes in compiled.items():
            if any(rx.search(str(path)) for rx in regexes):
                present.add(atype)
    if match_protected_branch(base_ref, protected_branches):
        present.add("protected_branch_merge")

    best = "repo_change"
    best_rank = RISK_RANK["repo_change"]
    for atype in present:
        rank = RISK_RANK.get(atype, RISK_RANK["repo_change"])
        if rank > best_rank:
            best, best_rank = atype, rank
    return best


# ---------------------------------------------------------------------------
# Payment domain
# ---------------------------------------------------------------------------
# Amount extraction, spend limits and the wallet chain/recipient allowlists now
# live in api/domains/payment/. They are imported above and re-exported so
# existing call sites are unaffected; the engine calls into them at exactly the
# points, and in exactly the order, it used to run them inline.


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
    ATTESTATION_ACTIONS: frozenset = frozenset(
        {
            "promptfoo_eval",
            "repo_change",
        }
    )

    # Owned by the payment domain (api/domains/payment/amounts.py) and aliased
    # here so existing readers of PolicyEngine.AMOUNT_REQUIRED_ACTIONS and
    # PolicyEngine.AMOUNT_FIELDS see the same values they always have. The
    # membership of AMOUNT_REQUIRED_ACTIONS is a live telemetry experiment; it
    # is not widened to tidy up a refactor.
    AMOUNT_REQUIRED_ACTIONS: frozenset = AMOUNT_REQUIRED_ACTIONS
    AMOUNT_FIELDS: tuple = AMOUNT_FIELDS

    # Runtime actions: PASS/BLOCK/ESCALATE semantics.
    # The caller is asking the system to authorize a live operation.
    TRUST_THRESHOLDS = {
        "financial_transaction": 30,
        # WalletConnect CWP rail (Track A). A wallet transaction or signature
        # is a live, irreversible operation, so it sits at the same threshold
        # as a financial transaction rather than at the generic default.
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
        registered_policy: RegisteredPolicy | None = None,
        client_policy_hash: str | None = None,
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
            registered_policy: The agent's server-registered governing policy,
                or None. When None, policy binding is advisory (no block) so the
                feature can roll out before every agent has registered.
            client_policy_hash: The policy hash the caller asserts it ran with.

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

        # 2a. Check the action type is one the engine actually governs.
        # An action type absent from both policy tables has no threshold
        # and no spend rule, so approving it would mean approving something
        # nothing has evaluated. Registration is what makes an action real.
        registered_result = self._check_action_registered(action_type)
        if not registered_result.allowed:
            return registered_result

        # 2b. Policy binding (Tier A): the server, not the client-asserted
        # action_type, decides the minimum risk class. Rejects a mismatched
        # policy hash or a downgrade of a code/release change.
        binding_result = self._check_policy_binding(
            action_type, payload, registered_policy, client_policy_hash
        )
        if not binding_result.allowed:
            return binding_result

        # 3. Check trust score threshold
        trust_result = self._check_trust_score(agent, action_type)
        if not trust_result.allowed:
            return trust_result

        # 3b. WalletConnect CWP chain/recipient allowlists (Track A). A no-op
        # for every non-wallet action type and for any wallet agent without a
        # configured wallet_policy, so existing behaviour is unchanged.
        wallet_result = self._check_wallet_policy(agent, action_type, payload)
        if not wallet_result.allowed:
            return wallet_result

        # 4. Check timestamp validity
        timestamp_result = self._check_timestamp(timestamp)
        if not timestamp_result.allowed:
            return timestamp_result

        # 5. Check rate limits
        rate_result = self._check_rate_limits(agent)
        if not rate_result.allowed:
            return rate_result

        # 6. Check spending limits (for amount-bearing actions). Fail closed:
        # a malformed amount, or a missing amount on an action type that
        # requires one, is blocked rather than treated as $0.
        try:
            amount = self._extract_amount(payload)
        except AmountError as exc:
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.BLOCKED,
                violation=PolicyViolation.AMOUNT_INVALID,
                reason=str(exc),
            )

        if amount is None and action_type in self.AMOUNT_REQUIRED_ACTIONS:
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.BLOCKED,
                violation=PolicyViolation.AMOUNT_INVALID,
                reason=(
                    f"Action '{action_type}' requires a numeric spend amount "
                    f"(one of: {', '.join(self.AMOUNT_FIELDS)})."
                ),
            )

        if (
            amount is None
            and action_type not in self.AMOUNT_REQUIRED_ACTIONS
            and action_type not in self.ATTESTATION_ACTIONS
        ):
            # AMOUNT_REQUIRED_ACTIONS names only financial_transaction, so every
            # other runtime action with no amount field skips the spend caps
            # entirely. Widening that set would change behaviour for action
            # types that work today, so count what a wider set would have
            # denied and decide separately with the data. Counted rather than
            # logged: /verify is the hot path, and the question this answers is
            # "which action types, how often", not "which request".
            spend_check_skipped_total.labels(action_type=action_type).inc()

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

    def _check_policy_binding(
        self,
        action_type: str,
        payload: dict[str, Any],
        registered_policy: RegisteredPolicy | None,
        client_policy_hash: str | None,
    ) -> PolicyResult:
        """Bind the request to the agent's registered policy (Tier A).

        Two checks, both applying only to the code/release action types governed
        by ``.inntris.yml``:

        1. **Policy hash** — the caller must present the registered policy's
           hash, proving it ran the policy the org registered.
        2. **No downgrade** — re-derive the minimum required action type from
           the change (``changed_files`` + ``base_ref``) using the *registered*
           mapping, and reject an asserted action type that is weaker.

        Advisory when no policy is registered (returns APPROVED): lets the
        feature deploy before every agent has registered. The action remains a
        convenience classifier; this is the server-side authority over it.
        """
        if registered_policy is None:
            return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)

        if action_type not in CI_GUARD_ACTIONS:
            return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)

        if client_policy_hash != registered_policy.policy_hash:
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.BLOCKED,
                violation=PolicyViolation.POLICY_HASH_MISMATCH,
                reason=(
                    "Submitted policy hash does not match the policy registered "
                    "for this agent. The CI workflow must run the registered "
                    ".inntris.yml."
                ),
            )

        changed_files = payload.get("changed_files") if isinstance(payload, dict) else None
        if changed_files:
            base_ref = payload.get("base_ref") if isinstance(payload, dict) else None
            required = strongest_required_action_type(
                changed_files,
                base_ref,
                registered_policy.mapping,
                registered_policy.protected_branches,
            )
            if RISK_RANK.get(action_type, 0) < RISK_RANK.get(required, 0):
                return PolicyResult(
                    allowed=False,
                    verdict=ActionVerdict.BLOCKED,
                    violation=PolicyViolation.ACTION_TYPE_DOWNGRADE,
                    reason=(
                        f"This change requires action type '{required}' but was "
                        f"submitted as '{action_type}'."
                    ),
                )

        return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)

    def _check_action_registered(self, action_type: str) -> PolicyResult:
        """Verify the action type is one this engine governs.

        ``allowed_actions`` is operator-supplied, so before the schema layer
        validated it a typo like ``wallet_transactions`` (plural) minted a live
        action type that no policy table named. Such a type matched no trust
        threshold and no spend rule, and so passed every check by being unknown
        to all of them. Unregistered types are now denied at the gate.
        """
        if action_type in KNOWN_ACTION_TYPES:
            return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)

        return PolicyResult(
            allowed=False,
            verdict=ActionVerdict.BLOCKED,
            violation=PolicyViolation.ACTION_TYPE_UNKNOWN,
            reason=(
                f"Action type '{action_type}' is not a registered action type. "
                "Registered types: " + ", ".join(sorted(KNOWN_ACTION_TYPES)) + "."
            ),
        )

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

        # No permissive fallback: an action type with no registered
        # threshold is denied rather than gated at an invented default.
        # ``_check_action_registered`` already rejects these upstream; this
        # is the second lock on the same door, so a future caller that
        # reaches the trust check by another route still fails closed.
        threshold = self.TRUST_THRESHOLDS.get(action_type)
        if threshold is None:
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.BLOCKED,
                violation=PolicyViolation.ACTION_TYPE_UNKNOWN,
                reason=(
                    f"Action type '{action_type}' has no registered trust "
                    "threshold and cannot be authorized."
                ),
            )

        if agent.trust_score < threshold:
            return PolicyResult(
                allowed=False,
                verdict=ActionVerdict.BLOCKED,
                violation=PolicyViolation.TRUST_SCORE_TOO_LOW,
                reason=f"Trust score {agent.trust_score} is below threshold {threshold} for action '{action_type}'.",
            )

        return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)

    def _check_wallet_policy(
        self,
        agent: AgentRecord,
        action_type: str,
        payload: dict[str, Any],
    ) -> PolicyResult:
        """Evaluate the agent's opt-in chain/recipient allowlists.

        The rules moved to ``api.domains.payment.policy.check_wallet_policy``
        unchanged; this is the engine's dispatch point into the payment
        domain and it stays at the same position in ``evaluate``.
        """
        return check_wallet_policy(agent, action_type, payload)

    def _check_timestamp(self, timestamp: datetime) -> PolicyResult:
        """Check if timestamp is within acceptable range."""
        now = datetime.now(UTC)
        ts = timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp

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
        """Check spending limits for amount-bearing actions.

        The rules moved to
        ``api.domains.payment.policy.check_spending_limits`` unchanged.
        This dispatch is deliberately NOT gated on the action type being a
        payment action: every amount-bearing request was subject to the
        organisation's caps before the split, and still is.
        """
        return check_spending_limits(agent, amount, self.daily_spend)

    def _extract_amount(self, payload: dict[str, Any]) -> Decimal | None:
        """Extract and validate a transaction amount from the payload.

        The rules moved to ``api.domains.payment.amounts.extract_amount``
        unchanged. Kept as a method because ``api/legacy_main.py`` calls it
        to compute the reservation amount, and the test suite calls it
        directly.
        """
        return extract_amount(payload)

    def _compute_limits_remaining(
        self,
        agent: AgentRecord,
        amount: Decimal | None,
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

    # Score adjustments for different events.
    #
    # These MUST be integers: ``trust_score`` is an INTEGER column and
    # ``calculate_adjustment`` clamps via ``int()``. The previous values used
    # +0.1 for an approval, so ``int(50 + 0.1) == 50`` — scores could never
    # rise, which made the 70/80 trust thresholds for admin/CI/deploy actions
    # unreachable for any real agent. Integer accrual lets an agent climb from
    # the 50 baseline toward those thresholds through consistent good behavior.
    ADJUSTMENTS = {
        "action_approved": +1,
        "action_blocked_policy": -2,
        "action_blocked_rate_limit": -1,
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

        Scores above BASE_SCORE decay down, scores below decay up. The decay
        steps by at least one point per day so scores just off the baseline are
        not frozen by integer truncation — the prior ``int(40.1) == 40`` left
        below-baseline scores stuck forever. The step never overshoots
        BASE_SCORE.
        """
        if current_score == TrustScorer.BASE_SCORE:
            return current_score

        direction = 1 if current_score < TrustScorer.BASE_SCORE else -1
        distance = abs(current_score - TrustScorer.BASE_SCORE)
        step = max(1, round(distance * TrustScorer.DAILY_DECAY_RATE))

        new_score = current_score + (direction * step)

        # Do not cross the baseline in a single decay step.
        if direction == 1:
            new_score = min(new_score, TrustScorer.BASE_SCORE)
        else:
            new_score = max(new_score, TrustScorer.BASE_SCORE)

        return max(0, min(100, int(new_score)))


# The canonical set of action types the system recognises: everything with a
# registered trust threshold, plus the attestation actions that are exempt from
# trust gating by design. The admin write path validates ``allowed_actions``
# against this set, and ``PolicyEngine._check_action_registered`` denies
# anything outside it, so an action type cannot be admitted at one layer and
# unknown at the other.
KNOWN_ACTION_TYPES: frozenset[str] = (
    frozenset(PolicyEngine.TRUST_THRESHOLDS) | PolicyEngine.ATTESTATION_ACTIONS
)
