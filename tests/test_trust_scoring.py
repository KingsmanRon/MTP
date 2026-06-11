"""Tests for trust-score accrual and decay.

Regression for the dead-trust-score bug: integer truncation of a +0.1 approval
adjustment (``int(50 + 0.1) == 50``) meant scores could only ever fall, making
the 70/80 trust thresholds for admin/CI/deploy actions unreachable. Adjustments
are now integers so consistent good behavior climbs the score.
"""
from api.policy import TrustScorer


class TestAccrual:
    def test_single_approval_raises_score(self):
        assert TrustScorer.calculate_adjustment(50, "action_approved") == 51

    def test_repeated_approvals_climb_to_high_threshold(self):
        score = 50
        for _ in range(30):
            score = TrustScorer.calculate_adjustment(score, "action_approved")
        # 50 + 30 = 80 → reaches the protected_branch_merge / deploy threshold.
        assert score == 80

    def test_score_clamped_at_100(self):
        score = 99
        for _ in range(10):
            score = TrustScorer.calculate_adjustment(score, "action_approved")
        assert score == 100

    def test_policy_block_lowers_score(self):
        assert TrustScorer.calculate_adjustment(50, "action_blocked_policy") == 48

    def test_signature_invalid_is_severe(self):
        assert TrustScorer.calculate_adjustment(50, "signature_invalid") == 30

    def test_score_clamped_at_zero(self):
        assert TrustScorer.calculate_adjustment(5, "signature_invalid") == 0

    def test_unknown_event_is_noop(self):
        assert TrustScorer.calculate_adjustment(50, "nonexistent_event") == 50


class TestDecay:
    def test_at_baseline_is_stable(self):
        assert TrustScorer.apply_daily_decay(50) == 50

    def test_above_baseline_decays_down(self):
        assert TrustScorer.apply_daily_decay(90) < 90

    def test_below_baseline_decays_up_not_frozen(self):
        # The prior int(40.1) == 40 bug froze below-baseline scores forever.
        assert TrustScorer.apply_daily_decay(40) > 40

    def test_decay_does_not_cross_baseline(self):
        # One point above baseline decays to exactly baseline, not below.
        assert TrustScorer.apply_daily_decay(51) == 50
        assert TrustScorer.apply_daily_decay(49) == 50

    def test_decay_converges_to_baseline(self):
        score = 100
        for _ in range(10_000):
            score = TrustScorer.apply_daily_decay(score)
        assert score == TrustScorer.BASE_SCORE
