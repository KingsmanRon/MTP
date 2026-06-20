"""Tier A: server-side policy binding and change re-classification.

These tests cover the security backbone that makes the backend -- not the
client-asserted action_type -- the authority over a code/release change.
"""
import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest

from api.models import ActionVerdict, AgentRecord, AgentStatus, RegisteredPolicy
from api.policy import (
    PolicyEngine,
    PolicyViolation,
    canonical_policy_hash,
    glob_to_regex,
    strongest_required_action_type,
)

_VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "classification" / "vectors.json").read_text(
        encoding="utf-8"
    )
)
_POLICY = _VECTORS["policy"]


def _agent(trust_score=50, status=AgentStatus.ACTIVE, allowed=None, blocked=None):
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
        allowed_actions=allowed
        or [
            "repo_change",
            "ci_workflow_change",
            "protected_branch_merge",
            "production_deployment",
        ],
        blocked_actions=blocked or [],
        rate_limit_per_minute=60,
        last_action_at=None,
        total_actions_count=0,
        total_blocked_count=0,
        metadata={},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def _registered(policy_hash="b" * 64):
    return RegisteredPolicy(
        policy_hash=policy_hash,
        mapping=_POLICY["mapping"],
        protected_branches=_POLICY["protected_branches"],
        version=1,
    )


# ---------------------------------------------------------------------------
# Golden vectors: the Python classifier must agree with the JS action
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("case", _VECTORS["cases"], ids=lambda c: c["name"])
def test_strongest_required_matches_golden_vectors(case):
    result = strongest_required_action_type(
        case["files"],
        case["base_ref"],
        _POLICY["mapping"],
        _POLICY["protected_branches"],
    )
    assert result == case["expected"]


def test_canonical_policy_hash_matches_golden_vector():
    # The server-derived hash must equal what the JS action sends; the JS side
    # asserts the same constant (github-action/index.test.js).
    computed = canonical_policy_hash(
        _POLICY["mapping"], _POLICY["protected_branches"]
    )
    assert computed == _VECTORS["policy_hash"]


def test_glob_to_regex_semantics():
    assert glob_to_regex("src/auth/**").search("src/auth/session.ts")
    assert not glob_to_regex("src/auth/**").search("src/authentication.ts")
    assert glob_to_regex("**/.env*").search(".env")
    assert glob_to_regex("**/.env*").search("config/.env.local")
    assert not glob_to_regex("a*").search("a/b.ts")  # * does not cross a slash


# ---------------------------------------------------------------------------
# Policy binding
# ---------------------------------------------------------------------------
def test_binding_is_advisory_when_no_policy_registered():
    engine = PolicyEngine()
    result = engine._check_policy_binding(
        "repo_change", {"changed_files": ["infra/main.tf"]}, None, None
    )
    assert result.allowed is True


def test_binding_skips_non_ci_actions():
    engine = PolicyEngine()
    # A financial action is not governed by .inntris.yml; binding is a no-op
    # even with a registered policy and no client hash.
    result = engine._check_policy_binding(
        "financial_transaction", {"amount": 10}, _registered(), None
    )
    assert result.allowed is True


def test_binding_blocks_policy_hash_mismatch():
    engine = PolicyEngine()
    result = engine._check_policy_binding(
        "repo_change",
        {"changed_files": ["docs/x.md"]},
        _registered(policy_hash="b" * 64),
        client_policy_hash="c" * 64,
    )
    assert result.allowed is False
    assert result.verdict == ActionVerdict.BLOCKED
    assert result.violation == PolicyViolation.POLICY_HASH_MISMATCH


def test_binding_blocks_action_type_downgrade():
    engine = PolicyEngine()
    # Caller asserts repo_change but the change touches infra (production_deployment).
    result = engine._check_policy_binding(
        "repo_change",
        {"changed_files": ["infra/main.tf"], "base_ref": "feature/x"},
        _registered(),
        client_policy_hash="b" * 64,
    )
    assert result.allowed is False
    assert result.violation == PolicyViolation.ACTION_TYPE_DOWNGRADE
    assert "production_deployment" in result.reason


def test_binding_blocks_branch_downgrade():
    engine = PolicyEngine()
    # Docs into main is a protected_branch_merge; asserting repo_change is a downgrade.
    result = engine._check_policy_binding(
        "repo_change",
        {"changed_files": ["docs/x.md"], "base_ref": "main"},
        _registered(),
        client_policy_hash="b" * 64,
    )
    assert result.allowed is False
    assert result.violation == PolicyViolation.ACTION_TYPE_DOWNGRADE


def test_binding_allows_matching_or_stronger_assertion():
    engine = PolicyEngine()
    # Exactly the required type.
    exact = engine._check_policy_binding(
        "production_deployment",
        {"changed_files": ["infra/main.tf"], "base_ref": "feature/x"},
        _registered(),
        client_policy_hash="b" * 64,
    )
    assert exact.allowed is True
    # Over-asserting (stronger than required) is safe and allowed.
    stronger = engine._check_policy_binding(
        "production_deployment",
        {"changed_files": ["docs/x.md"], "base_ref": "feature/x"},
        _registered(),
        client_policy_hash="b" * 64,
    )
    assert stronger.allowed is True


# ---------------------------------------------------------------------------
# Full evaluate() integration: binding runs before the trust-score gate
# ---------------------------------------------------------------------------
def test_evaluate_blocks_downgrade_before_trust_check():
    engine = PolicyEngine()
    # A high-trust agent still cannot downgrade a deployment to repo_change.
    agent = _agent(trust_score=100)
    result = engine.evaluate(
        agent=agent,
        action_type="repo_change",
        payload={"changed_files": ["infra/main.tf"], "base_ref": "main"},
        timestamp=datetime.now(timezone.utc),
        registered_policy=_registered(),
        client_policy_hash="b" * 64,
    )
    assert result.allowed is False
    assert result.violation == PolicyViolation.ACTION_TYPE_DOWNGRADE


def test_evaluate_unregistered_is_backward_compatible():
    engine = PolicyEngine()
    agent = _agent(trust_score=100)
    # No registered policy => binding advisory => the call proceeds to the
    # normal trust gate and is approved for a vetted agent.
    result = engine.evaluate(
        agent=agent,
        action_type="production_deployment",
        payload={"changed_files": ["infra/main.tf"], "base_ref": "main"},
        timestamp=datetime.now(timezone.utc),
    )
    assert result.allowed is True
    assert result.verdict == ActionVerdict.APPROVED
