"""WalletConnect CWP wallet policy (Track A).

Two things must hold together: the new chain and recipient allowlists must
work, and every existing action type must behave exactly as it did before.
The regression class at the bottom is the second half of that contract.
"""
from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from api.models import ActionVerdict, AgentRecord, AgentStatus, UpdateAgentRequest
from api.policy import (
    PolicyEngine,
    PolicyViolation,
    WalletPolicyError,
    recipient_in_allowlist,
    validate_wallet_policy,
)

APPROVED_RECIPIENT = "0x1111111111111111111111111111111111111111"
SECOND_RECIPIENT = "0x2222222222222222222222222222222222222222"
BLOCKED_RECIPIENT = "0x9999999999999999999999999999999999999999"
DEMO_CHAIN = "eip155:8453"

WALLET_ACTIONS = [
    "wallet_transaction",
    "wallet_signature",
    "financial_transaction",
    "admin_action",
    "tool_call",
    "api_call",
    "email_send",
    "data_export",
    "promptfoo_eval",
    "repo_change",
]


def _agent(metadata=None, trust_score=60, allowed_actions=None):
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
        allowed_actions=allowed_actions or WALLET_ACTIONS,
        blocked_actions=[],
        rate_limit_per_minute=60,
        last_action_at=None,
        total_actions_count=0,
        total_blocked_count=0,
        metadata=metadata if metadata is not None else {},
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _wallet_payload(chain=DEMO_CHAIN, recipient=APPROVED_RECIPIENT, operation="send-transaction"):
    payload = {
        "platform": "walletconnect-cwp",
        "rail": "walletconnect_cwp",
        "trust_level": "external_cwp_provider",
        "resource": "wallet",
        "resource_id": f"{chain}:0xACCOUNT" if chain else "wallet:*",
        "operation": operation,
        "payload_hash": "a" * 64,
        "request_ref": "wc:demo:verify",
        "downstream_provider": "companion",
        "risk_flags": ["wallet", "signing", "financial"],
        "policy_context": {"cwp_operation": operation},
    }
    if chain is not None:
        payload["chain"] = chain
    if recipient is not None:
        payload["recipient"] = recipient
    return payload


def _evaluate(agent, action_type="wallet_transaction", payload=None):
    return PolicyEngine().evaluate(
        agent=agent,
        action_type=action_type,
        payload=payload if payload is not None else _wallet_payload(),
        timestamp=datetime.now(UTC),
    )


DEMO_POLICY = {
    "wallet_policy": {
        "allowed_chains": [DEMO_CHAIN],
        "allowed_recipients": {DEMO_CHAIN: [APPROVED_RECIPIENT, SECOND_RECIPIENT]},
    }
}


class TestTrustThresholds:
    def test_wallet_action_types_are_registered_at_30(self):
        assert PolicyEngine.TRUST_THRESHOLDS["wallet_transaction"] == 30
        assert PolicyEngine.TRUST_THRESHOLDS["wallet_signature"] == 30

    @pytest.mark.parametrize("action_type", ["wallet_transaction", "wallet_signature"])
    def test_below_threshold_is_blocked(self, action_type):
        result = _evaluate(_agent(trust_score=29), action_type)
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.TRUST_SCORE_TOO_LOW

    @pytest.mark.parametrize("action_type", ["wallet_transaction", "wallet_signature"])
    def test_at_threshold_is_approved(self, action_type):
        assert _evaluate(_agent(trust_score=30), action_type).verdict == ActionVerdict.APPROVED

    def test_wallet_actions_are_not_attestation_pass_throughs(self):
        assert "wallet_transaction" not in PolicyEngine.ATTESTATION_ACTIONS
        assert "wallet_signature" not in PolicyEngine.ATTESTATION_ACTIONS


class TestWalletPolicyEnforcement:
    def test_allowed_chain_and_allowed_recipient_passes(self):
        result = _evaluate(_agent(DEMO_POLICY))
        assert result.verdict == ActionVerdict.APPROVED, result.reason
        assert result.violation is None

    def test_second_allowlisted_recipient_passes(self):
        result = _evaluate(
            _agent(DEMO_POLICY), payload=_wallet_payload(recipient=SECOND_RECIPIENT)
        )
        assert result.verdict == ActionVerdict.APPROVED

    def test_blocked_chain(self):
        result = _evaluate(_agent(DEMO_POLICY), payload=_wallet_payload(chain="eip155:1"))
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_CHAIN_NOT_ALLOWED

    def test_allowed_chain_with_blocked_recipient(self):
        result = _evaluate(
            _agent(DEMO_POLICY), payload=_wallet_payload(recipient=BLOCKED_RECIPIENT)
        )
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_RECIPIENT_NOT_ALLOWED

    def test_recipient_missing_while_allowlist_configured(self):
        result = _evaluate(_agent(DEMO_POLICY), payload=_wallet_payload(recipient=None))
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_RECIPIENT_REQUIRED

    def test_empty_recipient_string_is_treated_as_missing(self):
        result = _evaluate(_agent(DEMO_POLICY), payload=_wallet_payload(recipient="   "))
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_RECIPIENT_REQUIRED

    def test_chain_missing_while_chain_allowlist_configured(self):
        result = _evaluate(_agent(DEMO_POLICY), payload=_wallet_payload(chain=None))
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_CHAIN_NOT_ALLOWED

    def test_chain_missing_with_only_a_recipient_allowlist(self):
        policy = {"wallet_policy": {"allowed_recipients": {DEMO_CHAIN: [APPROVED_RECIPIENT]}}}
        result = _evaluate(_agent(policy), payload=_wallet_payload(chain=None))
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_CHAIN_NOT_ALLOWED

    def test_chain_match_is_exact_not_prefix(self):
        policy = {"wallet_policy": {"allowed_chains": ["eip155:8453"]}}
        result = _evaluate(_agent(policy), payload=_wallet_payload(chain="eip155:84531"))
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_CHAIN_NOT_ALLOWED

    def test_chain_allowlist_without_recipient_allowlist_permits_any_recipient(self):
        policy = {"wallet_policy": {"allowed_chains": [DEMO_CHAIN]}}
        result = _evaluate(_agent(policy), payload=_wallet_payload(recipient=BLOCKED_RECIPIENT))
        assert result.verdict == ActionVerdict.APPROVED

    def test_allowlist_for_a_different_chain_does_not_gate_this_one(self):
        policy = {
            "wallet_policy": {
                "allowed_chains": [DEMO_CHAIN, "eip155:10"],
                "allowed_recipients": {"eip155:10": [APPROVED_RECIPIENT]},
            }
        }
        result = _evaluate(_agent(policy), payload=_wallet_payload(recipient=BLOCKED_RECIPIENT))
        assert result.verdict == ActionVerdict.APPROVED

    def test_empty_allowlist_for_a_chain_blocks_every_recipient(self):
        policy = {"wallet_policy": {"allowed_recipients": {DEMO_CHAIN: []}}}
        result = _evaluate(_agent(policy))
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_RECIPIENT_NOT_ALLOWED


class TestEvmAddressCasing:
    def test_checksummed_recipient_matches_lowercase_allowlist(self):
        policy = {
            "wallet_policy": {
                "allowed_recipients": {DEMO_CHAIN: ["0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"]}
            }
        }
        result = _evaluate(
            _agent(policy),
            payload=_wallet_payload(recipient="0xAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCd"),
        )
        assert result.verdict == ActionVerdict.APPROVED

    def test_lowercase_recipient_matches_checksummed_allowlist(self):
        policy = {
            "wallet_policy": {
                "allowed_recipients": {DEMO_CHAIN: ["0xAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCd"]}
            }
        }
        result = _evaluate(
            _agent(policy),
            payload=_wallet_payload(recipient="0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
        )
        assert result.verdict == ActionVerdict.APPROVED

    def test_non_evm_namespace_is_case_sensitive(self):
        chain = "solana:mainnet"
        assert recipient_in_allowlist(chain, "AbCd", ["AbCd"]) is True
        assert recipient_in_allowlist(chain, "abcd", ["AbCd"]) is False

    def test_address_is_never_rewritten(self):
        # A trailing space is a different address, not a formatting artefact.
        assert recipient_in_allowlist("eip155:1", " 0xabc", ["0xabc"]) is False


class TestMalformedWalletPolicy:
    @pytest.mark.parametrize(
        "policy",
        [
            "not-an-object",
            ["eip155:8453"],
            {"allowed_chains": "eip155:8453"},
            {"allowed_chains": []},
            {"allowed_chains": [123]},
            {"allowed_chains": ["  "]},
            {"allowed_recipients": ["0xabc"]},
            {"allowed_recipients": {DEMO_CHAIN: "0xabc"}},
            {"allowed_recipients": {DEMO_CHAIN: [123]}},
            {"allowed_recipients": {DEMO_CHAIN: [""]}},
            {"allowed_recipients": {"": ["0xabc"]}},
        ],
    )
    def test_malformed_policy_blocks_wallet_transactions(self, policy):
        result = _evaluate(_agent({"wallet_policy": policy}))
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_POLICY_INVALID

    def test_malformed_policy_also_blocks_wallet_signatures(self):
        result = _evaluate(
            _agent({"wallet_policy": "broken"}),
            action_type="wallet_signature",
            payload=_wallet_payload(chain=None, recipient=None, operation="sign-message"),
        )
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.WALLET_POLICY_INVALID

    def test_malformed_policy_does_not_affect_other_action_types(self):
        result = _evaluate(
            _agent({"wallet_policy": "broken"}),
            action_type="financial_transaction",
            payload={"amount": "10.00"},
        )
        assert result.verdict == ActionVerdict.APPROVED

    def test_unknown_top_level_keys_are_tolerated(self):
        policy = {"allowed_chains": [DEMO_CHAIN], "future_field": {"anything": True}}
        assert validate_wallet_policy(policy) == ([DEMO_CHAIN], None)

    def test_validate_raises_wallet_policy_error(self):
        with pytest.raises(WalletPolicyError):
            validate_wallet_policy({"allowed_chains": {}})


class TestWalletSignature:
    def test_signature_is_not_gated_on_chain(self):
        result = _evaluate(
            _agent(DEMO_POLICY),
            action_type="wallet_signature",
            payload=_wallet_payload(chain=None, recipient=None, operation="sign-message"),
        )
        assert result.verdict == ActionVerdict.APPROVED

    def test_signature_is_not_gated_on_recipient(self):
        result = _evaluate(
            _agent(DEMO_POLICY),
            action_type="wallet_signature",
            payload=_wallet_payload(recipient=BLOCKED_RECIPIENT, operation="sign-typed-data"),
        )
        assert result.verdict == ActionVerdict.APPROVED


class TestNoWalletPolicyConfigured:
    def test_wallet_transaction_passes_with_no_policy(self):
        result = _evaluate(_agent({}))
        assert result.verdict == ActionVerdict.APPROVED

    def test_wallet_transaction_passes_with_unrelated_metadata(self):
        result = _evaluate(_agent({"sandbox": False, "source": "cli"}))
        assert result.verdict == ActionVerdict.APPROVED

    def test_no_policy_still_enforces_the_action_allowlist(self):
        result = _evaluate(_agent({}, allowed_actions=["tool_call"]))
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.ACTION_NOT_ALLOWED

    def test_no_policy_still_enforces_the_agent_status(self):
        agent = _agent({})
        agent.status = AgentStatus.SUSPENDED
        result = _evaluate(agent)
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.AGENT_NOT_ACTIVE


class TestWalletTransactionAmountSemantics:
    """Track A does not give wallet transactions USD spend semantics."""

    def test_wallet_transaction_does_not_require_an_amount(self):
        assert "wallet_transaction" not in PolicyEngine.AMOUNT_REQUIRED_ACTIONS
        assert "wallet_signature" not in PolicyEngine.AMOUNT_REQUIRED_ACTIONS

    def test_wallet_payload_carries_no_field_core_reads_as_an_amount(self):
        payload = _wallet_payload()
        for field in PolicyEngine.AMOUNT_FIELDS:
            assert field not in payload

    def test_wallet_transaction_reserves_no_spend(self):
        assert PolicyEngine()._extract_amount(_wallet_payload()) is None


class TestExistingBehaviourUnchanged:
    """Regression guard: no wallet policy, no behaviour change."""

    def test_financial_transaction_still_requires_an_amount(self):
        result = _evaluate(
            _agent(DEMO_POLICY), action_type="financial_transaction", payload={"payee": "acme"}
        )
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.AMOUNT_INVALID

    def test_financial_transaction_still_enforces_the_per_action_limit(self):
        result = _evaluate(
            _agent(DEMO_POLICY), action_type="financial_transaction", payload={"amount": "500.00"}
        )
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation == PolicyViolation.PER_ACTION_LIMIT_EXCEEDED

    def test_financial_transaction_still_approves_within_limits(self):
        result = _evaluate(
            _agent(DEMO_POLICY), action_type="financial_transaction", payload={"amount": "10.00"}
        )
        assert result.verdict == ActionVerdict.APPROVED

    def test_financial_transaction_is_unaffected_by_a_blocked_wallet_chain(self):
        payload = {"amount": "10.00", "chain": "eip155:1", "recipient": BLOCKED_RECIPIENT}
        result = _evaluate(
            _agent(DEMO_POLICY), action_type="financial_transaction", payload=payload
        )
        assert result.verdict == ActionVerdict.APPROVED

    @pytest.mark.parametrize(
        "action_type",
        ["tool_call", "api_call", "email_send", "data_export", "admin_action"],
    )
    def test_other_runtime_actions_ignore_the_wallet_policy(self, action_type):
        agent = _agent(DEMO_POLICY, trust_score=80)
        payload = {"chain": "eip155:1", "recipient": BLOCKED_RECIPIENT}
        assert _evaluate(agent, action_type, payload).verdict == ActionVerdict.APPROVED

    @pytest.mark.parametrize("action_type", ["promptfoo_eval", "repo_change"])
    def test_attestation_actions_remain_pass_through(self, action_type):
        agent = _agent(DEMO_POLICY, trust_score=0)
        assert _evaluate(agent, action_type, {}).verdict == ActionVerdict.APPROVED

    def test_existing_trust_thresholds_are_untouched(self):
        assert PolicyEngine.TRUST_THRESHOLDS["financial_transaction"] == 30
        assert PolicyEngine.TRUST_THRESHOLDS["email_send"] == 20
        assert PolicyEngine.TRUST_THRESHOLDS["api_call"] == 10
        assert PolicyEngine.TRUST_THRESHOLDS["tool_call"] == 10
        assert PolicyEngine.TRUST_THRESHOLDS["data_export"] == 40
        assert PolicyEngine.TRUST_THRESHOLDS["admin_action"] == 70
        assert PolicyEngine.TRUST_THRESHOLDS["ci_workflow_change"] == 80
        assert PolicyEngine.TRUST_THRESHOLDS["protected_branch_merge"] == 80
        assert PolicyEngine.TRUST_THRESHOLDS["production_deployment"] == 80


class TestWalletPolicyWriteValidation:
    def test_a_valid_wallet_policy_is_accepted(self):
        request = UpdateAgentRequest(metadata=DEMO_POLICY)
        assert request.metadata == DEMO_POLICY

    def test_a_malformed_wallet_policy_is_rejected_at_write_time(self):
        with pytest.raises(ValueError, match="allowed_chains"):
            UpdateAgentRequest(metadata={"wallet_policy": {"allowed_chains": "eip155:8453"}})

    def test_metadata_without_a_wallet_policy_is_untouched(self):
        request = UpdateAgentRequest(metadata={"team": "payments"})
        assert request.metadata == {"team": "payments"}

    def test_lifecycle_metadata_remains_rejected_by_the_endpoint_guard(self):
        # The model does not police lifecycle keys; PATCH /admin/agents does.
        # This documents that the wallet-policy validator did not take that over.
        request = UpdateAgentRequest(metadata={"wallet_policy": {"allowed_chains": [DEMO_CHAIN]}})
        assert "sandbox" not in (request.metadata or {})
