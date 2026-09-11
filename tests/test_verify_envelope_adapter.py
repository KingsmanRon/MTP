"""Phase 2 — the /verify to ActionEnvelope compatibility adapter.

The adapter translates and nothing else. These tests pin the three
properties that make it safe: the deployed signed action hash rides
through untouched, the new execution action hash is separate and stable,
and identity comes from the authenticated agent record rather than from
the request body.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

from api.adapters.verify_envelope import (
    GENERAL_DOMAIN,
    LEGACY_REFERENCES_KEY,
    AmbiguousTargetError,
    EnvelopeAdapterError,
    build_action_envelope,
    decision_to_policy_result,
    domain_for_action_type,
    lift_target,
)
from api.core.authority.authority import DelegatedAuthorityClaim
from api.core.authority.decision import (
    ConsequenceClass,
    Decision,
    DecisionReason,
    PolicyDecision,
    PolicySnapshot,
)
from api.crypto import CryptoService
from api.domains.payment.policy import PAYMENT_DOMAIN
from api.models import ActionVerdict, AgentRecord, AgentStatus
from api.policy_contracts import PolicyViolation

AGENT_ID = UUID("11111111-2222-3333-4444-555555555555")
ORG_ID = UUID("99999999-8888-7777-6666-555555555555")
TIMESTAMP = "2026-04-17T12:00:00Z"
NONCE = "nonce-abc"
CHAIN = "eip155:8453"
RECIPIENT = "0x1111111111111111111111111111111111111111"

PAYMENT_PAYLOAD = {"amount": "10.00", "currency": "USD", "recipient": "acct_123"}


def agent(**overrides) -> AgentRecord:
    fields = {
        "id": AGENT_ID,
        "org_id": ORG_ID,
        "name": "payment-agent",
        "public_key": b"\x00" * 32,
        "public_key_fingerprint": "a" * 64,
        "trust_score": 80,
        "status": AgentStatus.ACTIVE,
        "daily_limit_usd": Decimal("1000"),
        "per_action_limit_usd": Decimal("100"),
        "allowed_actions": ["financial_transaction", "wallet_transaction", "api_call"],
        "blocked_actions": [],
        "rate_limit_per_minute": 60,
        "last_action_at": None,
        "total_actions_count": 0,
        "total_blocked_count": 0,
        "metadata": {},
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    fields.update(overrides)
    return AgentRecord(**fields)


def snapshot() -> PolicySnapshot:
    return PolicySnapshot(policy_hash="b" * 64, captured_at=datetime(2026, 4, 17, tzinfo=UTC))


class TestSignedActionHashIsCarriedNotRecomputed:
    def test_the_deployed_hash_rides_through_unchanged(self) -> None:
        signed = CryptoService.compute_action_hash(
            agent_id=str(AGENT_ID),
            action_type="financial_transaction",
            payload=PAYMENT_PAYLOAD,
            nonce=NONCE,
            timestamp=TIMESTAMP,
            sig_version=2,
        )
        envelope = build_action_envelope(
            agent=agent(),
            action_type="financial_transaction",
            payload=PAYMENT_PAYLOAD,
            signed_action_hash=signed,
            nonce=NONCE,
            timestamp=TIMESTAMP,
        )
        assert envelope.signed_action_hash == signed

    def test_the_signed_hash_vector_is_the_one_phase_1_pinned(self) -> None:
        """Byte-for-byte: this digest is already in deployed receipts."""
        assert CryptoService.compute_action_hash(
            agent_id=str(AGENT_ID),
            action_type="financial_transaction",
            payload=PAYMENT_PAYLOAD,
            nonce=NONCE,
            timestamp=TIMESTAMP,
            sig_version=2,
        ) == "54c1b2efb425d09f13a99de1d0bf43656bc5ce7b62255c07992d584ad6228d82"

    def test_the_two_hashes_are_different_and_never_interchanged(self) -> None:
        signed = CryptoService.compute_action_hash(
            agent_id=str(AGENT_ID),
            action_type="financial_transaction",
            payload=PAYMENT_PAYLOAD,
            nonce=NONCE,
            timestamp=TIMESTAMP,
        )
        envelope = build_action_envelope(
            agent=agent(),
            action_type="financial_transaction",
            payload=PAYMENT_PAYLOAD,
            signed_action_hash=signed,
            nonce=NONCE,
            timestamp=TIMESTAMP,
        )
        assert envelope.execution_action_hash != envelope.signed_action_hash

    def test_an_absent_signed_hash_is_allowed(self) -> None:
        envelope = build_action_envelope(
            agent=agent(), action_type="financial_transaction", payload=PAYMENT_PAYLOAD
        )
        assert envelope.signed_action_hash is None


class TestExecutionActionHashIsStable:
    def test_the_payment_envelope_hash_is_pinned(self) -> None:
        envelope = build_action_envelope(
            agent=agent(),
            action_type="financial_transaction",
            payload=PAYMENT_PAYLOAD,
            nonce=NONCE,
            timestamp=TIMESTAMP,
        )
        assert envelope.execution_action_hash == (
            "09de51aacc5a07df8d4457f971a8b21a4bd334d1bc82cb247a5ea717d920511f"
        )

    def test_request_provenance_does_not_move_it(self) -> None:
        baseline = build_action_envelope(
            agent=agent(),
            action_type="financial_transaction",
            payload=PAYMENT_PAYLOAD,
            nonce=NONCE,
            timestamp=TIMESTAMP,
        )
        replayed = build_action_envelope(
            agent=agent(),
            action_type="financial_transaction",
            payload=PAYMENT_PAYLOAD,
            nonce="a-different-nonce",
            timestamp="2027-01-01T00:00:00Z",
        )
        assert replayed.execution_action_hash == baseline.execution_action_hash

    def test_a_changed_recipient_moves_it(self) -> None:
        baseline = build_action_envelope(
            agent=agent(), action_type="financial_transaction", payload=PAYMENT_PAYLOAD
        )
        elsewhere = build_action_envelope(
            agent=agent(),
            action_type="financial_transaction",
            payload={**PAYMENT_PAYLOAD, "recipient": "acct_999"},
        )
        assert elsewhere.execution_action_hash != baseline.execution_action_hash

    def test_a_changed_amount_moves_it(self) -> None:
        baseline = build_action_envelope(
            agent=agent(), action_type="financial_transaction", payload=PAYMENT_PAYLOAD
        )
        raised = build_action_envelope(
            agent=agent(),
            action_type="financial_transaction",
            payload={**PAYMENT_PAYLOAD, "amount": "10000.00"},
        )
        assert raised.execution_action_hash != baseline.execution_action_hash

    def test_delegated_authority_metadata_does_not_move_it(self) -> None:
        baseline = build_action_envelope(
            agent=agent(), action_type="financial_transaction", payload=PAYMENT_PAYLOAD
        )
        delegated = build_action_envelope(
            agent=agent(),
            action_type="financial_transaction",
            payload=PAYMENT_PAYLOAD,
            delegated_authority_reference=DelegatedAuthorityClaim(
                issuer="external-issuer", external_reference_id="ref-1"
            ),
            consequence_class=ConsequenceClass.C3,
        )
        assert delegated.execution_action_hash == baseline.execution_action_hash


class TestIdentityComesFromTheServer:
    def test_principal_and_organisation_come_from_the_agent_record(self) -> None:
        envelope = build_action_envelope(
            agent=agent(), action_type="financial_transaction", payload=PAYMENT_PAYLOAD
        )
        assert envelope.principal_id == str(AGENT_ID)
        assert envelope.organisation_id == str(ORG_ID)

    def test_a_payload_claiming_another_organisation_is_ignored(self) -> None:
        hostile = {**PAYMENT_PAYLOAD, "org_id": str(uuid4()), "agent_id": str(uuid4())}
        envelope = build_action_envelope(
            agent=agent(), action_type="financial_transaction", payload=hostile
        )
        assert envelope.organisation_id == str(ORG_ID)
        assert envelope.principal_id == str(AGENT_ID)

    def test_no_agent_record_means_no_envelope(self) -> None:
        with pytest.raises(EnvelopeAdapterError, match="authenticated agent record"):
            build_action_envelope(
                agent=None, action_type="financial_transaction", payload=PAYMENT_PAYLOAD
            )


class TestDomainLabelling:
    @pytest.mark.parametrize(
        "action_type", ["financial_transaction", "wallet_transaction", "wallet_signature"]
    )
    def test_payment_action_types_get_the_payment_domain(self, action_type: str) -> None:
        assert domain_for_action_type(action_type) == PAYMENT_DOMAIN

    @pytest.mark.parametrize("action_type", ["api_call", "email_send", "data_export"])
    def test_everything_else_gets_the_general_domain(self, action_type: str) -> None:
        assert domain_for_action_type(action_type) == GENERAL_DOMAIN


class TestTargetLifting:
    def test_a_recipient_becomes_the_target_and_leaves_the_payload(self) -> None:
        remaining, target = lift_target(
            {"amount": "10.00", "recipient": "acct_123"}, "financial_transaction"
        )
        assert remaining == {"amount": "10.00"}
        assert target is not None
        assert target.resource_id == "acct_123"
        assert target.resource_type == "account"

    def test_a_wallet_chain_becomes_the_target_type(self) -> None:
        _remaining, target = lift_target(
            {"chain": CHAIN, "recipient": RECIPIENT}, "wallet_transaction"
        )
        assert target is not None
        assert target.resource_type == CHAIN
        assert target.resource_id == RECIPIENT

    def test_a_resource_pair_becomes_the_target_when_no_destination_is_named(self) -> None:
        remaining, target = lift_target(
            {"resource": "database", "resource_id": "db-1"}, "data_export"
        )
        assert remaining == {}
        assert target is not None
        assert (target.resource_type, target.resource_id) == ("database", "db-1")

    def test_a_resource_and_a_recipient_are_not_a_conflict(self) -> None:
        """A real wallet payload names the acting account and the recipient."""
        remaining, target = lift_target(
            {
                "chain": CHAIN,
                "recipient": RECIPIENT,
                "resource": "wallet",
                "resource_id": f"{CHAIN}:0xACCOUNT",
            },
            "wallet_transaction",
        )
        assert target is not None
        assert target.resource_id == RECIPIENT
        assert remaining[LEGACY_REFERENCES_KEY] == {
            "resource": "wallet",
            "resource_id": f"{CHAIN}:0xACCOUNT",
        }

    def test_the_unchosen_references_stay_inside_the_hash(self) -> None:
        with_reference = build_action_envelope(
            agent=agent(),
            action_type="wallet_transaction",
            payload={
                "chain": CHAIN,
                "recipient": RECIPIENT,
                "resource_id": f"{CHAIN}:0xACCOUNT",
            },
        )
        without_reference = build_action_envelope(
            agent=agent(),
            action_type="wallet_transaction",
            payload={"chain": CHAIN, "recipient": RECIPIENT},
        )
        assert (
            with_reference.execution_action_hash != without_reference.execution_action_hash
        )

    def test_two_disagreeing_destinations_fail_closed(self) -> None:
        with pytest.raises(AmbiguousTargetError, match="more than one destination"):
            lift_target(
                {"recipient": "acct_123", "payee": "acct_999"}, "financial_transaction"
            )

    def test_two_agreeing_destinations_are_accepted(self) -> None:
        _remaining, target = lift_target(
            {"recipient": "acct_123", "payee": "acct_123"}, "financial_transaction"
        )
        assert target is not None
        assert target.resource_id == "acct_123"

    def test_a_target_type_with_no_id_fails_closed(self) -> None:
        with pytest.raises(EnvelopeAdapterError, match="no target id"):
            lift_target({"resource": "database"}, "data_export")

    def test_a_blank_target_value_fails_closed(self) -> None:
        with pytest.raises(EnvelopeAdapterError, match="non-empty string"):
            lift_target({"recipient": "   "}, "financial_transaction")

    def test_a_payload_with_no_target_is_untouched(self) -> None:
        remaining, target = lift_target({"operation": "read"}, "api_call")
        assert remaining == {"operation": "read"}
        assert target is None

    def test_a_caller_cannot_pre_supply_the_reserved_references_key(self) -> None:
        with pytest.raises(EnvelopeAdapterError, match="reserved"):
            lift_target(
                {
                    "recipient": RECIPIENT,
                    "resource_id": "acct_1",
                    LEGACY_REFERENCES_KEY: {"spoof": "x"},
                },
                "wallet_transaction",
            )

    def test_the_lifted_envelope_satisfies_the_phase_1_duplicate_rule(self) -> None:
        """Phase 1 rejects a payload that also names a target; lifting is why."""
        envelope = build_action_envelope(
            agent=agent(),
            action_type="wallet_transaction",
            payload={"chain": CHAIN, "recipient": RECIPIENT, "resource_id": "acct_1"},
        )
        assert "recipient" not in envelope.action.payload
        assert "resource_id" not in envelope.action.payload
        assert envelope.action.target is not None


class TestTimestampTolerance:
    def test_an_iso_string_with_z_parses(self) -> None:
        envelope = build_action_envelope(
            agent=agent(),
            action_type="api_call",
            payload={"operation": "read"},
            timestamp=TIMESTAMP,
        )
        assert envelope.occurred_at == datetime(2026, 4, 17, 12, 0, 0, tzinfo=UTC)

    def test_a_naive_timestamp_is_read_as_utc_like_the_legacy_check(self) -> None:
        envelope = build_action_envelope(
            agent=agent(),
            action_type="api_call",
            payload={"operation": "read"},
            timestamp=datetime(2026, 4, 17, 12, 0, 0),
        )
        assert envelope.occurred_at == datetime(2026, 4, 17, 12, 0, 0, tzinfo=UTC)

    def test_an_unparseable_timestamp_fails_closed(self) -> None:
        with pytest.raises(EnvelopeAdapterError, match="ISO-8601"):
            build_action_envelope(
                agent=agent(),
                action_type="api_call",
                payload={"operation": "read"},
                timestamp="not-a-date",
            )


class TestDecisionToWireMapping:
    def test_allow_maps_to_the_approved_verdict(self) -> None:
        result = decision_to_policy_result(
            PolicyDecision(decision=Decision.ALLOW, policy_snapshot=snapshot()),
            limits_remaining={"daily_remaining_usd": "990.00"},
        )
        assert result.allowed is True
        assert result.verdict == ActionVerdict.APPROVED
        assert result.violation is None
        assert result.limits_remaining == {"daily_remaining_usd": "990.00"}

    def test_a_block_keeps_the_existing_violation_code(self) -> None:
        result = decision_to_policy_result(
            PolicyDecision(
                decision=Decision.BLOCK,
                policy_snapshot=snapshot(),
                reasons=(DecisionReason.PER_ACTION_LIMIT_EXCEEDED,),
            )
        )
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.violation is PolicyViolation.PER_ACTION_LIMIT_EXCEEDED

    def test_an_authority_reason_does_not_invent_a_wire_code(self) -> None:
        """The /verify vocabulary is not extended by this phase."""
        result = decision_to_policy_result(
            PolicyDecision(
                decision=Decision.BLOCK,
                policy_snapshot=snapshot(),
                reasons=(DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING,),
            )
        )
        assert result.violation is None
        assert result.reason == "authority_required_but_missing"

    def test_require_approval_is_never_reported_as_approved(self) -> None:
        from api.core.authority.decision import ApprovalRequirement

        result = decision_to_policy_result(
            PolicyDecision(
                decision=Decision.REQUIRE_APPROVAL,
                policy_snapshot=snapshot(),
                approval_requirement=ApprovalRequirement(),
            )
        )
        assert result.allowed is False
        assert result.verdict == ActionVerdict.BLOCKED
        assert result.reason == "approval_required"

    def test_every_wire_verdict_string_is_one_that_already_existed(self) -> None:
        for decision in (
            PolicyDecision(decision=Decision.ALLOW, policy_snapshot=snapshot()),
            PolicyDecision(
                decision=Decision.BLOCK,
                policy_snapshot=snapshot(),
                reasons=(DecisionReason.ACTION_BLOCKED,),
            ),
        ):
            result = decision_to_policy_result(decision)
            assert result.verdict in set(ActionVerdict)
