"""Phase 4 — receipt v3 authenticated evidence, and v1/v2 left alone.

The property that matters most: a v3 authority field cannot be altered
and made to verify by recomputing the fingerprint. That is exactly the
attack a bare fingerprint does not stop, and it is why v3 signs.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api import jcs
from api.receipts.v3 import (
    EVIDENCE_PAYLOAD_FORMAT,
    RECEIPT_SCHEMA_V3,
    AuthorityEvidenceChain,
    ConsumptionEvidenceV3,
    DecisionEvidenceV3,
    EvidenceError,
    EvidenceEventType,
    OutcomeEvidenceV3,
    evidence_payload_hash,
    load_evidence_signing_key,
    sign_evidence_event,
    verify_evidence_event,
)

FIXTURES = Path(__file__).parent / "fixtures" / "receipts"
NOW = datetime(2026, 4, 17, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def key():
    return load_evidence_signing_key(environment="test")


def legacy_fingerprint(payload: dict) -> str:
    """The v1/v2 algorithm, reproduced exactly as api/legacy_main.py has it."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def decision_body(**overrides) -> dict:
    fields = {
        "audit_id": "99999999-8888-7777-6666-555555555555",
        "agent_id": "11111111-2222-3333-4444-555555555555",
        "organisation_id": "22222222-3333-4444-5555-666666666666",
        "action_type": "financial_transaction",
        "domain": "payment",
        "decision": "allow",
        "execution_action_hash": "a" * 64,
        "policy_snapshot_format": "inntris-payment-authority-policy-v1",
        "policy_snapshot_digest": "b" * 64,
        "signed_action_hash": "c" * 64,
        "legacy_policy_hash": "d" * 64,
        "grant_id": "grant-1",
        "authority_issuer": "external-issuer",
        "authority_reference_id": "ref-1",
        "authority_artefact_digest": "e" * 64,
        "executor_binding_digest": "f" * 64,
    }
    fields.update(overrides)
    return DecisionEvidenceV3(**fields).to_body()


def signed_decision(key, **overrides):
    return sign_evidence_event(
        event_id="ev-decision-1",
        event_type=EvidenceEventType.DECISION,
        body=decision_body(**overrides),
        key=key,
        recorded_at=NOW,
    )


class TestLegacyReceiptsAreUntouched:
    @pytest.mark.parametrize("version", ["v1", "v2"])
    def test_the_stored_fixture_still_verifies_under_its_own_algorithm(
        self, version: str
    ) -> None:
        fixture = json.loads((FIXTURES / f"receipt_{version}.json").read_text())
        assert legacy_fingerprint(fixture["fingerprint_payload"]) == (
            fixture["receipt_fingerprint"]
        )
        assert fixture["schema_version"] == version

    @pytest.mark.parametrize("version", ["v1", "v2"])
    def test_the_legacy_algorithm_is_not_jcs(self, version: str) -> None:
        """v3 uses JCS; v1/v2 must keep their historical serializer.

        They agree for this payload, but the point is that v1/v2 are
        computed by the frozen code path, not by the new one.
        """
        fixture = json.loads((FIXTURES / f"receipt_{version}.json").read_text())
        assert fixture["canonicalisation"].startswith("json.dumps(sort_keys=True")

    def test_v1_and_v2_differ_only_by_policy_binding(self) -> None:
        v1 = json.loads((FIXTURES / "receipt_v1.json").read_text())
        v2 = json.loads((FIXTURES / "receipt_v2.json").read_text())
        assert v1["fingerprint_payload"]["policy_hash"] is None
        assert v2["fingerprint_payload"]["policy_hash"] is not None
        assert v1["receipt_fingerprint"] != v2["receipt_fingerprint"]

    def test_the_legacy_field_set_is_exactly_seven_fields(self) -> None:
        """Adding a field to v1/v2 would silently change every fingerprint."""
        v2 = json.loads((FIXTURES / "receipt_v2.json").read_text())
        assert set(v2["fingerprint_payload"]) == {
            "action_hash",
            "action_type",
            "agent_id",
            "audit_id",
            "policy_hash",
            "timestamp",
            "verdict",
        }

    def test_v3_is_a_separate_version_not_a_reuse_of_v2(self) -> None:
        assert RECEIPT_SCHEMA_V3 == "v3"


class TestEvidenceIsSignedNotJustHashed:
    def test_a_decision_event_verifies(self, key) -> None:
        assert verify_evidence_event(signed_decision(key), public_key_b64=key.public_key_b64)

    def test_the_payload_hash_is_jcs_over_the_versioned_payload(self, key) -> None:
        event = signed_decision(key)
        assert event.evidence_payload_hash == jcs.sha256_hex(event.payload)
        assert event.payload["format"] == EVIDENCE_PAYLOAD_FORMAT

    def test_a_wrong_key_does_not_verify(self, key) -> None:
        other = load_evidence_signing_key(environment="test")
        result = verify_evidence_event(
            signed_decision(key), public_key_b64=other.public_key_b64
        )
        assert not result
        assert any("signature" in reason for reason in result.failures)

    @pytest.mark.parametrize(
        "field",
        [
            "execution_action_hash",
            "policy_snapshot_digest",
            "policy_snapshot_format",
            "signed_action_hash",
            "legacy_policy_hash",
            "grant_id",
            "authority_issuer",
            "authority_reference_id",
            "authority_artefact_digest",
            "executor_binding_digest",
            "decision",
            "organisation_id",
            "agent_id",
        ],
    )
    def test_tampering_with_any_authority_field_is_detected(self, key, field) -> None:
        event = signed_decision(key)
        record = event.as_public_dict()
        record["payload"]["body"][field] = "tampered"
        assert not verify_evidence_event(record, public_key_b64=key.public_key_b64)

    @pytest.mark.parametrize(
        "field",
        [
            "execution_action_hash",
            "policy_snapshot_digest",
            "grant_id",
            "executor_binding_digest",
        ],
    )
    def test_tampering_plus_a_recomputed_hash_still_fails(self, key, field) -> None:
        """The attack a bare fingerprint cannot survive.

        The attacker edits a field AND recomputes the hash so it matches
        the edited payload. Verification still fails, because the
        signature was made over the original hash and they cannot forge a
        new one.
        """
        event = signed_decision(key)
        record = event.as_public_dict()
        record["payload"]["body"][field] = "tampered"
        record["evidence_payload_hash"] = evidence_payload_hash(record["payload"])

        result = verify_evidence_event(record, public_key_b64=key.public_key_b64)
        assert not result
        assert any("signature" in reason for reason in result.failures)
        assert not any("evidence_payload_hash" in reason for reason in result.failures), (
            "the hash now matches; only the signature exposes the tamper"
        )

    def test_a_forged_signature_does_not_verify(self, key) -> None:
        event = signed_decision(key)
        record = event.as_public_dict()
        record["signature_b64"] = base64.b64encode(b"\x00" * 64).decode("ascii")
        assert not verify_evidence_event(record, public_key_b64=key.public_key_b64)

    def test_the_verification_material_travels_with_the_event(self, key) -> None:
        record = signed_decision(key).as_public_dict()
        assert record["signing_key_id"].startswith("authority-evidence-")
        assert len(record["signing_key_fingerprint"]) == 64


class TestEvidenceChainIsLinkedAndImmutable:
    def _chain(self, key) -> AuthorityEvidenceChain:
        decision = signed_decision(key)
        consumption = sign_evidence_event(
            event_id="ev-consumption-1",
            event_type=EvidenceEventType.CONSUMPTION,
            body=ConsumptionEvidenceV3(
                consumption_audit_id="audit-2",
                grant_id="grant-1",
                execution_action_hash="a" * 64,
                execution_ref="exec-1",
                outcome="authorised",
                executor_binding_digest="f" * 64,
                consumed_at=NOW + timedelta(seconds=30),
            ).to_body(),
            key=key,
            recorded_at=NOW + timedelta(seconds=30),
            parent=decision,
        )
        outcome = sign_evidence_event(
            event_id="ev-outcome-1",
            event_type=EvidenceEventType.OUTCOME,
            body=OutcomeEvidenceV3(
                grant_id="grant-1",
                outcome_state="succeeded",
                outcome_reference="rail-ref-1",
                recorded_at=NOW + timedelta(minutes=1),
            ).to_body(),
            key=key,
            recorded_at=NOW + timedelta(minutes=1),
            parent=consumption,
        )
        return AuthorityEvidenceChain(decision, consumption, outcome)

    def test_a_full_chain_verifies(self, key) -> None:
        assert self._chain(key).verify(public_key_b64=key.public_key_b64)

    def test_the_decision_event_is_unchanged_when_later_events_are_added(
        self, key
    ) -> None:
        """A decision receipt is never mutated by what happens afterwards."""
        decision = signed_decision(key)
        before = decision.as_public_dict()
        chain = self._chain(key)
        assert chain.decision.evidence_payload_hash == before["evidence_payload_hash"]
        assert chain.decision.signature_b64 == before["signature_b64"]
        assert verify_evidence_event(chain.decision, public_key_b64=key.public_key_b64)

    def test_each_event_commits_to_its_parent(self, key) -> None:
        chain = self._chain(key)
        assert chain.consumption.parent_event_id == chain.decision.event_id
        assert chain.consumption.parent_payload_hash == (
            chain.decision.evidence_payload_hash
        )
        assert chain.outcome.parent_event_id == chain.consumption.event_id

    def test_re_parenting_an_event_breaks_verification(self, key) -> None:
        chain = self._chain(key)
        forged = chain.consumption.as_public_dict()
        forged["payload"]["parent_event_id"] = "some-other-decision"
        forged["evidence_payload_hash"] = evidence_payload_hash(forged["payload"])
        assert not verify_evidence_event(
            forged, public_key_b64=key.public_key_b64, parent=chain.decision
        )

    def test_a_mismatched_parent_is_reported(self, key) -> None:
        chain = self._chain(key)
        other_decision = sign_evidence_event(
            event_id="ev-decision-other",
            event_type=EvidenceEventType.DECISION,
            body=decision_body(grant_id="grant-other"),
            key=key,
            recorded_at=NOW,
        )
        result = verify_evidence_event(
            chain.consumption, public_key_b64=key.public_key_b64, parent=other_decision
        )
        assert not result
        assert any("parent" in reason for reason in result.failures)

    def test_a_chain_without_an_outcome_still_verifies(self, key) -> None:
        full = self._chain(key)
        partial = AuthorityEvidenceChain(full.decision, full.consumption)
        assert partial.verify(public_key_b64=key.public_key_b64)
        assert len(partial.events()) == 2


class TestSigningKeySeparation:
    def test_production_refuses_an_unconfigured_key(self) -> None:
        """An ephemeral key nobody can publish verifies against nothing."""
        with pytest.raises(EvidenceError, match="required outside development"):
            load_evidence_signing_key(environment="production", seed_b64=None)

    def test_a_configured_seed_is_used(self) -> None:
        seed = base64.b64encode(b"\x07" * 32).decode("ascii")
        first = load_evidence_signing_key(environment="production", seed_b64=seed)
        second = load_evidence_signing_key(environment="production", seed_b64=seed)
        assert first.public_key_b64 == second.public_key_b64

    def test_a_malformed_seed_is_refused(self) -> None:
        with pytest.raises(EvidenceError):
            load_evidence_signing_key(environment="production", seed_b64="not-base64!!")
        with pytest.raises(EvidenceError, match="32-byte"):
            load_evidence_signing_key(
                environment="production", seed_b64=base64.b64encode(b"short").decode()
            )

    def test_the_key_is_not_an_agent_key_or_anchor_wallet(self, key) -> None:
        """Distinct key id namespace, so evidence cannot be misread."""
        assert key.key_id.startswith("authority-evidence-")

    def test_evidence_never_carries_raw_credential_contents(self, key) -> None:
        """Only a reference and a digest of the external artefact."""
        body = signed_decision(key).payload["body"]
        assert "authority_artefact_digest" in body
        assert not any(
            suspicious in body
            for suspicious in ("credential", "secret", "token", "raw_artefact")
        )


class TestEvidenceValidation:
    def test_a_naive_timestamp_is_refused(self, key) -> None:
        with pytest.raises(EvidenceError, match="timezone-aware"):
            sign_evidence_event(
                event_id="ev-1",
                event_type=EvidenceEventType.DECISION,
                body=decision_body(),
                key=key,
                recorded_at=datetime(2026, 4, 17, 12, 0, 0),
            )

    def test_a_blank_required_field_is_refused(self) -> None:
        with pytest.raises(EvidenceError):
            DecisionEvidenceV3(
                audit_id="",
                agent_id="a",
                organisation_id="o",
                action_type="t",
                domain="payment",
                decision="allow",
                execution_action_hash="a" * 64,
                policy_snapshot_format="f",
                policy_snapshot_digest="b" * 64,
            ).to_body()

    def test_consumption_requires_its_binding_and_reference(self) -> None:
        with pytest.raises(EvidenceError):
            ConsumptionEvidenceV3(
                consumption_audit_id="a",
                grant_id="g",
                execution_action_hash="a" * 64,
                execution_ref="",
                outcome="authorised",
                executor_binding_digest="f" * 64,
            ).to_body()
