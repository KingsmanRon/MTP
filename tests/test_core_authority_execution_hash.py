"""Phase 1 — the ``inntris-execution-action-v1`` semantic hash.

Two contracts are pinned here.

1. The new execution action hash covers the semantic act and only the
   semantic act: representation of the same act cannot change it, and a
   change to the act must change it, while decision, provenance and
   binding context must not.

2. The deployed signed action hash is untouched. ``compute_action_hash``
   still produces the exact digests it produced before this phase, for
   every signing-envelope version. Those digests sit in receipts,
   approval tokens and on-chain anchors, so the vectors below are
   byte-for-byte constants, not recomputations.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from api import jcs
from api.core.authority.decision import ConsequenceClass
from api.core.authority.envelope import (
    EXECUTION_ACTION_HASH_FORMAT,
    MAX_PAYLOAD_DEPTH,
    RESERVED_TARGET_PAYLOAD_KEYS,
    ActionEnvelope,
    ExecutableAction,
    ResourceReference,
)
from api.core.authority.errors import InvalidEnvelopeError
from api.crypto import CryptoService


def build_action(**overrides: object) -> ExecutableAction:
    """A representative act. Overrides replace individual members."""
    kwargs: dict = {
        "principal_id": "agent-1",
        "organisation_id": "org-1",
        "domain": "payments",
        "action_type": "financial_transaction",
        "payload": {"amount": "10.00", "currency": "USD"},
        "target": ResourceReference(resource_type="account", resource_id="acct_123"),
    }
    kwargs.update(overrides)
    return ExecutableAction(**kwargs)  # type: ignore[arg-type]


class TestRepresentationDoesNotChangeTheHash:
    def test_key_order_does_not_change_the_hash(self) -> None:
        insertion_order = build_action(payload={"amount": "10.00", "currency": "USD"})
        reverse_order = build_action(payload={"currency": "USD", "amount": "10.00"})
        assert insertion_order.execution_action_hash == reverse_order.execution_action_hash

    def test_whitespace_in_the_source_document_does_not_change_the_hash(self) -> None:
        compact = json.loads('{"amount":"10.00","currency":"USD"}')
        spaced = json.loads('{\n  "currency" : "USD" ,\n  "amount" : "10.00"\n}')
        assert build_action(payload=compact).execution_action_hash == (
            build_action(payload=spaced).execution_action_hash
        )

    def test_canonical_form_carries_no_insignificant_whitespace(self) -> None:
        canonical = jcs.canonicalize(build_action().preimage()).decode("utf-8")
        assert " " not in canonical.replace('"amount":"10.00"', "")
        assert "\n" not in canonical

    def test_keyword_argument_order_does_not_change_the_hash(self) -> None:
        one = ExecutableAction(
            principal_id="agent-1",
            organisation_id="org-1",
            domain="payments",
            action_type="api_call",
        )
        other = ExecutableAction(
            action_type="api_call",
            domain="payments",
            organisation_id="org-1",
            principal_id="agent-1",
        )
        assert one.execution_action_hash == other.execution_action_hash


class TestActChangesTheHash:
    def test_payload_change_changes_the_hash(self) -> None:
        baseline = build_action()
        raised = build_action(payload={"amount": "10000.00", "currency": "USD"})
        assert raised.execution_action_hash != baseline.execution_action_hash

    def test_adding_a_payload_field_changes_the_hash(self) -> None:
        baseline = build_action()
        extended = build_action(payload={"amount": "10.00", "currency": "USD", "memo": "x"})
        assert extended.execution_action_hash != baseline.execution_action_hash

    def test_target_change_changes_the_hash(self) -> None:
        baseline = build_action()
        elsewhere = build_action(
            target=ResourceReference(resource_type="account", resource_id="acct_999")
        )
        assert elsewhere.execution_action_hash != baseline.execution_action_hash

    def test_target_type_change_changes_the_hash(self) -> None:
        baseline = build_action()
        other_type = build_action(
            target=ResourceReference(resource_type="ledger", resource_id="acct_123")
        )
        assert other_type.execution_action_hash != baseline.execution_action_hash

    def test_principal_change_changes_the_hash(self) -> None:
        assert (
            build_action(principal_id="agent-2").execution_action_hash
            != build_action().execution_action_hash
        )

    def test_organisation_change_changes_the_hash(self) -> None:
        assert (
            build_action(organisation_id="org-2").execution_action_hash
            != build_action().execution_action_hash
        )

    def test_domain_change_changes_the_hash(self) -> None:
        assert (
            build_action(domain="messaging").execution_action_hash
            != build_action().execution_action_hash
        )

    def test_action_type_change_changes_the_hash(self) -> None:
        assert (
            build_action(action_type="api_call").execution_action_hash
            != build_action().execution_action_hash
        )

    def test_identical_acts_hash_identically(self) -> None:
        assert build_action().execution_action_hash == build_action().execution_action_hash


class TestSurroundingContextDoesNotChangeTheHash:
    """Decision, provenance and binding context are not part of the act."""

    def test_envelope_hash_is_the_action_hash(self) -> None:
        action = build_action()
        envelope = ActionEnvelope(action=action)
        assert envelope.execution_action_hash == action.execution_action_hash

    def test_provenance_does_not_change_the_hash(self) -> None:
        action = build_action()
        bare = ActionEnvelope(action=action)
        with_provenance = ActionEnvelope(
            action=action,
            nonce="nonce-abc",
            occurred_at=datetime(2026, 4, 17, 12, 0, 0, tzinfo=UTC),
        )
        assert with_provenance.execution_action_hash == bare.execution_action_hash

    def test_consequence_classification_does_not_change_the_hash(self) -> None:
        action = build_action()
        low = ActionEnvelope(action=action, consequence_class=ConsequenceClass.C1)
        critical = ActionEnvelope(action=action, consequence_class=ConsequenceClass.C4)
        assert low.execution_action_hash == critical.execution_action_hash

    def test_delegation_metadata_does_not_change_the_hash(self) -> None:
        from api.core.authority.authority import DelegatedAuthorityClaim

        action = build_action()
        bare = ActionEnvelope(action=action)
        delegated = ActionEnvelope(
            action=action,
            delegated_authority_reference=DelegatedAuthorityClaim(
                issuer="external-issuer", external_reference_id="ref-1"
            ),
        )
        assert delegated.execution_action_hash == bare.execution_action_hash

    def test_signed_action_hash_does_not_change_the_hash(self) -> None:
        action = build_action()
        bare = ActionEnvelope(action=action)
        signed = ActionEnvelope(action=action, signed_action_hash="a" * 64)
        assert signed.execution_action_hash == bare.execution_action_hash

    def test_preimage_omits_decision_and_provenance_members(self) -> None:
        preimage = build_action().preimage()
        for absent in (
            "policy_hash",
            "authority_reference",
            "delegated_authority_reference",
            "consequence_class",
            "grant_id",
            "nonce",
            "occurred_at",
            "timestamp",
            "executor_binding",
            "signed_action_hash",
        ):
            assert absent not in preimage


class TestOmittedVersusNull:
    def test_absent_target_is_omitted_from_the_preimage(self) -> None:
        assert "target" not in build_action(target=None).preimage()

    def test_absent_target_hashes_differently_from_a_present_one(self) -> None:
        assert (
            build_action(target=None).execution_action_hash != build_action().execution_action_hash
        )

    def test_target_none_and_target_omitted_are_the_same_act(self) -> None:
        explicit_none = build_action(target=None)
        omitted = ExecutableAction(
            principal_id="agent-1",
            organisation_id="org-1",
            domain="payments",
            action_type="financial_transaction",
            payload={"amount": "10.00", "currency": "USD"},
        )
        assert explicit_none.execution_action_hash == omitted.execution_action_hash

    def test_null_inside_the_payload_is_a_real_value(self) -> None:
        with_null = build_action(payload={"memo": None})
        without = build_action(payload={})
        assert with_null.execution_action_hash != without.execution_action_hash
        assert jcs.canonicalize(with_null.preimage()).decode("utf-8").count("null") == 1

    def test_empty_payload_is_still_a_required_preimage_member(self) -> None:
        assert build_action(payload={}).preimage()["payload"] == {}


class TestDuplicateTargetRepresentationIsRejected:
    @pytest.mark.parametrize("key", sorted(RESERVED_TARGET_PAYLOAD_KEYS))
    def test_every_reserved_key_is_rejected(self, key: str) -> None:
        with pytest.raises(InvalidEnvelopeError, match="exactly once"):
            build_action(payload={key: "acct_999"})

    def test_a_conflicting_recipient_is_rejected_before_hashing(self) -> None:
        with pytest.raises(InvalidEnvelopeError) as excinfo:
            ExecutableAction(
                principal_id="agent-1",
                organisation_id="org-1",
                domain="payments",
                action_type="financial_transaction",
                payload={"amount": "10.00", "recipient": "acct_999"},
                target=ResourceReference(resource_type="account", resource_id="acct_123"),
            )
        assert "recipient" in str(excinfo.value)

    def test_an_agreeing_duplicate_is_rejected_too(self) -> None:
        """Agreement is a judgement every layer would have to re-make identically."""
        with pytest.raises(InvalidEnvelopeError):
            ExecutableAction(
                principal_id="agent-1",
                organisation_id="org-1",
                domain="payments",
                action_type="financial_transaction",
                payload={"recipient": "acct_123"},
                target=ResourceReference(resource_type="account", resource_id="acct_123"),
            )

    def test_a_target_expressed_only_in_the_payload_is_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError):
            build_action(payload={"resource_id": "acct_123"}, target=None)

    def test_reserved_keys_are_only_reserved_at_the_top_level(self) -> None:
        nested = build_action(payload={"metadata": {"recipient": "free-text"}})
        assert nested.execution_action_hash


class TestFormatVersioning:
    def test_the_format_identifier_is_the_documented_one(self) -> None:
        assert EXECUTION_ACTION_HASH_FORMAT == "inntris-execution-action-v1"

    def test_the_format_is_a_required_preimage_member(self) -> None:
        assert build_action().preimage()["format"] == EXECUTION_ACTION_HASH_FORMAT

    def test_a_different_format_cannot_collide_with_v1(self) -> None:
        v1 = build_action().preimage()
        v2 = dict(v1, format="inntris-execution-action-v2")
        assert jcs.sha256_hex(v2) != jcs.sha256_hex(v1)

    def test_the_format_is_not_caller_supplied(self) -> None:
        """No envelope field selects the version, so no caller can steer it."""
        with pytest.raises(TypeError):
            ExecutableAction(  # type: ignore[call-arg]
                principal_id="agent-1",
                organisation_id="org-1",
                domain="payments",
                action_type="financial_transaction",
                format="inntris-execution-action-v2",
            )

    def test_a_payload_key_named_format_cannot_shadow_the_version(self) -> None:
        spoofed = build_action(payload={"format": "inntris-execution-action-v2", "amount": "10.00"})
        assert spoofed.preimage()["format"] == EXECUTION_ACTION_HASH_FORMAT
        assert spoofed.execution_action_hash != build_action().execution_action_hash

    def test_the_signed_request_hash_and_the_execution_hash_are_different_hashes(
        self,
    ) -> None:
        """They answer different questions and must never be interchanged."""
        action = build_action()
        signed = CryptoService.compute_action_hash(
            agent_id=action.principal_id,
            action_type=action.action_type,
            payload=dict(action.payload),
            nonce="nonce-abc",
            timestamp=datetime(2026, 4, 17, 12, 0, 0, tzinfo=UTC),
        )
        assert signed != action.execution_action_hash


class TestPinnedExecutionHashes:
    """Pinned so a later refactor cannot silently move the hash space."""

    def test_action_with_target(self) -> None:
        assert build_action().execution_action_hash == (
            "ea2d11c67d289d570663822e082d98059cbad87fc9c5956848c586684d6a308d"
        )

    def test_action_without_target(self) -> None:
        assert build_action(target=None).execution_action_hash == (
            "ae675d47c7e9195c345ee200e13f6d26753b6d228e431d6ec19deea29adf53b4"
        )

    def test_canonical_preimage_bytes(self) -> None:
        assert jcs.canonicalize(build_action().preimage()).decode("utf-8") == (
            '{"action_type":"financial_transaction","domain":"payments",'
            '"format":"inntris-execution-action-v1","organisation":"org-1",'
            '"payload":{"amount":"10.00","currency":"USD"},"principal":"agent-1",'
            '"target":{"resource_id":"acct_123","resource_type":"account"}}'
        )


class TestRejectedValues:
    def test_decimal_is_rejected_with_guidance(self) -> None:
        from decimal import Decimal

        with pytest.raises(InvalidEnvelopeError, match="unsupported type"):
            build_action(payload={"amount": Decimal("10.00")})

    def test_datetime_in_the_payload_is_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="unsupported type"):
            build_action(payload={"at": datetime(2026, 4, 17, tzinfo=UTC)})

    def test_bytes_in_the_payload_are_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="unsupported type"):
            build_action(payload={"blob": b"\x00\x01"})

    def test_a_set_in_the_payload_is_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="unsupported type"):
            build_action(payload={"tags": {"a", "b"}})

    def test_non_string_payload_keys_are_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="keys must be strings"):
            build_action(payload={1: "one"})

    def test_nan_is_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="NaN or Infinity"):
            build_action(payload={"quantity": float("nan")})

    def test_infinity_is_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="NaN or Infinity"):
            build_action(payload={"quantity": float("inf")})

    def test_excessive_nesting_is_rejected(self) -> None:
        deep: object = "leaf"
        for _ in range(MAX_PAYLOAD_DEPTH + 2):
            deep = {"nested": deep}
        with pytest.raises(InvalidEnvelopeError, match="maximum depth"):
            build_action(payload=deep)

    @pytest.mark.parametrize("field", ["principal_id", "organisation_id", "domain", "action_type"])
    def test_empty_identifiers_are_rejected(self, field: str) -> None:
        with pytest.raises(InvalidEnvelopeError, match="must not be empty"):
            build_action(**{field: ""})

    @pytest.mark.parametrize("field", ["principal_id", "organisation_id", "domain", "action_type"])
    def test_non_string_identifiers_are_rejected(self, field: str) -> None:
        with pytest.raises(InvalidEnvelopeError, match="must be a string"):
            build_action(**{field: 7})

    def test_control_characters_in_identifiers_are_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="control characters"):
            build_action(principal_id="agent\n1")

    def test_surrounding_whitespace_in_identifiers_is_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="whitespace"):
            build_action(principal_id=" agent-1 ")

    def test_non_nfc_identifiers_are_rejected_rather_than_normalised(self) -> None:
        composed = "café-org"
        decomposed = "café-org"
        assert composed != decomposed
        assert build_action(organisation_id=composed).execution_action_hash
        with pytest.raises(InvalidEnvelopeError, match="NFC"):
            build_action(organisation_id=decomposed)

    def test_payload_strings_are_not_normalised(self) -> None:
        """Payload is opaque: it is canonicalized verbatim, never rewritten."""
        composed = build_action(payload={"note": "café"})
        decomposed = build_action(payload={"note": "café"})
        assert composed.execution_action_hash != decomposed.execution_action_hash

    def test_a_non_mapping_payload_is_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="payload must be a mapping"):
            build_action(payload=[("amount", "10.00")])

    def test_a_target_that_is_not_a_resource_reference_is_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="ResourceReference"):
            build_action(target={"resource_type": "account", "resource_id": "acct_123"})


class TestImmutability:
    def test_the_action_is_frozen(self) -> None:
        action = build_action()
        with pytest.raises(AttributeError):
            action.principal_id = "agent-2"  # type: ignore[misc]

    def test_the_stored_payload_cannot_be_mutated(self) -> None:
        action = build_action()
        with pytest.raises(TypeError):
            action.payload["amount"] = "10000.00"  # type: ignore[index]

    def test_mutating_the_source_payload_does_not_move_the_hash(self) -> None:
        source = {"amount": "10.00", "currency": "USD"}
        action = build_action(payload=source)
        before = action.execution_action_hash
        source["amount"] = "10000.00"
        assert action.execution_action_hash == before

    def test_nested_payload_structures_are_frozen(self) -> None:
        action = build_action(payload={"metadata": {"a": 1}, "tags": ["x"]})
        with pytest.raises(TypeError):
            action.payload["metadata"]["a"] = 2  # type: ignore[index]
        assert action.payload["tags"] == ("x",)


class TestEnvelopeValidation:
    def test_a_malformed_signed_action_hash_is_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="signed_action_hash"):
            ActionEnvelope(action=build_action(), signed_action_hash="not-a-digest")

    def test_an_uppercase_signed_action_hash_is_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="signed_action_hash"):
            ActionEnvelope(action=build_action(), signed_action_hash="A" * 64)

    def test_a_naive_occurred_at_is_rejected(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="timezone-aware"):
            ActionEnvelope(action=build_action(), occurred_at=datetime(2026, 4, 17, 12, 0, 0))

    def test_occurred_at_is_normalised_to_utc(self) -> None:
        from datetime import timedelta, timezone

        envelope = ActionEnvelope(
            action=build_action(),
            occurred_at=datetime(2026, 4, 17, 14, 0, 0, tzinfo=timezone(timedelta(hours=2))),
        )
        assert envelope.occurred_at == datetime(2026, 4, 17, 12, 0, 0, tzinfo=UTC)

    def test_a_resolved_authority_cannot_be_smuggled_in_as_a_claim(self) -> None:
        with pytest.raises(InvalidEnvelopeError, match="DelegatedAuthorityClaim"):
            ActionEnvelope(
                action=build_action(),
                delegated_authority_reference={"verification_status": "verified"},
            )

    def test_envelope_forwards_the_acts_identity(self) -> None:
        action = build_action()
        envelope = ActionEnvelope(action=action)
        assert envelope.principal_id == action.principal_id
        assert envelope.organisation_id == action.organisation_id
        assert envelope.domain == action.domain
        assert envelope.action_type == action.action_type


class TestExistingSignedActionHashIsUnchanged:
    """Byte-for-byte constants. These digests are already in the field."""

    AGENT_ID = "11111111-2222-3333-4444-555555555555"
    PAYLOAD = {"amount": "10.00", "currency": "USD", "recipient": "acct_123"}
    NONCE = "nonce-abc"
    TIMESTAMP = datetime(2026, 4, 17, 12, 0, 0, tzinfo=UTC)

    @pytest.mark.parametrize(
        ("sig_version", "expected"),
        [
            (1, "157a62b30ac239f1e8e2169b33eaf97e63dce053970ee1978d3d476d48357d33"),
            (2, "54c1b2efb425d09f13a99de1d0bf43656bc5ce7b62255c07992d584ad6228d82"),
            (3, "54c1b2efb425d09f13a99de1d0bf43656bc5ce7b62255c07992d584ad6228d82"),
        ],
    )
    def test_action_hash_vectors(self, sig_version: int, expected: str) -> None:
        assert (
            CryptoService.compute_action_hash(
                agent_id=self.AGENT_ID,
                action_type="financial_transaction",
                payload=self.PAYLOAD,
                nonce=self.NONCE,
                timestamp=self.TIMESTAMP,
                sig_version=sig_version,
            )
            == expected
        )

    @pytest.mark.parametrize(
        ("sig_version", "expected"),
        [
            (1, "3987d7443692026204714c53fc6748c2fe41a444bbda6a639aae9ffa37cb9711"),
            (2, "58ead22051f4a4a7806773abcff49fe34e39399ef74115e4bd9315aac102ccbc"),
            (3, "f5819242ddecf61f54930e104b69fddd64cae9e0e96b5673712861e514c9119c"),
        ],
    )
    def test_action_hash_vectors_where_the_versions_diverge(
        self, sig_version: int, expected: str
    ) -> None:
        """An integer-valued float separates the three envelope versions."""
        assert (
            CryptoService.compute_action_hash(
                agent_id="agent-float",
                action_type="api_call",
                payload={"quantity": 1.0, "note": "café"},
                nonce="n2",
                timestamp=self.TIMESTAMP,
                sig_version=sig_version,
            )
            == expected
        )

    def test_payload_hash_vector(self) -> None:
        assert CryptoService.compute_payload_hash(self.PAYLOAD) == (
            "e3a5763fcb7a169639f6aa5eed9b9f82c2fa058ccb0cb66c71b5ac85a2785672"
        )

    def test_the_default_signing_envelope_version_is_unchanged(self) -> None:
        assert CryptoService.SIG_VERSION_DEFAULT == CryptoService.SIG_VERSION_CURRENT == 2

    def test_the_new_hash_reuses_the_repositorys_jcs_implementation(self) -> None:
        action = build_action()
        assert action.execution_action_hash == jcs.sha256_hex(action.preimage())
