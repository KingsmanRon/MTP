"""Phase 7A, Gate 4 — v3 evidence signing, publication, and the public verifier.

The property under test is the one that makes v3 worth anything: a third
party with the events, the published key, and the standalone verifier can
tell a genuine chain from a doctored one, and Inntris cannot help them or
hinder them.

So the tests here run the **published** ``verify_pack.py`` as a subprocess
against real packs, rather than calling into `api.receipts.v3`. Testing the
library against itself would prove that Core agrees with Core. What matters
is that the thing we hand to the public says no to the forgeries.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from nacl.signing import SigningKey

from api import jcs
from api.receipts.key_registry import (
    KeyPublicationError,
    PublishedKey,
    PublishedKeyRegistry,
    PublishedKeyStatus,
    assert_key_is_published,
    assert_key_separation,
    load_published_keys,
)
from api.receipts.schema_v3 import RECEIPT_SCHEMA_V3_DOCUMENT
from api.receipts.v3 import (
    EVIDENCE_SIGNING_KEY_ENV,
    EvidenceError,
    EvidenceEventType,
    load_evidence_signing_key,
    sign_evidence_event,
    verify_evidence_event,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPO_ROOT / "evidence_pack" / "pack_contents" / "verify_pack.py"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "receipts"

#: Deterministic so failures reproduce. Test-only: it signs nothing outside
#: this file and verifies nothing in production.
EVIDENCE_SEED = hashlib.sha256(b"gate-4-authority-evidence-seed").digest()
EVIDENCE_KEY = SigningKey(EVIDENCE_SEED)
EVIDENCE_PUBLIC = bytes(EVIDENCE_KEY.verify_key)
EVIDENCE_FINGERPRINT = hashlib.sha256(EVIDENCE_PUBLIC).hexdigest()

PACK_SEED = hashlib.sha256(b"gate-4-pack-manifest-seed").digest()
PACK_KEY = SigningKey(PACK_SEED)


# =============================================================================
# Key separation
# =============================================================================


class TestKeySeparation:
    """A key that can assert two things can be misread as asserting the wrong
    one, so this is enforced rather than documented."""

    def test_a_clean_environment_passes(self) -> None:
        assert_key_separation(EVIDENCE_SEED, environ={})

    def test_reusing_the_agent_request_key_is_refused(self) -> None:
        env = {"INNTRIS_PRIVATE_KEY_B64": base64.b64encode(EVIDENCE_SEED).decode()}
        with pytest.raises(KeyPublicationError, match="agent request-signing key"):
            assert_key_separation(EVIDENCE_SEED, environ=env)

    def test_reusing_the_anchor_wallet_is_refused(self) -> None:
        env = {"BLOCKCHAIN_PRIVATE_KEY": "0x" + EVIDENCE_SEED.hex()}
        with pytest.raises(KeyPublicationError, match="anchor wallet"):
            assert_key_separation(EVIDENCE_SEED, environ=env)

    def test_reusing_the_evidence_pack_seed_is_refused(self) -> None:
        env = {"EVIDENCE_PACK_SIGNING_SEED": EVIDENCE_SEED.hex()}
        with pytest.raises(KeyPublicationError, match="evidence-pack manifest seed"):
            assert_key_separation(EVIDENCE_SEED, environ=env)

    def test_a_different_key_in_the_same_variable_is_fine(self) -> None:
        other = hashlib.sha256(b"a different key entirely").digest()
        env = {"BLOCKCHAIN_PRIVATE_KEY": other.hex()}
        assert_key_separation(EVIDENCE_SEED, environ=env)

    def test_the_loader_enforces_separation(self, monkeypatch) -> None:
        monkeypatch.setenv("ENVIRONMENT", "development")
        monkeypatch.setenv("BLOCKCHAIN_PRIVATE_KEY", "0x" + EVIDENCE_SEED.hex())
        with pytest.raises(KeyPublicationError):
            load_evidence_signing_key(seed_b64=base64.b64encode(EVIDENCE_SEED).decode())


# =============================================================================
# Publication gate
# =============================================================================


def _registry(status: PublishedKeyStatus = PublishedKeyStatus.ACTIVE) -> PublishedKeyRegistry:
    return PublishedKeyRegistry(
        keys=(
            PublishedKey(
                key_id="iae-2026-01",
                public_key=EVIDENCE_PUBLIC,
                fingerprint=EVIDENCE_FINGERPRINT,
                status=status,
                effective_date=datetime.now(UTC).date(),
            ),
        )
    )


class TestPublicationGate:
    def test_production_refuses_an_unpublished_key(self) -> None:
        with pytest.raises(KeyPublicationError, match="not in the published key"):
            assert_key_is_published(
                EVIDENCE_FINGERPRINT,
                environment="production",
                registry=PublishedKeyRegistry(),
            )

    def test_production_refuses_a_retired_key(self) -> None:
        with pytest.raises(KeyPublicationError, match="must not sign new evidence"):
            assert_key_is_published(
                EVIDENCE_FINGERPRINT,
                environment="production",
                registry=_registry(PublishedKeyStatus.RETIRED),
            )

    def test_production_accepts_a_published_active_key(self) -> None:
        published = assert_key_is_published(
            EVIDENCE_FINGERPRINT, environment="production", registry=_registry()
        )
        assert published is not None
        assert published.key_id == "iae-2026-01"

    def test_development_tolerates_an_unpublished_key(self) -> None:
        assert (
            assert_key_is_published(
                EVIDENCE_FINGERPRINT,
                environment="development",
                registry=PublishedKeyRegistry(),
            )
            is None
        )

    def test_the_loader_uses_the_published_key_id(self, monkeypatch) -> None:
        """An event should name the identifier a verifier can look up, not a
        locally derived one."""
        monkeypatch.setattr(
            "api.receipts.key_registry.load_published_keys", lambda *_a, **_k: _registry()
        )
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.delenv("INNTRIS_PRIVATE_KEY_B64", raising=False)
        monkeypatch.delenv("BLOCKCHAIN_PRIVATE_KEY", raising=False)
        key = load_evidence_signing_key(seed_b64=base64.b64encode(EVIDENCE_SEED).decode())
        assert key.key_id == "iae-2026-01"

    def test_production_refuses_a_missing_seed_entirely(self, monkeypatch) -> None:
        monkeypatch.delenv(EVIDENCE_SIGNING_KEY_ENV, raising=False)
        with pytest.raises(EvidenceError, match="required outside development"):
            load_evidence_signing_key(environment="production")

    def test_the_repository_publishes_no_authority_key_yet(self) -> None:
        """The release state, asserted so it cannot change silently.

        No ``iae-`` key is published, so production CANNOT sign v3 evidence.
        When the production key ceremony happens this test changes with the
        mirror, deliberately -- publishing a signing key should require
        touching a test that says what was published.
        """
        assert load_published_keys(REPO_ROOT).authority_evidence_keys() == ()

    def test_two_active_authority_keys_are_refused(self) -> None:
        other = SigningKey(hashlib.sha256(b"second active").digest())
        registry = PublishedKeyRegistry(
            keys=_registry().keys
            + (
                PublishedKey(
                    key_id="iae-2026-02",
                    public_key=bytes(other.verify_key),
                    fingerprint=hashlib.sha256(bytes(other.verify_key)).hexdigest(),
                    status=PublishedKeyStatus.ACTIVE,
                    effective_date=datetime.now(UTC).date(),
                ),
            )
        )
        with pytest.raises(KeyPublicationError, match="more than one active"):
            registry.active_authority_evidence_key()

    def test_a_retired_key_stays_discoverable(self) -> None:
        """Evidence signed while a key was active must stay verifiable."""
        document = _registry(PublishedKeyStatus.RETIRED).as_discovery_document()
        assert document["keys"][0]["status"] == "retired"
        assert document["keys"][0]["fingerprint_sha256"] == EVIDENCE_FINGERPRINT


# =============================================================================
# Building a chain, and the published verifier's verdict on it
# =============================================================================


_EVENT_COUNTER = itertools.count(1)


def _event(event_type: EvidenceEventType, body: dict, parent=None, key: SigningKey | None = None):
    from api.receipts.v3 import EvidenceSigningKey

    signing = EvidenceSigningKey(signing_key=key or EVIDENCE_KEY, key_id="iae-2026-01")
    return sign_evidence_event(
        event_id=str(uuid4()),
        event_type=event_type,
        body=body,
        key=signing,
        recorded_at=datetime.now(UTC),
        parent=parent,
    )


GRANT_ID = "11111111-2222-3333-4444-555555555555"
ACTION_HASH = "ab" * 32
EXECUTOR_DIGEST = "cd" * 32


def build_chain(*, decision: str = "allow", spent: bool = True, outcome: bool = True):
    decision_event = _event(
        EvidenceEventType.DECISION,
        {
            "decision": decision,
            "grant_id": GRANT_ID,
            "execution_action_hash": ACTION_HASH,
            "executor_binding_digest": EXECUTOR_DIGEST,
            "agent_id": "agent-1",
            "organisation_id": "org-1",
        },
    )
    chain = {"decision": decision_event.as_public_dict()}
    if not spent:
        return chain

    consumption_event = _event(
        EvidenceEventType.CONSUMPTION,
        {
            "grant_id": GRANT_ID,
            "execution_action_hash": ACTION_HASH,
            "executor_binding_digest": EXECUTOR_DIGEST,
            "agent_id": "agent-1",
            "organisation_id": "org-1",
            "execution_ref": "exec-1",
        },
        parent=decision_event,
    )
    chain["consumption"] = consumption_event.as_public_dict()
    if outcome:
        chain["outcome"] = _event(
            EvidenceEventType.OUTCOME,
            {"grant_id": GRANT_ID, "outcome": "succeeded"},
            parent=consumption_event,
        ).as_public_dict()
    return chain


def build_pack(tmp_path: Path, chains: dict[str, dict], *, key_b64: str | None = None):
    """A real, signed evidence pack carrying v3 chains."""
    from evidence_pack.builder import EvidencePackBuilder

    builder = EvidencePackBuilder(
        pack_name="gate-4-test-pack",
        snapshot_time=datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC),
        authority_evidence_key={
            "key_id": "iae-2026-01",
            "public_key_b64": (
                key_b64 if key_b64 is not None else base64.b64encode(EVIDENCE_PUBLIC).decode()
            ),
            "fingerprint_sha256": EVIDENCE_FINGERPRINT,
        },
    )
    for chain_id, chain in chains.items():
        builder.add_authority_evidence(chain, chain_id=chain_id)
    path = tmp_path / "pack.zip"
    builder.build(path, PACK_KEY)
    return path


def run_verifier(
    pack: Path, *, pin_evidence_key: bytes | None = None
) -> subprocess.CompletedProcess:
    command = [sys.executable, str(VERIFIER), str(pack)]
    if pin_evidence_key is not None:
        command += ["--evidence-pubkey", pin_evidence_key.hex()]
    return subprocess.run(command, capture_output=True, text=True, timeout=180)


class TestPublishedVerifierAcceptsGenuineEvidence:
    def test_a_full_chain_verifies(self, tmp_path) -> None:
        pack = build_pack(tmp_path, {"chain-1": build_chain()})
        result = run_verifier(pack)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "v3 chain verifies (decision, consumption, outcome)" in result.stdout

    def test_an_unspent_decision_is_a_complete_chain_of_one(self, tmp_path) -> None:
        pack = build_pack(tmp_path, {"chain-1": build_chain(spent=False)})
        result = run_verifier(pack)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "v3 chain verifies (decision)" in result.stdout

    def test_the_verifier_warns_that_v3_is_not_anchored(self, tmp_path) -> None:
        """A reader must not conclude from a green result that the evidence
        commitment is on-chain. It is not."""
        pack = build_pack(tmp_path, {"chain-1": build_chain()})
        result = run_verifier(pack)
        assert "not itself" in result.stdout and "anchored" in result.stdout


class TestPublishedVerifierRejectsForgeries:
    """Each of these is a move somebody would actually make."""

    def _expect_failure(self, tmp_path, chain, needle: str) -> None:
        result = run_verifier(build_pack(tmp_path, {"chain-1": chain}))
        assert result.returncode != 0, result.stdout
        assert needle in result.stdout, result.stdout

    def test_editing_a_body_field_is_caught(self, tmp_path) -> None:
        """Change the outcome to 'succeeded' after a failure, without
        recomputing anything."""
        chain = build_chain()
        chain["outcome"]["payload"]["body"]["outcome"] = "TAMPERED"
        self._expect_failure(tmp_path, chain, "evidence_payload_hash does not match the payload")

    def test_editing_a_body_field_and_recomputing_the_hash_is_still_caught(self, tmp_path) -> None:
        """The important one: recomputing the hash is exactly what a tamperer
        does, and it is the signature that makes the hash mean anything."""
        chain = build_chain()
        chain["outcome"]["payload"]["body"]["outcome"] = "TAMPERED"
        chain["outcome"]["evidence_payload_hash"] = jcs.sha256_hex(chain["outcome"]["payload"])
        self._expect_failure(
            tmp_path, chain, "signature does not verify over the recomputed payload hash"
        )

    def test_editing_an_outer_envelope_field_is_caught(self, tmp_path) -> None:
        """The outer copy is free to edit -- the signature still verifies over
        the untouched payload -- so a reader trusting it reads something
        nobody signed."""
        chain = build_chain()
        chain["decision"]["signing_key_id"] = "iae-somebody-elses-key"
        self._expect_failure(tmp_path, chain, "outer signing_key_id contradicts the signed payload")

    def test_deleting_an_outer_envelope_field_is_caught(self, tmp_path) -> None:
        """Absence must not read as equal to a signed null."""
        chain = build_chain(spent=False)
        del chain["decision"]["parent_event_id"]
        self._expect_failure(tmp_path, chain, "outer parent_event_id is missing from the envelope")

    def test_re_parenting_an_event_is_caught(self, tmp_path) -> None:
        chain = build_chain()
        chain["consumption"]["payload"]["parent_event_id"] = chain["outcome"]["event_id"]
        self._expect_failure(tmp_path, chain, "evidence_payload_hash does not match the payload")

    def test_a_chain_signed_by_a_different_key_is_caught(self, tmp_path) -> None:
        """Forge the whole chain with your own key and publish the matching
        public key in the manifest: the pack is internally consistent and the
        manifest names a key that is not the published one."""
        attacker = SigningKey(hashlib.sha256(b"attacker").digest())
        forged = {
            "decision": _event(
                EvidenceEventType.DECISION,
                {
                    "decision": "allow",
                    "grant_id": GRANT_ID,
                    "execution_action_hash": ACTION_HASH,
                    "executor_binding_digest": EXECUTOR_DIGEST,
                },
                key=attacker,
            ).as_public_dict()
        }
        # The manifest still names the REAL published key, which is the case
        # a reader who checked the mirror is in.
        pack = build_pack(tmp_path, {"chain-1": forged})
        result = run_verifier(pack)
        assert result.returncode != 0
        assert "signature does not verify" in result.stdout

    def test_a_wholesale_forgery_is_internally_consistent_and_says_so(self, tmp_path) -> None:
        """Sign the evidence with your own key AND name that key in the
        manifest. Nothing INSIDE the pack can catch this, and the verifier
        must not pretend otherwise: it warns and prints the fingerprint to
        compare against the published mirror."""
        attacker = SigningKey(hashlib.sha256(b"attacker-2").digest())
        forged = {
            "decision": _event(
                EvidenceEventType.DECISION,
                {
                    "decision": "allow",
                    "grant_id": GRANT_ID,
                    "execution_action_hash": ACTION_HASH,
                    "executor_binding_digest": EXECUTOR_DIGEST,
                },
                key=attacker,
            ).as_public_dict()
        }
        pack = build_pack(
            tmp_path,
            {"chain-1": forged},
            key_b64=base64.b64encode(bytes(attacker.verify_key)).decode(),
        )
        result = run_verifier(pack)
        assert result.returncode == 0, result.stdout
        assert "no --evidence-pubkey pinned" in result.stdout
        assert hashlib.sha256(bytes(attacker.verify_key)).hexdigest() in result.stdout

    def test_pinning_the_published_key_catches_the_wholesale_forgery(self, tmp_path) -> None:
        """The reader who checked the published mirror pins the real key. Now
        the forgery has nowhere to go."""
        attacker = SigningKey(hashlib.sha256(b"attacker-2").digest())
        forged = {
            "decision": _event(
                EvidenceEventType.DECISION,
                {
                    "decision": "allow",
                    "grant_id": GRANT_ID,
                    "execution_action_hash": ACTION_HASH,
                    "executor_binding_digest": EXECUTOR_DIGEST,
                },
                key=attacker,
            ).as_public_dict()
        }
        pack = build_pack(
            tmp_path,
            {"chain-1": forged},
            key_b64=base64.b64encode(bytes(attacker.verify_key)).decode(),
        )
        result = run_verifier(pack, pin_evidence_key=EVIDENCE_PUBLIC)
        assert result.returncode != 0, result.stdout
        assert "NOT the pinned published key" in result.stdout

    def test_pinning_the_published_key_accepts_genuine_evidence(self, tmp_path) -> None:
        pack = build_pack(tmp_path, {"chain-1": build_chain()})
        result = run_verifier(pack, pin_evidence_key=EVIDENCE_PUBLIC)
        assert result.returncode == 0, result.stdout
        assert "matches the pinned published key" in result.stdout

    def test_a_consumption_of_a_different_grant_is_caught(self, tmp_path) -> None:
        """Every hash chains perfectly and the history is a fabrication: this
        is what the continuity checks exist for."""
        decision_event = _event(
            EvidenceEventType.DECISION,
            {
                "decision": "allow",
                "grant_id": GRANT_ID,
                "execution_action_hash": ACTION_HASH,
                "executor_binding_digest": EXECUTOR_DIGEST,
            },
        )
        consumption_event = _event(
            EvidenceEventType.CONSUMPTION,
            {
                "grant_id": "99999999-9999-9999-9999-999999999999",
                "execution_action_hash": ACTION_HASH,
                "executor_binding_digest": EXECUTOR_DIGEST,
            },
            parent=decision_event,
        )
        chain = {
            "decision": decision_event.as_public_dict(),
            "consumption": consumption_event.as_public_dict(),
        }
        self._expect_failure(tmp_path, chain, "consumption grant_id does not match the decision")

    def test_a_consumption_after_a_block_is_caught(self, tmp_path) -> None:
        """Authority that was refused cannot have been spent."""
        chain = build_chain(decision="block", outcome=False)
        self._expect_failure(
            tmp_path, chain, "a consumption follows a decision that was not an allow"
        )

    def test_an_outcome_without_a_consumption_is_caught(self, tmp_path) -> None:
        decision_event = _event(
            EvidenceEventType.DECISION,
            {
                "decision": "allow",
                "grant_id": GRANT_ID,
                "execution_action_hash": ACTION_HASH,
                "executor_binding_digest": EXECUTOR_DIGEST,
            },
        )
        chain = {
            "decision": decision_event.as_public_dict(),
            "outcome": _event(
                EvidenceEventType.OUTCOME,
                {"grant_id": GRANT_ID, "outcome": "succeeded"},
                parent=decision_event,
            ).as_public_dict(),
        }
        self._expect_failure(tmp_path, chain, "an outcome without a consumption")

    def test_evidence_with_no_named_key_is_refused(self, tmp_path) -> None:
        """A pack whose evidence names no key cannot be checked against any
        key the pack commits to."""
        from api.jcs import canonicalize
        from evidence_pack.builder import EvidencePackBuilder

        builder = EvidencePackBuilder(
            pack_name="gate-4-unnamed-key",
            snapshot_time=datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC),
        )
        # Bypass add_authority_evidence, which refuses this at the producer.
        builder._entries["authority_evidence/chain-1.json"] = canonicalize(build_chain())
        path = tmp_path / "pack.zip"
        builder.build(path, PACK_KEY)
        result = run_verifier(path)
        assert result.returncode != 0
        assert "names no authority-evidence public key" in result.stdout

    def test_the_producer_refuses_evidence_without_a_key(self) -> None:
        from evidence_pack.builder import EvidencePackBuilder

        builder = EvidencePackBuilder(
            pack_name="x", snapshot_time=datetime(2026, 9, 11, tzinfo=UTC)
        )
        with pytest.raises(ValueError, match="authority_evidence_key is required"):
            builder.add_authority_evidence(build_chain())


# =============================================================================
# v1 and v2 are frozen
# =============================================================================


class TestLegacyReceiptsAreUnaffected:
    """v3 is additive. A v1 or v2 receipt must verify exactly as it did."""

    @pytest.mark.parametrize("name", ["receipt_v1.json", "receipt_v2.json"])
    def test_the_stored_fingerprint_still_recomputes(self, name) -> None:
        fixture = json.loads((FIXTURES / name).read_text())
        canonical = json.dumps(
            fixture["fingerprint_payload"], sort_keys=True, separators=(",", ":")
        )
        assert hashlib.sha256(canonical.encode()).hexdigest() == fixture["receipt_fingerprint"]

    @pytest.mark.parametrize("name", ["receipt_v1.json", "receipt_v2.json"])
    def test_the_published_verifier_recomputes_it_identically(self, name) -> None:
        """The frozen v1/v2 contract, run through the shipped verifier's own
        implementation rather than a copy of it.

        This is the regression that matters for Gate 4: adding v3 to
        verify_pack.py must not move a v1 or v2 fingerprint by one bit.
        """
        import importlib.util

        spec = importlib.util.spec_from_file_location("verify_pack_under_test", VERIFIER)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        fixture = json.loads((FIXTURES / name).read_text())
        assert (
            module.recompute_fingerprint(fixture["fingerprint_payload"])
            == fixture["receipt_fingerprint"]
        )

    def test_a_pack_with_no_v3_evidence_verifies_as_before(self, tmp_path) -> None:
        from evidence_pack.builder import EvidencePackBuilder

        fixture = json.loads((FIXTURES / "receipt_v2.json").read_text())
        receipt = dict(fixture["fingerprint_payload"])
        receipt["schema_version"] = fixture["schema_version"]
        receipt["receipt_fingerprint"] = fixture["receipt_fingerprint"]

        builder = EvidencePackBuilder(
            pack_name="legacy-only",
            snapshot_time=datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC),
        )
        builder.add_receipt(receipt)
        path = tmp_path / "pack.zip"
        builder.build(path, PACK_KEY)
        result = run_verifier(path)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "fingerprint matches" in result.stdout


# =============================================================================
# Canonicalisation agreement between producer and published verifier
# =============================================================================


class TestCanonicalisationAgreement:
    """The verifier reimplements JCS with no dependencies. If the two ever
    disagree, genuine evidence stops verifying — so this compares them."""

    def _verifier_module(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("verify_pack_jcs", VERIFIER)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module

    @pytest.mark.parametrize(
        "value",
        [
            {},
            {"a": 1, "b": None, "c": True},
            {"b": "second", "a": "first"},
            {"unicode": "café ☕ 𝄞"},
            {"escapes": 'tab\there "quoted" back\\slash\nnewline'},
            {"control": "\x00\x1f"},
            {"nested": {"deep": [1, 2, {"x": "y"}]}},
            {"ints": [0, -1, 10**18]},
            {"floats": [1.0, 0.5, 1e-7, 1.5e21]},
            {"empty_list": [], "empty_obj": {}},
        ],
    )
    def test_the_two_implementations_agree(self, value) -> None:
        assert self._verifier_module().jcs_sha256_hex(value) == jcs.sha256_hex(value)

    def test_they_agree_on_a_real_evidence_payload(self) -> None:
        chain = build_chain()
        for event in chain.values():
            assert (
                self._verifier_module().jcs_sha256_hex(event["payload"])
                == event["evidence_payload_hash"]
            )


# =============================================================================
# The producer schema
# =============================================================================


class TestProducerSchema:
    def test_the_schema_names_the_discovery_endpoint(self) -> None:
        verification = RECEIPT_SCHEMA_V3_DOCUMENT["x-verification"]
        assert verification["key_discovery"] == "/.well-known/inntris-authority-keys.json"

    def test_the_schema_does_not_claim_the_event_is_anchored(self) -> None:
        text = json.dumps(RECEIPT_SCHEMA_V3_DOCUMENT)
        assert "not itself" in RECEIPT_SCHEMA_V3_DOCUMENT["x-verification"]["not_anchored"]
        assert "settled" in text

    def test_the_schema_is_serialisable(self) -> None:
        assert json.loads(json.dumps(RECEIPT_SCHEMA_V3_DOCUMENT))["$id"] == (
            "/schema/receipt/v3.json"
        )


class TestLibraryAndVerifierAgreeOnVerdicts:
    """Belt and braces: the in-process verifier must reach the same verdict as
    the shipped one, or one of them is wrong about genuine evidence."""

    def test_a_genuine_event_verifies_in_process_too(self) -> None:
        chain = build_chain()
        result = verify_evidence_event(
            chain["decision"],
            public_key_b64=base64.b64encode(EVIDENCE_PUBLIC).decode(),
        )
        assert result.valid, result.failures

    def test_a_tampered_event_fails_in_process_too(self) -> None:
        chain = build_chain()
        chain["decision"]["payload"]["body"]["decision"] = "TAMPERED"
        chain["decision"]["evidence_payload_hash"] = jcs.sha256_hex(chain["decision"]["payload"])
        result = verify_evidence_event(
            chain["decision"],
            public_key_b64=base64.b64encode(EVIDENCE_PUBLIC).decode(),
        )
        assert not result.valid
