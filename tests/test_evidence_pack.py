"""Evidence pack guarantees: determinism, chain of custody, standalone verification.

These tests pin the three properties the pack exists to provide:

1. **Byte determinism** — identical inputs produce a byte-identical archive
   (and the attested object is the signed manifest, not the container).
2. **Custody at every hop** — a file that changes between ingest and pack
   assembly hard-fails the build, and re-verification is logged as an event.
3. **Standalone verification** — the embedded ``verify_pack.py`` validates a
   pack with zero Inntris dependencies (its pure-Python Ed25519 and
   Keccak-256 fallbacks are cross-checked against pynacl and Web3 here).
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from nacl.encoding import RawEncoder
from nacl.signing import SigningKey

from evidence_pack import (
    CustodyIntegrityError,
    DeterministicZipError,
    EvidencePackBuilder,
    ingest_file,
)
from evidence_pack.deterministic_zip import validate_arcname, write_deterministic_zip
from workers.anchor_worker import compute_merkle_proof, compute_merkle_root

SNAPSHOT = datetime(2026, 6, 30, 0, 0, 0, tzinfo=UTC)
VERIFIER_PATH = (
    Path(__file__).parent.parent / "evidence_pack" / "pack_contents" / "verify_pack.py"
)


def _load_verifier_module(name: str = "verify_pack_embedded"):
    spec = importlib.util.spec_from_file_location(name, VERIFIER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_receipt(agent_key: SigningKey, audit_id: str, payload_seed: str) -> dict:
    action_hash = hashlib.sha256(payload_seed.encode()).hexdigest()
    receipt = {
        "audit_id": audit_id,
        "agent_id": "0be76c5e-93d2-4d4a-a86e-53c8a1d3f6b1",
        "action_type": "financial_transaction",
        "action_hash": action_hash,
        "policy_hash": "a" * 64,
        "timestamp": "2026-06-15T12:00:00Z",
        "verdict": "approved",
        "signature_valid": True,
    }
    canonical = json.dumps(
        {
            "action_hash": receipt["action_hash"],
            "action_type": receipt["action_type"],
            "agent_id": receipt["agent_id"],
            "audit_id": receipt["audit_id"],
            "policy_hash": receipt["policy_hash"],
            "timestamp": receipt["timestamp"],
            "verdict": receipt["verdict"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    receipt["receipt_fingerprint"] = hashlib.sha256(canonical.encode()).hexdigest()
    signed = agent_key.sign(bytes.fromhex(action_hash))
    receipt["signature_b64"] = base64.b64encode(signed.signature).decode()
    receipt["public_key_b64"] = base64.b64encode(
        agent_key.verify_key.encode(encoder=RawEncoder)
    ).decode()
    return receipt


def _make_anchored_batch(receipts: list[dict]) -> list[dict]:
    """Build proofs for a batch of receipts using the real anchor-worker tree."""
    leaves = [receipt["action_hash"] for receipt in receipts]
    root = compute_merkle_root(leaves)
    proofs = []
    for index, receipt in enumerate(receipts):
        path = compute_merkle_proof(leaves, index)
        proofs.append(
            {
                "audit_id": receipt["audit_id"],
                "action_hash": receipt["action_hash"],
                "status": "anchored",
                "proof": [node["hash"] for node in path],
                "positions": [node["position"] == 1 for node in path],
                "merkle_root": root,
                "tx_hash": "0x" + "b" * 64,
                "chain_id": 8453,
            }
        )
    return proofs


def _build_sample_pack(tmp_path: Path, out_name: str = "pack.zip"):
    """Ingest evidence, mint receipts+proofs, and build a full pack."""
    signing_key = SigningKey(b"\x11" * 32)
    agent_key = SigningKey(b"\x22" * 32)

    evidence_dir = tmp_path / "source"
    evidence_dir.mkdir(exist_ok=True)
    log_file = evidence_dir / "pilot.log"
    log_file.write_text("blocked wire_transfer $250,000 at 2026-06-14T09:00:00Z\n")
    policy_file = evidence_dir / "policy.json"
    policy_file.write_text('{"blocked": ["wire_transfer"]}\n')

    records = [
        ingest_file(log_file, "pilot.log", ingested_at=datetime(2026, 6, 14, tzinfo=UTC)),
        ingest_file(policy_file, "policy.json", ingested_at=datetime(2026, 6, 14, tzinfo=UTC)),
    ]

    receipts = [
        _make_receipt(agent_key, "11111111-1111-4111-8111-111111111111", "payload-one"),
        _make_receipt(agent_key, "22222222-2222-4222-8222-222222222222", "payload-two"),
        _make_receipt(agent_key, "33333333-3333-4333-8333-333333333333", "payload-three"),
    ]
    proofs = _make_anchored_batch(receipts)

    builder = EvidencePackBuilder(
        pack_name="pilot-test-2026-06",
        snapshot_time=SNAPSHOT,
        inntris_commit="deadbeef",
        anchor={
            "network": "base-mainnet",
            "chain_id": 8453,
            "contract": "0x0600eA15802c8d2EA429371b2EB0aacCFe321480",
        },
    )
    for record in records:
        builder.add_evidence(record)
    for receipt, proof in zip(receipts, proofs, strict=True):
        builder.add_receipt(receipt, proof=proof)
    builder.add_document("scope.md", "# Scope\nCovered workflow: treasury transfers.\n")

    result = builder.build(tmp_path / out_name, signing_key)
    return result, signing_key, records


# =============================================================================
# 1) Deterministic container
# =============================================================================


class TestDeterministicZip:
    def test_same_entries_same_bytes_regardless_of_order(self, tmp_path):
        entries = [("b.txt", b"bravo"), ("a/c.txt", b"charlie"), ("a.txt", b"alpha")]
        write_deterministic_zip(tmp_path / "one.zip", entries, snapshot_time=SNAPSHOT)
        write_deterministic_zip(tmp_path / "two.zip", reversed(entries), snapshot_time=SNAPSHOT)
        assert (tmp_path / "one.zip").read_bytes() == (tmp_path / "two.zip").read_bytes()

    def test_entries_sorted_and_metadata_pinned(self, tmp_path):
        write_deterministic_zip(
            tmp_path / "pack.zip", {"z.txt": b"z", "a.txt": b"a"}, snapshot_time=SNAPSHOT
        )
        with zipfile.ZipFile(tmp_path / "pack.zip") as zf:
            infos = zf.infolist()
        assert [info.filename for info in infos] == ["a.txt", "z.txt"]
        for info in infos:
            assert info.date_time == (2026, 6, 30, 0, 0, 0)
            assert info.create_system == 3
            assert info.external_attr == (0o100644 << 16)

    def test_source_date_epoch_overrides_snapshot(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "315532800")  # 1980-01-01T00:00:00Z
        write_deterministic_zip(tmp_path / "pack.zip", {"a.txt": b"a"}, snapshot_time=SNAPSHOT)
        with zipfile.ZipFile(tmp_path / "pack.zip") as zf:
            assert zf.infolist()[0].date_time == (1980, 1, 1, 0, 0, 0)

    @pytest.mark.parametrize(
        "arcname",
        ["/abs.txt", "../up.txt", "a//b.txt", "dir/", "back\\slash.txt", "", "./dot.txt"],
    )
    def test_rejects_unsafe_arcnames(self, arcname):
        with pytest.raises(DeterministicZipError):
            validate_arcname(arcname)

    def test_rejects_duplicate_arcnames(self, tmp_path):
        with pytest.raises(DeterministicZipError, match="duplicate"):
            write_deterministic_zip(
                tmp_path / "pack.zip",
                [("a.txt", b"one"), ("a.txt", b"two")],
                snapshot_time=SNAPSHOT,
            )


class TestPackDeterminism:
    def test_two_builds_are_byte_identical(self, tmp_path):
        result_one, _, records = _build_sample_pack(tmp_path, "one.zip")

        # Touch the source files (same content, new mtimes) and rebuild in a
        # different order-independent pass: bytes must not change.
        for record in records:
            source = Path(record.source_path)
            source.write_bytes(source.read_bytes())
        result_two, _, _ = _build_sample_pack(tmp_path, "two.zip")

        assert (tmp_path / "one.zip").read_bytes() == (tmp_path / "two.zip").read_bytes()
        assert result_one.zip_sha256 == result_two.zip_sha256
        assert result_one.manifest_sha256 == result_two.manifest_sha256

    def test_attested_hash_is_manifest_hash_not_container(self, tmp_path):
        result, _, _ = _build_sample_pack(tmp_path)
        with zipfile.ZipFile(result.zip_path) as zf:
            manifest_raw = zf.read("manifest.json")
            sig_body = json.loads(zf.read("manifest.sig.json"))
        assert hashlib.sha256(manifest_raw).hexdigest() == result.manifest_sha256
        assert sig_body["manifest_sha256"] == result.manifest_sha256
        assert result.manifest_sha256 != result.zip_sha256

    def test_manifest_covers_every_file_both_directions(self, tmp_path):
        result, _, _ = _build_sample_pack(tmp_path)
        with zipfile.ZipFile(result.zip_path) as zf:
            names = set(zf.namelist())
            manifest = json.loads(zf.read("manifest.json"))
        listed = {entry["path"] for entry in manifest["files"]}
        assert listed == names - {"manifest.json", "manifest.sig.json"}
        assert {"verify_pack.py", "METHODOLOGY.md", "custody_log.json"} <= listed


# =============================================================================
# 2) Chain of custody
# =============================================================================


class TestCustody:
    def test_tampered_file_hard_fails_the_build(self, tmp_path):
        source = tmp_path / "evidence.log"
        source.write_text("original content\n")
        record = ingest_file(source, "evidence.log")

        source.write_text("tampered content\n")  # storage corruption / swap

        builder = EvidencePackBuilder(pack_name="t", snapshot_time=SNAPSHOT)
        with pytest.raises(CustodyIntegrityError, match="retrieval re-verification"):
            builder.add_evidence(record)

    def test_reverification_is_logged_as_custody_event(self, tmp_path):
        result, _, _ = _build_sample_pack(tmp_path)
        with zipfile.ZipFile(result.zip_path) as zf:
            custody_log = json.loads(zf.read("custody_log.json"))
        events = custody_log["events"]
        reverified = [e for e in events if e["event"] == "hash_reverified_at_retrieval"]
        ingested = [e for e in events if e["event"] == "ingested"]
        assert len(reverified) == 2  # one per evidence file
        assert len(ingested) == 2
        for event in reverified:
            assert event["result"] == "match"
            assert event["ingest_sha256"] == event["retrieval_sha256"]
            assert event["verified_at"] == "2026-06-30T00:00:00Z"

    def test_ingest_records_stream_hash(self, tmp_path):
        source = tmp_path / "big.bin"
        content = b"\xab" * (3 * 1024 * 1024 + 17)
        source.write_bytes(content)
        record = ingest_file(source, "big.bin")
        assert record.sha256 == hashlib.sha256(content).hexdigest()
        assert record.size_bytes == len(content)


# =============================================================================
# 3) Standalone verification (embedded verifier, zero Inntris dependencies)
# =============================================================================


class TestPureCryptoFallbacks:
    def test_pure_keccak256_matches_web3(self):
        module = _load_verifier_module()
        from web3 import Web3

        vectors = [b"", b"abc", b"getBatch(bytes32)", b"\x00" * 136, b"x" * 1000]
        for data in vectors:
            assert module.pure_keccak256(data) == bytes(Web3.keccak(data)), data

    def test_pure_ed25519_matches_pynacl(self):
        module = _load_verifier_module()
        key = SigningKey(b"\x33" * 32)
        public = key.verify_key.encode(encoder=RawEncoder)
        message = b"the attested object is the manifest"
        signature = key.sign(message).signature

        assert module.pure_ed25519_verify(public, message, signature) is True
        assert module.pure_ed25519_verify(public, message + b"!", signature) is False
        tampered = bytearray(signature)
        tampered[0] ^= 0x01
        assert module.pure_ed25519_verify(public, message, bytes(tampered)) is False

    def test_verifier_orchestration_runs_on_pure_fallbacks(self, tmp_path, monkeypatch):
        """Block pynacl/eth-hash/web3 imports: the verifier must still pass."""
        result, signing_key, _ = _build_sample_pack(tmp_path)

        class _Block:
            blocked = {"nacl", "eth_hash", "web3"}

            def find_spec(self, name, path=None, target=None):  # noqa: ARG002
                if name.split(".")[0] in self.blocked:
                    raise ImportError(f"{name} blocked for pure-python test")
                return None

        for mod_name in list(sys.modules):
            if mod_name.split(".")[0] in _Block.blocked:
                monkeypatch.delitem(sys.modules, mod_name)
        monkeypatch.setattr(sys, "meta_path", [_Block(), *sys.meta_path])

        module = _load_verifier_module("verify_pack_pure")
        keccak, keccak_impl = module.load_keccak256()
        _, ed_impl = module.load_ed25519_verify()
        assert keccak_impl == "pure-python"
        assert ed_impl == "pure-python (RFC 8032)"

        pinned = signing_key.verify_key.encode(encoder=RawEncoder)
        assert module.verify_pack(result.zip_path, pinned, None, None) == 0


class TestVerifierEndToEnd:
    def _run_verifier(self, tmp_path: Path, pack: Path, *extra: str):
        if pack.is_dir():
            verifier = pack / "verify_pack.py"
        else:
            verifier = tmp_path / "verify_pack.py"
            with zipfile.ZipFile(pack) as zf:
                verifier.write_bytes(zf.read("verify_pack.py"))
        return subprocess.run(
            [sys.executable, str(verifier), str(pack), *extra],
            capture_output=True,
            text=True,
            timeout=120,
        )

    def test_built_pack_verifies_with_pinned_key(self, tmp_path):
        result, signing_key, _ = _build_sample_pack(tmp_path)
        pubkey_hex = signing_key.verify_key.encode(encoder=RawEncoder).hex()
        proc = self._run_verifier(tmp_path, result.zip_path, "--pubkey", pubkey_hex)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "all attempted checks passed" in proc.stdout
        assert "merkle root rebuilt" in proc.stdout
        assert "matches the pinned --pubkey" in proc.stdout

    def test_wrong_pinned_key_fails(self, tmp_path):
        result, _, _ = _build_sample_pack(tmp_path)
        wrong = SigningKey(b"\x44" * 32).verify_key.encode(encoder=RawEncoder).hex()
        proc = self._run_verifier(tmp_path, result.zip_path, "--pubkey", wrong)
        assert proc.returncode == 1
        assert "does NOT match --pubkey" in proc.stdout

    def _rewrite_zip(self, source: Path, target: Path, mutate) -> None:
        with zipfile.ZipFile(source) as zf:
            entries = {name: zf.read(name) for name in zf.namelist()}
        mutate(entries)
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, content in entries.items():
                zf.writestr(name, content)

    def test_tampered_evidence_file_fails(self, tmp_path):
        result, _, _ = _build_sample_pack(tmp_path)
        tampered = tmp_path / "tampered.zip"

        def mutate(entries):
            entries["evidence/pilot.log"] = b"rewritten history\n"

        self._rewrite_zip(result.zip_path, tampered, mutate)
        proc = self._run_verifier(tmp_path, tampered)
        assert proc.returncode == 1
        assert "sha256 mismatch for evidence/pilot.log" in proc.stdout

    def test_tampered_manifest_breaks_signature(self, tmp_path):
        result, _, _ = _build_sample_pack(tmp_path)
        tampered = tmp_path / "tampered.zip"

        def mutate(entries):
            manifest = json.loads(entries["manifest.json"])
            manifest["pack_name"] = "forged"
            entries["manifest.json"] = json.dumps(manifest).encode()

        self._rewrite_zip(result.zip_path, tampered, mutate)
        proc = self._run_verifier(tmp_path, tampered)
        assert proc.returncode == 1
        assert "does NOT verify" in proc.stdout or "sha256 mismatch" in proc.stdout

    def test_smuggled_file_fails(self, tmp_path):
        result, _, _ = _build_sample_pack(tmp_path)
        tampered = tmp_path / "tampered.zip"

        def mutate(entries):
            entries["evidence/extra.txt"] = b"not in the manifest"

        self._rewrite_zip(result.zip_path, tampered, mutate)
        proc = self._run_verifier(tmp_path, tampered)
        assert proc.returncode == 1
        assert "not listed in manifest" in proc.stdout

    def test_tampered_receipt_breaks_fingerprint_and_merkle(self, tmp_path):
        result, _, _ = _build_sample_pack(tmp_path)
        tampered = tmp_path / "tampered.zip"
        audit_id = "11111111-1111-4111-8111-111111111111"

        def mutate(entries):
            receipt = json.loads(entries[f"receipts/{audit_id}.json"])
            receipt["verdict"] = "blocked"  # rewrite history
            entries[f"receipts/{audit_id}.json"] = json.dumps(receipt).encode()

        self._rewrite_zip(result.zip_path, tampered, mutate)
        proc = self._run_verifier(tmp_path, tampered)
        assert proc.returncode == 1
        assert f"sha256 mismatch for receipts/{audit_id}.json" in proc.stdout
        assert "fingerprint mismatch" in proc.stdout

    def test_verifier_works_on_extracted_directory(self, tmp_path):
        result, signing_key, _ = _build_sample_pack(tmp_path)
        extracted = tmp_path / "extracted"
        with zipfile.ZipFile(result.zip_path) as zf:
            zf.extractall(extracted)
        pubkey_hex = signing_key.verify_key.encode(encoder=RawEncoder).hex()
        proc = self._run_verifier(tmp_path, extracted, "--pubkey", pubkey_hex)
        assert proc.returncode == 0, proc.stdout + proc.stderr
