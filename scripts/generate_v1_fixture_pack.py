#!/usr/bin/env python3
"""Generate the frozen v1 evidence pack used as the manifest-v2 regression corpus.

Why this exists
---------------
Manifest v2 (Block B1) breaks the pack format. B1.1 requires that the v2
verifier still verifies v1 packs — but no v1 pack has ever existed in either
this repository or ``Inntris/inntris-verify``, so there was nothing to test
against.

A v1 pack's *container* stays reproducible from METHODOLOGY.md after the
break. Its *signature* does not: re-creating one later would mean signing a
synthetic pack with the production key ``ipk-2026-01``, which manufactures a
genuine-looking production artifact. So the fixture has to be minted while
the v1 builder is still ``HEAD``, and it has to be signed with a throwaway
key that is deliberately absent from the published registry.

The test key
------------
``FIXTURE_SIGNING_SEED`` below is derived from a fixed ASCII string and is
committed in the clear on purpose. It is a test key and nothing else:

* it MUST NOT appear in ``KEYS.md`` or
  ``frontend/public/.well-known/inntris-keys.txt`` — publishing it in the
  canonical registry would make it pinnable, and a pack signed by it would
  then be indistinguishable from a production artifact to a verifier that
  trusts the registry;
* the regression test therefore passes ``--pubkey`` explicitly rather than
  resolving the key from the registry.

This is the same hazard Block A3 exists to prevent, approached from the
other direction.

Regenerating
------------
    python scripts/generate_v1_fixture_pack.py

Output is byte-identical across runs and machines (fixed seed, fixed
snapshot time, pinned ``SOURCE_DATE_EPOCH``). Regenerating after the v1
builder is gone will NOT reproduce these bytes — that is the point, and the
committed pack is the artifact of record.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from nacl.encoding import RawEncoder  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

from evidence_pack import EvidencePackBuilder, ingest_file  # noqa: E402
from workers.anchor_worker import compute_merkle_proof, compute_merkle_root  # noqa: E402

FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "packs" / "v1"
PACK_NAME = "v1-format-fixture"
PACK_FILENAME = "inntris-v1-format-fixture.zip"

# Frozen inputs. Every one of these feeds the pack hash; changing any of them
# changes the fixture and invalidates the regression corpus.
SNAPSHOT = datetime(2026, 6, 30, 0, 0, 0, tzinfo=UTC)
SOURCE_DATE_EPOCH = str(int(SNAPSHOT.timestamp()))
INGESTED_AT = datetime(2026, 6, 14, 0, 0, 0, tzinfo=UTC)
RECEIPT_TIMESTAMP = "2026-06-15T12:00:00Z"
AGENT_ID = "0be76c5e-93d2-4d4a-a86e-53c8a1d3f6b1"

# Test keys — see the module docstring. Never publish either of these.
FIXTURE_SIGNING_SEED = hashlib.sha256(
    b"inntris-v1-fixture-manifest-key-do-not-publish"
).digest()
FIXTURE_AGENT_SEED = hashlib.sha256(
    b"inntris-v1-fixture-agent-key-do-not-publish"
).digest()

EVIDENCE_FILES = {
    "pilot.log": "blocked wire_transfer $250,000 at 2026-06-14T09:00:00Z\n",
    "policy.json": '{"blocked": ["wire_transfer"]}\n',
}

RECEIPT_SEEDS = [
    ("11111111-1111-4111-8111-111111111111", "v1-fixture-payload-one"),
    ("22222222-2222-4222-8222-222222222222", "v1-fixture-payload-two"),
    ("33333333-3333-4333-8333-333333333333", "v1-fixture-payload-three"),
]

ANCHOR = {
    "network": "base-mainnet",
    "chain_id": 8453,
    "contract": "0x0600eA15802c8d2EA429371b2EB0aacCFe321480",
}


def _make_receipt(agent_key: SigningKey, audit_id: str, payload_seed: str) -> dict:
    """A v1 public receipt, fingerprinted under the seven-field contract.

    Mirrors ``_build_public_record`` in api/main.py as it stands at v1 —
    including the Python-sorted-JSON fingerprint, which Block B replaces.
    """
    action_hash = hashlib.sha256(payload_seed.encode()).hexdigest()
    receipt = {
        "audit_id": audit_id,
        "agent_id": AGENT_ID,
        "action_type": "financial_transaction",
        "action_hash": action_hash,
        "policy_hash": "a" * 64,
        "timestamp": RECEIPT_TIMESTAMP,
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


def _make_proofs(receipts: list[dict]) -> list[dict]:
    """Merkle proofs built with the real anchor-worker tree."""
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


def generate(out_dir: Path = FIXTURE_DIR) -> Path:
    """Write the fixture pack and its public-key sidecar. Returns the zip path."""
    os.environ["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH

    signing_key = SigningKey(FIXTURE_SIGNING_SEED)
    agent_key = SigningKey(FIXTURE_AGENT_SEED)

    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / PACK_FILENAME

    with tempfile.TemporaryDirectory() as tmp:
        source_dir = Path(tmp)
        records = []
        for name, content in EVIDENCE_FILES.items():
            path = source_dir / name
            path.write_text(content)
            records.append(ingest_file(path, name, ingested_at=INGESTED_AT))

        receipts = [
            _make_receipt(agent_key, audit_id, seed) for audit_id, seed in RECEIPT_SEEDS
        ]
        proofs = _make_proofs(receipts)

        builder = EvidencePackBuilder(
            pack_name=PACK_NAME,
            snapshot_time=SNAPSHOT,
            inntris_commit="v1-format-fixture",
            anchor=ANCHOR,
            notes=(
                "Frozen v1-format regression fixture. Signed with a throwaway test "
                "key that is deliberately absent from KEYS.md. NOT a production "
                "artifact."
            ),
        )
        for record in records:
            builder.add_evidence(record)
        for receipt, proof in zip(receipts, proofs, strict=True):
            builder.add_receipt(receipt, proof=proof)

        result = builder.build(zip_path, signing_key)

    public_key = signing_key.verify_key.encode(encoder=RawEncoder)
    (out_dir / "PUBKEY.hex").write_text(public_key.hex() + "\n")

    print(f"pack            : {result.zip_path}")
    print(f"manifest sha256 : {result.manifest_sha256}")
    print(f"zip sha256      : {result.zip_sha256}")
    print(f"files           : {result.file_count}")
    print(f"test pubkey     : {public_key.hex()}")
    print("\nverify with:")
    print(
        f"  python evidence_pack/pack_contents/verify_pack.py {zip_path} "
        f"--pubkey {public_key.hex()}"
    )
    return zip_path


if __name__ == "__main__":
    generate()
