#!/usr/bin/env python3
"""Build a deterministic, custody-checked, independently verifiable evidence pack.

Three subcommands mirror the custody hops:

  keygen   Generate an Ed25519 manifest signing key (hex seed) and print the
           public key + fingerprint to publish.

  ingest   Hash source artifacts as they enter custody and append their
           ingest records to a JSON ledger. Run this when evidence is
           captured, not when the pack is assembled.

  build    Assemble the pack from an ingest ledger plus receipt/proof JSON
           exports. Every ledger file is RE-HASHED at this point and compared
           against its ingest-time SHA-256 — a mismatch aborts the build.
           The output ZIP is byte-reproducible (honors SOURCE_DATE_EPOCH) and
           embeds verify_pack.py + METHODOLOGY.md for offline verification.

Examples:
    python scripts/build_evidence_pack.py keygen --out signing.key
    python scripts/build_evidence_pack.py ingest --ledger ledger.json evidence/*.log
    SOURCE_DATE_EPOCH=1750000000 python scripts/build_evidence_pack.py build \
        --ledger ledger.json --receipts-dir receipts/ \
        --name pilot-acme-2026-06 --snapshot-time 2026-06-30T00:00:00Z \
        --signing-key-file signing.key --out pack.zip
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from nacl.encoding import RawEncoder  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

from evidence_pack import (  # noqa: E402
    CustodyIntegrityError,
    EvidencePackBuilder,
    EvidenceRecord,
    ingest_file,
)

BASE_MAINNET_ANCHOR = {
    "network": "base-mainnet",
    "chain_id": 8453,
    "contract": "0x0600eA15802c8d2EA429371b2EB0aacCFe321480",
}


def _parse_snapshot_time(value: str) -> datetime:
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise argparse.ArgumentTypeError("snapshot time must include a timezone (use Z)")
    return moment.astimezone(UTC)


def _load_signing_key(path: Path) -> SigningKey:
    seed_hex = path.read_text().strip()
    return SigningKey(bytes.fromhex(seed_hex))


def cmd_keygen(args: argparse.Namespace) -> int:
    key = SigningKey.generate()
    out = Path(args.out)
    out.write_text(key.encode(encoder=RawEncoder).hex() + "\n")
    out.chmod(0o600)
    public = key.verify_key.encode(encoder=RawEncoder)
    print(f"signing key seed written to {out} (keep private, mode 0600)")
    print(f"public key (hex)   : {public.hex()}")
    print(f"public key (b64)   : {base64.b64encode(public).decode()}")
    print(f"key fingerprint    : {hashlib.sha256(public).hexdigest()}")
    print("Publish the public key/fingerprint out-of-band so verifiers can pin it.")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger)
    records = json.loads(ledger_path.read_text()) if ledger_path.exists() else []
    known = {record["arcname"] for record in records}

    for raw in args.files:
        source = Path(raw)
        if not source.is_file():
            print(f"error: {source} is not a file", file=sys.stderr)
            return 1
        arcname = args.prefix + source.name
        if arcname in known:
            print(f"error: arcname {arcname!r} already in ledger", file=sys.stderr)
            return 1
        record = ingest_file(source, arcname)
        records.append(record.to_dict())
        known.add(arcname)
        print(f"ingested {source} -> {arcname} sha256={record.sha256}")

    ledger_path.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    print(f"ledger updated: {ledger_path} ({len(records)} record(s))")
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    builder = EvidencePackBuilder(
        pack_name=args.name,
        snapshot_time=args.snapshot_time,
        inntris_commit=args.commit,
        anchor=BASE_MAINNET_ANCHOR if args.anchor == "base-mainnet" else None,
        notes=args.notes,
    )

    if args.ledger:
        for data in json.loads(Path(args.ledger).read_text()):
            try:
                builder.add_evidence(EvidenceRecord.from_dict(data))
            except CustodyIntegrityError as exc:
                print(f"CUSTODY FAILURE — build aborted.\n{exc}", file=sys.stderr)
                return 2

    if args.receipts_dir:
        receipts_dir = Path(args.receipts_dir)
        proofs_dir = Path(args.proofs_dir) if args.proofs_dir else receipts_dir / "proofs"
        for receipt_path in sorted(receipts_dir.glob("*.json")):
            receipt = json.loads(receipt_path.read_text())
            proof_path = proofs_dir / receipt_path.name
            proof = json.loads(proof_path.read_text()) if proof_path.is_file() else None
            builder.add_receipt(receipt, proof=proof)

    signing_key = _load_signing_key(Path(args.signing_key_file))
    result = builder.build(args.out, signing_key)

    print(f"pack written        : {result.zip_path}")
    print(f"files               : {result.file_count}")
    print(f"custody events      : {result.custody_event_count}")
    print(f"manifest sha256     : {result.manifest_sha256}  <- the attested pack hash")
    print(f"container sha256    : {result.zip_sha256}")
    print("verify offline with : python verify_pack.py <pack> --pubkey <published-key>")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate an Ed25519 manifest signing key")
    keygen.add_argument("--out", required=True, help="file to write the hex seed to")
    keygen.set_defaults(func=cmd_keygen)

    ingest = sub.add_parser("ingest", help="hash artifacts into the custody ledger")
    ingest.add_argument("files", nargs="+", help="source files entering custody")
    ingest.add_argument("--ledger", required=True, help="JSON ledger to append records to")
    ingest.add_argument("--prefix", default="", help="arcname prefix inside evidence/")
    ingest.set_defaults(func=cmd_ingest)

    build = sub.add_parser("build", help="assemble the pack (re-verifies every ingest hash)")
    build.add_argument("--name", required=True, help="pack name, e.g. pilot-acme-2026-06")
    build.add_argument(
        "--snapshot-time",
        required=True,
        type=_parse_snapshot_time,
        help="evidence snapshot time, ISO 8601 UTC (e.g. 2026-06-30T00:00:00Z)",
    )
    build.add_argument("--ledger", default=None, help="ingest ledger from the ingest step")
    build.add_argument("--receipts-dir", default=None, help="directory of receipt JSON exports")
    build.add_argument(
        "--proofs-dir",
        default=None,
        help="directory of proof JSON exports (default: <receipts-dir>/proofs)",
    )
    build.add_argument("--signing-key-file", required=True, help="hex seed file from keygen")
    build.add_argument("--commit", default=None, help="Inntris commit SHA for the manifest")
    build.add_argument(
        "--anchor",
        choices=["base-mainnet", "none"],
        default="base-mainnet",
        help="anchor metadata to embed (default: base-mainnet AnchorRegistry)",
    )
    build.add_argument("--notes", default=None, help="freeform manifest notes")
    build.add_argument("--out", required=True, help="output .zip path")
    build.set_defaults(func=cmd_build)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
