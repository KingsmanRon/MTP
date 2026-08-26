#!/usr/bin/env python3
"""Reconcile a Merkle proof against Base, and optionally repair the database.

Why this exists
---------------
On 2026-08-25 a Merkle root that Base had anchored was recorded as
``dead_letter``. The worker had broadcast the transaction, lost the receipt to
an RPC 403, rebroadcast, been told ``RootAlreadyAnchored`` in a form it could
not decode, and eventually given up. The chain and the database disagreed, and
the database was wrong.

Requeuing such a row is the wrong repair: it asks the worker to submit a root
the contract will reject. The right repair is to read Base, establish what is
actually true, and write that.

Safety
------
Read-only by default. ``--apply`` is required to write, and a proof is only
ever marked ``confirmed`` when the chain says so:

  * a receipt with status 1 whose ``to`` is the expected AnchorRegistry, or
  * ``isAnchored(root)`` true plus a ``getBatch`` that returns a real batch.

Nothing is inferred from a transaction having been sent. ``dead_lettered_at``
is preserved on repair so the incident stays visible in the record.

Usage
-----
    # Investigate (no writes)
    python -m scripts.reconcile_anchor_proof --proof-id 9400cba3-...

    # Include specific candidate transactions to check first
    python -m scripts.reconcile_anchor_proof --proof-id 9400cba3-... \\
        --candidate-tx 0xc5a6c34b... --candidate-tx 0xcd568081...

    # Repair after reviewing the read-only output
    python -m scripts.reconcile_anchor_proof --proof-id 9400cba3-... --apply

    # Survey every proof that is not confirmed
    python -m scripts.reconcile_anchor_proof --all-unconfirmed

Environment: DATABASE_URL, BLOCKCHAIN_PROVIDER_URL, ANCHOR_CONTRACT_ADDRESS.
No private key is needed or used — this tool never sends a transaction.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import asyncpg
from web3 import Web3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workers.anchor_worker import (  # noqa: E402
    ANCHOR_REGISTRY_ABI,
    BASE_CHAIN_ID,
    normalize_transaction_hash,
)

EXIT_OK = 0
EXIT_UNRESOLVED = 1
EXIT_ERROR = 2


@dataclass
class Finding:
    proof_id: UUID
    root: str
    db_status: str
    confirmed: bool
    source: str
    detail: str
    transaction_hash: str | None = None
    block_number: int | None = None
    gas_used: int | None = None


class ChainReader:
    """Read-only view of the AnchorRegistry. Holds no key and cannot send."""

    def __init__(self, rpc_url: str, contract_address: str, chain_id: int) -> None:
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.contract = self.w3.eth.contract(
            address=self.contract_address, abi=ANCHOR_REGISTRY_ABI
        )
        self.expected_chain_id = chain_id

    def assert_chain(self) -> None:
        actual = self.w3.eth.chain_id
        if actual != self.expected_chain_id:
            raise SystemExit(
                f"FATAL: RPC serves chain {actual}, expected {self.expected_chain_id}. "
                "Refusing to reconcile against the wrong chain."
            )

    @staticmethod
    def _root_bytes(root: str) -> bytes:
        body = root[2:] if root.startswith("0x") else root
        raw = bytes.fromhex(body)
        if len(raw) != 32:
            raise ValueError(f"Merkle root must be 32 bytes, got {len(raw)}")
        return raw

    def receipt(self, tx_hash: str) -> dict[str, Any] | None:
        try:
            return dict(self.w3.eth.get_transaction_receipt(tx_hash))
        except Exception:
            return None

    def is_anchored(self, root: str) -> bool:
        return bool(self.contract.functions.isAnchored(self._root_bytes(root)).call())

    def get_batch(self, root: str) -> dict[str, Any] | None:
        batch_id, log_count, timestamp, submitter = self.contract.functions.getBatch(
            self._root_bytes(root)
        ).call()
        if batch_id == 0:
            return None
        return {
            "batch_id": batch_id,
            "log_count": log_count,
            "timestamp": timestamp,
            "submitter": submitter,
        }

    def batch_anchored_event(self, receipt: dict[str, Any], root: str) -> bool:
        """True if this receipt carries a BatchAnchored for exactly this root."""
        try:
            events = self.contract.events.BatchAnchored().process_receipt(
                receipt, errors=__import__("web3").logs.DISCARD
            )
        except Exception:
            return False
        want = self._root_bytes(root)
        for ev in events:
            got = ev["args"].get("merkleRoot")
            if isinstance(got, (bytes, bytearray)) and bytes(got) == want:
                return True
        return False


def reconcile_one(
    chain: ChainReader,
    proof: dict[str, Any],
    candidates: list[str],
) -> Finding:
    """Establish the truth for one proof by reading Base. Writes nothing."""
    root = proof["root_hash"]
    base = {
        "proof_id": proof["id"],
        "root": root,
        "db_status": proof["status"],
    }

    # Candidate transactions: the row's own hash first, then any supplied.
    ordered: list[str] = []
    for tx in [proof.get("transaction_hash"), *candidates]:
        if tx and tx not in ordered:
            ordered.append(normalize_transaction_hash(tx))

    for tx_hash in ordered:
        receipt = chain.receipt(tx_hash)
        if receipt is None:
            print(f"    {tx_hash}  no receipt on chain")
            continue

        status = receipt.get("status")
        to_addr = receipt.get("to")
        print(f"    {tx_hash}  status={status} to={to_addr} block={receipt.get('blockNumber')}")

        if status != 1:
            continue
        if to_addr and to_addr.lower() != chain.contract_address.lower():
            print("      -> targets a different contract; not evidence for this proof")
            continue
        if not chain.batch_anchored_event(receipt, root):
            print("      -> no BatchAnchored event for this exact root; skipping")
            continue

        return Finding(
            **base,
            confirmed=True,
            source="receipt",
            detail=f"BatchAnchored for this root in {tx_hash}",
            transaction_hash=normalize_transaction_hash(receipt["transactionHash"]),
            block_number=receipt["blockNumber"],
            gas_used=receipt["gasUsed"],
        )

    # No candidate proved it. Ask the contract directly.
    if not chain.is_anchored(root):
        return Finding(
            **base,
            confirmed=False,
            source="unresolved",
            detail="AnchorRegistry does not hold this root",
        )

    batch = chain.get_batch(root)
    if batch is None:
        return Finding(
            **base,
            confirmed=False,
            source="unresolved",
            detail="isAnchored true but getBatch returned no batch — do not repair",
        )

    return Finding(
        **base,
        confirmed=True,
        source="contract_state",
        detail=(
            f"AnchorRegistry holds batch {batch['batch_id']} "
            f"(log_count={batch['log_count']}, submitter={batch['submitter']}) "
            "but no candidate transaction was identified"
        ),
        transaction_hash=proof.get("transaction_hash"),
    )


async def apply_repair(conn: asyncpg.Connection, finding: Finding) -> None:
    """Write the chain's answer. dead_lettered_at is deliberately preserved."""
    await conn.execute(
        """
        UPDATE merkle_proofs
        SET status = 'confirmed',
            transaction_hash = COALESCE($2, transaction_hash),
            block_number = COALESCE($3, block_number),
            gas_used = COALESCE($4, gas_used),
            confirmed_at = COALESCE(confirmed_at, NOW()),
            reconciled_at = COALESCE(reconciled_at, NOW()),
            next_retry_at = NULL,
            error_message = $5
        WHERE id = $1
        """,
        finding.proof_id,
        finding.transaction_hash,
        finding.block_number,
        finding.gas_used,
        f"reconciled from chain ({finding.source}): {finding.detail}",
    )


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--proof-id", help="merkle_proofs.id to reconcile")
    group.add_argument("--root", help="Merkle root hash (64 hex chars)")
    group.add_argument(
        "--all-unconfirmed",
        action="store_true",
        help="survey every proof not already confirmed",
    )
    ap.add_argument(
        "--candidate-tx",
        action="append",
        default=[],
        help="additional transaction hash to check (repeatable)",
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="write the repair. Without this the tool only reports.",
    )
    args = ap.parse_args()

    dsn = os.getenv("DATABASE_URL", "").strip()
    rpc = os.getenv("BLOCKCHAIN_PROVIDER_URL", "").strip()
    contract = os.getenv("ANCHOR_CONTRACT_ADDRESS", "").strip()
    missing = [
        n for n, v in
        (("DATABASE_URL", dsn), ("BLOCKCHAIN_PROVIDER_URL", rpc),
         ("ANCHOR_CONTRACT_ADDRESS", contract))
        if not v
    ]
    if missing:
        print(f"FATAL: missing environment: {', '.join(missing)}", file=sys.stderr)
        return EXIT_ERROR

    chain = ChainReader(rpc, contract, BASE_CHAIN_ID)
    chain.assert_chain()
    print(f"Chain {chain.expected_chain_id} via {rpc}")
    print(f"AnchorRegistry {chain.contract_address}")
    print(f"Mode: {'APPLY (will write)' if args.apply else 'READ-ONLY'}\n")

    conn = await asyncpg.connect(dsn)
    try:
        if args.all_unconfirmed:
            rows = await conn.fetch(
                """
                SELECT id, root_hash, status, transaction_hash, block_number,
                       retry_count, dead_lettered_at
                FROM merkle_proofs
                WHERE status <> 'confirmed'
                ORDER BY created_at ASC
                """
            )
        elif args.proof_id:
            rows = await conn.fetch(
                "SELECT id, root_hash, status, transaction_hash, block_number,"
                " retry_count, dead_lettered_at FROM merkle_proofs WHERE id = $1",
                UUID(args.proof_id),
            )
        else:
            root = args.root[2:] if args.root.startswith("0x") else args.root
            rows = await conn.fetch(
                "SELECT id, root_hash, status, transaction_hash, block_number,"
                " retry_count, dead_lettered_at FROM merkle_proofs WHERE root_hash = $1",
                root,
            )

        if not rows:
            print("No matching merkle_proofs row.", file=sys.stderr)
            return EXIT_ERROR

        findings: list[Finding] = []
        for row in rows:
            proof = dict(row)
            print(f"proof {proof['id']}  status={proof['status']} "
                  f"retry_count={proof['retry_count']}")
            print(f"  root {proof['root_hash']}")
            finding = reconcile_one(chain, proof, args.candidate_tx)
            findings.append(finding)

            verdict = "CONFIRMED ON CHAIN" if finding.confirmed else "UNRESOLVED"
            print(f"  => {verdict} ({finding.source}): {finding.detail}")

            if finding.confirmed and args.apply:
                await apply_repair(conn, finding)
                print(f"  => repaired: status=confirmed "
                      f"tx={finding.transaction_hash} block={finding.block_number}")
            elif finding.confirmed:
                print("  => not written (read-only). Re-run with --apply to repair.")
            print()

        confirmed = sum(1 for f in findings if f.confirmed)
        print(f"{confirmed}/{len(findings)} proof(s) confirmed on chain.")
        return EXIT_OK if confirmed == len(findings) else EXIT_UNRESOLVED
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
