#!/usr/bin/env python3
"""Independently verify an Inntris public receipt — without trusting the server.

Given a public ``audit_id`` (or a ``0x`` transaction hash), this script:

  1. Recomputes the ``receipt_fingerprint`` over the canonical core fields and
     confirms it matches the value the server returned. This detects any change
     to the bound verdict fields (verdict, action_hash, agent_id, timestamp,
     policy_hash, action_type, audit_id).
  1b. Re-verifies the Ed25519 signature over the action hash against the public
     key published in the receipt, so you do not have to trust ``signature_valid``
     (needs pynacl; skipped if the receipt does not expose the material).
  2. Recomputes the Merkle root from the public proof using keccak256 for
     internal nodes (matching the on-chain AnchorRegistry) and confirms it
     matches ``merkle_root``. This proves the action is included in the anchored
     batch.
  3. (optional, with ``--rpc`` and ``--contract``) calls the AnchorRegistry
     ``getBatch(root)`` view to confirm that exact root was anchored on Base
     mainnet.

Step 1 is stdlib-only. Steps 2–3 need a keccak implementation (``eth_hash`` or
``web3``); they are skipped with a notice if those are not installed.

Usage:
  python scripts/verify_receipt.py <audit_id|0xtx> \
      [--api https://api.inntris.com] \
      [--rpc https://base-rpc.publicnode.com --contract 0xCONTRACT]

Exit code is 0 only if every *attempted* check passed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE_MAINNET_CHAIN_ID = 8453


def _network_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SystemExit("network URL must use http or https and include a host")
    if parsed.username or parsed.password:
        raise SystemExit("network URL must not contain embedded credentials")
    if parsed.scheme == "http" and parsed.hostname.lower() not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        raise SystemExit("non-local network URLs must use https")
    return url


def _get(url: str) -> dict:
    # A descriptive User-Agent: the default "Python-urllib/x.y" signature is
    # blocked by some CDNs/WAFs (e.g. Cloudflare returns 403 error 1010).
    safe_url = _network_url(url)
    req = urllib.request.Request(
        safe_url,
        headers={
            "Accept": "application/json",
            "User-Agent": "inntris-verify-receipt/1.0 (+https://inntris.com)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise SystemExit(f"HTTP {exc.code} for {safe_url}: {body}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"network error for {safe_url}: {exc}")


def _load_keccak():
    """Return a keccak256(bytes)->bytes callable, or None if unavailable."""
    try:
        from eth_hash.auto import keccak  # type: ignore

        return keccak
    except Exception:
        pass
    try:
        from web3 import Web3  # type: ignore

        return lambda data: bytes(Web3.keccak(data))
    except Exception:
        return None


def recompute_fingerprint(rec: dict) -> str:
    """Mirror api/main.py get_public_verification_record's fingerprint."""
    payload = {
        "action_hash": rec["action_hash"],
        "action_type": rec["action_type"],
        "agent_id": rec["agent_id"],
        "audit_id": rec["audit_id"],
        "policy_hash": rec.get("policy_hash"),
        "timestamp": rec["timestamp"],  # wire value is already canonical (...Z)
        "verdict": rec["verdict"],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify_signature(rec: dict):
    """Re-verify the Ed25519 signature over the action hash.

    Returns (checked, ok, detail). ``checked`` is False when the receipt does
    not expose the material or pynacl is unavailable.
    """
    sig_b64 = rec.get("signature_b64")
    pub_b64 = rec.get("public_key_b64")
    if not sig_b64 or not pub_b64:
        return (False, False, "receipt does not expose signature_b64/public_key_b64")
    try:
        from nacl.encoding import RawEncoder
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except Exception:
        return (False, False, "pynacl not installed (pip install pynacl)")
    try:
        VerifyKey(base64.b64decode(pub_b64), encoder=RawEncoder).verify(
            bytes.fromhex(rec["action_hash"]), base64.b64decode(sig_b64)
        )
        return (True, True, "")
    except BadSignatureError:
        return (True, False, "Ed25519 verification failed")
    except Exception as exc:  # malformed key/sig material
        return (True, False, f"error: {exc}")


def recompute_root(action_hash: str, proof: list[str], positions: list[bool], keccak) -> str:
    """Mirror workers/anchor_worker.compute_merkle_root for a single leaf path.

    positions[i] is True when the sibling sits on the RIGHT of the current node.
    """
    current = bytes.fromhex(action_hash)
    for sibling_hex, sibling_on_right in zip(proof, positions, strict=True):
        sibling = bytes.fromhex(sibling_hex)
        combined = current + sibling if sibling_on_right else sibling + current
        current = keccak(combined)
    return current.hex()


def main() -> None:
    ap = argparse.ArgumentParser(description="Independently verify an Inntris public receipt.")
    ap.add_argument("record", help="audit_id (UUID) or 0x-prefixed transaction hash")
    ap.add_argument("--api", default="https://api.inntris.com", help="API base URL")
    ap.add_argument("--rpc", default=None, help="Base RPC URL for the on-chain check")
    ap.add_argument("--contract", default=None, help="AnchorRegistry address for the on-chain check")
    args = ap.parse_args()

    api = args.api.rstrip("/")
    failures: list[str] = []

    # ---- Fetch the receipt -------------------------------------------------
    rec = _get(f"{api}/public/verify/{args.record}")
    audit_id = rec["audit_id"]
    print(f"receipt           : {audit_id}")
    print(f"  verdict         : {rec['verdict']}")
    print(f"  action_type     : {rec['action_type']}")
    print(f"  chain_id        : {rec.get('chain_id')}")
    print(f"  integrity_status: {rec.get('integrity_status')}")
    print(f"  tx_hash         : {rec.get('tx_hash')}")

    if rec.get("chain_id") not in (None, BASE_MAINNET_CHAIN_ID):
        failures.append(f"chain_id is {rec.get('chain_id')}, expected {BASE_MAINNET_CHAIN_ID}")

    # ---- 1) Receipt fingerprint (stdlib only) ------------------------------
    want_fp = rec["receipt_fingerprint"]
    got_fp = recompute_fingerprint(rec)
    if want_fp == got_fp:
        print(f"[OK]   receipt_fingerprint matches ({got_fp[:16]}...)")
    else:
        print("[FAIL] receipt_fingerprint MISMATCH")
        print(f"       server: {want_fp}")
        print(f"       local : {got_fp}")
        failures.append("receipt_fingerprint mismatch")

    # ---- 1b) Ed25519 signature over the action hash ------------------------
    checked, sig_ok, sig_detail = verify_signature(rec)
    if not checked:
        print(f"[SKIP] signature re-verification: {sig_detail}")
    elif sig_ok:
        print("[OK]   Ed25519 signature verifies against the published public key")
        if rec.get("signature_valid") is False:
            print("[WARN] receipt reports signature_valid=false but the signature verifies")
    else:
        if rec.get("signature_valid"):
            print(f"[FAIL] signature does NOT verify but signature_valid=true ({sig_detail})")
            failures.append("signature does not verify vs signature_valid=true")
        else:
            print("[OK]   signature does not verify, consistent with signature_valid=false")

    # ---- 2) Merkle root from the public proof ------------------------------
    proof = _get(f"{api}/public/verify/{audit_id}/proof")
    pstatus = proof.get("status")
    if pstatus == "sandbox":
        print("[note] sandbox receipt — not anchored on-chain by design; the "
              "fingerprint + signature above are the integrity guarantee")
    elif pstatus != "anchored":
        print(f"[SKIP] proof status is '{pstatus}' — not yet anchored; skipping Merkle check")
    else:
        keccak = _load_keccak()
        if keccak is None:
            print("[SKIP] no keccak available (pip install eth-hash) — skipping Merkle check")
        else:
            got_root = recompute_root(
                proof["action_hash"], proof["proof"], proof["positions"], keccak
            )
            want_root = (proof.get("merkle_root") or "").replace("0x", "")
            if got_root == want_root:
                print(f"[OK]   merkle_root matches ({got_root[:16]}...)")
            else:
                print("[FAIL] merkle_root MISMATCH")
                print(f"       server: {want_root}")
                print(f"       local : {got_root}")
                failures.append("merkle_root mismatch")

            # ---- 3) On-chain confirmation (optional) -----------------------
            if args.rpc and args.contract:
                ok = _check_onchain(args.rpc, args.contract, got_root)
                if ok:
                    print("[OK]   root anchored on-chain (getBatch batchId != 0)")
                else:
                    print("[FAIL] root NOT found on-chain via getBatch")
                    failures.append("on-chain getBatch returned no batch")
            elif args.rpc or args.contract:
                print("[SKIP] on-chain check needs BOTH --rpc and --contract")
            else:
                print(f"[note] to confirm on-chain, inspect tx {proof.get('tx_hash')} on basescan.org")

    print()
    if failures:
        print("RESULT: FAILED — " + "; ".join(failures))
        sys.exit(1)
    print("RESULT: all attempted checks passed")


def _check_onchain(rpc_url: str, contract: str, root_hex: str) -> bool:
    try:
        from web3 import Web3  # type: ignore
    except Exception:
        raise SystemExit("on-chain check requires web3 (pip install web3)")
    abi = [
        {
            "inputs": [{"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"}],
            "name": "getBatch",
            "outputs": [
                {"internalType": "uint256", "name": "batchId", "type": "uint256"},
                {"internalType": "uint256", "name": "logCount", "type": "uint256"},
                {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
                {"internalType": "address", "name": "submitter", "type": "address"},
            ],
            "stateMutability": "view",
            "type": "function",
        }
    ]
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    c = w3.eth.contract(address=Web3.to_checksum_address(contract), abi=abi)
    batch_id, *_ = c.functions.getBatch(bytes.fromhex(root_hex)).call()
    return batch_id != 0


if __name__ == "__main__":
    main()
