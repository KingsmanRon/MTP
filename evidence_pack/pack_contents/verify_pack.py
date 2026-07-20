#!/usr/bin/env python3
"""Standalone offline verifier for an Inntris evidence pack.

This script ships INSIDE every evidence pack and verifies the pack with zero
Inntris dependencies — no Inntris endpoint, no Inntris library, no network at
all except the optional on-chain step, which talks only to a Base RPC node of
YOUR choosing. Verification that routes through the vendor of the evidence is
circular; this script exists so it never has to.

What it checks, in order:

1. The Ed25519 signature in ``manifest.sig.json`` over the exact bytes of
   ``manifest.json`` (pass ``--pubkey`` to pin the publicly published Inntris
   signing key instead of trusting the copy embedded in the pack).
2. Every file listed in the manifest is present and its SHA-256 leaf matches;
   every file in the pack is listed in the manifest (nothing smuggled in or
   silently dropped).
3. Each receipt's ``receipt_fingerprint`` recomputed from the canonical
   seven-field contract, and the agent's Ed25519 signature over the action
   hash.
4. Each Merkle inclusion proof rebuilt leaf-to-root with keccak256 (matching
   the on-chain AnchorRegistry), compared against the recorded root.
5. Optionally (``--rpc``): ``AnchorRegistry.getBatch(root)`` called directly
   via raw JSON-RPC ``eth_call`` to confirm the root is anchored on Base.

Requirements: Python 3.10+ standard library only. If ``pynacl`` or
``eth-hash`` happen to be installed they are used for speed; otherwise
built-in pure-Python Ed25519 (RFC 8032) and Keccak-256 implementations are
used. Run it like:

    python verify_pack.py /path/to/pack.zip
    python verify_pack.py /path/to/extracted-pack-dir --pubkey <hex-or-b64>
    python verify_pack.py pack.zip --rpc https://base-rpc.publicnode.com

Exit code is 0 only if every attempted check passed. See METHODOLOGY.md in
this pack for the exact canonicalization and hash-scheme contract.
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
import zipfile
from pathlib import Path
from typing import Any

MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig.json"

# =============================================================================
# Pure-Python Keccak-256 (original Keccak padding, as used by Ethereum).
# Used only when eth-hash / web3 is not installed. Validated against
# keccak256(b"") == c5d2460186...45d85a470 at startup.
# =============================================================================

_MASK64 = (1 << 64) - 1

_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_KECCAK_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotl64(value: int, shift: int) -> int:
    shift %= 64
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(lanes: list[list[int]]) -> list[list[int]]:
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        # theta
        c = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        lanes = [[lanes[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(lanes[x][y], _KECCAK_ROTATIONS[x][y])
        # chi
        lanes = [
            [b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)]
            for x in range(5)
        ]
        # iota
        lanes[0][0] ^= round_constant
    return lanes


def pure_keccak256(data: bytes) -> bytes:
    rate = 136  # bytes; capacity 512 bits for a 256-bit digest
    padded = bytearray(data)
    pad_len = rate - (len(padded) % rate)
    padded += bytes(pad_len)
    padded[len(data)] ^= 0x01  # original Keccak domain bit (not SHA-3's 0x06)
    padded[-1] ^= 0x80

    lanes = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            lanes[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        lanes = _keccak_f1600(lanes)

    out = bytearray()
    for i in range(4):  # 4 lanes * 8 bytes = 32-byte digest
        out += lanes[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out)


def load_keccak256():
    """Prefer an installed keccak; fall back to the pure-Python sponge."""
    try:
        from eth_hash.auto import keccak  # type: ignore

        return (lambda data: bytes(keccak(data))), "eth-hash"
    except ImportError:
        pass
    try:
        from web3 import Web3  # type: ignore

        return (lambda data: bytes(Web3.keccak(data))), "web3"
    except ImportError:
        pass
    empty = pure_keccak256(b"").hex()
    assert empty == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", (
        "pure-Python keccak self-test failed"
    )
    return pure_keccak256, "pure-python"


# =============================================================================
# Pure-Python Ed25519 verification (RFC 8032, verify-only).
# Used only when pynacl is not installed. Slow (~50ms/verification) but has
# no dependencies, which is the point.
# =============================================================================

_ED_P = 2**255 - 19
_ED_Q = 2**252 + 27742317777372353535851937790883648493  # group order


def _ed_inv(x: int) -> int:
    return pow(x, _ED_P - 2, _ED_P)


_ED_D = (-121665 * _ed_inv(121666)) % _ED_P
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)

_EdPoint = tuple[int, int, int, int]  # extended homogeneous (X, Y, Z, T)

_ED_IDENTITY: _EdPoint = (0, 1, 1, 0)


def _ed_point_add(p1: _EdPoint, p2: _EdPoint) -> _EdPoint:
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % _ED_P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % _ED_P
    c = 2 * p1[3] * p2[3] * _ED_D % _ED_P
    d = 2 * p1[2] * p2[2] % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_point_mul(scalar: int, point: _EdPoint) -> _EdPoint:
    result = _ED_IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _ed_point_add(result, point)
        point = _ed_point_add(point, point)
        scalar >>= 1
    return result


def _ed_point_equal(p1: _EdPoint, p2: _EdPoint) -> bool:
    # Compare projective coordinates: X1/Z1 == X2/Z2 and Y1/Z1 == Y2/Z2.
    if (p1[0] * p2[2] - p2[0] * p1[2]) % _ED_P != 0:
        return False
    return (p1[1] * p2[2] - p2[1] * p1[2]) % _ED_P == 0


def _ed_recover_x(y: int, sign: int) -> int | None:
    if y >= _ED_P:
        return None
    x2 = (y * y - 1) * _ed_inv(_ED_D * y * y + 1) % _ED_P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = x * _ED_SQRT_M1 % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


_ED_G_Y = 4 * _ed_inv(5) % _ED_P
_ED_G_X = _ed_recover_x(_ED_G_Y, 0)
assert _ED_G_X is not None
_ED_G: _EdPoint = (_ED_G_X, _ED_G_Y, 1, _ED_G_X * _ED_G_Y % _ED_P)


def _ed_point_decompress(compressed: bytes) -> _EdPoint | None:
    if len(compressed) != 32:
        return None
    y = int.from_bytes(compressed, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _ED_P)


def pure_ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    point_a = _ed_point_decompress(public_key)
    if point_a is None:
        return False
    r_bytes = signature[:32]
    point_r = _ed_point_decompress(r_bytes)
    if point_r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_Q:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % _ED_Q
    lhs = _ed_point_mul(s, _ED_G)
    rhs = _ed_point_add(point_r, _ed_point_mul(k, point_a))
    return _ed_point_equal(lhs, rhs)


def load_ed25519_verify():
    """Prefer pynacl; fall back to the pure-Python RFC 8032 implementation."""
    try:
        from nacl.exceptions import BadSignatureError  # type: ignore
        from nacl.signing import VerifyKey  # type: ignore

        def _nacl_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
            try:
                VerifyKey(public_key).verify(message, signature)
                return True
            except (BadSignatureError, ValueError, TypeError):
                return False

        return _nacl_verify, "pynacl"
    except ImportError:
        # RFC 8032 §7.1 TEST 3 known answer, checked at startup like the
        # keccak fallback above (plus a bit-flipped negative control).
        pk = bytes.fromhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
        msg = bytes.fromhex("af82")
        sig = bytes.fromhex(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        )
        assert pure_ed25519_verify(pk, msg, sig) and not pure_ed25519_verify(
            pk, msg, sig[:-1] + bytes([sig[-1] ^ 0x01])
        ), "pure-Python Ed25519 self-test failed"
        return pure_ed25519_verify, "pure-python (RFC 8032)"


# =============================================================================
# Pack reading (works on the .zip or an extracted directory)
# =============================================================================


class PackReader:
    def __init__(self, pack_path: Path):
        self.pack_path = pack_path
        if pack_path.is_dir():
            self._zip = None
        else:
            self._zip = zipfile.ZipFile(pack_path)

    def names(self) -> list[str]:
        if self._zip is not None:
            return [n for n in self._zip.namelist() if not n.endswith("/")]
        return sorted(
            str(p.relative_to(self.pack_path)).replace("\\", "/")
            for p in self.pack_path.rglob("*")
            if p.is_file()
        )

    def read(self, name: str) -> bytes:
        if self._zip is not None:
            return self._zip.read(name)
        return (self.pack_path / name).read_bytes()


# =============================================================================
# Receipt / Merkle checks (mirror docs/RECEIPT_CANONICALIZATION.md)
# =============================================================================


def recompute_fingerprint(receipt: dict[str, Any]) -> str:
    """The seven-field canonical fingerprint contract, byte-for-byte."""
    payload = {
        "action_hash": receipt["action_hash"],
        "action_type": receipt["action_type"],
        "agent_id": receipt["agent_id"],
        "audit_id": receipt["audit_id"],
        "policy_hash": receipt.get("policy_hash"),
        "timestamp": receipt["timestamp"],
        "verdict": receipt["verdict"],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def recompute_merkle_root(
    action_hash: str, proof: list[str], positions: list[bool], keccak256
) -> str:
    """Rebuild the root from a leaf. positions[i] True == sibling on the RIGHT."""
    if len(proof) != len(positions):
        raise ValueError(
            f"malformed proof: {len(proof)} siblings but {len(positions)} positions"
        )
    current = bytes.fromhex(action_hash)
    for sibling_hex, sibling_on_right in zip(proof, positions, strict=True):
        sibling = bytes.fromhex(sibling_hex)
        combined = current + sibling if sibling_on_right else sibling + current
        current = keccak256(combined)
    return current.hex()


# =============================================================================
# Optional on-chain check: raw eth_call to AnchorRegistry.getBatch(bytes32)
# =============================================================================


def _network_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("network URL must use http or https and include a host")
    if parsed.username or parsed.password:
        raise ValueError("network URL must not contain embedded credentials")
    if parsed.scheme == "http" and parsed.hostname.lower() not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        raise ValueError("non-local network URLs must use https")
    return url


def _rpc_call(rpc_url: str, method: str, params: list[Any]) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    # _network_url rejects file and other local-resource schemes above.
    req = urllib.request.Request(
        _network_url(rpc_url),
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosemgrep
        reply = json.loads(resp.read().decode())
    if "error" in reply:
        raise RuntimeError(f"RPC error: {reply['error']}")
    return reply["result"]


def check_root_onchain(rpc_url: str, contract: str, root_hex: str, keccak256) -> tuple[bool, str]:
    """Call getBatch(root); anchored iff the returned batchId is nonzero."""
    selector = keccak256(b"getBatch(bytes32)")[:4]
    data = "0x" + selector.hex() + root_hex.replace("0x", "").rjust(64, "0")
    result = _rpc_call(rpc_url, "eth_call", [{"to": contract, "data": data}, "latest"])
    raw = bytes.fromhex(result.replace("0x", ""))
    if len(raw) < 32:
        return False, f"short eth_call return ({len(raw)} bytes)"
    batch_id = int.from_bytes(raw[:32], "big")
    if batch_id == 0:
        return False, "getBatch returned batchId=0 (root not anchored)"
    detail = f"batchId={batch_id}"
    if len(raw) >= 96:
        detail += f", logCount={int.from_bytes(raw[32:64], 'big')}"
        detail += f", anchoredAt={int.from_bytes(raw[64:96], 'big')}"
    return True, detail


# =============================================================================
# Main verification flow
# =============================================================================


class Reporter:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def ok(self, message: str) -> None:
        print(f"[OK]   {message}")

    def fail(self, message: str) -> None:
        print(f"[FAIL] {message}")
        self.failures.append(message)

    def skip(self, message: str) -> None:
        print(f"[SKIP] {message}")

    def warn(self, message: str) -> None:
        print(f"[WARN] {message}")


def _decode_key_argument(value: str) -> bytes:
    """Accept a 64-char hex or base64 Ed25519 public key."""
    candidate = value.strip()
    if len(candidate) == 64:
        try:
            return bytes.fromhex(candidate)
        except ValueError:
            pass
    return base64.b64decode(candidate)


def verify_pack(
    pack_path: Path,
    pinned_pubkey: bytes | None,
    rpc_url: str | None,
    contract_override: str | None,
) -> int:
    report = Reporter()
    keccak256, keccak_impl = load_keccak256()
    ed25519_verify, ed_impl = load_ed25519_verify()
    print(f"pack      : {pack_path}")
    print(f"crypto    : keccak256 via {keccak_impl}, Ed25519 via {ed_impl}")
    print()

    reader = PackReader(pack_path)
    names = set(reader.names())

    # ---- 1) Manifest signature --------------------------------------------
    if MANIFEST_NAME not in names or SIGNATURE_NAME not in names:
        report.fail(f"pack must contain {MANIFEST_NAME} and {SIGNATURE_NAME}")
        print(f"\nRESULT: FAILED — {'; '.join(report.failures)}")
        return 1

    manifest_raw = reader.read(MANIFEST_NAME)
    manifest = json.loads(manifest_raw)
    sig_body = json.loads(reader.read(SIGNATURE_NAME))

    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    if manifest_sha256 == sig_body.get("manifest_sha256"):
        report.ok(f"manifest sha256 matches signature file ({manifest_sha256[:16]}...)")
    else:
        report.fail(
            f"manifest sha256 mismatch: computed {manifest_sha256}, "
            f"signature file says {sig_body.get('manifest_sha256')}"
        )

    embedded_pubkey = base64.b64decode(sig_body["public_key_b64"])
    signature = base64.b64decode(sig_body["signature_b64"])
    key_fingerprint = hashlib.sha256(embedded_pubkey).hexdigest()

    if pinned_pubkey is not None:
        if embedded_pubkey == pinned_pubkey:
            report.ok("embedded signing key matches the pinned --pubkey")
        else:
            report.fail(
                "embedded signing key does NOT match --pubkey "
                f"(embedded fingerprint {key_fingerprint})"
            )
    else:
        report.warn(
            "no --pubkey pinned: the signature proves internal consistency only. "
            f"Cross-check this key fingerprint against Inntris's published keys: {key_fingerprint}"
        )

    if ed25519_verify(embedded_pubkey, manifest_raw, signature):
        report.ok("Ed25519 signature over manifest.json verifies")
    else:
        report.fail("Ed25519 signature over manifest.json does NOT verify")

    # ---- 2) File inventory: SHA-256 leaves, both directions ----------------
    manifest_files = {entry["path"]: entry for entry in manifest.get("files", [])}
    pack_files = names - {MANIFEST_NAME, SIGNATURE_NAME}

    missing = sorted(set(manifest_files) - pack_files)
    unlisted = sorted(pack_files - set(manifest_files))
    for path in missing:
        report.fail(f"listed in manifest but missing from pack: {path}")
    for path in unlisted:
        report.fail(f"present in pack but not listed in manifest: {path}")

    leaf_failures = 0
    for path in sorted(set(manifest_files) & pack_files):
        content = reader.read(path)
        digest = hashlib.sha256(content).hexdigest()
        entry = manifest_files[path]
        if digest != entry["sha256"]:
            report.fail(
                f"sha256 mismatch for {path}: manifest {entry['sha256']}, computed {digest}"
            )
            leaf_failures += 1
        elif len(content) != entry.get("size_bytes", len(content)):
            report.fail(f"size mismatch for {path}")
            leaf_failures += 1
    if not leaf_failures and not missing and not unlisted:
        report.ok(f"all {len(manifest_files)} file hashes match the signed manifest")

    # ---- 3) Receipts: fingerprint + agent signature ------------------------
    receipt_names = sorted(n for n in pack_files if n.startswith("receipts/"))
    proof_names = {n for n in pack_files if n.startswith("proofs/")}
    anchored_roots: dict[str, str] = {}  # root -> example audit_id

    for name in receipt_names:
        receipt = json.loads(reader.read(name))
        audit_id = receipt.get("audit_id", name)

        want_fp = receipt.get("receipt_fingerprint")
        got_fp = recompute_fingerprint(receipt)
        if want_fp == got_fp:
            report.ok(f"receipt {audit_id}: fingerprint matches ({got_fp[:16]}...)")
        else:
            report.fail(f"receipt {audit_id}: fingerprint mismatch (computed {got_fp})")

        sig_b64 = receipt.get("signature_b64")
        pub_b64 = receipt.get("public_key_b64")
        if sig_b64 and pub_b64:
            sig_ok = ed25519_verify(
                base64.b64decode(pub_b64),
                bytes.fromhex(receipt["action_hash"]),
                base64.b64decode(sig_b64),
            )
            if sig_ok:
                report.ok(f"receipt {audit_id}: agent Ed25519 signature verifies")
            elif receipt.get("signature_valid") is False:
                report.ok(
                    f"receipt {audit_id}: signature does not verify, "
                    "consistent with signature_valid=false"
                )
            else:
                report.fail(f"receipt {audit_id}: agent Ed25519 signature does NOT verify")
        else:
            report.skip(f"receipt {audit_id}: no signature material exposed")

        # ---- 4) Merkle inclusion proof ---------------------------------
        proof_name = f"proofs/{audit_id}.json"
        if proof_name not in proof_names:
            report.skip(f"receipt {audit_id}: no proof file in pack")
            continue
        proof = json.loads(reader.read(proof_name))
        status = proof.get("status")
        if status == "sandbox":
            report.skip(f"receipt {audit_id}: sandbox receipt, not anchored by design")
            continue
        if status not in ("anchored", "confirmed"):
            report.skip(f"receipt {audit_id}: proof status '{status}', not yet anchored")
            continue
        if proof.get("action_hash") != receipt.get("action_hash"):
            report.fail(f"receipt {audit_id}: proof action_hash differs from receipt")
            continue
        try:
            got_root = recompute_merkle_root(
                proof["action_hash"], proof["proof"], proof["positions"], keccak256
            )
        except (ValueError, KeyError, TypeError) as exc:
            report.fail(f"receipt {audit_id}: malformed merkle proof ({exc})")
            continue
        want_root = (proof.get("merkle_root") or "").replace("0x", "")
        if got_root == want_root:
            report.ok(f"receipt {audit_id}: merkle root rebuilt ({got_root[:16]}...)")
            anchored_roots.setdefault(got_root, audit_id)
        else:
            report.fail(
                f"receipt {audit_id}: merkle root mismatch "
                f"(recorded {want_root}, computed {got_root})"
            )

    if not receipt_names:
        report.warn("pack contains no receipts/ entries")

    # ---- 5) Optional on-chain anchor check ---------------------------------
    anchor_meta = manifest.get("anchor") or {}
    contract = contract_override or anchor_meta.get("contract")
    if rpc_url and anchored_roots and contract:
        chain_id_hex = _rpc_call(rpc_url, "eth_chainId", [])
        chain_id = int(chain_id_hex, 16)
        expected_chain = anchor_meta.get("chain_id")
        if expected_chain and chain_id != int(expected_chain):
            report.fail(f"RPC chain id {chain_id} != manifest anchor chain_id {expected_chain}")
        for root, audit_id in sorted(anchored_roots.items()):
            try:
                anchored, detail = check_root_onchain(rpc_url, contract, root, keccak256)
            except (urllib.error.URLError, RuntimeError, ValueError) as exc:
                report.fail(f"on-chain check errored for root {root[:16]}...: {exc}")
                continue
            if anchored:
                report.ok(f"root {root[:16]}... anchored on-chain ({detail})")
            else:
                report.fail(f"root {root[:16]}... NOT anchored on-chain ({detail}) [{audit_id}]")
    elif rpc_url and anchored_roots:
        report.skip("on-chain check: no contract address (use --contract or manifest anchor)")
    elif rpc_url:
        report.skip("on-chain check: no anchored roots to verify")
    else:
        report.skip(
            "on-chain check not requested (offline mode). "
            "Re-run with --rpc <base-rpc-url> to confirm roots in the AnchorRegistry."
        )

    print()
    if report.failures:
        print(f"RESULT: FAILED — {len(report.failures)} check(s) failed")
        for failure in report.failures:
            print(f"  - {failure}")
        return 1
    print("RESULT: all attempted checks passed")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify an Inntris evidence pack offline, with no Inntris dependencies."
    )
    parser.add_argument("pack", help="path to the evidence pack .zip or an extracted directory")
    parser.add_argument(
        "--pubkey",
        default=None,
        help="pin the published Inntris manifest signing key (hex or base64) "
        "instead of trusting the copy embedded in the pack",
    )
    parser.add_argument(
        "--rpc",
        default=None,
        help="Base JSON-RPC URL for the optional on-chain AnchorRegistry check",
    )
    parser.add_argument(
        "--contract",
        default=None,
        help="AnchorRegistry address (defaults to the manifest's anchor.contract)",
    )
    args = parser.parse_args()

    pinned = _decode_key_argument(args.pubkey) if args.pubkey else None
    sys.exit(verify_pack(Path(args.pack), pinned, args.rpc, args.contract))


if __name__ == "__main__":
    main()
