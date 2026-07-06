"""The signed pack manifest — the attested object.

The SHA-256 that gets anchored, quoted, or compared is computed over the
JCS-canonical (RFC 8785) bytes of ``manifest.json`` — a sorted list of
per-file SHA-256 leaves plus pack metadata — **not** over the ZIP container.
The container is mere packaging: a verifier who re-hashes every listed file
and re-checks the Ed25519 signature over the manifest bytes has verified the
evidence, whatever bytes the wrapper happens to have. (The wrapper is still
built deterministically — see ``deterministic_zip.py`` — so the container
hash is reproducible too; it just isn't the thing being attested.)
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from nacl.encoding import RawEncoder
from nacl.signing import SigningKey

from api.jcs import canonicalize

FORMAT_NAME = "inntris-evidence-pack"
FORMAT_VERSION = "1.0"

# Arcnames excluded from the manifest's file list: the manifest cannot list
# its own hash, and the signature file is derived from the manifest.
MANIFEST_ARCNAME = "manifest.json"
SIGNATURE_ARCNAME = "manifest.sig.json"


def build_manifest(
    *,
    pack_name: str,
    snapshot_time_utc: str,
    files: dict[str, bytes],
    custody_events: list[dict[str, Any]],
    inntris_commit: str | None = None,
    anchor: dict[str, Any] | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    """Assemble the manifest dict covering every pack file.

    ``files`` maps arcname -> content bytes for every entry that will land in
    the archive except ``manifest.json`` / ``manifest.sig.json``.
    """
    file_entries = [
        {
            "path": arcname,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
        }
        for arcname, content in sorted(files.items(), key=lambda kv: kv[0].encode("utf-8"))
    ]
    manifest: dict[str, Any] = {
        "format": FORMAT_NAME,
        "format_version": FORMAT_VERSION,
        "pack_name": pack_name,
        "snapshot_time": snapshot_time_utc,
        "hash_scheme": {
            "file_leaves": "sha256",
            "manifest_hash": "sha256 over RFC 8785 (JCS) canonical manifest bytes",
            "merkle_interior": "keccak256 (matches AnchorRegistry.sol)",
            "signature": "Ed25519 over the canonical manifest bytes",
        },
        "files": file_entries,
        "custody_event_count": len(custody_events),
    }
    if inntris_commit:
        manifest["inntris_commit"] = inntris_commit
    if anchor:
        manifest["anchor"] = anchor
    if notes:
        manifest["notes"] = notes
    return manifest


def manifest_bytes(manifest: dict[str, Any]) -> bytes:
    """JCS-canonical bytes of the manifest — the exact signed/hashed input."""
    return canonicalize(manifest)


def sign_manifest(manifest: dict[str, Any], signing_key: SigningKey) -> dict[str, Any]:
    """Sign the canonical manifest bytes; returns the manifest.sig.json body.

    Ed25519 is deterministic, so the same manifest and key always produce the
    same signature — the signature file does not break byte reproducibility.
    """
    payload = manifest_bytes(manifest)
    manifest_sha256 = hashlib.sha256(payload).hexdigest()
    signed = signing_key.sign(payload)
    verify_key_bytes = signing_key.verify_key.encode(encoder=RawEncoder)
    return {
        "algorithm": "Ed25519",
        "signed_over": "JCS (RFC 8785) canonical bytes of manifest.json",
        "manifest_sha256": manifest_sha256,
        "signature_b64": base64.b64encode(signed.signature).decode("ascii"),
        "public_key_b64": base64.b64encode(verify_key_bytes).decode("ascii"),
        "public_key_sha256_fingerprint": hashlib.sha256(verify_key_bytes).hexdigest(),
    }
