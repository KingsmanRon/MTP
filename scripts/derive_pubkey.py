"""Derive the Ed25519 public key from an existing Inntris signing seed.

Prints only the public half. Never prints, logs, or returns the secret seed.
Usage: py scripts/derive_pubkey.py <path-to-signing.key>
"""

from __future__ import annotations

import sys
from pathlib import Path

from nacl.signing import SigningKey


class SigningSeedError(ValueError):
    """The signing seed file cannot be safely decoded."""


def derive_public_key(path: Path) -> str:
    """Return the hexadecimal public key derived from a 32-byte hex seed."""
    if not path.is_file():
        raise SigningSeedError(f"no such file: {path.resolve()}")

    try:
        raw = path.read_text(encoding="ascii").strip()
    except UnicodeError as exc:
        raise SigningSeedError("file contents are not ASCII hexadecimal") from exc

    if len(raw) != 64:
        raise SigningSeedError(
            f"expected a 64-character hex seed, got {len(raw)} characters; "
            "this file is probably not a raw seed"
        )
    try:
        seed = bytes.fromhex(raw)
    except ValueError as exc:
        raise SigningSeedError("file contents are not valid hexadecimal") from exc
    return SigningKey(seed).verify_key.encode().hex()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: py scripts/derive_pubkey.py <path-to-signing.key>", file=sys.stderr)
        return 1

    try:
        public_key = derive_public_key(Path(args[0]))
    except SigningSeedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print()
    print("  PUBLIC KEY (hex), safe to publish:")
    print(f"  {public_key}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
