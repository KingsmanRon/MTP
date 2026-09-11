"""Validate the local offline verifier publication contract.

This check is intentionally standard-library only so it can run in CI and on
an operator workstation without installing the Inntris application.
"""

from __future__ import annotations

import hashlib
import re
import sys
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = Path("verify_publication.lock")
MIRROR_PATH = Path("frontend/public/.well-known/inntris-keys.txt")
GITATTRIBUTES_PATH = Path(".gitattributes")
PENDING_MARKER = "PENDING-PUBLICATION-DO-NOT-PIN"

PINNED_PATHS = {
    Path("evidence_pack/pack_contents/verify_pack.py"),
    Path("evidence_pack/pack_contents/METHODOLOGY.md"),
}
REQUIRED_ATTRIBUTES = {
    "evidence_pack/pack_contents/verify_pack.py text eol=lf",
    "evidence_pack/pack_contents/METHODOLOGY.md text eol=lf",
    "verify_publication.lock text eol=lf",
    "frontend/public/.well-known/inntris-keys.txt text eol=lf",
}

_LOCK_ENTRY = re.compile(r"^(?P<digest>[0-9a-f]{64})  (?P<path>\S+)$")
_MIRROR_HASH = re.compile(
    r"^(?P<name>verify_pack\.py|METHODOLOGY\.md) sha256 (?P<digest>[0-9a-f]{64})$"
)
# Two kinds of key live in this file and they assert different things:
#
#   ipk-  evidence-pack MANIFEST signing key. Says "Inntris assembled this
#         pack and it has not changed since".
#   iae-  AUTHORITY EVIDENCE signing key (Phase 7A, Gate 4). Says "Inntris
#         Core decided this, spent that, and recorded this outcome".
#
# The prefixes are distinct so a reader can never mistake one assertion for
# the other, and the checker below refuses a file where one key claims to be
# both.
_KEY_ENTRY = re.compile(
    r"^(?P<key_id>(?P<kind>ipk|iae)-\d{4}-\d{2}) "
    r"(?P<public_key>[0-9a-f]{64}) "
    r"sha256 (?P<fingerprint>[0-9a-f]{64}) "
    r"(?P<status>active|retired) "
    r"(?P<effective_date>\d{4}-\d{2}-\d{2})$"
)


class PublicationCheckError(RuntimeError):
    """The local publication contract is incomplete or inconsistent."""


def canonical_text_bytes(path: Path) -> bytes:
    """Read UTF-8 text using universal newlines and return canonical LF bytes."""
    return path.read_text(encoding="utf-8").encode("utf-8")


def load_pins(root: Path) -> dict[Path, str]:
    """Load and strictly validate the publication lock entries."""
    pins: dict[Path, str] = {}
    lock_file = root / LOCK_PATH
    for line_number, raw_line in enumerate(lock_file.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _LOCK_ENTRY.fullmatch(line)
        if match is None:
            raise PublicationCheckError(f"malformed lock entry at line {line_number}")
        path = Path(match.group("path"))
        if path in pins:
            raise PublicationCheckError(f"duplicate lock entry for {path.as_posix()}")
        pins[path] = match.group("digest")

    if set(pins) != PINNED_PATHS:
        missing = sorted(path.as_posix() for path in PINNED_PATHS - set(pins))
        unexpected = sorted(path.as_posix() for path in set(pins) - PINNED_PATHS)
        raise PublicationCheckError(
            f"lock paths do not match the publication contract; "
            f"missing={missing}, unexpected={unexpected}"
        )
    return pins


def check_attributes(root: Path) -> None:
    """Require LF checkout rules for every publication control file."""
    attributes_file = root / GITATTRIBUTES_PATH
    configured = {
        line.strip()
        for line in attributes_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    missing = sorted(REQUIRED_ATTRIBUTES - configured)
    if missing:
        raise PublicationCheckError(f"missing required .gitattributes rules: {missing}")


def check_pinned_files(root: Path, pins: dict[Path, str]) -> None:
    """Verify the exact canonical bytes that the pack builder embeds."""
    for relative_path, expected_digest in pins.items():
        actual_digest = hashlib.sha256(canonical_text_bytes(root / relative_path)).hexdigest()
        if actual_digest != expected_digest:
            raise PublicationCheckError(
                f"canonical hash mismatch for {relative_path.as_posix()}: "
                f"expected {expected_digest}, got {actual_digest}"
            )


def check_mirror(root: Path, pins: dict[Path, str]) -> list[tuple[str, str]]:
    """Validate the public key and verifier hashes in the website mirror."""
    mirror_lines = [
        line.strip()
        for line in (root / MIRROR_PATH).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if any(PENDING_MARKER in line for line in mirror_lines):
        raise PublicationCheckError("the public key mirror still contains the pending marker")

    key_entries: dict[str, tuple[str, str]] = {}
    kinds: dict[str, list[tuple[str, str]]] = {"ipk": [], "iae": []}
    seen_public_keys: dict[str, str] = {}
    mirror_hashes: dict[str, str] = {}
    for line in mirror_lines:
        key_match = _KEY_ENTRY.fullmatch(line)
        if key_match is not None:
            key_id = key_match.group("key_id")
            if key_id in key_entries:
                raise PublicationCheckError(f"duplicate key ID in the public mirror: {key_id}")
            public_key = bytes.fromhex(key_match.group("public_key"))
            if public_key == bytes(32):
                raise PublicationCheckError(
                    "the published Ed25519 public key must not be all zeroes"
                )
            date.fromisoformat(key_match.group("effective_date"))
            fingerprint = hashlib.sha256(public_key).hexdigest()
            if fingerprint != key_match.group("fingerprint"):
                raise PublicationCheckError(f"fingerprint mismatch for {key_id}")
            # One key, one meaning. A key published as both a pack-manifest
            # key and an authority-evidence key could have a signature over
            # one kind of statement read as the other.
            previous = seen_public_keys.get(fingerprint)
            if previous is not None:
                raise PublicationCheckError(
                    f"{key_id} publishes the same public key as {previous}; a key "
                    "must assert exactly one kind of thing"
                )
            seen_public_keys[fingerprint] = key_id
            key_entries[key_id] = (key_match.group("status"), fingerprint)
            kinds[key_match.group("kind")].append((key_id, key_match.group("status")))
            continue

        hash_match = _MIRROR_HASH.fullmatch(line)
        if hash_match is not None:
            name = hash_match.group("name")
            if name in mirror_hashes:
                raise PublicationCheckError(f"duplicate hash in the public mirror: {name}")
            mirror_hashes[name] = hash_match.group("digest")
            continue

        raise PublicationCheckError(f"unrecognised entry in the public key mirror: {line}")

    if not kinds["ipk"] or not any(status == "active" for _id, status in kinds["ipk"]):
        raise PublicationCheckError(
            "the public key mirror must contain at least one active ipk- "
            "evidence-pack signing key"
        )

    # Authority-evidence keys (iae-) are OPTIONAL in this file and mandatory
    # only once v3 evidence is published. Until an active one exists,
    # api/receipts/key_registry.py refuses to sign v3 evidence in production,
    # which is the mechanical form of the Phase 7A Gate 4 rule "do not emit
    # publicly advertised v3 receipts until the verifier publication gate
    # passes". What IS checked here: at most one may be active, because two
    # active signing keys leave a reader unable to say which should have
    # signed a given event -- and leave an operator responding to a
    # compromise unable to say which to revoke.
    active_authority = [key_id for key_id, status in kinds["iae"] if status == "active"]
    if len(active_authority) > 1:
        raise PublicationCheckError(
            "more than one active authority-evidence key is published: "
            + ", ".join(sorted(active_authority))
        )

    expected_hashes = {path.name: digest for path, digest in pins.items()}
    if mirror_hashes != expected_hashes:
        raise PublicationCheckError(
            f"the .well-known hash mirror does not match the publication lock: "
            f"expected={expected_hashes}, actual={mirror_hashes}"
        )

    return [(key_id, fingerprint) for key_id, (_, fingerprint) in sorted(key_entries.items())]


def validate_publication(root: Path = PROJECT_ROOT) -> list[str]:
    """Validate every local publication invariant and return safe status lines."""
    pins = load_pins(root)
    check_attributes(root)
    check_pinned_files(root, pins)
    published_keys = check_mirror(root, pins)
    messages = [f"pinned {path.as_posix()} {digest}" for path, digest in sorted(pins.items())]
    messages.extend(
        f"published key {key_id} fingerprint {fingerprint}"
        for key_id, fingerprint in published_keys
    )
    if not any(key_id.startswith("iae-") for key_id, _fp in published_keys):
        messages.append(
            "no active authority-evidence (iae-) key is published; receipt v3 "
            "evidence CANNOT be signed in production until one is"
        )
    return messages


def main() -> int:
    try:
        messages = validate_publication()
    except (OSError, UnicodeError, ValueError, PublicationCheckError) as exc:
        print(f"ERROR: verifier publication check failed: {exc}", file=sys.stderr)
        return 1
    for message in messages:
        print(f"OK: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
