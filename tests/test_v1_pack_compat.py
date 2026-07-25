"""Manifest v1 backward-compatibility corpus (Block B1.1).

Manifest v2 breaks the pack format. B1.1 requires the v2 verifier to still
verify v1 packs, which needs a genuine v1 pack to test against — and none
existed in this repository or in ``Inntris/inntris-verify``.

``tests/fixtures/packs/v1/`` holds that pack, minted while the v1 builder was
still ``HEAD``. These tests pin it:

* the currently shipped verifier verifies it (the actual B1.1 regression —
  this test is what fails if manifest v2 breaks v1 packs);
* its bytes have not drifted;
* its signing key is absent from the published registry, so it can never be
  mistaken for a production artifact.

The pack is intentionally NOT part of the verifier publication contract
(``verify_publication.lock`` / ``SHA256SUMS``). It is a test artifact with no
third-party consumers; pinning it there would drag a six-location
cross-repository republication into every fixture refresh for no external
benefit. See ``docs/INNTRIS_WORK_PLAN.md`` §12.4.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "packs" / "v1"
PACK_PATH = FIXTURE_DIR / "inntris-v1-format-fixture.zip"
PUBKEY_PATH = FIXTURE_DIR / "PUBKEY.hex"
VERIFIER_PATH = REPO_ROOT / "evidence_pack" / "pack_contents" / "verify_pack.py"
KEY_MIRROR_PATH = REPO_ROOT / "frontend" / "public" / ".well-known" / "inntris-keys.txt"

# Pinned so an accidental regeneration, a corrupted checkout, or a silent
# rewrite is a test failure rather than a quietly different corpus. Update
# this ONLY alongside a deliberate, reviewed fixture change.
EXPECTED_PACK_SHA256 = "4e6bebb091a8408e99227a8fc85dac5ff0ed23c1cd32e32f0f09f4025525d993"
EXPECTED_MANIFEST_SHA256 = "61156f80c49b513e1e76b311ea7a6ee9e067121e0962e468da339fc64c0bbe5c"


@pytest.fixture(scope="module")
def fixture_pubkey() -> str:
    return PUBKEY_PATH.read_text().strip()


def test_fixture_pack_bytes_are_pinned() -> None:
    """The committed v1 corpus has not drifted."""
    digest = hashlib.sha256(PACK_PATH.read_bytes()).hexdigest()
    assert digest == EXPECTED_PACK_SHA256, (
        "the v1 fixture pack changed. It is a frozen regression corpus — a v1 "
        "pack cannot be honestly regenerated once the v1 builder is gone. If "
        "this change is deliberate, update EXPECTED_PACK_SHA256 and say why in "
        "the commit message."
    )


def test_shipped_verifier_verifies_the_v1_pack(fixture_pubkey: str) -> None:
    """B1.1: the current verifier still verifies a v1-format pack.

    This is the test that must keep passing across the manifest v2 break. It
    runs the verifier as a subprocess — the way an auditor runs it — rather
    than importing it, so the exit code is part of the contract.
    """
    result = subprocess.run(
        [sys.executable, str(VERIFIER_PATH), str(PACK_PATH), "--pubkey", fixture_pubkey],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"v1 pack failed verification (exit {result.returncode}).\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert EXPECTED_MANIFEST_SHA256[:16] in result.stdout
    assert "RESULT: FAILED" not in result.stdout


def test_verifier_rejects_a_tampered_v1_pack(tmp_path: Path, fixture_pubkey: str) -> None:
    """A single flipped byte in the archive must fail verification."""
    tampered = tmp_path / "tampered.zip"
    raw = bytearray(PACK_PATH.read_bytes())
    # Flip a byte inside the compressed body, past the first local header.
    raw[len(raw) // 2] ^= 0xFF
    tampered.write_bytes(bytes(raw))

    result = subprocess.run(
        [sys.executable, str(VERIFIER_PATH), str(tampered), "--pubkey", fixture_pubkey],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode != 0, (
        "a tampered pack verified successfully — the integrity check is not "
        f"doing its job.\nstdout:\n{result.stdout}"
    )


def test_verifier_rejects_the_wrong_pinned_key() -> None:
    """Pinning any other key must fail, even though the pack is self-consistent."""
    wrong_key = "00" * 31 + "01"
    result = subprocess.run(
        [sys.executable, str(VERIFIER_PATH), str(PACK_PATH), "--pubkey", wrong_key],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode != 0
    assert "does NOT match" in result.stdout


def test_fixture_key_is_absent_from_the_published_registry(fixture_pubkey: str) -> None:
    """The fixture's signing key must never become pinnable.

    Publishing it in the registry would make a test-key-signed pack
    indistinguishable from a production artifact to any verifier that trusts
    the registry — the Block A3 hazard, approached from the other direction.
    """
    mirror = KEY_MIRROR_PATH.read_text()
    assert fixture_pubkey not in mirror, (
        "the v1 fixture signing key appears in the published key mirror. "
        "Remove it: a test key in the canonical registry makes synthetic packs "
        "verifiable as production artifacts."
    )
    fingerprint = hashlib.sha256(bytes.fromhex(fixture_pubkey)).hexdigest()
    assert fingerprint not in mirror
