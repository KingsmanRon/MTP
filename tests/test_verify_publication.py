"""Publication contract and safe public-key derivation checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import check_verify_publication, derive_pubkey

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ZERO_SEED_PUBLIC_KEY = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"


def test_current_publication_contract_is_complete() -> None:
    """The digests are hard-coded deliberately.

    This test failing is the point: a change to the published verifier or
    methodology must force a conscious re-publication of the lock, the
    inntris-verify mirror and the .well-known copy in the same sitting,
    rather than drifting quietly.

    Updated in Phase 7A, Gate 4, when verify_pack.py gained receipt-v3
    chain verification and METHODOLOGY.md gained section 5b.
    """
    messages = check_verify_publication.validate_publication(PROJECT_ROOT)

    assert any("verify_pack.py aa48f28b" in message for message in messages)
    assert any("METHODOLOGY.md 75c4c26e" in message for message in messages)
    assert any("fingerprint 089c7611" in message for message in messages)


def test_no_authority_evidence_key_is_published_yet() -> None:
    """Receipt v3 cannot be signed in production until one is.

    Gate 4 requires that publicly advertised v3 receipts wait for the
    verifier publication gate. That is enforced in
    api/receipts/key_registry.py rather than remembered, and this records
    the current state: no iae- key exists, so production refuses to sign.
    """
    messages = check_verify_publication.validate_publication(PROJECT_ROOT)

    assert not any("published key iae-" in message for message in messages)
    assert any("CANNOT be signed in production" in message for message in messages)


def test_publication_checker_rejects_pending_key_marker(tmp_path: Path) -> None:
    mirror_path = tmp_path / check_verify_publication.MIRROR_PATH
    mirror_path.parent.mkdir(parents=True)
    mirror_path.write_text(
        "ipk-2026-01 PENDING-PUBLICATION-DO-NOT-PIN active 2026-07-XX\n",
        encoding="utf-8",
    )

    with pytest.raises(check_verify_publication.PublicationCheckError, match="pending marker"):
        check_verify_publication.check_mirror(tmp_path, {})


def test_publication_checker_rejects_wrong_key_fingerprint(tmp_path: Path) -> None:
    mirror_path = tmp_path / check_verify_publication.MIRROR_PATH
    mirror_path.parent.mkdir(parents=True)
    mirror_path.write_text(
        f"ipk-2026-01 {ZERO_SEED_PUBLIC_KEY} sha256 {'0' * 64} active 2026-07-20\n",
        encoding="utf-8",
    )

    with pytest.raises(
        check_verify_publication.PublicationCheckError, match="fingerprint mismatch"
    ):
        check_verify_publication.check_mirror(tmp_path, {})


def test_derive_pubkey_prints_only_public_material(tmp_path: Path, capsys) -> None:
    seed_hex = "00" * 32
    seed_path = tmp_path / "signing.key"
    seed_path.write_text(seed_hex, encoding="ascii")

    assert derive_pubkey.main([str(seed_path)]) == 0
    captured = capsys.readouterr()

    assert ZERO_SEED_PUBLIC_KEY in captured.out
    assert seed_hex not in captured.out
    assert seed_hex not in captured.err


def test_derive_pubkey_rejects_invalid_hex_without_echoing_it(tmp_path: Path, capsys) -> None:
    invalid_seed = "g" * 64
    seed_path = tmp_path / "signing.key"
    seed_path.write_text(invalid_seed, encoding="ascii")

    assert derive_pubkey.main([str(seed_path)]) == 1
    captured = capsys.readouterr()

    assert "not valid hexadecimal" in captured.err
    assert invalid_seed not in captured.out
    assert invalid_seed not in captured.err
