"""Publication contract and safe public-key derivation checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import check_verify_publication, derive_pubkey

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ZERO_SEED_PUBLIC_KEY = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"


def test_current_publication_contract_is_complete() -> None:
    messages = check_verify_publication.validate_publication(PROJECT_ROOT)

    assert any("verify_pack.py 332928c8" in message for message in messages)
    assert any("METHODOLOGY.md 4ca88e16" in message for message in messages)
    assert any("fingerprint 089c7611" in message for message in messages)


def test_publication_checker_rejects_pending_key_marker(tmp_path: Path) -> None:
    mirror_path = tmp_path / check_verify_publication.MIRROR_PATH
    mirror_path.parent.mkdir(parents=True)
    mirror_path.write_text(
        "ipk-2026-01 PENDING-PUBLICATION-DO-NOT-PIN active 2026-07-XX\n",
        encoding="utf-8",
    )

    with pytest.raises(check_verify_publication.PublicationCheckError, match="pending marker"):
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
