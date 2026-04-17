"""Phase 0.3 regression tests for timestamp canonicalization.

The previous ``compute_action_hash`` implementation called
``timestamp.isoformat()`` with no tz handling, so the same instant
represented as a naive datetime, a UTC-aware datetime, and an
offset-aware datetime (``+02:00``) all produced three different hashes
— and therefore three incompatible signatures. This test pins the fix:
all three representations of 2026-04-17T12:00:00Z now hash to the same
value, and the canonical wire form uses the ``Z`` suffix that matches
pydantic v2 and ``api/main.py::canonical_wire_timestamp``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from api.crypto import CryptoError, CryptoService


class TestCanonicalizeTimestamp:
    def test_utc_aware_datetime_uses_z_suffix(self) -> None:
        dt = datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)
        assert CryptoService.canonicalize_timestamp(dt) == "2026-04-17T12:00:00Z"

    def test_preserves_microseconds(self) -> None:
        dt = datetime(2026, 4, 17, 12, 0, 0, 123456, tzinfo=timezone.utc)
        assert (
            CryptoService.canonicalize_timestamp(dt)
            == "2026-04-17T12:00:00.123456Z"
        )

    def test_non_utc_tz_is_normalized_to_utc(self) -> None:
        paris = timezone(timedelta(hours=2))
        dt = datetime(2026, 4, 17, 14, 0, 0, tzinfo=paris)
        assert CryptoService.canonicalize_timestamp(dt) == "2026-04-17T12:00:00Z"

    def test_naive_datetime_is_assumed_utc(self) -> None:
        dt = datetime(2026, 4, 17, 12, 0, 0)
        assert CryptoService.canonicalize_timestamp(dt) == "2026-04-17T12:00:00Z"

    def test_string_with_z_suffix_round_trips(self) -> None:
        assert (
            CryptoService.canonicalize_timestamp("2026-04-17T12:00:00Z")
            == "2026-04-17T12:00:00Z"
        )

    def test_string_with_offset_is_converted(self) -> None:
        assert (
            CryptoService.canonicalize_timestamp("2026-04-17T14:00:00+02:00")
            == "2026-04-17T12:00:00Z"
        )

    def test_invalid_string_raises_crypto_error(self) -> None:
        with pytest.raises(CryptoError):
            CryptoService.canonicalize_timestamp("not-a-date")

    def test_non_datetime_non_string_raises_crypto_error(self) -> None:
        with pytest.raises(CryptoError):
            CryptoService.canonicalize_timestamp(1234567890)  # type: ignore[arg-type]


class TestActionHashIsTimezoneIndependent:
    AGENT_ID = "4f0e4fd5-5e2f-4e95-a2d5-78b0a7b0d66a"
    ACTION = "financial_transaction"
    PAYLOAD = {"amount": 150.0, "currency": "USD", "recipient": "u@example.com"}
    NONCE = "nonce-0xdeadbeef"

    def _hash(self, ts) -> str:
        return CryptoService.compute_action_hash(
            self.AGENT_ID, self.ACTION, self.PAYLOAD, self.NONCE, ts
        )

    def test_same_instant_in_different_forms_hashes_identically(self) -> None:
        utc_dt = datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)
        naive_dt = datetime(2026, 4, 17, 12, 0, 0)
        paris_dt = datetime(
            2026, 4, 17, 14, 0, 0, tzinfo=timezone(timedelta(hours=2))
        )
        z_string = "2026-04-17T12:00:00Z"
        offset_string = "2026-04-17T14:00:00+02:00"

        canonical = self._hash(utc_dt)

        assert self._hash(naive_dt) == canonical
        assert self._hash(paris_dt) == canonical
        assert self._hash(z_string) == canonical
        assert self._hash(offset_string) == canonical

    def test_different_instants_hash_differently(self) -> None:
        a = datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)
        b = datetime(2026, 4, 17, 12, 0, 1, tzinfo=timezone.utc)
        assert self._hash(a) != self._hash(b)
