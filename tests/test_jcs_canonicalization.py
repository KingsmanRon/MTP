"""Phase 1B.1 — JCS canonicalization + multi-language test vectors.

These tests enforce two contracts:

1. ``api.jcs.canonicalize`` produces byte-for-byte the canonical form
   recorded in ``tests/fixtures/canonicalization/jcs_vectors.json``,
   and ``api.jcs.sha256_hex`` produces the matching digest.
2. ``CryptoService.compute_action_hash`` with ``sig_version=3`` routes
   the payload through JCS and still produces a deterministic result
   independent of whether the input dict is iterated in insertion or
   alphabetical order.

Any other-language SDK (Node, Go, Rust, …) that implements RFC 8785
correctly MUST pass the same vectors. Failure of a vector in another
language is a bug in that SDK, not in the vectors.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from api import jcs
from api.crypto import CryptoError, CryptoService

VECTORS_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "canonicalization"
    / "jcs_vectors.json"
)


def _load_vectors() -> list[dict]:
    data = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    return data["vectors"]


VECTORS = _load_vectors()


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
class TestJCSVectors:
    def test_canonical_bytes_match(self, vector: dict) -> None:
        actual = jcs.canonicalize(vector["input"]).decode("utf-8")
        assert actual == vector["canonical"]

    def test_sha256_matches(self, vector: dict) -> None:
        actual = jcs.sha256_hex(vector["input"])
        assert actual == vector["sha256"]


class TestJCSInvariants:
    def test_insertion_order_does_not_affect_output(self) -> None:
        a = {"b": 2, "a": 1, "c": 3}
        b = {"c": 3, "a": 1, "b": 2}
        assert jcs.canonicalize(a) == jcs.canonicalize(b)

    def test_nan_is_rejected(self) -> None:
        with pytest.raises(jcs.JCSError):
            jcs.canonicalize({"bad": float("nan")})

    def test_infinity_is_rejected(self) -> None:
        with pytest.raises(jcs.JCSError):
            jcs.canonicalize({"bad": float("inf")})

    def test_non_string_key_is_rejected(self) -> None:
        with pytest.raises(jcs.JCSError):
            jcs.canonicalize({1: "oops"})

    def test_unsupported_type_is_rejected(self) -> None:
        with pytest.raises(jcs.JCSError):
            jcs.canonicalize({"when": datetime.now(UTC)})

    def test_negative_zero_serializes_like_positive_zero(self) -> None:
        assert jcs.canonicalize(-0.0) == b"0"
        assert jcs.canonicalize(0.0) == b"0"

    def test_integer_valued_float_drops_fraction(self) -> None:
        assert jcs.canonicalize(1.0) == b"1"
        assert jcs.canonicalize(100.0) == b"100"
        assert jcs.canonicalize(-42.0) == b"-42"

    def test_large_integer_valued_float_uses_exponent(self) -> None:
        # 1e21 crosses the ECMA-262 threshold for exponent notation.
        assert jcs.canonicalize(1e21) == b"1e+21"


class TestSigVersion3:
    AGENT_ID = "4f0e4fd5-5e2f-4e95-a2d5-78b0a7b0d66a"
    ACTION = "financial_transaction"
    NONCE = "nonce-0xdeadbeef"
    TS = datetime(2026, 4, 17, 12, 0, 0, tzinfo=UTC)

    def test_jcs_and_current_hashes_differ(self) -> None:
        # A payload that contains an integer-valued float is the easiest
        # way to see JCS and sort-keys diverge: Python's json serializes
        # 1.0 as "1.0"; JCS emits "1".
        payload = {"amount": 1.0}
        current = CryptoService.compute_action_hash(
            self.AGENT_ID, self.ACTION, payload, self.NONCE, self.TS,
            sig_version=CryptoService.SIG_VERSION_CURRENT,
        )
        jcs_hash = CryptoService.compute_action_hash(
            self.AGENT_ID, self.ACTION, payload, self.NONCE, self.TS,
            sig_version=CryptoService.SIG_VERSION_JCS,
        )
        assert current != jcs_hash

    def test_jcs_is_insertion_order_independent(self) -> None:
        a = {"b": 2, "a": 1}
        b = {"a": 1, "b": 2}
        ha = CryptoService.compute_action_hash(
            self.AGENT_ID, self.ACTION, a, self.NONCE, self.TS,
            sig_version=CryptoService.SIG_VERSION_JCS,
        )
        hb = CryptoService.compute_action_hash(
            self.AGENT_ID, self.ACTION, b, self.NONCE, self.TS,
            sig_version=CryptoService.SIG_VERSION_JCS,
        )
        assert ha == hb

    def test_jcs_rejects_nan_as_crypto_error(self) -> None:
        with pytest.raises(CryptoError):
            CryptoService.compute_action_hash(
                self.AGENT_ID, self.ACTION, {"bad": float("nan")},
                self.NONCE, self.TS,
                sig_version=CryptoService.SIG_VERSION_JCS,
            )

    def test_unknown_version_still_raises(self) -> None:
        with pytest.raises(CryptoError):
            CryptoService.compute_action_hash(
                self.AGENT_ID, self.ACTION, {"ok": 1},
                self.NONCE, self.TS, sig_version=99,
            )
