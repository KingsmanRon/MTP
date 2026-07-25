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

import hashlib
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

    def test_jcs_diverges_from_python_sorted_json(self) -> None:
        """Why versions 1 and 2 had to go, stated as an assertion.

        An integer-valued float is the cheapest way to see the divergence:
        Python's json serializes 1.0 as "1.0"; JCS emits "1". The old
        envelopes hashed the former, so a Node or Go signer producing correct
        JCS bytes would have failed verification here with no diagnosable
        cause. The envelope now hashes only the JCS form.
        """
        payload = {"amount": 1.0}
        legacy_canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        assert legacy_canonical == '{"amount":1.0}'
        assert jcs.canonicalize(payload) == b'{"amount":1}'
        assert hashlib.sha256(legacy_canonical.encode()).hexdigest() != jcs.sha256_hex(payload)

    def test_legacy_envelope_versions_are_rejected(self) -> None:
        """Versions 1 and 2 are deleted, not merely non-default."""
        for dead in (1, 2):
            with pytest.raises(CryptoError, match="Only 3"):
                CryptoService.compute_action_hash(
                    self.AGENT_ID, self.ACTION, {"a": 1}, self.NONCE, self.TS,
                    sig_version=dead,
                )

    def test_registered_policy_hash_is_bound_into_the_envelope(self) -> None:
        """B2.3/B2.4: the signature — and so the anchored leaf — covers policy."""
        args = (self.AGENT_ID, self.ACTION, {"a": 1}, self.NONCE, self.TS)
        unbound = CryptoService.compute_action_hash(*args)
        bound = CryptoService.compute_action_hash(*args, registered_policy_hash="a" * 64)
        other = CryptoService.compute_action_hash(*args, registered_policy_hash="b" * 64)
        assert unbound != bound != other
        assert unbound != other
        # Explicit None and omission must agree, or callers diverge on the
        # common unregistered-policy case.
        assert CryptoService.compute_action_hash(*args, registered_policy_hash=None) == unbound

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


class TestEnvelopeV3CrossLanguageContract:
    """B3.3: envelope v3 is byte-identical across implementations.

    The vectors in ``envelope_v3_vectors.json`` are asserted from Python here
    and from Node in ``github-action/index.test.js``. Both suites pin the same
    hex, so a divergence in either canonicalizer fails loudly on both sides
    rather than surfacing as an unexplainable signature rejection in
    production.

    ``1.0`` in the payload is deliberate: it is the cheapest input that
    separates JCS from Python's sorted-JSON, and the case the deleted v1/v2
    envelopes got wrong.
    """

    VECTORS = json.loads(
        (
            Path(__file__).parent
            / "fixtures"
            / "canonicalization"
            / "envelope_v3_vectors.json"
        ).read_text()
    )

    def test_every_vector_reproduces(self) -> None:
        for case in self.VECTORS["cases"]:
            assert jcs.sha256_hex(case["payload"]) == case["payload_hash"], case["name"]
            computed = CryptoService.compute_action_hash(
                agent_id=self.VECTORS["agent_id"],
                action_type=case["action_type"],
                payload=case["payload"],
                nonce=self.VECTORS["nonce"],
                timestamp=self.VECTORS["timestamp"],
                registered_policy_hash=case["registered_policy_hash"],
            )
            assert computed == case["action_hash"], case["name"]

    def test_vectors_cover_both_policy_states(self) -> None:
        """A contract that only covers the bound case misses the common one."""
        states = {case["registered_policy_hash"] is None for case in self.VECTORS["cases"]}
        assert states == {True, False}
