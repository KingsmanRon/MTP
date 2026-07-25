"""Regression tests for the public verification receipt fingerprint.

The receipt fingerprint is computed on the backend in
``api/main.py::get_public_verification_record`` and independently
recomputed on the frontend in
``frontend/src/lib/proof-state.ts::computeReceiptFingerprint``. The
two implementations MUST hash byte-identical canonical forms —
otherwise every public receipt renders "Fingerprint mismatch —
receipt may be tampered" in the Proof Completeness panel.

These tests pin:

1. The UTC wire-format timestamp helper (``+00:00`` -> ``Z``).
2. The SHA-256 of a v2 canonical payload.
3. The SHA-256 of a canonical payload with a null derived hash.

The expected hex values are shared verbatim with the frontend test in
``frontend/src/lib/__tests__/proof-state.test.ts`` so any drift on
either side fails loudly on both sides.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone

from api.main import canonical_wire_timestamp


def _canonical_fingerprint(payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class TestCanonicalWireTimestamp:
    def test_utc_uses_z_suffix_matching_pydantic_wire_format(self) -> None:
        dt = datetime(2026, 4, 7, 22, 22, 25, tzinfo=UTC)
        assert canonical_wire_timestamp(dt) == "2026-04-07T22:22:25Z"

    def test_utc_with_microseconds_keeps_microseconds(self) -> None:
        dt = datetime(2026, 4, 7, 22, 22, 25, 123456, tzinfo=UTC)
        assert canonical_wire_timestamp(dt) == "2026-04-07T22:22:25.123456Z"

    def test_non_utc_offset_is_preserved(self) -> None:
        dt = datetime(2026, 4, 7, 22, 22, 25, tzinfo=timezone(timedelta(hours=-5)))
        assert canonical_wire_timestamp(dt) == "2026-04-07T22:22:25-05:00"

    def test_naive_datetime_has_no_suffix(self) -> None:
        dt = datetime(2026, 4, 7, 22, 22, 25)
        assert canonical_wire_timestamp(dt) == "2026-04-07T22:22:25"

    def test_isoformat_plus_00_00_would_not_match_wire(self) -> None:
        # Regression guard: the pre-fix backend hashed `dt.isoformat()` which
        # emits "+00:00" for UTC, while pydantic v2 ships "Z" on the wire.
        dt = datetime(2026, 4, 7, 22, 22, 25, tzinfo=UTC)
        assert dt.isoformat() == "2026-04-07T22:22:25+00:00"
        assert canonical_wire_timestamp(dt) != dt.isoformat()


class TestReceiptFingerprintParity:
    V3_PAYLOAD: dict[str, object] = {
        "action_hash":
            "b913fee92806720122d84285c779582172446c1c1c03645cb865f93fc36b8b5b",
        "action_type": "financial_transaction",
        "agent_id": "11111111-2222-3333-4444-555555555555",
        "audit_id": "d8dd0902-4750-42d2-9516-92bf6362e815",
        "effective_controls_hash":
            "b5e687b5bd9878f561f8050e994fbd8632fec823503fa4bd8c047a3e3b14f686",
        "timestamp": "2026-04-07T22:22:25Z",
        "verdict": "approved",
    }

    V3_EXPECTED_HEX = (
        "51d1f4afecd9e10a83edc1779ee2a3f70301bf2b951ffe59dc51cdcc28570c0c"
    )
    NULL_HASH_EXPECTED_HEX = (
        "1aafd28570dd0cf98651172fd6fa23f7040fc0c677da06ba1e76bcd7cd86eac7"
    )

    def test_v3_fingerprint_matches_frontend_expected_hex(self) -> None:
        assert _canonical_fingerprint(self.V3_PAYLOAD) == self.V3_EXPECTED_HEX

    def test_fingerprint_with_null_effective_controls_hash(self) -> None:
        payload = dict(self.V3_PAYLOAD)
        payload["effective_controls_hash"] = None
        payload["verdict"] = "blocked"
        assert _canonical_fingerprint(payload) == self.NULL_HASH_EXPECTED_HEX

    def test_plus_00_00_timestamp_would_hash_differently(self) -> None:
        # If the backend regressed to `dt.isoformat()` for a UTC datetime,
        # this hash would differ from V3_EXPECTED_HEX and every receipt
        # would report fingerprint mismatch.
        legacy = dict(self.V3_PAYLOAD)
        legacy["timestamp"] = "2026-04-07T22:22:25+00:00"
        assert _canonical_fingerprint(legacy) != self.V3_EXPECTED_HEX


class TestEffectiveControlsHashRename:
    """B2.1: the derived hash is named for what it actually commits to.

    ``policy_hash`` read as though a receipt proved "allowed under registered
    policy version N". It proves "these were the controls in force" — status,
    allow/block lists, spend limits, rate limit, trust score. The registered
    document hash is a different value on ``agent_policies``.

    These tests pin both halves of the rename: v3 receipts commit to the new
    key, and v1/v2 receipts keep verifying under the old one.
    """

    _CORE = {
        "action_hash": "a" * 64,
        "action_type": "financial_transaction",
        "agent_id": "0be76c5e-93d2-4d4a-a86e-53c8a1d3f6b1",
        "audit_id": "11111111-1111-4111-8111-111111111111",
        "timestamp": "2026-06-15T12:00:00Z",
        "verdict": "approved",
    }

    def test_renamed_key_holds_the_same_sort_position(self) -> None:
        """The field set is unchanged in size and order — only the name moved."""
        v2 = sorted([*self._CORE, "policy_hash"])
        v3 = sorted([*self._CORE, "effective_controls_hash"])
        assert len(v2) == len(v3) == 7
        assert v2.index("policy_hash") == v3.index("effective_controls_hash") == 4

    def test_v3_fingerprint_differs_from_v2_for_the_same_value(self) -> None:
        """The rename is bound: it changes the fingerprint, it is not cosmetic."""
        value = "c" * 64
        v2 = _canonical_fingerprint({**self._CORE, "policy_hash": value})
        v3 = _canonical_fingerprint({**self._CORE, "effective_controls_hash": value})
        assert v2 != v3

    def test_verifier_selects_the_key_by_schema_version(self) -> None:
        """verify_pack.py must not read v3 receipts with the v1/v2 key."""
        import importlib.util
        from pathlib import Path

        verifier_path = (
            Path(__file__).parent.parent
            / "evidence_pack"
            / "pack_contents"
            / "verify_pack.py"
        )
        spec = importlib.util.spec_from_file_location("verify_pack_rename", verifier_path)
        verify_pack = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify_pack)

        assert verify_pack.fingerprint_hash_field({"schema_version": "v3"}) == (
            "effective_controls_hash"
        )
        for legacy in ({"schema_version": "v1"}, {"schema_version": "v2"}, {}):
            assert verify_pack.fingerprint_hash_field(legacy) == "policy_hash"

        value = "d" * 64
        v3_receipt = {**self._CORE, "schema_version": "v3", "effective_controls_hash": value}
        assert verify_pack.recompute_fingerprint(v3_receipt) == _canonical_fingerprint(
            {**self._CORE, "effective_controls_hash": value}
        )

        v2_receipt = {**self._CORE, "schema_version": "v2", "policy_hash": value}
        assert verify_pack.recompute_fingerprint(v2_receipt) == _canonical_fingerprint(
            {**self._CORE, "policy_hash": value}
        )
