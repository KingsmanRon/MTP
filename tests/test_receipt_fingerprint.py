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
3. The SHA-256 of a v1 canonical payload (null ``policy_hash``).

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
    V2_PAYLOAD: dict[str, object] = {
        "action_hash":
            "b913fee92806720122d84285c779582172446c1c1c03645cb865f93fc36b8b5b",
        "action_type": "financial_transaction",
        "agent_id": "11111111-2222-3333-4444-555555555555",
        "audit_id": "d8dd0902-4750-42d2-9516-92bf6362e815",
        "policy_hash":
            "b5e687b5bd9878f561f8050e994fbd8632fec823503fa4bd8c047a3e3b14f686",
        "timestamp": "2026-04-07T22:22:25Z",
        "verdict": "approved",
    }

    V2_EXPECTED_HEX = (
        "2fc29223fb1265448f2da2afd730628d228bcf3b09bb29b7006d5b19ce30bf63"
    )
    V1_EXPECTED_HEX = (
        "7085431bb41614f6d847cddbf0f579d38550caeb77720de27bc78f5faa7f3c7c"
    )

    def test_v2_fingerprint_matches_frontend_expected_hex(self) -> None:
        assert _canonical_fingerprint(self.V2_PAYLOAD) == self.V2_EXPECTED_HEX

    def test_v1_fingerprint_with_null_policy_hash(self) -> None:
        payload = dict(self.V2_PAYLOAD)
        payload["policy_hash"] = None
        payload["verdict"] = "blocked"
        assert _canonical_fingerprint(payload) == self.V1_EXPECTED_HEX

    def test_plus_00_00_timestamp_would_hash_differently(self) -> None:
        # If the backend regressed to `dt.isoformat()` for a UTC datetime,
        # this hash would differ from V2_EXPECTED_HEX and every receipt
        # would report fingerprint mismatch.
        legacy = dict(self.V2_PAYLOAD)
        legacy["timestamp"] = "2026-04-07T22:22:25+00:00"
        assert _canonical_fingerprint(legacy) != self.V2_EXPECTED_HEX
