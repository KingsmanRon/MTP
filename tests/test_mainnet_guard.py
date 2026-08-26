"""Tests for mainnet-only enforcement on GET /public/verify/{record_id}."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

from api.main import _compute_anchor_status, _compute_integrity_status, app

client = TestClient(app)


def _mock_row(chain_id: int):
    """Build a minimal mock row dict."""
    row = {
        "id": uuid4(),
        "timestamp": datetime.now(UTC),
        "verdict": "approved",
        "verdict_reason": None,
        "action_type": "tool_call",
        "agent_id": uuid4(),
        "agent_name": "test-agent",
        "org_id": uuid4(),
        "payload": {},
        "trust_score_at_time": 80,
        "action_hash": "a" * 64,
        "signature_valid": True,
        "merkle_root": None,
        "tx_hash": None,
        "block_number": None,
        "chain_id": chain_id,
        "anchored_at": None,
        "merkle_root_id": None,
        "policy_hash": None,
    }
    m = MagicMock()
    m.__getitem__ = lambda _self, k: row[k]
    m.get = lambda k, d=None: row.get(k, d)
    return m


class TestMainnetGuard:
    def test_sepolia_record_returns_410(self):
        """GET /public/verify/{id} must return 410 for chain_id == 84532."""
        with patch("api.main.db_pool") as mock_pool:
            conn = AsyncMock()
            conn.fetchrow = AsyncMock(return_value=_mock_row(chain_id=84532))
            mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
            response = client.get("/public/verify/00000000-0000-0000-0000-000000000001")
        assert response.status_code == 410
        detail = response.json()["detail"].lower()
        assert "testnet" in detail or "legacy" in detail or "chain" in detail


class TestReceiptAndAnchorStatus:
    def test_valid_signature_is_verified_without_anchor(self):
        assert _compute_integrity_status(signature_valid=True) == "verified"

    def test_invalid_signature_fails_receipt_integrity(self):
        assert _compute_integrity_status(signature_valid=False) == "failed"

    def test_sandbox_is_explicit(self):
        assert _compute_integrity_status(signature_valid=True, sandbox=True) == "sandbox"

    def test_failed_proof_is_separate_from_receipt_integrity(self):
        assert _compute_anchor_status("failed", None, None) == "failed"
        assert _compute_integrity_status(signature_valid=True) == "verified"

    def test_submitted_transaction_stays_pending(self):
        assert _compute_anchor_status("submitted", "0x" + "a" * 64, None) == "pending"

    def test_confirmed_requires_transaction_and_block(self):
        tx_hash = "0x" + "a" * 64
        assert _compute_anchor_status("confirmed", tx_hash, 123) == "confirmed"
        assert _compute_anchor_status("confirmed", tx_hash, None) == "failed"
