"""Tests for mainnet-only enforcement on GET /public/verify/{record_id}."""
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from uuid import uuid4
from datetime import datetime, timezone

from api.main import app, _compute_integrity_status

client = TestClient(app)


def _mock_row(chain_id: int):
    """Build a minimal mock row dict."""
    row = {
        "id": uuid4(),
        "timestamp": datetime.now(timezone.utc),
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
    m.__getitem__ = lambda self, k: row[k]
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


class TestComputeIntegrityStatus:
    def test_no_tx_hash_returns_pending_anchor(self):
        assert _compute_integrity_status(tx_hash=None) == "pending_anchor"

    def test_empty_tx_hash_returns_pending_anchor(self):
        assert _compute_integrity_status(tx_hash="") == "pending_anchor"

    def test_tx_hash_present_returns_verified(self):
        assert _compute_integrity_status(tx_hash="0x" + "a" * 64) == "verified"
