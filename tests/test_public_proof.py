"""Tests for GET /public/verify/{audit_id}/proof (unauthenticated)."""
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)

FAKE_AUDIT_ID = uuid4()
FAKE_ORG_ID = uuid4()
FAKE_PROOF_ID = uuid4()


def _log_row(anchored: bool):
    row = {
        "id": FAKE_AUDIT_ID,
        "timestamp": datetime(2026, 4, 13, 12, 0, 0, tzinfo=UTC),
        "action_hash": "b" * 64,
        "merkle_root_id": FAKE_PROOF_ID if anchored else None,
        "merkle_leaf_index": 0 if anchored else None,
        "policy_hash": None,
    }
    m = MagicMock()
    m.__getitem__ = lambda _self, k: row[k]
    m.get = lambda k, d=None: row.get(k, d)
    return m


def _proof_row(status="confirmed", transaction_hash="0x" + "d" * 64):
    row = {
        "id": FAKE_PROOF_ID,
        "root_hash": "c" * 64,
        "transaction_hash": transaction_hash,
        "block_number": 12345,
        "chain_id": 8453,
        "status": status,
        "confirmed_at": datetime(2026, 4, 13, 13, 0, 0, tzinfo=UTC),
        "leaf_hashes": ["b" * 64, "e" * 64],
        "submitted_by": None,
    }
    m = MagicMock()
    m.__getitem__ = lambda _self, k: row[k]
    m.get = lambda k, d=None: row.get(k, d)
    return m


class TestPublicProofEndpoint:
    def test_anchored_receipt_returns_200_with_full_proof(self):
        fake_proof = [{"hash": "a" * 64, "position": 1}]
        with patch("api.main.db_pool") as mock_pool, \
             patch.dict("sys.modules", {"workers.anchor_worker": MagicMock(compute_merkle_proof=MagicMock(return_value=fake_proof))}):
            conn = AsyncMock()
            conn.fetchrow = AsyncMock(side_effect=[_log_row(anchored=True), _proof_row()])
            mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
            response = client.get(f"/public/verify/{FAKE_AUDIT_ID}/proof")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "anchored"
        assert body["audit_id"] == str(FAKE_AUDIT_ID)
        assert body["action_hash"] == "b" * 64
        assert body["merkle_root"] == "c" * 64
        assert body["tx_hash"] == "0x" + "d" * 64
        assert body["chain_id"] == 8453
        assert isinstance(body["proof"], list)
        assert body["timestamp"] == "2026-04-13T12:00:00Z"

    def test_unanchored_receipt_returns_pending_state_not_404(self):
        with patch("api.main.db_pool") as mock_pool:
            conn = AsyncMock()
            conn.fetchrow = AsyncMock(return_value=_log_row(anchored=False))
            mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
            response = client.get(f"/public/verify/{FAKE_AUDIT_ID}/proof")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "pending_anchor"
        assert body["tx_hash"] is None
        assert body["merkle_root"] is None
        assert body["proof"] == []

    def test_sandbox_receipt_returns_sandbox_status(self):
        row = {
            "id": FAKE_AUDIT_ID,
            "timestamp": datetime(2026, 4, 13, 12, 0, 0, tzinfo=UTC),
            "action_hash": "b" * 64,
            "merkle_root_id": None,
            "merkle_leaf_index": None,
            "policy_hash": None,
            "metadata": {"sandbox": True, "test_request": True},
        }
        m = MagicMock()
        m.__getitem__ = lambda _self, k: row[k]
        m.get = lambda k, d=None: row.get(k, d)
        with patch("api.main.db_pool") as mock_pool:
            conn = AsyncMock()
            conn.fetchrow = AsyncMock(return_value=m)
            mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
            response = client.get(f"/public/verify/{FAKE_AUDIT_ID}/proof")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "sandbox"
        assert body["tx_hash"] is None
        assert body["merkle_root"] is None

    def test_failed_proof_row_returns_failed_not_anchored(self):
        with patch("api.main.db_pool") as mock_pool:
            conn = AsyncMock()
            conn.fetchrow = AsyncMock(
                side_effect=[
                    _log_row(anchored=True),
                    _proof_row(status="dead_letter", transaction_hash=None),
                ]
            )
            mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
            response = client.get(f"/public/verify/{FAKE_AUDIT_ID}/proof")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "failed"
        assert body["tx_hash"] is None
        assert body["proof"] == []

    def test_missing_audit_log_returns_404(self):
        with patch("api.main.db_pool") as mock_pool:
            conn = AsyncMock()
            conn.fetchrow = AsyncMock(return_value=None)
            mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
            response = client.get(f"/public/verify/{uuid4()}/proof")
        assert response.status_code == 404

    def test_endpoint_requires_no_auth(self):
        """No X-API-Key header should be needed."""
        with patch("api.main.db_pool") as mock_pool:
            conn = AsyncMock()
            conn.fetchrow = AsyncMock(return_value=None)
            mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
            mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
            # No auth headers — should get 404 (not found), not 401 (unauthorized)
            response = client.get(f"/public/verify/{uuid4()}/proof")
        assert response.status_code == 404
