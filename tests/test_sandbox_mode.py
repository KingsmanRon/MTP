"""Sandbox mode (#5): sandbox agents stay off the mainnet anchor path.

A sandbox agent's /verify audit rows must carry metadata.test_request=true — the
anchor worker's existing exclusion key (get_unanchored_logs) — plus a sandbox
flag, and the public receipt must report sandbox=true / integrity_status=sandbox
instead of a forever-"pending_anchor".
"""
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from fastapi.testclient import TestClient

from api.main import _audit_metadata, app, get_db

client = TestClient(app)


def test_sandbox_agent_audit_row_excluded_from_anchoring():
    metadata = _audit_metadata(client_policy_hash=None, sandbox=True)
    # test_request is exactly what workers.anchor_worker.get_unanchored_logs filters out.
    assert metadata.get("test_request") is True
    assert metadata.get("sandbox") is True


def test_non_sandbox_agent_row_not_flagged():
    metadata = _audit_metadata(client_policy_hash=None, sandbox=False)
    assert "test_request" not in metadata
    assert "sandbox" not in metadata


# ---------------------------------------------------------------------------
# Receipt surfacing
# ---------------------------------------------------------------------------

class _AcquireCtx:
    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *exc):
        return False


def _row(values):
    m = MagicMock()
    m.__getitem__ = lambda _self, k: values[k]
    m.get = lambda k, d=None: values.get(k, d)
    return m


def _receipt_db(row_values):
    conn = MagicMock()
    conn.fetchrow = AsyncMock(return_value=_row(row_values))
    db = MagicMock()
    db.acquire = lambda: _AcquireCtx(conn)
    org = MagicMock()
    org.name = "Test Org"
    db.get_organization_by_id = AsyncMock(return_value=org)
    return db


def test_receipt_surfaces_sandbox():
    rid = uuid4()
    row = {
        "id": rid, "timestamp": datetime.now(UTC),
        "verdict": "approved", "verdict_reason": None, "action_type": "tool_call",
        "agent_id": uuid4(), "agent_name": "sb", "org_id": uuid4(),
        "payload": {}, "trust_score_at_time": 50,
        "action_hash": "a" * 64, "signature_valid": True,
        "signature": None, "agent_public_key": None,
        "merkle_root": None, "tx_hash": None, "block_number": None,
        "chain_id": 8453, "anchored_at": None, "merkle_root_id": None,
        "effective_controls_hash": None, "metadata": {"sandbox": True, "test_request": True},
    }
    db = _receipt_db(row)
    app.dependency_overrides[get_db] = lambda: db
    try:
        resp = client.get(f"/public/verify/{rid}")
    finally:
        app.dependency_overrides.clear()
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["sandbox"] is True
    assert data["integrity_status"] == "sandbox"
