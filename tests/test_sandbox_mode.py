"""Sandbox mode (#5): sandbox agents stay off the mainnet anchor path.

A sandbox agent's /verify audit rows must carry metadata.test_request=true — the
anchor worker's existing exclusion key (get_unanchored_logs) — plus a sandbox
flag, and the public receipt must report sandbox=true / integrity_status=sandbox
instead of a forever-"pending_anchor".
"""
from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

from api.main import app, get_db
from api.models import AgentRecord, AgentStatus

client = TestClient(app)


def _agent_record(agent_id, org_id, *, metadata):
    now = datetime.now(UTC)
    return AgentRecord(
        id=agent_id, org_id=org_id, name="Verifier",
        public_key=b"\x00" * 32, public_key_fingerprint="a" * 64,
        trust_score=50, status=AgentStatus.ACTIVE,
        daily_limit_usd=Decimal("1000"), per_action_limit_usd=Decimal("100"),
        allowed_actions=["tool_call"], blocked_actions=[],
        rate_limit_per_minute=60, last_action_at=None,
        total_actions_count=0, total_blocked_count=0,
        metadata=metadata, created_at=now, updated_at=now,
    )


def _post_bad_signature(agent):
    """Drive the 401 sig-fail path (reached before Redis), capturing the audit row."""
    db = MagicMock()
    db.get_agent_by_id = AsyncMock(return_value=agent)
    db.insert_audit_log = AsyncMock(return_value=uuid4())
    db.update_agent_after_verification = AsyncMock()
    app.dependency_overrides[get_db] = lambda: db
    try:
        with patch("api.main._dispatch_verdict_webhook", new_callable=AsyncMock):
            resp = client.post("/verify", json={
                "agent_id": str(agent.id), "action_type": "tool_call",
                "payload": {"resource": "file", "operation": "read"},
                "signature": "!" * 64, "nonce": "n-1",
                "timestamp": "2026-06-16T12:00:00Z",
            })
    finally:
        app.dependency_overrides.clear()
    return resp, db


def test_sandbox_agent_audit_row_excluded_from_anchoring():
    agent = _agent_record(uuid4(), uuid4(), metadata={"sandbox": True})
    resp, db = _post_bad_signature(agent)
    assert resp.status_code == 401
    entry = db.insert_audit_log.await_args.args[0]
    # test_request is exactly what workers.anchor_worker.get_unanchored_logs filters out.
    assert entry.metadata.get("test_request") is True
    assert entry.metadata.get("sandbox") is True


def test_non_sandbox_agent_row_not_flagged():
    agent = _agent_record(uuid4(), uuid4(), metadata={})
    resp, db = _post_bad_signature(agent)
    assert resp.status_code == 401
    entry = db.insert_audit_log.await_args.args[0]
    assert "test_request" not in entry.metadata
    assert "sandbox" not in entry.metadata


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
        "policy_hash": None, "metadata": {"sandbox": True, "test_request": True},
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
