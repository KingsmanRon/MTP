"""
Regression tests for admin response serialization.

Both endpoints below previously raised ``fastapi.exceptions.ResponseValidationError``
(HTTP 500) because values came back from asyncpg in a shape the Pydantic response
models reject:

* ``GET /admin/agents`` — the ``metadata`` JSONB column is returned as a raw JSON
  *string* (no JSON codec is registered on the pool), but ``AgentSummary.metadata``
  expects a ``dict``.
* ``GET /admin/audit/search`` — the ``request_ip`` INET column is decoded by asyncpg
  into an ``ipaddress.IPv4Address`` object, but ``AuditLogSummary.request_ip``
  expects a ``str``.
"""
from datetime import UTC, datetime
from ipaddress import IPv4Address
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from fastapi.testclient import TestClient

from api.main import app, get_db, verify_api_key
from api.tenant_boundary import get_admin_tenant_database

client = TestClient(app)

ORG_ID = uuid4()


def _acquire_returning(conn):
    """Wrap a mock connection in a sync-callable async context manager."""
    acm = MagicMock()
    acm.__aenter__ = AsyncMock(return_value=conn)
    acm.__aexit__ = AsyncMock(return_value=False)
    db = MagicMock()
    db.acquire = MagicMock(return_value=acm)
    return db


def _override_tenant_db(db_mock):
    app.dependency_overrides[get_db] = lambda: db_mock
    app.dependency_overrides[get_admin_tenant_database] = lambda: db_mock


def test_list_agents_parses_jsonb_metadata_string():
    """metadata returned as a JSON string must be parsed into a dict, not 500."""
    now = datetime.now(UTC)
    agent_row = {
        "id": uuid4(),
        "org_id": ORG_ID,
        "name": "events-bootstrap",
        "public_key_fingerprint": "ab:cd",
        "trust_score": 100,
        "status": "active",
        "daily_limit_usd": 100.0,
        "per_action_limit_usd": 10.0,
        "allowed_actions": [],
        "blocked_actions": [],
        "rate_limit_per_minute": 60,
        "last_action_at": None,
        "total_actions_count": 0,
        "total_blocked_count": 0,
        "metadata": '{"source": "events_v1_bootstrap", "non_cryptographic": true}',
        "created_at": now,
        "updated_at": None,
    }

    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=[agent_row])
    db_mock = _acquire_returning(conn)

    _override_tenant_db(db_mock)
    app.dependency_overrides[verify_api_key] = lambda: {"org_id": ORG_ID}
    try:
        response = client.get("/admin/agents")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    body = response.json()
    assert body[0]["metadata"] == {
        "source": "events_v1_bootstrap",
        "non_cryptographic": True,
    }


def test_search_audit_logs_serializes_inet_request_ip():
    """request_ip returned as an IPv4Address must serialize to a string, not 500."""
    now = datetime.now(UTC)
    log_row = {
        "id": uuid4(),
        "agent_id": uuid4(),
        "agent_name": "events-bootstrap",
        "timestamp": now,
        "action_type": "events_v1",
        "action_hash": "deadbeef",
        "payload": {"k": "v"},
        "verdict": "approved",
        "verdict_reason": None,
        "signature_valid": True,
        "request_ip": IPv4Address("100.64.0.10"),
        "request_user_agent": None,
        "response_time_ms": 0,
        "trust_score_at_time": 100,
        "merkle_root_id": None,
        "merkle_leaf_index": None,
    }

    conn = AsyncMock()
    conn.fetchval = AsyncMock(return_value=1)
    conn.fetch = AsyncMock(return_value=[log_row])
    db_mock = _acquire_returning(conn)

    _override_tenant_db(db_mock)
    app.dependency_overrides[verify_api_key] = lambda: {"org_id": ORG_ID}
    try:
        response = client.get("/admin/audit/search?limit=10&offset=0")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 1
    assert body["logs"][0]["request_ip"] == "100.64.0.10"
    assert body["logs"][0]["transaction_hash"] is None
    assert body["logs"][0]["tx_hash"] is None


def test_search_audit_logs_surfaces_transaction_hash_when_anchored():
    """Anchored rows must expose the on-chain tx hash so the UI shows 'Anchored'."""
    now = datetime.now(UTC)
    tx_hash = "0x" + "ab" * 32
    log_row = {
        "id": uuid4(),
        "agent_id": uuid4(),
        "agent_name": "events-bootstrap",
        "timestamp": now,
        "action_type": "events_v1",
        "action_hash": "deadbeef",
        "payload": {"k": "v"},
        "verdict": "approved",
        "verdict_reason": None,
        "signature_valid": True,
        "request_ip": None,
        "request_user_agent": None,
        "response_time_ms": 0,
        "trust_score_at_time": 100,
        "merkle_root_id": uuid4(),
        "merkle_leaf_index": 0,
        "transaction_hash": tx_hash,
        "chain_id": 8453,
        "block_number": 46764053,
    }

    conn = AsyncMock()
    conn.fetchval = AsyncMock(return_value=1)
    conn.fetch = AsyncMock(return_value=[log_row])
    db_mock = _acquire_returning(conn)

    _override_tenant_db(db_mock)
    app.dependency_overrides[verify_api_key] = lambda: {"org_id": ORG_ID}
    try:
        response = client.get("/admin/audit/search?limit=10&offset=0")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    log = response.json()["logs"][0]
    assert log["transaction_hash"] == tx_hash
    assert log["tx_hash"] == tx_hash
    assert log["chain_id"] == 8453
    assert log["block_number"] == 46764053
