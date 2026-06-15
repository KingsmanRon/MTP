"""Tests for POST /public/agents/register and /public/agents/register-promptfoo."""
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from fastapi.testclient import TestClient

from api.main import app, get_db, get_redis

client = TestClient(app)

VALID_PAYLOAD = {
    "email": "agent@example.com",
    "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  # 32 zero bytes base64
    "adapter_metadata": {"platform": "custom", "version": "1.0"},
}

# Base64 string that is >=44 chars but decodes to 37 bytes (not 32) — triggers 400
WRONG_LENGTH_KEY = "c2hvcnRfa2V5X3RoYXRfaXNfbm90X2V4YWN0bHlfMzJieXRlcw=="


def _make_db_mock():
    """
    Return a Database-like mock whose .acquire() is a regular (non-async) context manager
    wrapper so 'async with database.acquire() as conn' works.
    """
    org_id = uuid4()
    agent_id = uuid4()

    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=None)       # no existing org
    conn.fetchval = AsyncMock(return_value=org_id)     # org insert

    # acquire() must be a sync callable returning an async context manager
    acm = MagicMock()
    acm.__aenter__ = AsyncMock(return_value=conn)
    acm.__aexit__ = AsyncMock(return_value=False)

    db = MagicMock()
    db.acquire = MagicMock(return_value=acm)
    db.create_agent = AsyncMock(return_value=agent_id)
    db.update_agent_status = AsyncMock()
    return db


class TestPublicRegisterAgent:
    def test_register_new_org_returns_201(self):
        db_mock = _make_db_mock()

        app.dependency_overrides[get_db] = lambda: db_mock
        app.dependency_overrides[get_redis] = lambda: None  # Redis None = fail-open
        try:
            response = client.post("/public/agents/register", json=VALID_PAYLOAD)
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 201
        body = response.json()
        assert "agent_id" in body
        assert "public_key_fingerprint" in body
        assert "org_id" in body
        assert body["status"] == "active"
        db_mock.update_agent_status.assert_awaited_once()
        assert db_mock.update_agent_status.await_args.args[1].value == "active"

    def test_register_rate_limited_after_5_requests(self):
        redis_mock = AsyncMock()
        redis_mock.incr = AsyncMock(return_value=6)  # over limit
        redis_mock.expire = AsyncMock(return_value=True)

        db_mock = _make_db_mock()
        app.dependency_overrides[get_db] = lambda: db_mock
        app.dependency_overrides[get_redis] = lambda: redis_mock
        try:
            response = client.post("/public/agents/register", json=VALID_PAYLOAD)
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 429

    def test_register_promptfoo_returns_201_with_promptfoo_tag(self):
        payload = {
            "email": "promptfoo@example.com",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "adapter_metadata": {},
        }
        db_mock = _make_db_mock()

        app.dependency_overrides[get_db] = lambda: db_mock
        app.dependency_overrides[get_redis] = lambda: None
        try:
            response = client.post("/public/agents/register-promptfoo", json=payload)
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 201
        body = response.json()
        assert "agent_id" in body
        assert "promptfoo" in body.get("message", "").lower()
        db_mock.update_agent_status.assert_awaited_once()
        assert db_mock.update_agent_status.await_args.args[1].value == "active"

    def test_invalid_base64_public_key_returns_400(self):
        # Valid base64 format but decodes to 37 bytes — fails our 32-byte check
        bad_payload = dict(VALID_PAYLOAD)
        bad_payload["public_key"] = WRONG_LENGTH_KEY

        db_mock = _make_db_mock()
        app.dependency_overrides[get_db] = lambda: db_mock
        app.dependency_overrides[get_redis] = lambda: None
        try:
            response = client.post("/public/agents/register", json=bad_payload)
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 400
