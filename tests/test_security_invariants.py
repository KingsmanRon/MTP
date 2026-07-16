"""Focused regressions for backend security invariants."""
from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.main import _api_key_prefix, app, get_db, get_redis, require_api_scope
from api.models import AgentRecord, AgentStatus

client = TestClient(app)


@pytest.mark.asyncio
async def test_read_scope_cannot_satisfy_write_dependency():
    dependency = require_api_scope("write")
    with pytest.raises(HTTPException) as exc:
        await dependency({"org_id": uuid4(), "scopes": ["read"]})
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_admin_scope_satisfies_write_dependency():
    dependency = require_api_scope("write")
    auth = {"org_id": uuid4(), "scopes": ["admin"]}
    assert await dependency(auth) == auth


def test_api_key_prefix_uses_random_key_material_and_fits_schema():
    live_key = "inntris_live_sk_" + "a" * 32
    standard_key = "inntris_" + "b" * 32
    assert _api_key_prefix(live_key) == "a" * 8
    assert _api_key_prefix(standard_key) == "b" * 8
    assert len(_api_key_prefix(standard_key)) == 8


def _agent_record(agent_id, org_id):
    now = datetime.now(UTC)
    return AgentRecord(
        id=agent_id,
        org_id=org_id,
        name="Verifier",
        public_key=b"\x00" * 32,
        public_key_fingerprint="a" * 64,
        trust_score=50,
        status=AgentStatus.ACTIVE,
        daily_limit_usd=Decimal("1000"),
        per_action_limit_usd=Decimal("100"),
        allowed_actions=["tool_call"],
        blocked_actions=[],
        rate_limit_per_minute=60,
        last_action_at=None,
        total_actions_count=0,
        total_blocked_count=0,
        metadata={},
        created_at=now,
        updated_at=now,
    )


class _RedisPipeline:
    def __init__(self, redis):
        self.redis = redis
        self.operations = []

    def incr(self, key):
        self.operations.append(("incr", key, None))
        return self

    def expire(self, key, seconds):
        self.operations.append(("expire", key, seconds))
        return self

    async def execute(self):
        results = []
        for operation, key, value in self.operations:
            if operation == "incr":
                self.redis.values[key] = self.redis.values.get(key, 0) + 1
                results.append(self.redis.values[key])
            else:
                self.redis.expiries[key] = value
                results.append(True)
        return results


class _RedisTelemetryStub:
    def __init__(self):
        self.values = {}
        self.expiries = {}

    def pipeline(self, transaction=True):
        assert transaction is True
        return _RedisPipeline(self)

    async def incr(self, key):
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    async def expire(self, key, ttl):
        self.expiries[key] = ttl
        return True

    async def decr(self, key):
        self.values[key] = self.values.get(key, 0) - 1
        return self.values[key]

    async def delete(self, key):
        self.values.pop(key, None)
        self.expiries.pop(key, None)
        return 1


def test_malformed_signature_is_bounded_attack_telemetry_only():
    agent_id = uuid4()
    org_id = uuid4()
    db = MagicMock()
    db.get_agent_by_id = AsyncMock(return_value=_agent_record(agent_id, org_id))
    db.insert_audit_log = AsyncMock()
    db.update_agent_after_verification = AsyncMock()
    db.reserve_rate_and_spend = AsyncMock()
    db.create_security_alert = AsyncMock()
    redis_stub = _RedisTelemetryStub()

    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_redis] = lambda: redis_stub
    try:
        with patch("api.main._dispatch_verdict_webhook", new_callable=AsyncMock):
            response = client.post(
                "/verify",
                json={
                    "agent_id": str(agent_id),
                    "action_type": "tool_call",
                    "payload": {"resource": "file", "operation": "read"},
                    "signature": "!" * 64,
                    "nonce": "n-1",
                    "timestamp": "2026-06-16T12:00:00Z",
                    "policy_hash": "c" * 64,
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401
    assert response.json()["audit_id"] is None
    db.insert_audit_log.assert_not_called()
    db.update_agent_after_verification.assert_not_called()
    db.reserve_rate_and_spend.assert_not_called()
    db.create_security_alert.assert_awaited_once()

    attack_keys = [
        key for key in redis_stub.values
        if ":security:signature_invalid:" in key
    ]
    assert len(attack_keys) == 2
    assert all(redis_stub.expiries[key] <= 3600 for key in attack_keys)
