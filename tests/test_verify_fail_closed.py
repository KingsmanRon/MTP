"""/verify fail-closed accounting and replay semantics.

Two invariants:

* A Redis outage on any verification dependency returns HTTP 503 and
  increments ``inntris_verify_unavailable_total`` so the Prometheus rule
  pages the operator — Redis is a security boundary, its outage is a
  product outage.
* A detected nonce replay is a caller error: HTTP 401, counted as a replay,
  and never reported as service unavailability. (Regression: the replay
  rejection used to be swallowed by the Redis error handler and surfaced
  as a 503.)
"""

from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from api.agent_client import build_signed_verify_request
from api.main import app, get_db, get_redis
from api.models import AgentRecord, AgentStatus
from api.observability import verify_unavailable_total

client = TestClient(app)


def _agent_record(agent_id, org_id, public_key: bytes):
    now = datetime.now(UTC)
    return AgentRecord(
        id=agent_id,
        org_id=org_id,
        name="Verifier",
        public_key=public_key,
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
        self.operations.append(("incr", key))
        return self

    def expire(self, key, _seconds):
        self.operations.append(("expire", key))
        return self

    async def execute(self):
        results = []
        for operation, key in self.operations:
            if operation == "incr":
                self.redis.values[key] = self.redis.values.get(key, 0) + 1
                results.append(self.redis.values[key])
            else:
                results.append(True)
        return results


class _RedisStub:
    """Counter-capable stub whose nonce SET behaviour is scripted per test."""

    def __init__(self, *, nonce_set_result=True, nonce_set_error=None):
        self.values = {}
        self.nonce_set_result = nonce_set_result
        self.nonce_set_error = nonce_set_error

    def pipeline(self, transaction=True):
        assert transaction is True
        return _RedisPipeline(self)

    async def incr(self, key):
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    async def decr(self, key):
        self.values[key] = self.values.get(key, 0) - 1
        return self.values[key]

    async def expire(self, _key, _ttl):
        return True

    async def delete(self, key):
        self.values.pop(key, None)
        return 1

    async def set(self, _key, _value, ex=None, nx=None):
        del ex, nx
        if self.nonce_set_error is not None:
            raise self.nonce_set_error
        return self.nonce_set_result


def _counter_value(component: str) -> float:
    for metric in verify_unavailable_total.collect():
        for sample in metric.samples:
            if (
                sample.name.endswith("_total")
                and sample.labels.get("component") == component
            ):
                return sample.value
    return 0.0


def _post_signed_verify(redis_stub):
    signing_key = SigningKey.generate()
    agent_id = uuid4()
    db = MagicMock()
    db.get_agent_by_id = AsyncMock(
        return_value=_agent_record(agent_id, uuid4(), bytes(signing_key.verify_key))
    )
    body = build_signed_verify_request(
        agent_id=str(agent_id),
        signing_key=signing_key,
        action_type="tool_call",
        payload={"resource": "file", "operation": "read"},
    )

    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_redis] = lambda: redis_stub
    try:
        with patch("api.main._dispatch_verdict_webhook", new_callable=AsyncMock):
            return client.post("/verify", json=body), db
    finally:
        app.dependency_overrides.clear()


def test_nonce_replay_returns_401_not_503():
    response, db = _post_signed_verify(_RedisStub(nonce_set_result=False))

    assert response.status_code == 401
    assert "Nonce already used" in response.json()["detail"]
    db.insert_audit_log.assert_not_called()


def test_nonce_cache_outage_returns_503_and_counts_unavailability():
    before = _counter_value("nonce_cache")
    response, db = _post_signed_verify(
        _RedisStub(nonce_set_error=ConnectionError("redis down"))
    )

    assert response.status_code == 503
    assert _counter_value("nonce_cache") == before + 1
    db.insert_audit_log.assert_not_called()


def test_missing_redis_fails_closed_and_counts_abuse_limiter():
    before = _counter_value("abuse_limiter")
    signing_key = SigningKey.generate()
    agent_id = uuid4()
    db = MagicMock()
    body = build_signed_verify_request(
        agent_id=str(agent_id),
        signing_key=signing_key,
        action_type="tool_call",
        payload={"resource": "file", "operation": "read"},
    )

    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_redis] = lambda: None
    try:
        response = client.post("/verify", json=body)
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 503
    assert _counter_value("abuse_limiter") == before + 1
    db.get_agent_by_id.assert_not_called()
