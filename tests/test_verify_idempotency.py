"""Durable ``/verify`` idempotency and structured denial contracts."""

from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient
from nacl.encoding import RawEncoder
from nacl.signing import SigningKey

from api.agent_client import build_signed_verify_request
from api.crypto import CryptoService
from api.database import LimitReservationError
from api.main import app, get_db, get_redis
from api.models import AgentRecord, AgentStatus

client = TestClient(app)


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


class _RedisStub:
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

    async def set(self, key, value, *, ex=None, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
        if ex is not None:
            self.expiries[key] = ex
        return True


def _agent(agent_id, org_id, public_key):
    now = datetime.now(UTC)
    return AgentRecord(
        id=agent_id,
        org_id=org_id,
        name="Corporate card test agent",
        public_key=public_key,
        public_key_fingerprint=CryptoService.compute_public_key_fingerprint(public_key),
        trust_score=50,
        status=AgentStatus.ACTIVE,
        daily_limit_usd=Decimal("100"),
        per_action_limit_usd=Decimal("100"),
        allowed_actions=["financial_transaction"],
        blocked_actions=[],
        rate_limit_per_minute=60,
        last_action_at=None,
        total_actions_count=0,
        total_blocked_count=0,
        metadata={},
        created_at=now,
        updated_at=now,
    )


class _VerifyDatabase:
    def __init__(self, agent, *, reservation_error=None):
        self.agent = agent
        self.reservation_error = reservation_error
        self.idempotency = {}
        self.audit_entries = []
        self.reserve_calls = []
        self.release_calls = []
        self.trust_updates = []

    async def get_agent_by_id(self, agent_id):
        assert agent_id == self.agent.id
        return self.agent

    async def claim_verify_request(self, **kwargs):
        key = (kwargs["agent_id"], kwargs["request_ref"])
        existing = self.idempotency.get(key)
        if existing is not None:
            return "existing", existing
        record = {
            **kwargs,
            "state": "processing",
            "agent_id": kwargs["agent_id"],
        }
        self.idempotency[key] = record
        return "new", record

    async def complete_verify_request(self, **kwargs):
        key = (kwargs["agent_id"], kwargs["request_ref"])
        record = self.idempotency[key]
        record.update(
            {
                **kwargs,
                "state": "completed",
                "audit_log_id": kwargs["audit_id"],
                "response_timestamp": kwargs["response_timestamp"],
                "sandbox": False,
            }
        )

    async def abandon_verify_request(self, *, agent_id, request_ref, action_hash):
        key = (agent_id, request_ref)
        if self.idempotency.get(key, {}).get("action_hash") == action_hash:
            self.idempotency.pop(key, None)

    async def get_rate_limit_count(self, _agent_id, _window_type, _window_start):
        return 0, Decimal("0")

    async def get_daily_spend(self, _agent_id):
        return Decimal("0")

    async def get_active_agent_policy(self, _agent_id):
        return None

    async def reserve_rate_and_spend(self, **kwargs):
        self.reserve_calls.append(kwargs)
        if self.reservation_error is not None:
            raise self.reservation_error
        return 1, kwargs["amount"], uuid4()

    async def release_spend_reservation(self, **kwargs):
        self.release_calls.append(kwargs)
        return True

    async def insert_audit_log(self, entry, derive_chain_hash=False):
        assert derive_chain_hash is True
        audit_id = uuid4()
        self.audit_entries.append((audit_id, entry))
        return audit_id

    async def update_agent_after_verification(self, agent_id, score, was_approved):
        self.trust_updates.append((agent_id, score, was_approved))


def _signed_body(signing_key, agent_id, *, request_ref, amount, nonce):
    payload = {
        "amount": amount,
        "currency": "USD",
        "provider": "highnote",
        "rail": "card",
        "request_ref": request_ref,
    }
    body = build_signed_verify_request(
        agent_id=str(agent_id),
        signing_key=signing_key,
        action_type="financial_transaction",
        payload=payload,
        nonce=nonce,
        timestamp=datetime.now(UTC),
        sig_version=3,
    )
    body["request_ref"] = request_ref
    return body


def _post_with(db, redis_stub, body):
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_redis] = lambda: redis_stub
    try:
        with patch("api.main._dispatch_verdict_webhook", new_callable=AsyncMock):
            return client.post("/verify", json=body)
    finally:
        app.dependency_overrides.clear()


def test_authenticated_policy_block_is_structured_audited_and_idempotent():
    agent_id = uuid4()
    signing_key = SigningKey.generate()
    public_key = bytes(signing_key.verify_key.encode(RawEncoder))
    db = _VerifyDatabase(_agent(agent_id, uuid4(), public_key))
    redis_stub = _RedisStub()
    body = _signed_body(
        signing_key,
        agent_id,
        request_ref="highnote:request-blocked",
        amount="250.00",
        nonce="blocked-nonce",
    )

    first = _post_with(db, redis_stub, body)
    second = _post_with(db, redis_stub, body)

    assert first.status_code == 403
    assert first.json() == {
        **{key: first.json()[key] for key in ("audit_id", "timestamp")},
        "verdict": "blocked",
        "violation_code": "per_action_limit_exceeded",
        "detail": "Amount $250.00 exceeds per-action limit of $100.",
        "idempotency_status": "new",
    }
    assert second.status_code == 403
    assert second.json()["audit_id"] == first.json()["audit_id"]
    assert second.json()["idempotency_status"] == "replayed"
    assert len(db.audit_entries) == 1
    assert db.reserve_calls == []


def test_approved_retry_returns_original_token_without_second_reservation():
    agent_id = uuid4()
    signing_key = SigningKey.generate()
    public_key = bytes(signing_key.verify_key.encode(RawEncoder))
    db = _VerifyDatabase(_agent(agent_id, uuid4(), public_key))
    redis_stub = _RedisStub()
    body = _signed_body(
        signing_key,
        agent_id,
        request_ref="highnote:request-approved",
        amount="50.00",
        nonce="approved-nonce",
    )

    first = _post_with(db, redis_stub, body)
    second = _post_with(db, redis_stub, body)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["audit_id"] == second.json()["audit_id"]
    assert first.json()["approval_token"] == second.json()["approval_token"]
    assert first.json()["idempotency_status"] == "new"
    assert second.json()["idempotency_status"] == "replayed"
    assert len(db.audit_entries) == 1
    assert len(db.reserve_calls) == 1


def test_same_request_ref_with_altered_signed_action_conflicts_before_reservation():
    agent_id = uuid4()
    signing_key = SigningKey.generate()
    public_key = bytes(signing_key.verify_key.encode(RawEncoder))
    db = _VerifyDatabase(_agent(agent_id, uuid4(), public_key))
    redis_stub = _RedisStub()
    first_body = _signed_body(
        signing_key,
        agent_id,
        request_ref="highnote:request-conflict",
        amount="50.00",
        nonce="conflict-one",
    )
    altered_body = _signed_body(
        signing_key,
        agent_id,
        request_ref="highnote:request-conflict",
        amount="60.00",
        nonce="conflict-two",
    )

    first = _post_with(db, redis_stub, first_body)
    altered = _post_with(db, redis_stub, altered_body)

    assert first.status_code == 200
    assert altered.status_code == 409
    assert altered.json()["error"] == "idempotency_conflict"
    assert len(db.audit_entries) == 1
    assert len(db.reserve_calls) == 1


def test_atomic_rate_rejection_returns_structured_429_and_audit_id():
    agent_id = uuid4()
    signing_key = SigningKey.generate()
    public_key = bytes(signing_key.verify_key.encode(RawEncoder))
    db = _VerifyDatabase(
        _agent(agent_id, uuid4(), public_key),
        reservation_error=LimitReservationError("rate", 61),
    )
    body = _signed_body(
        signing_key,
        agent_id,
        request_ref="highnote:request-rate",
        amount="10.00",
        nonce="rate-nonce",
    )

    response = _post_with(db, _RedisStub(), body)

    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"
    assert response.json()["verdict"] == "rate_limited"
    assert response.json()["violation_code"] == "rate_limit_exceeded"
    assert response.json()["audit_id"] == str(db.audit_entries[0][0])


def test_request_ref_must_be_covered_by_the_signed_payload():
    agent_id = uuid4()
    signing_key = SigningKey.generate()
    public_key = bytes(signing_key.verify_key.encode(RawEncoder))
    body = build_signed_verify_request(
        agent_id=str(agent_id),
        signing_key=signing_key,
        action_type="financial_transaction",
        payload={"amount": "10.00", "currency": "USD", "request_ref": "signed-ref"},
        timestamp=datetime.now(UTC),
        sig_version=3,
    )
    body["request_ref"] = "different-unsigned-ref"

    response = _post_with(
        _VerifyDatabase(_agent(agent_id, uuid4(), public_key)),
        _RedisStub(),
        body,
    )

    assert response.status_code == 422
    assert "payload.request_ref must equal request_ref" in response.text
