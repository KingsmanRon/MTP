"""Tests for the /verify-token downstream enforcement endpoint.

The approval token is an HMAC over SERVER_SECRET; bare validity checks need no
DB, so these run against the FastAPI app directly. This is the primitive that
lets a downstream executor refuse to act without a valid, action-bound
approval. Consumption (consume=true) additionally records an anchored
``token_consumed`` audit event and fails closed when it cannot.
"""
from uuid import uuid4

from fastapi.testclient import TestClient

from api.crypto import CryptoService
from api.main import SERVER_SECRET, app, get_db_optional

client = TestClient(app)

AGENT_ID = str(uuid4())
ACTION_TYPE = "financial_transaction"
PAYLOAD = {"amount": 50, "currency": "USD"}
NONCE = "nonce-abc"
TIMESTAMP = "2026-06-10T10:30:00Z"


def _action_hash():
    return CryptoService.compute_action_hash(
        agent_id=AGENT_ID,
        action_type=ACTION_TYPE,
        payload=PAYLOAD,
        nonce=NONCE,
        timestamp=TIMESTAMP,
        sig_version=2,
    )


def _token(action_hash=None, expiry_minutes=5):
    return CryptoService.generate_approval_token(
        agent_id=AGENT_ID,
        action_hash=action_hash or _action_hash(),
        verdict="approved",
        server_secret=SERVER_SECRET,
        expiry_minutes=expiry_minutes,
    )


class TestVerifyToken:
    def test_valid_token_accepted(self):
        resp = client.post("/verify-token", json={"approval_token": _token()})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["valid"] is True
        assert body["verdict"] == "approved"
        assert body["agent_id"] == AGENT_ID

    def test_tampered_token_rejected(self):
        bad = _token()[:-4] + ("AAAA" if not _token().endswith("AAAA") else "BBBB")
        resp = client.post("/verify-token", json={"approval_token": bad})
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    def test_garbage_token_rejected(self):
        resp = client.post("/verify-token", json={"approval_token": "not-a-token"})
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    def test_expired_token_rejected(self):
        resp = client.post("/verify-token", json={"approval_token": _token(expiry_minutes=-1)})
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    def test_agent_id_mismatch_rejected(self):
        resp = client.post(
            "/verify-token",
            json={"approval_token": _token(), "agent_id": str(uuid4())},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is False
        assert "agent_id" in body["reason"]

    def test_action_binding_match(self):
        resp = client.post(
            "/verify-token",
            json={
                "approval_token": _token(),
                "agent_id": AGENT_ID,
                "action_type": ACTION_TYPE,
                "payload": PAYLOAD,
                "nonce": NONCE,
                "timestamp": TIMESTAMP,
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["valid"] is True
        assert body["action_hash_matches"] is True

    def test_action_binding_mismatch_rejected(self):
        # Same token, but the caller presents a different action (amount tampered).
        resp = client.post(
            "/verify-token",
            json={
                "approval_token": _token(),
                "action_type": ACTION_TYPE,
                "payload": {"amount": 5000, "currency": "USD"},
                "nonce": NONCE,
                "timestamp": TIMESTAMP,
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is False
        assert body["action_hash_matches"] is False


class _FakeDatabase:
    """Database stub for the token-consumption audit write.

    Captures inserted audit entries so tests can assert exactly what would be
    chained and anchored. ``trust_score=None`` simulates an unknown agent;
    ``fail_insert=True`` simulates a DB outage during the audit write.
    """

    def __init__(self, trust_score=50, fail_insert=False, metadata=None):
        self.trust_score = trust_score
        self.fail_insert = fail_insert
        self.metadata = metadata or {}
        self.entries = []
        self.consumed_token_ids: set[str] = set()
        self.consumed_token_digests: set[bytes] = set()
        self.consumptions: dict[str, tuple[bytes, str | None, str, object]] = {}

    def acquire(self):
        db = self

        class _Conn:
            async def fetchrow(self, query, *args):  # noqa: ARG002
                if db.trust_score is None:
                    return None
                return {"trust_score": db.trust_score, "metadata": db.metadata}

        class _Ctx:
            async def __aenter__(self):
                return _Conn()

            async def __aexit__(self, *exc):
                return False

        return _Ctx()

    async def insert_token_consumption(
        self,
        entry,
        *,
        token_id,
        token_digest,
        approved_action_hash,
        execution_ref=None,
    ):
        if self.fail_insert:
            raise RuntimeError("simulated database outage")
        existing = self.consumptions.get(token_id)
        if existing is not None:
            digest, existing_ref, action_hash, audit_id = existing
            if (
                execution_ref is not None
                and digest == token_digest
                and existing_ref == execution_ref
                and action_hash == approved_action_hash
            ):
                return audit_id, "idempotent"
            return None
        if token_digest in self.consumed_token_digests:
            return None
        audit_id = uuid4()
        self.consumed_token_ids.add(token_id)
        self.consumed_token_digests.add(token_digest)
        self.consumptions[token_id] = (
            token_digest,
            execution_ref,
            approved_action_hash,
            audit_id,
        )
        self.entries.append((entry, True))
        return audit_id, "consumed"


def _consume_body(execution_ref="x402-settlement-1"):
    return {
        "approval_token": _token(), "agent_id": AGENT_ID,
        "action_type": ACTION_TYPE, "payload": PAYLOAD,
        "nonce": NONCE, "timestamp": TIMESTAMP, "consume": True,
        "execution_ref": execution_ref,
    }


def _with_overrides(db=None):
    if db is not None:
        app.dependency_overrides[get_db_optional] = lambda: db


def test_consume_retry_with_same_execution_ref_is_idempotent():
    fake_db = _FakeDatabase()
    body = _consume_body()
    _with_overrides(db=fake_db)
    try:
        first = client.post("/verify-token", json=body)
        second = client.post("/verify-token", json=body)
    finally:
        app.dependency_overrides.clear()
    assert first.status_code == 200 and first.json()["valid"] is True
    assert second.status_code == 200 and second.json()["valid"] is True
    assert first.json()["consumption_status"] == "consumed"
    assert second.json()["consumption_status"] == "idempotent"
    assert first.json()["consumption_audit_id"] == second.json()["consumption_audit_id"]
    assert second.json()["execution_ref"] == "x402-settlement-1"
    assert len(fake_db.entries) == 1


def test_consume_with_different_execution_ref_is_replay_conflict():
    fake_db = _FakeDatabase()
    first_body = _consume_body("x402-settlement-1")
    second_body = {**first_body, "execution_ref": "x402-settlement-2"}
    _with_overrides(db=fake_db)
    try:
        first = client.post("/verify-token", json=first_body)
        second = client.post("/verify-token", json=second_body)
    finally:
        app.dependency_overrides.clear()
    assert first.json()["valid"] is True
    assert second.json()["valid"] is False
    assert "used" in (second.json()["reason"] or "").lower()


def test_legacy_consume_without_execution_ref_remains_single_use():
    fake_db = _FakeDatabase()
    body = _consume_body(None)
    _with_overrides(db=fake_db)
    try:
        first = client.post("/verify-token", json=body)
        second = client.post("/verify-token", json=body)
    finally:
        app.dependency_overrides.clear()
    assert first.json()["valid"] is True
    assert second.json()["valid"] is False


def test_consume_records_anchored_audit_event():
    fake_db = _FakeDatabase()
    _with_overrides(db=fake_db)
    try:
        resp = client.post("/verify-token", json=_consume_body())
    finally:
        app.dependency_overrides.clear()
    body = resp.json()
    assert body["valid"] is True
    assert body["consumption_audit_id"], "successful consume must return the audit id"

    assert len(fake_db.entries) == 1
    entry, derive_chain_hash = fake_db.entries[0]
    # Chained under the per-agent advisory lock like every /verify row.
    assert derive_chain_hash is True
    assert str(entry.agent_id) == AGENT_ID
    assert entry.action_type == "token_consumed"
    # References the original approval, under its own distinct leaf hash.
    assert entry.payload["original_action_hash"] == _action_hash()
    assert entry.metadata["original_action_hash"] == _action_hash()
    assert entry.action_hash != _action_hash()
    assert entry.payload["action_hash_matches"] is True
    # Recorded honestly as a server attestation, not an agent signature.
    assert entry.signature_valid is False
    assert entry.metadata["attestation_type"] == "token_consumption"
    # Anchor-eligible: the worker only excludes rows tagged test_request.
    assert "test_request" not in entry.metadata


def test_consume_requires_complete_action_parameters_before_state_change():
    fake_db = _FakeDatabase()
    _with_overrides(db=fake_db)
    try:
        resp = client.post(
            "/verify-token",
            json={"approval_token": _token(), "consume": True},
        )
    finally:
        app.dependency_overrides.clear()
    body = resp.json()
    assert body["valid"] is False
    assert "requires action_type" in (body["reason"] or "")
    assert fake_db.entries == []


def test_currently_sandboxed_agent_cannot_consume_execution_token():
    fake_db = _FakeDatabase(metadata={"sandbox": True})
    _with_overrides(db=fake_db)
    try:
        resp = client.post("/verify-token", json=_consume_body())
    finally:
        app.dependency_overrides.clear()
    assert resp.json()["valid"] is False
    assert resp.json()["sandbox"] is True
    assert fake_db.entries == []


def test_sandbox_claim_cannot_be_consumed_after_agent_promotion():
    sandbox_token = CryptoService.generate_approval_token(
        agent_id=AGENT_ID,
        action_hash=_action_hash(),
        verdict="approved",
        server_secret=SERVER_SECRET,
        sandbox=True,
    )
    body = _consume_body()
    body["approval_token"] = sandbox_token
    fake_db = _FakeDatabase(metadata={"sandbox": False})
    _with_overrides(db=fake_db)
    try:
        resp = client.post("/verify-token", json=body)
    finally:
        app.dependency_overrides.clear()
    assert resp.json()["valid"] is False
    assert resp.json()["sandbox"] is True
    assert fake_db.entries == []


def test_bare_check_stays_stateless():
    # Without consume, the endpoint must not touch the database at all.
    fake_db = _FakeDatabase()
    _with_overrides(db=fake_db)
    try:
        resp = client.post("/verify-token", json={"approval_token": _token()})
    finally:
        app.dependency_overrides.clear()
    body = resp.json()
    assert body["valid"] is True
    assert body["consumption_audit_id"] is None
    assert fake_db.entries == []


def test_consume_does_not_depend_on_cache_state():
    fake_db = _FakeDatabase()
    _with_overrides(db=fake_db)
    try:
        resp = client.post("/verify-token", json=_consume_body())
    finally:
        app.dependency_overrides.clear()
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


def test_consume_without_database_fails_closed_without_burning_token():
    # The durable database is the single-use authority.
    try:
        resp = client.post("/verify-token", json=_consume_body())
    finally:
        app.dependency_overrides.clear()
    body = resp.json()
    assert body["valid"] is False
    assert "database" in (body["reason"] or "").lower()


def test_consume_audit_write_failure_fails_closed_without_claiming_token():
    body = _consume_body()
    _with_overrides(db=_FakeDatabase(fail_insert=True))
    try:
        failed = client.post("/verify-token", json=body)
        # DB recovers: no transaction committed, so the same token can retry.
        app.dependency_overrides[get_db_optional] = lambda: _FakeDatabase()
        retried = client.post("/verify-token", json=body)
    finally:
        app.dependency_overrides.clear()
    assert failed.json()["valid"] is False
    assert "not consumed" in (failed.json()["reason"] or "").lower()
    assert retried.json()["valid"] is True


def test_consume_unknown_agent_fails_closed():
    # Agent row gone (e.g. never provisioned in this environment): the
    # consumption event cannot be attributed, so the consume is refused.
    _with_overrides(db=_FakeDatabase(trust_score=None))
    try:
        resp = client.post("/verify-token", json=_consume_body())
    finally:
        app.dependency_overrides.clear()
    assert resp.json()["valid"] is False


def test_dual_secret_rotation_accepts_old_secret():
    old = b"o" * 40
    new = b"n" * 40
    token = CryptoService.generate_approval_token(
        agent_id=AGENT_ID, action_hash=_action_hash(), verdict="approved",
        server_secret=old, expiry_minutes=5,
    )
    # During rotation we serve [new, old]; an old-secret token still verifies.
    assert CryptoService.verify_approval_token(token, [new, old]) is not None
    # Wrong secret only -> rejected.
    assert CryptoService.verify_approval_token(token, [new]) is None
    # Back-compat: a single bytes secret still works.
    assert CryptoService.verify_approval_token(token, old) is not None
