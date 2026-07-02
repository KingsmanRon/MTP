"""Tests for the /verify-token downstream enforcement endpoint.

The approval token is an HMAC over SERVER_SECRET; verifying it needs no DB, so
these run against the FastAPI app directly. This is the primitive that lets a
downstream executor refuse to act without a valid, action-bound approval.
"""
from uuid import uuid4

from fastapi.testclient import TestClient

from api.crypto import CryptoService
from api.main import SERVER_SECRET, app, get_redis

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


class _FakeRedis:
    """Minimal async Redis stub supporting ``SET key val EX nx`` for single-use."""

    def __init__(self):
        self.store: dict[str, str] = {}

    async def set(self, key, value, ex=None, nx=False):  # noqa: ARG002 — mirrors redis signature
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True


def test_consume_makes_token_single_use():
    fake = _FakeRedis()
    app.dependency_overrides[get_redis] = lambda: fake
    try:
        body = {
            "approval_token": _token(), "agent_id": AGENT_ID,
            "action_type": ACTION_TYPE, "payload": PAYLOAD,
            "nonce": NONCE, "timestamp": TIMESTAMP, "consume": True,
        }
        first = client.post("/verify-token", json=body)
        second = client.post("/verify-token", json=body)
    finally:
        app.dependency_overrides.clear()
    assert first.status_code == 200 and first.json()["valid"] is True
    assert second.status_code == 200 and second.json()["valid"] is False
    assert "used" in (second.json()["reason"] or "").lower()


def test_consume_without_cache_fails_closed():
    # No redis override -> get_redis returns the (None) module pool, so single-use
    # cannot be enforced and the gate must refuse rather than allow a double-spend.
    resp = client.post("/verify-token", json={"approval_token": _token(), "consume": True})
    assert resp.status_code == 200
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
