"""Tests for the /verify-token downstream enforcement endpoint.

The approval token is an HMAC over SERVER_SECRET; verifying it needs no DB, so
these run against the FastAPI app directly. This is the primitive that lets a
downstream executor refuse to act without a valid, action-bound approval.
"""
from uuid import uuid4

from fastapi.testclient import TestClient

from api.crypto import CryptoService
from api.main import SERVER_SECRET, app

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
