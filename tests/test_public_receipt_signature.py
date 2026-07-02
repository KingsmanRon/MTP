"""GET /public/verify/{id} exposes signature_b64 + public_key_b64 (F1).

A third party must be able to re-verify the Ed25519 signature over the action
hash from the public receipt alone, rather than trusting the server's
``signature_valid`` boolean. Malformed-submission sentinels (not real 64-byte
signatures) must NOT be surfaced.
"""
import base64
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from fastapi.testclient import TestClient
from nacl.encoding import RawEncoder
from nacl.signing import SigningKey, VerifyKey

from api.crypto import CryptoService
from api.main import app, get_db

client = TestClient(app)


class _AcquireCtx:
    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *exc):
        return False


def _row(values: dict):
    m = MagicMock()
    m.__getitem__ = lambda _self, k: values[k]
    m.get = lambda k, d=None: values.get(k, d)
    return m


def _mock_db(row_values: dict):
    conn = MagicMock()
    conn.fetchrow = AsyncMock(return_value=_row(row_values))
    db = MagicMock()
    db.acquire = lambda: _AcquireCtx(conn)
    org = MagicMock()
    org.name = "Test Org"
    db.get_organization_by_id = AsyncMock(return_value=org)
    return db


def _base_row(**overrides):
    values = {
        "id": uuid4(),
        "timestamp": datetime.now(UTC),
        "verdict": "approved",
        "verdict_reason": None,
        "action_type": "tool_call",
        "agent_id": uuid4(),
        "agent_name": "test-agent",
        "org_id": uuid4(),
        "payload": {},
        "trust_score_at_time": 80,
        "action_hash": CryptoService.compute_payload_hash({"x": 1}),
        "signature_valid": True,
        "signature": None,
        "agent_public_key": None,
        "merkle_root": None,
        "tx_hash": None,
        "block_number": None,
        "chain_id": 8453,
        "anchored_at": None,
        "merkle_root_id": None,
        "policy_hash": None,
    }
    values.update(overrides)
    return values


def test_receipt_exposes_signature_and_public_key_for_reverification():
    sk = SigningKey.generate()
    pub = bytes(sk.verify_key.encode(RawEncoder))
    action_hash = CryptoService.compute_payload_hash({"action": "x"})
    sig = sk.sign(bytes.fromhex(action_hash)).signature

    row = _base_row(action_hash=action_hash, signature=sig, agent_public_key=pub)
    db = _mock_db(row)

    app.dependency_overrides[get_db] = lambda: db
    try:
        resp = client.get(f"/public/verify/{row['id']}")
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert base64.b64decode(data["public_key_b64"]) == pub
    assert base64.b64decode(data["signature_b64"]) == sig
    # Independent re-verification succeeds against the published material —
    # raises BadSignatureError (test fails) if the receipt is inconsistent.
    VerifyKey(base64.b64decode(data["public_key_b64"]), encoder=RawEncoder).verify(
        bytes.fromhex(data["action_hash"]), base64.b64decode(data["signature_b64"])
    )


def test_receipt_hides_sentinel_signature():
    # Malformed submissions store a sentinel (see _decode_signature_for_audit),
    # which is not a 64-byte signature and must not be surfaced as signature_b64.
    sentinel = b"INVALID_SIGNATURE:deadbeef"
    pub = bytes(SigningKey.generate().verify_key.encode(RawEncoder))
    row = _base_row(signature=sentinel, agent_public_key=pub, signature_valid=False)
    db = _mock_db(row)

    app.dependency_overrides[get_db] = lambda: db
    try:
        resp = client.get(f"/public/verify/{row['id']}")
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["signature_b64"] is None
    assert base64.b64decode(data["public_key_b64"]) == pub
