"""Tests for POST /verify/debug and the self-diagnosing 401 on /verify.

These cover the integrator-onboarding path:

* ``/verify/debug`` is a dry-run signing diagnostic with NO side effects — a
  wrong signature here must not write an audit row or move the trust score.
* a signature failure on the real ``/verify`` must echo the action hash the
  server verified against (``expected_action_hash``) so a partner can find a
  canonicalization bug without parsing free text — while preserving the
  human ``detail`` string for back-compat and still recording the forensic row.
"""
import base64
from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient
from nacl.encoding import RawEncoder
from nacl.signing import SigningKey

from api.agent_client import build_signed_verify_request
from api.crypto import CryptoService
from api.database import AgentNotFoundError
from api.main import app, get_db
from api.models import AgentRecord, AgentStatus

client = TestClient(app)


def _agent_record(agent_id, org_id, public_key: bytes):
    now = datetime.now(UTC)
    return AgentRecord(
        id=agent_id,
        org_id=org_id,
        name="Verifier",
        public_key=public_key,
        public_key_fingerprint=CryptoService.compute_public_key_fingerprint(public_key),
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


def test_verify_debug_valid_signature_has_no_side_effects():
    agent_id = uuid4()
    org_id = uuid4()
    sk = SigningKey.generate()
    public_key = bytes(sk.verify_key.encode(RawEncoder))
    payload = {"resource": "file", "operation": "read"}

    db = MagicMock()
    db.get_agent_by_id = AsyncMock(return_value=_agent_record(agent_id, org_id, public_key))
    db.insert_audit_log = AsyncMock()
    db.update_agent_after_verification = AsyncMock()

    body = build_signed_verify_request(
        agent_id=str(agent_id),
        signing_key=sk,
        action_type="tool_call",
        payload=payload,
    )

    app.dependency_overrides[get_db] = lambda: db
    try:
        resp = client.post("/verify/debug", json=body)
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["agent_found"] is True
    assert data["signature_valid"] is True
    assert data["expected_action_hash"] == CryptoService.compute_action_hash(
        agent_id=str(agent_id),
        action_type="tool_call",
        payload=payload,
        nonce=body["nonce"],
        timestamp=body["timestamp"],
        sig_version=body["sig_version"],
    )
    # The whole point of the dry-run: no forensic row, no trust-score change.
    db.insert_audit_log.assert_not_called()
    db.update_agent_after_verification.assert_not_called()


def test_verify_debug_agent_not_found_is_not_an_error():
    agent_id = uuid4()
    sk = SigningKey.generate()

    db = MagicMock()
    db.get_agent_by_id = AsyncMock(side_effect=AgentNotFoundError("not found"))

    body = build_signed_verify_request(
        agent_id=str(agent_id),
        signing_key=sk,
        action_type="tool_call",
        payload={"x": 1},
    )

    app.dependency_overrides[get_db] = lambda: db
    try:
        resp = client.post("/verify/debug", json=body)
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["agent_found"] is False
    assert data["signature_valid"] is None
    # The action hash is computable without the agent — still returned so the
    # integrator can confirm their canonicalization before the agent exists.
    assert len(data["expected_action_hash"]) == 64


def test_verify_401_echoes_expected_action_hash_and_keeps_detail_string():
    agent_id = uuid4()
    org_id = uuid4()
    sk = SigningKey.generate()
    public_key = bytes(sk.verify_key.encode(RawEncoder))
    audit_id = uuid4()
    payload = {"resource": "file", "operation": "read"}

    db = MagicMock()
    db.get_agent_by_id = AsyncMock(return_value=_agent_record(agent_id, org_id, public_key))
    db.insert_audit_log = AsyncMock(return_value=audit_id)
    db.update_agent_after_verification = AsyncMock()

    app.dependency_overrides[get_db] = lambda: db
    try:
        with patch("api.main._dispatch_verdict_webhook", new_callable=AsyncMock):
            resp = client.post(
                "/verify",
                json={
                    "agent_id": str(agent_id),
                    "action_type": "tool_call",
                    "payload": payload,
                    # Structurally valid base64 of 64 zero bytes — decodes fine
                    # but is not a valid Ed25519 signature for this action.
                    "signature": base64.b64encode(b"\x00" * 64).decode(),
                    "nonce": "n-1",
                    "timestamp": "2026-06-16T12:00:00Z",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 401, resp.text
    data = resp.json()
    assert data["error"] == "signature_invalid"
    # Back-compat: existing callers read a human string from `detail`.
    assert isinstance(data["detail"], str)
    assert data["expected_action_hash"] == CryptoService.compute_action_hash(
        agent_id=str(agent_id),
        action_type="tool_call",
        payload=payload,
        nonce="n-1",
        timestamp="2026-06-16T12:00:00Z",
        sig_version=2,
    )
    assert data["audit_id"] == str(audit_id)
    # The real endpoint still records the forensic row (unlike /verify/debug).
    db.insert_audit_log.assert_awaited_once()
