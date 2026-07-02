"""Agent signing-key rotation: request validation and model defaults.

The rotation DB path (history insert + in-place key swap) is exercised by the
RLS integration suite; here we cover the pure pieces that gate the endpoint.
"""
import base64
from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest
from pydantic import ValidationError

from api.models import AgentRecord, AgentStatus, RotateAgentKeyRequest


def _b64_key(nbytes: int) -> str:
    return base64.b64encode(b"\x01" * nbytes).decode()


def test_rotate_request_accepts_32_byte_key():
    req = RotateAgentKeyRequest(public_key=_b64_key(32), reason="leak response")
    assert base64.b64decode(req.public_key) == b"\x01" * 32
    assert req.reason == "leak response"


def test_rotate_request_reason_is_optional():
    req = RotateAgentKeyRequest(public_key=_b64_key(32))
    assert req.reason is None


def test_rotate_request_rejects_oversized_reason():
    with pytest.raises(ValidationError):
        RotateAgentKeyRequest(public_key=_b64_key(32), reason="x" * 501)


def test_rotate_request_rejects_too_short_public_key():
    # A base64 string for a sub-32-byte key falls below the min length bound.
    with pytest.raises(ValidationError):
        RotateAgentKeyRequest(public_key=base64.b64encode(b"\x01" * 8).decode())


def test_agent_record_key_version_defaults():
    # Older callers / fixtures that omit the new fields stay valid.
    agent = AgentRecord(
        id=uuid4(),
        org_id=uuid4(),
        name="a",
        public_key=b"\x00" * 32,
        public_key_fingerprint="a" * 64,
        trust_score=50,
        status=AgentStatus.ACTIVE,
        daily_limit_usd=Decimal("0"),
        per_action_limit_usd=Decimal("0"),
        allowed_actions=[],
        blocked_actions=[],
        rate_limit_per_minute=60,
        last_action_at=None,
        total_actions_count=0,
        total_blocked_count=0,
        metadata={},
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    assert agent.key_version == 1
    assert agent.key_rotated_at is None
