"""Agent signing-key rotation: request validation and model defaults.

The rotation DB path (history insert + in-place key swap) is exercised by the
RLS integration suite; here we cover the pure pieces that gate the endpoint.
"""
import base64
from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from pydantic import ValidationError

from api.database import Database
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


@pytest.mark.asyncio
async def test_rotation_retains_only_the_retiring_public_key_for_historical_receipts():
    agent_id = uuid4()
    org_id = uuid4()
    old_public_key = b"\x01" * 32
    new_public_key = b"\x02" * 32
    old_fingerprint = "a" * 64
    new_fingerprint = "b" * 64
    rotated_at = datetime.now(UTC)

    conn = AsyncMock()
    conn.fetchrow = AsyncMock(
        side_effect=[
            {
                "public_key": old_public_key,
                "public_key_fingerprint": old_fingerprint,
                "key_version": 1,
            },
            {
                "key_version": 2,
                "public_key_fingerprint": new_fingerprint,
                "key_rotated_at": rotated_at,
            },
        ]
    )
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=conn)
    context.__aexit__ = AsyncMock(return_value=False)
    database = Database(MagicMock())
    database.acquire_as_tenant = MagicMock(return_value=context)

    result = await database.rotate_agent_key(
        agent_id=agent_id,
        org_id=org_id,
        new_public_key=new_public_key,
        new_fingerprint=new_fingerprint,
        retired_by="operator",
        reason="scheduled rotation",
    )

    history_insert = conn.execute.await_args
    assert "public_key" in history_insert.args[0]
    assert history_insert.args[1:] == (
        agent_id,
        old_public_key,
        old_fingerprint,
        1,
        "operator",
        "scheduled rotation",
    )
    assert result["key_version"] == 2
