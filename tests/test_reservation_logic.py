"""Unit tests for the atomic rate/spend reservation control flow.

The SQL itself requires a live Postgres (covered by integration runs), but the
Python decision logic — which limit trips, and that a trip raises and rolls
back rather than returning — is testable with a mocked connection. This is the
fix for the check-then-act race where concurrent requests all observed the same
headroom and all passed.
"""
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from api.database import Database, LimitReservationError
from api.models import ActionVerdict, AuditLogEntry


def _db_with_fetchvals(values):
    """Build a Database whose pooled connection returns ``values`` in order
    from successive fetchval calls, with working transaction/acquire CMs."""
    conn = AsyncMock()
    conn.fetchval = AsyncMock(side_effect=list(values))

    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=False)  # do not suppress exceptions
    conn.transaction = MagicMock(return_value=tx)

    acm = MagicMock()
    acm.__aenter__ = AsyncMock(return_value=conn)
    acm.__aexit__ = AsyncMock(return_value=False)

    pool = MagicMock()
    pool.acquire = MagicMock(return_value=acm)
    return Database(pool), conn


async def _reserve(db, amount, rate_limit, daily_limit):
    return await db.reserve_rate_and_spend(
        agent_id=uuid4(),
        minute_start=MagicMock(),
        day_start=MagicMock(),
        amount=amount,
        rate_limit_per_minute=rate_limit,
        daily_limit_usd=daily_limit,
        action_hash="a" * 64,
        approval_token_id="approval-token-1",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


@pytest.mark.asyncio
async def test_reservation_succeeds_within_limits():
    reservation_id = uuid4()
    db, conn = _db_with_fetchvals(
        [1, Decimal("20"), Decimal("30"), reservation_id]
    )
    minute_count, daily_spend, returned_id = await _reserve(
        db, amount=Decimal("50"), rate_limit=60, daily_limit=Decimal("1000")
    )
    assert minute_count == 1
    assert daily_spend == Decimal("100")
    assert returned_id == reservation_id
    assert conn.fetchval.await_count == 4


@pytest.mark.asyncio
async def test_rate_limit_trips_before_spend():
    # Minute counter already over the limit → raise before touching the day row.
    db, conn = _db_with_fetchvals([61])
    with pytest.raises(LimitReservationError) as exc:
        await _reserve(db, amount=Decimal("0"), rate_limit=60, daily_limit=Decimal("1000"))
    assert exc.value.kind == "rate"
    # Day-window upsert must not run once the minute window has tripped.
    assert conn.fetchval.await_count == 1


@pytest.mark.asyncio
async def test_daily_limit_trips_after_rate_ok():
    db, conn = _db_with_fetchvals([1, Decimal("200"), Decimal("900")])
    with pytest.raises(LimitReservationError) as exc:
        await _reserve(db, amount=Decimal("50"), rate_limit=60, daily_limit=Decimal("1000"))
    assert exc.value.kind == "daily"
    assert exc.value.observed == Decimal("1150")
    assert conn.fetchval.await_count == 3


@pytest.mark.asyncio
async def test_boundary_exactly_at_limit_is_allowed():
    reservation_id = uuid4()
    db, _conn = _db_with_fetchvals(
        [60, Decimal("100"), Decimal("800"), reservation_id]
    )
    minute_count, daily_spend, returned_id = await _reserve(
        db, amount=Decimal("100"), rate_limit=60, daily_limit=Decimal("1000")
    )
    assert minute_count == 60
    assert daily_spend == Decimal("1000")
    assert returned_id == reservation_id


@pytest.mark.asyncio
async def test_reservation_expires_stale_rows_before_calculating_spend():
    reservation_id = uuid4()
    db, conn = _db_with_fetchvals(
        [1, Decimal("0"), Decimal("0"), reservation_id]
    )

    await _reserve(
        db, amount=Decimal("10"), rate_limit=60, daily_limit=Decimal("1000")
    )

    expiry_update = conn.execute.await_args_list[1]
    assert "status = 'expired'" in expiry_update.args[0]


@pytest.mark.asyncio
async def test_release_only_changes_an_unconsumed_reservation():
    db, conn = _db_with_fetchvals([])
    conn.execute = AsyncMock(return_value="UPDATE 1")

    released = await db.release_spend_reservation(
        agent_id=uuid4(), action_hash="b" * 64, reason="verify_internal_error"
    )

    assert released is True
    query = conn.execute.await_args.args[0]
    assert "status = 'reserved'" in query
    assert "status = 'released'" in query


def _consumption_entry(agent_id, action_hash):
    return AuditLogEntry(
        agent_id=agent_id,
        action_type="token_consumed",
        action_hash="c" * 64,
        payload={"original_action_hash": action_hash},
        verdict=ActionVerdict.APPROVED,
        verdict_reason="Approval token consumed at execution boundary",
        signature=b"SERVER_ATTESTATION",
        signature_valid=False,
        request_ip=None,
        request_user_agent=None,
        response_time_ms=1,
        trust_score_at_time=50,
        chain_previous_hash=None,
        metadata={},
    )


@pytest.mark.asyncio
async def test_token_consumption_transitions_the_matching_reservation_atomically():
    agent_id = uuid4()
    action_hash = "a" * 64
    audit_id = uuid4()
    db, conn = _db_with_fetchvals([audit_id])
    conn.fetchrow = AsyncMock(side_effect=[None, {"status": "reserved"}])

    result = await db.insert_token_consumption(
        _consumption_entry(agent_id, action_hash),
        token_id="approval-token-1",
        token_digest=b"first-digest",
        approved_action_hash=action_hash,
        execution_ref="highnote:request-1",
    )

    assert result == (audit_id, "consumed")
    statements = [call.args[0] for call in conn.execute.await_args_list]
    assert any("INSERT INTO approval_token_consumptions" in sql for sql in statements)
    assert any("SET status = 'consumed'" in sql for sql in statements)


@pytest.mark.asyncio
async def test_same_execution_retry_is_idempotent_even_if_token_bytes_are_regenerated():
    agent_id = uuid4()
    action_hash = "a" * 64
    audit_id = uuid4()
    db, conn = _db_with_fetchvals([])
    conn.fetchrow = AsyncMock(
        return_value={
            "token_id": "approval-token-1",
            "token_digest": b"old-digest",
            "action_hash": action_hash,
            "audit_log_id": audit_id,
            "execution_ref": "highnote:request-1",
        }
    )

    result = await db.insert_token_consumption(
        _consumption_entry(agent_id, action_hash),
        token_id="approval-token-1",
        token_digest=b"regenerated-token-digest",
        approved_action_hash=action_hash,
        execution_ref="highnote:request-1",
    )

    assert result == (audit_id, "idempotent")
    assert conn.fetchval.await_count == 0
