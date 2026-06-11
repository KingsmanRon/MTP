"""Unit tests for the atomic rate/spend reservation control flow.

The SQL itself requires a live Postgres (covered by integration runs), but the
Python decision logic — which limit trips, and that a trip raises and rolls
back rather than returning — is testable with a mocked connection. This is the
fix for the check-then-act race where concurrent requests all observed the same
headroom and all passed.
"""
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from api.database import Database, LimitReservationError


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
    )


@pytest.mark.asyncio
async def test_reservation_succeeds_within_limits():
    db, conn = _db_with_fetchvals([1, Decimal("50")])
    minute_count, daily_spend = await _reserve(
        db, amount=Decimal("50"), rate_limit=60, daily_limit=Decimal("1000")
    )
    assert minute_count == 1
    assert daily_spend == Decimal("50")
    assert conn.fetchval.await_count == 2


@pytest.mark.asyncio
async def test_rate_limit_trips_before_spend():
    # Minute counter already over the limit → raise before touching the day row.
    db, conn = _db_with_fetchvals([61, Decimal("0")])
    with pytest.raises(LimitReservationError) as exc:
        await _reserve(db, amount=Decimal("0"), rate_limit=60, daily_limit=Decimal("1000"))
    assert exc.value.kind == "rate"
    # Day-window upsert must not run once the minute window has tripped.
    assert conn.fetchval.await_count == 1


@pytest.mark.asyncio
async def test_daily_limit_trips_after_rate_ok():
    db, conn = _db_with_fetchvals([1, Decimal("1500")])
    with pytest.raises(LimitReservationError) as exc:
        await _reserve(db, amount=Decimal("1500"), rate_limit=60, daily_limit=Decimal("1000"))
    assert exc.value.kind == "daily"
    assert exc.value.observed == Decimal("1500")
    assert conn.fetchval.await_count == 2


@pytest.mark.asyncio
async def test_boundary_exactly_at_limit_is_allowed():
    db, _conn = _db_with_fetchvals([60, Decimal("1000")])
    minute_count, daily_spend = await _reserve(
        db, amount=Decimal("1000"), rate_limit=60, daily_limit=Decimal("1000")
    )
    assert minute_count == 60
    assert daily_spend == Decimal("1000")
