"""Release blocking Postgres and Redis security integration checks."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from uuid import uuid4

import asyncpg
import pytest
from fastapi import HTTPException

from api.database import Database
from api.models import ActionVerdict, AuditLogEntry

DATABASE_URL = os.getenv("DATABASE_URL", "")
REDIS_URL = os.getenv("REDIS_URL", "")

_database_integration = pytest.mark.skipif(
    os.getenv("INNTRIS_DB_INTEGRATION") != "1" or not DATABASE_URL,
    reason="Postgres release integration requires INNTRIS_DB_INTEGRATION=1",
)
_redis_integration = pytest.mark.skipif(
    os.getenv("INNTRIS_REDIS_INTEGRATION") != "1" or not REDIS_URL,
    reason="Redis release integration requires INNTRIS_REDIS_INTEGRATION=1",
)


@_redis_integration
@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_redis_enforces_source_and_agent_limits(monkeypatch) -> None:
    import redis.asyncio as redis

    from api import main

    redis_conn = redis.from_url(REDIS_URL, decode_responses=True)
    agent_id = uuid4()
    monkeypatch.setattr(main, "VERIFY_SOURCE_ATTEMPTS_PER_MINUTE", 2)
    monkeypatch.setattr(main, "VERIFY_AGENT_ATTEMPTS_PER_MINUTE", 2)

    try:
        await main._check_authenticated_agent_limit(redis_conn, agent_id)
        await main._check_authenticated_agent_limit(redis_conn, agent_id)
        with pytest.raises(HTTPException) as exc:
            await main._check_authenticated_agent_limit(redis_conn, agent_id)
        assert exc.value.status_code == 429

        agent_keys = [
            key
            async for key in redis_conn.scan_iter(
                match=f"inntris:verify:authenticated:agent:{agent_id}:*"
            )
        ]
        assert agent_keys
        for key in agent_keys:
            assert 0 < await redis_conn.ttl(key) <= 120
            await redis_conn.delete(key)
    finally:
        await redis_conn.aclose()


@_database_integration
@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_postgres_excludes_sandbox_rows_from_anchor_selection() -> None:
    database = await Database.create(DATABASE_URL, min_size=1, max_size=2)
    org_id = uuid4()
    live_agent_id = uuid4()
    sandbox_agent_id = uuid4()
    live_log_id = uuid4()
    sandbox_log_id = uuid4()
    now = datetime.now(UTC)

    try:
        async with database.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO organizations (id, name, contact_email, api_key_hash)
                VALUES ($1, $2, $3, $4)
                """,
                org_id,
                f"anchor-selection-{org_id}",
                f"{org_id}@integration.invalid",
                hashlib.sha256(org_id.bytes).digest(),
            )
            with pytest.raises(asyncpg.CheckViolationError):
                await conn.execute(
                    """
                    INSERT INTO agents (
                        id, org_id, name, public_key, public_key_fingerprint,
                        status, metadata
                    ) VALUES ($1, $2, 'unapproved', $3, $4, 'active', '{}'::jsonb)
                    """,
                    uuid4(),
                    org_id,
                    hashlib.sha256(b"unapproved").digest(),
                    hashlib.sha256(b"unapproved").hexdigest(),
                )
            for agent_id, name, metadata in (
                (
                    live_agent_id,
                    "production",
                    {
                        "sandbox": False,
                        "production_approval_reference": "integration-test",
                        "production_approved_at": now.isoformat(),
                        "production_approved_by": "integration-test",
                    },
                ),
                (sandbox_agent_id, "sandbox", {"sandbox": True}),
            ):
                await conn.execute(
                    """
                    INSERT INTO agents (
                        id, org_id, name, public_key, public_key_fingerprint,
                        status, metadata
                    ) VALUES ($1, $2, $3, $4, $5, 'active', $6::jsonb)
                    """,
                    agent_id,
                    org_id,
                    name,
                    hashlib.sha256(agent_id.bytes).digest(),
                    hashlib.sha256(agent_id.bytes).hexdigest(),
                    json.dumps(metadata),
                )

            for log_id, agent_id, metadata in (
                (live_log_id, live_agent_id, {}),
                (
                    sandbox_log_id,
                    sandbox_agent_id,
                    {"sandbox": True, "test_request": True},
                ),
            ):
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        id, agent_id, timestamp, action_type, action_hash,
                        payload, verdict, signature, signature_valid,
                        trust_score_at_time, metadata
                    ) VALUES (
                        $1, $2, $3, 'tool_call', $4, '{}'::jsonb,
                        'approved', $5, true, 50, $6::jsonb
                    )
                    """,
                    log_id,
                    agent_id,
                    now,
                    hashlib.sha256(log_id.bytes).hexdigest(),
                    hashlib.sha512(log_id.bytes).digest(),
                    json.dumps(metadata),
                )

        selected = await database.get_unanchored_logs(limit=10000)
        selected_ids = {row["id"] for row in selected}
        assert live_log_id in selected_ids
        assert sandbox_log_id not in selected_ids
    finally:
        await database.close()


@_database_integration
@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_postgres_token_consumption_is_execution_idempotent() -> None:
    database = await Database.create(DATABASE_URL, min_size=1, max_size=2)
    org_id = uuid4()
    agent_id = uuid4()
    token_id = f"integration-token-{uuid4()}"
    token_digest = hashlib.sha256(token_id.encode()).digest()
    action_hash = hashlib.sha256(b"integration-action").hexdigest()
    execution_ref = f"integration-execution-{uuid4()}"

    try:
        async with database.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO organizations (id, name, contact_email, api_key_hash)
                VALUES ($1, $2, $3, $4)
                """,
                org_id,
                f"token-consumption-{org_id}",
                f"{org_id}@integration.invalid",
                hashlib.sha256(org_id.bytes).digest(),
            )
            await conn.execute(
                """
                INSERT INTO agents (
                    id, org_id, name, public_key, public_key_fingerprint,
                    status, metadata
                ) VALUES ($1, $2, $3, $4, $5, 'active', $6::jsonb)
                """,
                agent_id,
                org_id,
                "token-consumption",
                hashlib.sha256(agent_id.bytes).digest(),
                hashlib.sha256(agent_id.bytes).hexdigest(),
                json.dumps(
                    {
                        "sandbox": False,
                        "production_approval_reference": "integration-test",
                        "production_approved_at": datetime.now(UTC).isoformat(),
                        "production_approved_by": "integration-test",
                    }
                ),
            )

        entry = AuditLogEntry(
            agent_id=agent_id,
            action_type="token_consumed",
            action_hash=hashlib.sha256(token_digest).hexdigest(),
            payload={"event": "token_consumed", "execution_ref": execution_ref},
            verdict=ActionVerdict.APPROVED,
            verdict_reason="integration test",
            signature=b"TOKEN_CONSUMED",
            signature_valid=False,
            request_ip=None,
            request_user_agent=None,
            response_time_ms=None,
            trust_score_at_time=50,
            chain_previous_hash=None,
            metadata={"execution_ref": execution_ref},
        )

        first = await database.insert_token_consumption(
            entry,
            token_id=token_id,
            token_digest=token_digest,
            approved_action_hash=action_hash,
            execution_ref=execution_ref,
        )
        retry = await database.insert_token_consumption(
            entry,
            token_id=token_id,
            token_digest=token_digest,
            approved_action_hash=action_hash,
            execution_ref=execution_ref,
        )
        conflict = await database.insert_token_consumption(
            entry,
            token_id=token_id,
            token_digest=token_digest,
            approved_action_hash=action_hash,
            execution_ref=f"{execution_ref}-different",
        )

        assert first is not None and first[1] == "consumed"
        assert retry == (first[0], "idempotent")
        assert conflict is None

        async with database.acquire() as conn:
            receipt_count = await conn.fetchval(
                "SELECT COUNT(*) FROM approval_token_consumptions WHERE token_id = $1",
                token_id,
            )
        assert receipt_count == 1
    finally:
        await database.close()
