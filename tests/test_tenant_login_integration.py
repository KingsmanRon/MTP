"""Real-Postgres checks for the isolated tenant login.

Run after migration 0017 is applied. In normal environments, provide
TENANT_DATABASE_URL. CI may instead use ALEMBIC_DATABASE_URL to create a
superuser-backed test pool whose connections immediately switch session
authorisation to inntris_tenant_login; all tested queries then execute as the
restricted login role.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from uuid import UUID, uuid4

import pytest

asyncpg = pytest.importorskip("asyncpg")

from api.database import Database  # noqa: E402
from api.tenant_database import TenantDatabase  # noqa: E402

ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
SYSTEM_DSN = os.getenv("DATABASE_URL", "")
TENANT_DSN = os.getenv("TENANT_DATABASE_URL", "")
MIGRATOR_DSN = os.getenv("ALEMBIC_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (ENABLED and SYSTEM_DSN and (TENANT_DSN or MIGRATOR_DSN)),
    reason="requires real Postgres plus system DSN and tenant or migrator DSN",
)


@pytest.fixture
async def system_db():
    database = await Database.create(SYSTEM_DSN, min_size=1, max_size=1)
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
async def tenant_db():
    # Single connection makes context-leak tests non-vacuous.
    if TENANT_DSN:
        database = await TenantDatabase.create(TENANT_DSN, min_size=1, max_size=1)
    else:
        # CI migration credentials are superuser credentials for the ephemeral
        # test database. Drop that authority immediately at session level so
        # TenantDatabase sees exactly the login identity it is meant to guard.
        async def _become_tenant(conn):
            await conn.execute("SET SESSION AUTHORIZATION inntris_tenant_login")

        pool = await asyncpg.create_pool(
            MIGRATOR_DSN,
            min_size=1,
            max_size=1,
            command_timeout=30,
            statement_cache_size=0,
            init=_become_tenant,
        )
        assert pool is not None
        database = TenantDatabase(pool)
        await database.assert_safe_identity()

    try:
        yield database
    finally:
        await database.close()


async def _make_org(db: Database, name: str) -> UUID:
    async with db.acquire() as conn:
        return await conn.fetchval(
            """
            INSERT INTO organizations (name, contact_email, api_key_hash)
            VALUES ($1, $2, $3)
            RETURNING id
            """,
            name,
            f"{name}@tenant-login-test.local",
            hashlib.sha256(secrets.token_bytes(32)).digest(),
        )


async def _make_agent(db: Database, org_id: UUID, name: str) -> UUID:
    key = secrets.token_bytes(32)
    async with db.acquire() as conn:
        return await conn.fetchval(
            """
            INSERT INTO agents (org_id, name, public_key, public_key_fingerprint)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            """,
            org_id,
            name,
            key,
            hashlib.sha256(key).hexdigest(),
        )


@pytest.mark.asyncio
async def test_tenant_login_sees_only_its_org(system_db, tenant_db) -> None:
    org_a = await _make_org(system_db, f"tenant-login-a-{uuid4().hex[:8]}")
    org_b = await _make_org(system_db, f"tenant-login-b-{uuid4().hex[:8]}")
    await _make_agent(system_db, org_a, "tenant-a-agent")
    await _make_agent(system_db, org_b, "tenant-b-agent")

    async with tenant_db.tenant(org_a) as conn:
        seen = {row["org_id"] for row in await conn.fetch("SELECT org_id FROM agents")}

    assert seen == {org_a}


@pytest.mark.asyncio
async def test_cross_tenant_write_is_blocked(system_db, tenant_db) -> None:
    org_a = await _make_org(system_db, f"tenant-write-a-{uuid4().hex[:8]}")
    org_b = await _make_org(system_db, f"tenant-write-b-{uuid4().hex[:8]}")
    agent_b = await _make_agent(system_db, org_b, "foreign-agent")

    async with tenant_db.tenant(org_a) as conn:
        status = await conn.execute(
            "UPDATE agents SET name = 'hijacked' WHERE id = $1",
            agent_b,
        )
    assert status.endswith(" 0")


@pytest.mark.asyncio
async def test_context_does_not_leak_when_same_pool_connection_is_reused(
    system_db,
    tenant_db,
) -> None:
    org_a = await _make_org(system_db, f"tenant-reuse-a-{uuid4().hex[:8]}")
    org_b = await _make_org(system_db, f"tenant-reuse-b-{uuid4().hex[:8]}")
    await _make_agent(system_db, org_a, "reuse-a")
    await _make_agent(system_db, org_b, "reuse-b")

    async with tenant_db.tenant(org_a) as conn:
        assert await conn.fetchval("SELECT app.current_tenant()") == org_a

    async with tenant_db.tenant(org_b) as conn:
        assert await conn.fetchval("SELECT app.current_tenant()") == org_b
        seen = {row["org_id"] for row in await conn.fetch("SELECT org_id FROM agents")}
        assert seen == {org_b}


@pytest.mark.asyncio
async def test_rollback_does_not_leak_context(system_db, tenant_db) -> None:
    org_a = await _make_org(system_db, f"tenant-rollback-a-{uuid4().hex[:8]}")
    await _make_agent(system_db, org_a, "rollback-a")

    with pytest.raises(RuntimeError):
        async with tenant_db.tenant(org_a) as conn:
            assert await conn.fetchval("SELECT app.current_tenant()") == org_a
            raise RuntimeError("force rollback")

    org_b = await _make_org(system_db, f"tenant-rollback-b-{uuid4().hex[:8]}")
    async with tenant_db.tenant(org_b) as conn:
        assert await conn.fetchval("SELECT app.current_tenant()") == org_b


@pytest.mark.asyncio
async def test_tenant_login_cannot_set_role_worker(tenant_db) -> None:
    async with tenant_db.tenant(uuid4()) as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("SET LOCAL ROLE inntris_worker")
