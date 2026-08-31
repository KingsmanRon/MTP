"""Real-Postgres checks for the isolated tenant login.

Run after migration 0017 is applied. A real TENANT_DATABASE_URL is preferred.
In GitHub Actions only, if that variable is absent, the fixture generates an
ephemeral random password, assigns it to inntris_tenant_login, authenticates a
new connection as that role, then removes the password at teardown. This keeps
session_user == inntris_tenant_login, which is required for SET ROLE reachability
tests to be sound.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import UUID, uuid4

import pytest

asyncpg = pytest.importorskip("asyncpg")

from api.database import Database  # noqa: E402
from api.tenant_database import TENANT_LOGIN_ROLE, TenantDatabase  # noqa: E402

ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
SYSTEM_DSN = os.getenv("DATABASE_URL", "")
TENANT_DSN = os.getenv("TENANT_DATABASE_URL", "")
MIGRATOR_DSN = os.getenv("ALEMBIC_DATABASE_URL", "")
CI = os.getenv("CI", "").lower() == "true"

pytestmark = pytest.mark.skipif(
    not (ENABLED and SYSTEM_DSN and (TENANT_DSN or (CI and MIGRATOR_DSN))),
    reason="requires real Postgres plus system and genuine tenant login credentials",
)

TENANT_POLICY_TABLES = {
    "agent_key_history",
    "agent_policies",
    "agents",
    "api_keys",
    "audit_logs",
    "organizations",
    "policy_rules",
    "rate_limit_windows",
    "security_alerts",
    "spend_reservations",
    "verify_request_idempotency",
    "webhook_deliveries",
}
POLICYLESS_SYSTEM_TABLES = {
    "administrative_audit_events",
    "alembic_version",
    "approval_token_consumptions",
    "erasure_requests",
    "merkle_proofs",
}
EXPECTED_PUBLIC_TABLES = TENANT_POLICY_TABLES | POLICYLESS_SYSTEM_TABLES


def _tenant_dsn_from_migrator(dsn: str, password: str) -> str:
    parsed = urlsplit(dsn)
    if not parsed.scheme or not parsed.hostname:
        raise AssertionError("CI ALEMBIC_DATABASE_URL must be a PostgreSQL URL")
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port is not None else ""
    userinfo = f"{TENANT_LOGIN_ROLE}:{quote(password, safe='')}"
    return urlunsplit(
        (parsed.scheme, f"{userinfo}@{host}{port}", parsed.path, parsed.query, parsed.fragment)
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
    generated_password = False
    tenant_dsn = TENANT_DSN

    if not tenant_dsn:
        assert CI and MIGRATOR_DSN, "migrator fallback is CI-only"
        generated_password = True
        password = secrets.token_urlsafe(32)
        admin = await asyncpg.connect(MIGRATOR_DSN, statement_cache_size=0)
        try:
            statement = await admin.fetchval(
                "SELECT format('ALTER ROLE inntris_tenant_login PASSWORD %L', $1)",
                password,
            )
            await admin.execute(statement)
        finally:
            await admin.close()
        tenant_dsn = _tenant_dsn_from_migrator(MIGRATOR_DSN, password)

    database = await TenantDatabase.create(tenant_dsn, min_size=1, max_size=1)
    try:
        yield database
    finally:
        await database.close()
        if generated_password:
            admin = await asyncpg.connect(MIGRATOR_DSN, statement_cache_size=0)
            try:
                await admin.execute("ALTER ROLE inntris_tenant_login PASSWORD NULL")
            finally:
                await admin.close()


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
async def test_tenant_pool_authenticates_with_genuine_session_user(tenant_db) -> None:
    async with tenant_db._pool.acquire() as conn:
        identity = await conn.fetchrow(
            "SELECT session_user AS session_user, current_user AS current_user"
        )
    assert identity["session_user"] == TENANT_LOGIN_ROLE
    assert identity["current_user"] == TENANT_LOGIN_ROLE


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


@pytest.mark.asyncio
async def test_rls_drift_guard_classifies_every_public_table(system_db) -> None:
    async with system_db.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT c.relname AS table_name,
                   c.relrowsecurity AS rls_enabled,
                   c.relforcerowsecurity AS force_rls,
                   count(p.policyname) FILTER (
                       WHERE 'inntris_api' = ANY(p.roles)
                   ) AS tenant_policy_count
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_policies p
              ON p.schemaname = n.nspname
             AND p.tablename = c.relname
            WHERE n.nspname = 'public'
              AND c.relkind IN ('r', 'p')
            GROUP BY c.relname, c.relrowsecurity, c.relforcerowsecurity
            ORDER BY c.relname
            """
        )

    assert {row["table_name"] for row in rows} == EXPECTED_PUBLIC_TABLES
    for row in rows:
        assert row["rls_enabled"] is True
        assert row["force_rls"] is True
        if row["table_name"] in TENANT_POLICY_TABLES:
            assert row["tenant_policy_count"] >= 1
