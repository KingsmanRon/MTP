"""Phase 1C.1 — Postgres row-level security integration tests.

These tests exercise migration 005 (``database/migrations/005_rls_policies.sql``)
against a real Postgres instance. They verify that:

  * A connection scoped to tenant A cannot SELECT tenant B's rows.
  * Cross-tenant INSERT / UPDATE / DELETE are silently filtered or rejected
    by the ``WITH CHECK`` clause.
  * A missing ``app.current_org_id`` setting fails closed — every predicate
    evaluates to NULL, so the tenant role sees an empty result set instead
    of the full table.
  * The pool role (``inntris_worker``, BYPASSRLS) still sees everything,
    which is what the anchor worker and /verify public path rely on.

The tests are gated on ``INNTRIS_DB_INTEGRATION=1`` and a ``DATABASE_URL``
pointing at a database where:

  1. ``database/schemas.sql`` and ``database/migrations/005_rls_policies.sql``
     have been applied.
  2. The DSN connects as ``inntris_worker`` (so the downgrade via
     ``SET LOCAL ROLE inntris_api`` succeeds).

In CI we do not yet have a Postgres container wired up (explicitly deferred
per the enterprise-readiness plan), so these tests skip by default. Run
locally with:

    INNTRIS_DB_INTEGRATION=1 \
    DATABASE_URL=postgresql://inntris_worker@localhost/inntris_test \
    pytest tests/test_rls_policies.py
"""

from __future__ import annotations

import hashlib
import os
import secrets
from collections.abc import AsyncIterator
from uuid import UUID, uuid4

import pytest

asyncpg = pytest.importorskip("asyncpg")

from api.database import Database  # noqa: E402

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="RLS integration test requires INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    """Pool fixture. Connects as whatever role DATABASE_URL specifies.

    For the tenant-isolation assertions to be meaningful, that role must be
    ``inntris_worker`` (BYPASSRLS, with membership in ``inntris_api``). A
    superuser DSN would silently bypass every policy and give false-positive
    results, so we assert the role's BYPASSRLS posture up front.
    """
    database = await Database.create(DATABASE_URL, min_size=1, max_size=3)
    try:
        async with database.acquire() as conn:
            rolbypassrls = await conn.fetchval(
                "SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user"
            )
            assert rolbypassrls, (
                "RLS tests require a BYPASSRLS pool role (e.g. inntris_worker). "
                "Superuser DSNs also bypass RLS but give false-negative coverage — "
                "point DATABASE_URL at inntris_worker."
            )
        yield database
    finally:
        await database.close()


async def _make_org(db: Database, name: str) -> UUID:
    """Create an org as the pool role (BYPASSRLS so we are not fighting policy)."""
    async with db.acquire() as conn:
        return await conn.fetchval(
            """
            INSERT INTO organizations (name, contact_email, api_key_hash)
            VALUES ($1, $2, $3)
            RETURNING id
            """,
            name,
            f"{name}@rls-test.local",
            hashlib.sha256(secrets.token_bytes(32)).digest(),
        )


async def _make_agent(db: Database, org_id: UUID, name: str) -> UUID:
    """Create an agent under an org. BYPASSRLS setup path."""
    pk = secrets.token_bytes(32)
    async with db.acquire() as conn:
        return await conn.fetchval(
            """
            INSERT INTO agents (org_id, name, public_key, public_key_fingerprint)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            """,
            org_id,
            name,
            pk,
            hashlib.sha256(pk).hexdigest(),
        )


@pytest.mark.asyncio
async def test_tenant_sees_only_own_agents(db: Database) -> None:
    """acquire_as_tenant must filter out cross-tenant agent rows."""
    org_a = await _make_org(db, f"rls-a-{uuid4().hex[:8]}")
    org_b = await _make_org(db, f"rls-b-{uuid4().hex[:8]}")
    await _make_agent(db, org_a, "agent-a")
    await _make_agent(db, org_b, "agent-b")

    async with db.acquire_as_tenant(org_a) as conn:
        rows = await conn.fetch("SELECT id, name, org_id FROM agents")

    # Tenant A must see only agent-a. agent-b is under org_b and must be invisible.
    seen_orgs = {row["org_id"] for row in rows}
    assert seen_orgs == {org_a}, (
        f"tenant A saw cross-tenant rows: {seen_orgs}"
    )
    assert any(row["name"] == "agent-a" for row in rows)
    assert not any(row["name"] == "agent-b" for row in rows)


@pytest.mark.asyncio
async def test_tenant_sees_only_own_org_row(db: Database) -> None:
    """organizations policy: ``id = app.current_tenant()`` — only own row visible."""
    org_a = await _make_org(db, f"rls-a-{uuid4().hex[:8]}")
    org_b = await _make_org(db, f"rls-b-{uuid4().hex[:8]}")

    async with db.acquire_as_tenant(org_a) as conn:
        rows = await conn.fetch("SELECT id FROM organizations")

    ids = {row["id"] for row in rows}
    assert org_a in ids
    assert org_b not in ids


@pytest.mark.asyncio
async def test_cross_tenant_insert_rejected_by_with_check(db: Database) -> None:
    """Writing an agent under a foreign org must be blocked by WITH CHECK."""
    org_a = await _make_org(db, f"rls-a-{uuid4().hex[:8]}")
    org_b = await _make_org(db, f"rls-b-{uuid4().hex[:8]}")
    pk = secrets.token_bytes(32)

    # Scoped to A, but try to insert an agent owned by B.
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        async with db.acquire_as_tenant(org_a) as conn:
            await conn.execute(
                """
                INSERT INTO agents (org_id, name, public_key, public_key_fingerprint)
                VALUES ($1, $2, $3, $4)
                """,
                org_b,
                "smuggled-agent",
                pk,
                hashlib.sha256(pk).hexdigest(),
            )

    # The row must not exist — BYPASSRLS read confirms.
    async with db.acquire() as conn:
        leaked = await conn.fetchval(
            "SELECT count(*) FROM agents WHERE name = 'smuggled-agent'"
        )
    assert leaked == 0


@pytest.mark.asyncio
async def test_cross_tenant_update_filters_silently(db: Database) -> None:
    """UPDATE on a foreign row affects zero rows (policy filter, not an error)."""
    org_a = await _make_org(db, f"rls-a-{uuid4().hex[:8]}")
    org_b = await _make_org(db, f"rls-b-{uuid4().hex[:8]}")
    agent_b = await _make_agent(db, org_b, "target")

    async with db.acquire_as_tenant(org_a) as conn:
        status = await conn.execute(
            "UPDATE agents SET name = 'hijacked' WHERE id = $1", agent_b
        )
    # asyncpg returns 'UPDATE N' — N must be 0 because the row is invisible.
    assert status.endswith(" 0"), f"expected UPDATE 0, got {status}"

    async with db.acquire() as conn:
        name = await conn.fetchval("SELECT name FROM agents WHERE id = $1", agent_b)
    assert name == "target"


@pytest.mark.asyncio
async def test_missing_tenant_context_fails_closed(db: Database) -> None:
    """If SET LOCAL ROLE runs without setting current_org_id, rows are hidden.

    ``app.current_tenant()`` returns NULL when the setting is missing; every
    policy predicate becomes ``x = NULL`` → NULL → row filtered.
    """
    org_a = await _make_org(db, f"rls-a-{uuid4().hex[:8]}")
    await _make_agent(db, org_a, "agent-a")

    async with db.acquire() as conn, conn.transaction():
        await conn.execute("SET LOCAL ROLE inntris_api")
        # Intentionally skip set_config — simulate a bug that forgets context.
        rows = await conn.fetch("SELECT id FROM agents")

    assert rows == [], "missing tenant context must yield zero rows, not leak"


@pytest.mark.asyncio
async def test_audit_logs_are_tenant_scoped_via_agent(db: Database) -> None:
    """audit_logs policy uses EXISTS(agents.org_id = current_tenant())."""
    org_a = await _make_org(db, f"rls-a-{uuid4().hex[:8]}")
    org_b = await _make_org(db, f"rls-b-{uuid4().hex[:8]}")
    agent_a = await _make_agent(db, org_a, "audit-a")
    agent_b = await _make_agent(db, org_b, "audit-b")

    async with db.acquire() as conn:
        for agent_id in (agent_a, agent_b):
            await conn.execute(
                """
                INSERT INTO audit_logs (
                    agent_id, action_type, action_hash, payload,
                    verdict, signature, signature_valid, trust_score_at_time
                )
                VALUES ($1, 'api_call', $2, '{}'::jsonb, 'approved', $3, true, 50)
                """,
                agent_id,
                secrets.token_hex(32),
                secrets.token_bytes(64),
            )

    async with db.acquire_as_tenant(org_a) as conn:
        rows = await conn.fetch("SELECT agent_id FROM audit_logs")

    agent_ids = {row["agent_id"] for row in rows}
    assert agent_a in agent_ids
    assert agent_b not in agent_ids


@pytest.mark.asyncio
async def test_api_keys_rls_enabled(db: Database) -> None:
    """Phase 1C.1 enabled RLS on api_keys (schemas.sql had missed it)."""
    async with db.acquire() as conn:
        rls_enabled = await conn.fetchval(
            """
            SELECT relrowsecurity
            FROM pg_class
            WHERE relname = 'api_keys' AND relnamespace = 'public'::regnamespace
            """
        )
    assert rls_enabled is True


@pytest.mark.asyncio
async def test_rate_limit_windows_rls_enabled(db: Database) -> None:
    """Same for rate_limit_windows."""
    async with db.acquire() as conn:
        rls_enabled = await conn.fetchval(
            """
            SELECT relrowsecurity
            FROM pg_class
            WHERE relname = 'rate_limit_windows'
              AND relnamespace = 'public'::regnamespace
            """
        )
    assert rls_enabled is True


@pytest.mark.asyncio
async def test_helpers_exist(db: Database) -> None:
    """app.set_tenant and app.current_tenant must be present."""
    async with db.acquire() as conn:
        names = await conn.fetch(
            """
            SELECT proname
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'app'
            ORDER BY proname
            """
        )
    proc_names = {row["proname"] for row in names}
    assert "set_tenant" in proc_names
    assert "current_tenant" in proc_names
