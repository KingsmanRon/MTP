"""Real-Postgres regression for tenant-visible Merkle anchor rows.

This specifically protects the admin-dashboard failure introduced when tenant
routes moved onto the non-BYPASSRLS database identity while merkle_proofs had no
inntris_api SELECT policy.
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
    database = None

    try:
        if not tenant_dsn:
            assert CI and MIGRATOR_DSN, "migrator fallback is CI-only"
            generated_password = True
            password = secrets.token_urlsafe(32)
            admin = await asyncpg.connect(MIGRATOR_DSN, statement_cache_size=0)
            try:
                assert await admin.fetchval("SHOW log_statement") == "none"
                statement = await admin.fetchval(
                    "SELECT format('ALTER ROLE inntris_tenant_login PASSWORD %L', $1::text)",
                    password,
                )
                await admin.execute(statement)
            finally:
                await admin.close()
            tenant_dsn = _tenant_dsn_from_migrator(MIGRATOR_DSN, password)

        database = await TenantDatabase.create(tenant_dsn, min_size=1, max_size=1)
        yield database
    finally:
        if database is not None:
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
            f"{name}@merkle-tenant-test.local",
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


async def _make_confirmed_anchor(db: Database, agent_id: UUID, marker: str) -> UUID:
    action_hash = hashlib.sha256(f"action:{marker}".encode()).hexdigest()
    root_hash = hashlib.sha256(f"root:{marker}".encode()).hexdigest()
    tx_hash = "0x" + hashlib.sha256(f"tx:{marker}".encode()).hexdigest()

    async with db.acquire() as conn:
        proof_id = await conn.fetchval(
            """
            INSERT INTO merkle_proofs (
                root_hash, transaction_hash, block_number, contract_address,
                chain_id, status, log_count, start_timestamp, end_timestamp,
                leaf_hashes, confirmed_at
            )
            VALUES ($1, $2, 50536889, $3, 8453, 'confirmed', 1, now(), now(), $4, now())
            RETURNING id
            """,
            root_hash,
            tx_hash,
            "0x" + "12" * 20,
            [action_hash],
        )
        chain_sequence = await conn.fetchval(
            "SELECT COALESCE(MAX(chain_sequence), 0) + 1 FROM audit_logs WHERE agent_id = $1",
            agent_id,
        )
        await conn.execute(
            """
            INSERT INTO audit_logs (
                agent_id, action_type, action_hash, payload, verdict,
                signature, signature_valid, trust_score_at_time,
                chain_sequence, merkle_root_id, merkle_leaf_index
            )
            VALUES ($1, 'wallet_transaction', $2, '{}'::jsonb, 'approved',
                    $3, true, 100, $4, $5, 0)
            """,
            agent_id,
            action_hash,
            b"tenant-merkle-regression",
            chain_sequence,
            proof_id,
        )
    return proof_id


@pytest.mark.asyncio
async def test_merkle_anchor_visibility_follows_audit_tenant(system_db, tenant_db) -> None:
    org_a = await _make_org(system_db, f"merkle-tenant-a-{uuid4().hex[:8]}")
    org_b = await _make_org(system_db, f"merkle-tenant-b-{uuid4().hex[:8]}")
    agent_a = await _make_agent(system_db, org_a, "wallet-a")
    agent_b = await _make_agent(system_db, org_b, "wallet-b")
    proof_a = await _make_confirmed_anchor(system_db, agent_a, uuid4().hex)
    proof_b = await _make_confirmed_anchor(system_db, agent_b, uuid4().hex)

    async with tenant_db.tenant(org_a) as conn:
        rows_a = await conn.fetch(
            "SELECT id, status, transaction_hash, block_number FROM merkle_proofs ORDER BY id"
        )
    async with tenant_db.tenant(org_b) as conn:
        rows_b = await conn.fetch(
            "SELECT id, status, transaction_hash, block_number FROM merkle_proofs ORDER BY id"
        )

    assert {row["id"] for row in rows_a} == {proof_a}
    assert {row["id"] for row in rows_b} == {proof_b}
    assert rows_a[0]["status"] == "confirmed"
    assert rows_a[0]["transaction_hash"] is not None
    assert rows_a[0]["block_number"] == 50536889
    assert proof_b not in {row["id"] for row in rows_a}
    assert proof_a not in {row["id"] for row in rows_b}
