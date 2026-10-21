"""Restore ACL regression, against an isolated migrated PostgreSQL database.

DDL and grants are always rolled back, including on assertion failure.
"""

import os
from pathlib import Path

import pytest

asyncpg = pytest.importorskip("asyncpg")

DSN = os.getenv("ALEMBIC_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    os.getenv("INNTRIS_DB_INTEGRATION") != "1" or not DSN,
    reason="requires an isolated migrated Postgres and migration credential",
)
ASSERTIONS = (
    Path(__file__).resolve().parents[1] / "database/migrations/021_tenant_login_assertions.sql"
).read_text()


@pytest.mark.parametrize("acl_state", ["default", "empty", "public_grant"])
async def test_permission_gate_handles_restored_acls(acl_state):
    conn = await asyncpg.connect(DSN)
    transaction = conn.transaction()
    await transaction.start()
    try:
        # A view has table ACL semantics and is checked by the direct-grant
        # gate, without changing the allowlist of persistent application tables.
        await conn.execute(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES "
            "FROM PUBLIC, inntris_worker, inntris_api, inntris_tenant_login"
        )
        await conn.execute("CREATE VIEW public.restore_acl_probe AS SELECT 1 AS value")
        assert await conn.fetchval(
            "SELECT relacl IS NULL FROM pg_class WHERE oid='public.restore_acl_probe'::regclass"
        )
        if acl_state == "empty":
            await conn.execute("REVOKE ALL ON public.restore_acl_probe FROM CURRENT_USER")
            assert await conn.fetchval(
                "SELECT cardinality(relacl)=0 FROM pg_class "
                "WHERE oid='public.restore_acl_probe'::regclass"
            )
        if acl_state == "public_grant":
            await conn.execute("GRANT SELECT ON public.restore_acl_probe TO PUBLIC")
            with pytest.raises(asyncpg.RaiseError, match="direct public-schema table privileges"):
                await conn.execute(ASSERTIONS)
        else:
            await conn.execute(ASSERTIONS)
    finally:
        await transaction.rollback()
        await conn.close()
