"""Verify the tenant database credential and role postconditions.

This script is read-only. It applies no role changes, schema changes, or data
mutations. It is intended as the pre-merge production credential gate.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import asyncpg

from api.tenant_database import TenantDatabase

_ROOT = Path(__file__).resolve().parents[1]
_ASSERTIONS = _ROOT / "database" / "migrations" / "021_tenant_login_assertions.sql"


async def _run() -> None:
    system_dsn = os.getenv("DATABASE_URL", "").strip()
    tenant_dsn = os.getenv("TENANT_DATABASE_URL", "").strip()
    if not system_dsn:
        raise SystemExit("DATABASE_URL is required to verify database-wide role postconditions")
    if not tenant_dsn:
        raise SystemExit("TENANT_DATABASE_URL is required to verify the tenant credential")

    # Database-wide assertions are read-only and intentionally use the existing
    # server DSN. Do not print either DSN or underlying connection exceptions.
    try:
        conn = await asyncpg.connect(system_dsn, statement_cache_size=0)
        try:
            await conn.execute(_ASSERTIONS.read_text(encoding="utf-8"))
        finally:
            await conn.close()
    except Exception as exc:
        raise SystemExit("Tenant role postcondition verification failed") from exc

    try:
        tenant_db = await TenantDatabase.create(tenant_dsn, min_size=1, max_size=1)
        await tenant_db.close()
    except Exception as exc:
        raise SystemExit("Tenant credential verification failed") from exc

    print("tenant database role and credential verification passed")


if __name__ == "__main__":
    asyncio.run(_run())
