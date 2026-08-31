"""Runtime ownership of the non-BYPASSRLS tenant connection pool."""

from __future__ import annotations

import logging
import os

from fastapi import HTTPException, status

from api.tenant_database import TenantDatabase

logger = logging.getLogger(__name__)

# inntris_tenant_login has CONNECTION LIMIT 20. Production currently runs one
# web replica. Five tenant connections per replica leaves deliberate headroom
# for Supavisor/server overhead and horizontal scaling; see the PR-2 rollout
# notes for the budget arithmetic.
TENANT_DATABASE_MAX_SIZE = 5
TENANT_DATABASE_MIN_SIZE = 1

tenant_db_pool: TenantDatabase | None = None


def _is_production() -> bool:
    return (
        os.getenv("RAILWAY_ENVIRONMENT_NAME", "").lower() == "production"
        or os.getenv("ENVIRONMENT", "").lower() == "production"
    )


async def start_tenant_database() -> None:
    """Create and identity-check the tenant pool for the web process."""
    global tenant_db_pool
    if tenant_db_pool is not None:
        return

    dsn = os.getenv("TENANT_DATABASE_URL")
    if not dsn:
        if _is_production():
            raise RuntimeError("TENANT_DATABASE_URL is required in production")
        logger.warning("TENANT_DATABASE_URL is not configured; tenant routes will fail closed")
        return

    # TenantDatabase.create() includes the restricted-identity/RLS canary.
    tenant_db_pool = await TenantDatabase.create(
        dsn,
        min_size=TENANT_DATABASE_MIN_SIZE,
        max_size=TENANT_DATABASE_MAX_SIZE,
    )


async def stop_tenant_database() -> None:
    """Close the tenant pool without touching the system/worker pool."""
    global tenant_db_pool
    if tenant_db_pool is None:
        return
    await tenant_db_pool.close()
    tenant_db_pool = None


async def get_tenant_database() -> TenantDatabase:
    """FastAPI dependency that exposes only the TenantDatabase primitive."""
    if tenant_db_pool is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Tenant database unavailable",
        )
    return tenant_db_pool
