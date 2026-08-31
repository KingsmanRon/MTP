"""Tenant-scoped PostgreSQL access for Inntris.

This module deliberately exposes no generic raw-connection API. A caller must
supply a trusted organisation id, and every tenant transaction runs as
``inntris_api`` with transaction-local tenant context.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from uuid import UUID

import asyncpg
from asyncpg import Connection, Pool

TENANT_LOGIN_ROLE = "inntris_tenant_login"
TENANT_POLICY_ROLE = "inntris_api"
SYSTEM_ROLE = "inntris_worker"


class TenantDatabaseError(RuntimeError):
    """Raised when the tenant database boundary is unavailable or unsafe."""


class TenantDatabase:
    """NOBYPASSRLS pool that can only issue tenant-scoped transactions."""

    def __init__(self, pool: Pool):
        self._pool = pool

    @classmethod
    async def create(
        cls,
        dsn: str,
        min_size: int = 2,
        max_size: int = 10,
    ) -> "TenantDatabase":
        """Create and verify the tenant pool.

        ``statement_cache_size=0`` is required for Supavisor transaction
        pooling. The DSN itself is never included in errors or logs.
        """
        if not dsn or not dsn.strip():
            raise TenantDatabaseError("TENANT_DATABASE_URL is required for tenant database access")

        try:
            pool = await asyncpg.create_pool(
                dsn,
                min_size=min_size,
                max_size=max_size,
                command_timeout=30,
                statement_cache_size=0,
            )
        except Exception as exc:
            raise TenantDatabaseError("Failed to create tenant database pool") from exc

        if pool is None:
            raise TenantDatabaseError("Failed to create tenant database pool")

        database = cls(pool)
        try:
            await database.assert_safe_identity()
        except Exception:
            await pool.close()
            raise
        return database

    async def close(self) -> None:
        await self._pool.close()

    async def assert_safe_identity(self) -> None:
        """Fail unless the DSN authenticates as the intended restricted role."""
        async with self._pool.acquire() as conn:
            identity = await conn.fetchrow(
                """
                SELECT current_user AS current_user,
                       r.rolsuper AS is_superuser,
                       r.rolbypassrls AS bypass_rls
                FROM pg_roles r
                WHERE r.rolname = current_user
                """
            )
            if identity is None:
                raise TenantDatabaseError("Unable to resolve tenant database identity")
            if identity["current_user"] != TENANT_LOGIN_ROLE:
                raise TenantDatabaseError(
                    "TENANT_DATABASE_URL must authenticate as inntris_tenant_login"
                )
            if identity["is_superuser"] or identity["bypass_rls"]:
                raise TenantDatabaseError("Tenant database identity is privileged")

            can_reach_worker = await conn.fetchval(
                """
                SELECT pg_has_role(current_user, $1, 'MEMBER')
                    OR pg_has_role(current_user, $1, 'USAGE')
                """,
                SYSTEM_ROLE,
            )
            if can_reach_worker:
                raise TenantDatabaseError("Tenant database identity can reach inntris_worker")

            # Canary: with the tenant policy role but no tenant context, RLS must
            # reveal no tenant rows. This also proves SET ROLE is permitted.
            async with conn.transaction():
                await conn.execute(f"SET LOCAL ROLE {TENANT_POLICY_ROLE}")
                row_count = await conn.fetchval("SELECT count(*) FROM agents")
                if row_count != 0:
                    raise TenantDatabaseError(
                        "Tenant RLS canary failed: missing tenant context exposed rows"
                    )

    @asynccontextmanager
    async def tenant(self, org_id: UUID) -> AsyncGenerator[Connection, None]:
        """Yield a transaction scoped to one trusted organisation id."""
        if not isinstance(org_id, UUID):
            raise TypeError("org_id must be a UUID resolved from trusted authentication context")

        async with self._pool.acquire() as conn, conn.transaction():
            await conn.execute(f"SET LOCAL ROLE {TENANT_POLICY_ROLE}")
            await conn.execute(
                "SELECT set_config('app.current_org_id', $1, true)",
                str(org_id),
            )
            yield conn

    async def health_check(self) -> bool:
        """Check connectivity without exposing a raw connection to callers."""
        try:
            async with self._pool.acquire() as conn:
                return await conn.fetchval("SELECT 1") == 1
        except Exception:
            return False
