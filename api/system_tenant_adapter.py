"""SYSTEM compatibility adapter from legacy Database methods to TenantDatabase.

This module is deliberately classified SYSTEM, not tenant route code. It reuses
legacy Database method implementations while making the privileged constructor,
raw pool and privileged acquisition path unreachable. Every acquisition enters
TenantDatabase.tenant() with the organisation already resolved by server-side
authentication.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from uuid import UUID

from asyncpg import Connection

from api.database import Database
from api.tenant_database import TenantDatabase


class TenantScopedDatabase(Database):
    """Org-bound compatibility facade with no privileged system pool."""

    def __init__(self, tenant_database: TenantDatabase, trusted_org_id: UUID):
        # Do not call Database.__init__: this object never receives a system pool.
        self._tenant_database = tenant_database
        self._trusted_org_id = trusted_org_id

    @classmethod
    async def create(cls, *args, **kwargs):  # pragma: no cover - architecture guard
        raise RuntimeError("TenantScopedDatabase cannot create a database pool")

    async def close(self) -> None:  # pragma: no cover - owned by tenant_runtime
        raise RuntimeError("TenantScopedDatabase does not own the tenant pool")

    @property
    def _pool(self):  # pragma: no cover - fail closed on raw-pool access
        raise RuntimeError("Privileged/raw pool access is forbidden on tenant routes")

    @_pool.setter
    def _pool(self, value):  # pragma: no cover
        raise RuntimeError("Privileged/raw pool access is forbidden on tenant routes")

    @property
    def trusted_org_id(self) -> UUID:
        return self._trusted_org_id

    @asynccontextmanager
    async def acquire(self) -> AsyncGenerator[Connection, None]:
        """Compatibility acquisition backed only by TenantDatabase.tenant()."""
        async with self._tenant_database.tenant(self._trusted_org_id) as conn:
            yield conn

    @asynccontextmanager
    async def acquire_as_tenant(self, org_id: UUID) -> AsyncGenerator[Connection, None]:
        """Reject any attempt to replace the authenticated organisation."""
        if org_id != self._trusted_org_id:
            raise PermissionError("request organisation does not match authenticated tenant")
        async with self._tenant_database.tenant(self._trusted_org_id) as conn:
            yield conn
