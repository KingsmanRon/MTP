"""Production ASGI composition for Inntris Core.

The stable application implementation remains in :mod:`api.legacy_main` while
PR 2 installs a separate non-BYPASSRLS tenant database boundary on authenticated
customer routes. System verification, public evidence, migration and worker
behaviour remain unchanged.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager

from api import legacy_main as _legacy_main
from api.tenant_boundary import install_tenant_route_boundary
from api.tenant_runtime import start_tenant_database, stop_tenant_database

# Mutate the existing FastAPI dependency graph in place so established route
# semantics stay intact while direct tenant-handler database dependencies are
# replaced by the tenant-scoped primitive.
TENANT_BOUNDARY_PATHS = frozenset(install_tenant_route_boundary(_legacy_main.app))
_legacy_main.TENANT_BOUNDARY_PATHS = TENANT_BOUNDARY_PATHS

# Extend the existing application lifespan without registering additional
# deprecated on_event handlers. The original lifespan continues to own all
# established startup/shutdown behaviour; the tenant pool is nested inside it.
_original_lifespan = _legacy_main.app.router.lifespan_context


@asynccontextmanager
async def _tenant_lifespan(app):
    async with _original_lifespan(app):
        await start_tenant_database()
        try:
            yield
        finally:
            await stop_tenant_database()


_legacy_main.app.router.lifespan_context = _tenant_lifespan

# Preserve the historical api.main module surface for existing tests and
# operational tooling that monkeypatch globals such as db_pool. The ASGI app is
# the same object; only its tenant-facing dependency graph has been hardened.
sys.modules[__name__] = _legacy_main
