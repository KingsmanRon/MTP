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

# Execution-authority HTTP surface. It is registered here, on the same app,
# and calls the same internal services the legacy routes call -- there is no
# second evaluation or consumption path behind it.
from api.routes import authority as _authority_routes  # noqa: E402


async def _get_agent_or_404(database, agent_id):
    from fastapi import HTTPException

    try:
        agent = await database.get_agent_by_id(agent_id)
    except Exception as exc:  # AgentNotFoundError and any lookup failure
        raise HTTPException(status_code=404, detail="Agent not found") from exc
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


_authority_routes.register(
    _legacy_main.app,
    get_db=_legacy_main.get_db,
    require_api_scope=_legacy_main.require_api_scope,
    get_agent_or_404=_get_agent_or_404,
    server_secret_provider=lambda: _legacy_main.SERVER_SECRET,
)

# Preserve the historical api.main module surface for existing tests and
# operational tooling that monkeypatch globals such as db_pool. The ASGI app is
# the same object; only its tenant-facing dependency graph has been hardened.
sys.modules[__name__] = _legacy_main
