"""Production ASGI composition for Inntris Core.

The stable application implementation remains in :mod:`api.legacy_main` while
PR 2 installs a separate non-BYPASSRLS tenant database boundary on authenticated
customer routes. System verification, public evidence, migration and worker
behaviour remain unchanged.
"""

from __future__ import annotations

import sys

from api import legacy_main as _legacy_main
from api.tenant_boundary import install_tenant_route_boundary
from api.tenant_runtime import start_tenant_database, stop_tenant_database

# Mutate the existing FastAPI dependency graph in place so established route
# semantics stay intact while direct tenant-handler database dependencies are
# replaced by the tenant-scoped primitive.
TENANT_BOUNDARY_PATHS = frozenset(install_tenant_route_boundary(_legacy_main.app))
_legacy_main.TENANT_BOUNDARY_PATHS = TENANT_BOUNDARY_PATHS

# Match the existing application's lifecycle registration mechanism. FastAPI
# 0.141 no longer exposes app.add_event_handler(), while APIRouter.on_event()
# remains the compatibility path already used by legacy_main.
_legacy_main.app.router.on_event("startup")(start_tenant_database)
_legacy_main.app.router.on_event("shutdown")(stop_tenant_database)

# Preserve the historical api.main module surface for existing tests and
# operational tooling that monkeypatch globals such as db_pool. The ASGI app is
# the same object; only its tenant-facing dependency graph has been hardened.
sys.modules[__name__] = _legacy_main
