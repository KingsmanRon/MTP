"""Install the tenant/system database boundary on tenant-facing HTTP routes.

Authentication remains a SYSTEM concern: API-key/bearer lookup may use the
worker identity to discover the trusted organisation. The privileged Database
object is never passed to a tenant handler. Only an organisation-bound adapter
backed by TenantDatabase is supplied after authentication succeeds.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from fastapi import Depends, Header
from fastapi.dependencies.utils import get_dependant
from fastapi.routing import APIRoute

from api import legacy_main
from api.system_tenant_adapter import TenantScopedDatabase
from api.tenant_database import TenantDatabase
from api.tenant_runtime import get_tenant_database


def is_tenant_route(path: str) -> bool:
    """Return True only for authenticated customer/partner data surfaces."""
    if path in {"/v1/events", "/admin/test-verify", "/admin/usage"}:
        return True
    if path.startswith("/admin/agents"):
        return True
    if path.startswith("/admin/audit"):
        return True
    if path.startswith("/admin/alerts"):
        return True
    if path.startswith("/admin/api-keys"):
        return True
    if path == "/admin/organization" or path.startswith("/admin/organization/"):
        return True
    if path.startswith("/admin/webhook"):
        return True
    return False


async def get_admin_tenant_database(
    auth: dict = Depends(legacy_main.verify_api_key),
    tenant_database: TenantDatabase = Depends(get_tenant_database),
) -> TenantScopedDatabase:
    """Bind tenant DB access to the org resolved from the API key server-side."""
    org_id = auth.get("org_id")
    if not isinstance(org_id, UUID):
        org_id = UUID(str(org_id))
    return TenantScopedDatabase(tenant_database, org_id)


async def get_events_tenant_database(
    authorization: str | None = Header(None, alias="Authorization"),
    system_database=Depends(legacy_main.get_db),
    tenant_database: TenantDatabase = Depends(get_tenant_database),
) -> TenantScopedDatabase:
    """Resolve bearer identity with SYSTEM DB, then discard it before tenant work."""
    auth = await legacy_main._verify_bearer_token(authorization, system_database)
    org_id = auth["org_id"]
    if not isinstance(org_id, UUID):
        org_id = UUID(str(org_id))
    return TenantScopedDatabase(tenant_database, org_id)


def _replacement_for(route: APIRoute) -> Callable:
    if route.path == "/v1/events":
        return get_events_tenant_database
    return get_admin_tenant_database


def install_tenant_route_boundary(app) -> set[str]:
    """Replace direct privileged DB dependencies on classified tenant routes.

    Nested ``legacy_main.get_db`` use inside authentication is intentionally left
    intact: it is the SYSTEM identity resolver and its Database object is never
    passed to the route handler.
    """
    installed: set[str] = set()
    for route in app.routes:
        if not isinstance(route, APIRoute) or not is_tenant_route(route.path):
            continue

        replaced = False
        for index, dependency in enumerate(route.dependant.dependencies):
            if dependency.call is not legacy_main.get_db:
                continue
            provider = _replacement_for(route)
            replacement = get_dependant(path=route.path_format, call=provider)
            replacement.name = dependency.name
            replacement.use_cache = dependency.use_cache
            route.dependant.dependencies[index] = replacement
            replaced = True

        if replaced:
            installed.add(route.path)

    return installed
