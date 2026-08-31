from __future__ import annotations

import ast
import inspect
from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.routing import APIRoute

from api import legacy_main
from api.main import TENANT_BOUNDARY_PATHS, app
from api.system_tenant_adapter import TenantScopedDatabase
from api.tenant_boundary import (
    get_admin_tenant_database,
    get_events_tenant_database,
    is_tenant_route,
)
from api.tenant_database import TenantDatabase


def _direct_dependency_calls(route: APIRoute) -> set[object]:
    return {dependency.call for dependency in route.dependant.dependencies}


def test_tenant_database_has_no_generic_acquire() -> None:
    assert not hasattr(TenantDatabase, "acquire")


def test_master_operator_route_is_not_misclassified_as_tenant() -> None:
    assert is_tenant_route("/admin/organization") is True
    assert is_tenant_route("/admin/organizations") is False


def test_every_db_backed_tenant_route_has_privileged_dependency_removed() -> None:
    db_backed_tenant_routes = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or not is_tenant_route(route.path):
            continue
        calls = _direct_dependency_calls(route)
        assert legacy_main.get_db not in calls, (
            f"tenant route {route.path} can still directly acquire the privileged database"
        )
        if route.path in TENANT_BOUNDARY_PATHS:
            db_backed_tenant_routes.append(route.path)
            assert calls & {get_admin_tenant_database, get_events_tenant_database}

    assert db_backed_tenant_routes


def test_tenant_boundary_module_does_not_import_privileged_database_primitive() -> None:
    source = Path(inspect.getsourcefile(is_tenant_route)).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "api.database":
            forbidden.extend(alias.name for alias in node.names if alias.name == "Database")
    assert forbidden == []


@pytest.mark.asyncio
async def test_forged_org_id_cannot_rebind_scoped_database() -> None:
    trusted_org = uuid4()
    forged_org = uuid4()
    facade = TenantScopedDatabase(MagicMock(), trusted_org)

    assert facade.trusted_org_id == trusted_org
    with pytest.raises(PermissionError):
        async with facade.acquire_as_tenant(forged_org):
            pass


def test_tenant_route_facade_has_no_privileged_pool() -> None:
    facade = TenantScopedDatabase(MagicMock(), uuid4())
    with pytest.raises(RuntimeError, match="Privileged/raw pool access"):
        _ = facade._pool


@pytest.mark.asyncio
async def test_admin_tenant_database_uses_authenticated_org_only() -> None:
    trusted_org = uuid4()
    tenant_database = MagicMock(spec=TenantDatabase)
    scoped = await get_admin_tenant_database(
        auth={"org_id": trusted_org},
        tenant_database=tenant_database,
    )
    assert scoped.trusted_org_id == trusted_org
