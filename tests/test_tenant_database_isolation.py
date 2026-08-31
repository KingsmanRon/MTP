from __future__ import annotations

import inspect
from uuid import uuid4

import pytest

from api.tenant_database import TenantDatabase, TenantDatabaseError
from api.tenant_runtime import TENANT_DATABASE_MAX_SIZE, TENANT_DATABASE_MIN_SIZE


def test_tenant_database_exposes_no_generic_acquire() -> None:
    assert not hasattr(TenantDatabase, "acquire")
    assert hasattr(TenantDatabase, "tenant")


def test_tenant_context_api_requires_uuid() -> None:
    source = inspect.getsource(TenantDatabase.tenant)
    assert "isinstance(org_id, UUID)" in source
    assert 'raise TypeError("org_id must be a UUID' in source


def test_pool_disables_asyncpg_statement_cache() -> None:
    source = inspect.getsource(TenantDatabase.create)
    assert "statement_cache_size=0" in source


def test_tenant_pool_budget_is_deliberately_below_login_limit() -> None:
    assert TENANT_DATABASE_MIN_SIZE == 1
    assert TENANT_DATABASE_MAX_SIZE == 5
    assert TENANT_DATABASE_MAX_SIZE < 20


def test_startup_assertion_requires_exact_session_login_and_canary() -> None:
    source = inspect.getsource(TenantDatabase.assert_safe_identity)
    assert "session_user" in source
    assert "current_user" in source
    assert "inntris_tenant_login" in source
    assert "rolbypassrls" in source
    assert "rolsuper" in source
    assert "inntris_worker" in source
    assert "SELECT count(*) FROM agents" in source


@pytest.mark.asyncio
async def test_missing_dsn_fails_closed() -> None:
    with pytest.raises(TenantDatabaseError, match="TENANT_DATABASE_URL"):
        await TenantDatabase.create("")


def test_tenant_method_installs_context_in_one_round_trip() -> None:
    source = inspect.getsource(TenantDatabase.tenant)
    helper = inspect.getsource(TenantDatabase._enter_tenant_role)
    assert "set_config('role','inntris_api',true)" in helper
    assert "set_config('search_path','pg_catalog, public',true)" in helper
    assert "set_config('statement_timeout','30s',true)" in helper
    assert "set_config('idle_in_transaction_session_timeout','15s',true)" in helper
    assert "set_config('app.current_org_id',$1,true)" in helper
    assert "SET LOCAL ROLE" not in helper
    assert "await self._enter_tenant_role(conn, org_id)" in source
    assert "conn.transaction()" in source
    assert str(uuid4())
