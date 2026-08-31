from __future__ import annotations

import inspect
from uuid import uuid4

import pytest

from api.tenant_database import TenantDatabase, TenantDatabaseError


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


def test_startup_assertion_requires_exact_login_and_canary() -> None:
    source = inspect.getsource(TenantDatabase.assert_safe_identity)
    assert "inntris_tenant_login" in source
    assert "rolbypassrls" in source
    assert "rolsuper" in source
    assert "inntris_worker" in source
    assert "SET LOCAL ROLE" in source
    assert "SELECT count(*) FROM agents" in source


@pytest.mark.asyncio
async def test_missing_dsn_fails_closed() -> None:
    with pytest.raises(TenantDatabaseError, match="TENANT_DATABASE_URL"):
        await TenantDatabase.create("")


def test_tenant_method_installs_transaction_local_context() -> None:
    source = inspect.getsource(TenantDatabase.tenant)
    assert "SET LOCAL ROLE" in source
    assert "set_config('app.current_org_id', $1, true)" in source
    assert "conn.transaction()" in source
    assert str(uuid4())
