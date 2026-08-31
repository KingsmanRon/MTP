from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("alembic")

_REPO = Path(__file__).resolve().parents[1]
_REVISION = _REPO / "alembic" / "versions" / "0017_tenant_login_isolation.py"
_SQL = _REPO / "database" / "migrations" / "021_tenant_login_isolation.sql"
_ASSERTIONS = _REPO / "database" / "migrations" / "021_tenant_login_assertions.sql"


def _load_revision():
    spec = importlib.util.spec_from_file_location("alembic_0017_tenant_login_isolation", _REVISION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision_follows_rls_hardening() -> None:
    module = _load_revision()
    assert module.revision == "0017_tenant_login_isolation"
    assert module.down_revision == "0016_rls_hardening"
    assert module._SQL_FILE == _SQL
    assert module._ASSERTIONS_FILE == _ASSERTIONS


def test_role_is_unprivileged_and_passwordless_in_source() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "CREATE ROLE inntris_tenant_login" in sql
    for required in ("NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOBYPASSRLS", "NOINHERIT"):
        assert required in sql
    assert "PASSWORD" not in sql


def test_pg16_membership_is_non_inheriting_but_settable() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "server_version >= 160000" in sql
    assert "WITH INHERIT FALSE, SET TRUE" in sql


def test_login_receives_no_direct_table_or_sequence_grants() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public" in sql
    assert "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public" in sql
    assert "GRANT SELECT" not in sql
    assert "GRANT INSERT" not in sql
    assert "GRANT UPDATE" not in sql
    assert "GRANT DELETE" not in sql


def test_tenant_tables_force_rls() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    for table in (
        "organizations",
        "agents",
        "audit_logs",
        "policy_rules",
        "security_alerts",
        "api_keys",
        "rate_limit_windows",
    ):
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;" in sql


def test_assertions_cover_privileged_membership_and_policy_targeting() -> None:
    sql = _ASSERTIONS.read_text(encoding="utf-8")
    assert "pg_has_role('inntris_tenant_login', 'inntris_worker', 'MEMBER')" in sql
    assert "pg_has_role('inntris_api', 'inntris_worker', 'MEMBER')" in sql
    assert "ARRAY['service_role', 'postgres', 'supabase_admin']" in sql
    assert "acl.grantee IN (0, tenant_oid)" in sql
    assert "relforcerowsecurity" in sql
    assert "'inntris_api' = ANY(p.roles)" in sql


def test_downgrade_is_forward_only() -> None:
    module = _load_revision()
    with pytest.raises(NotImplementedError):
        module.downgrade()
