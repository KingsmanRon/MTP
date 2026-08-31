from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("alembic")

from alembic.config import Config  # noqa: E402
from alembic.script import ScriptDirectory  # noqa: E402

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


def test_alembic_has_exactly_one_head() -> None:
    config = Config(str(_REPO / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO / "alembic"))
    heads = ScriptDirectory.from_config(config).get_heads()
    assert heads == ["0017_tenant_login_isolation"]


def test_role_is_unprivileged_and_passwordless_in_source() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "CREATE ROLE inntris_tenant_login" in sql
    for required in (
        "NOSUPERUSER",
        "NOCREATEDB",
        "NOCREATEROLE",
        "NOBYPASSRLS",
        "NOINHERIT",
        "CONNECTION LIMIT 20",
    ):
        assert required in sql
    assert "PASSWORD" not in sql


def test_pg16_plus_membership_is_non_inheriting_but_settable() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "server_version >= 160000" in sql
    assert "WITH INHERIT FALSE, SET TRUE" in sql
    assert "including production PG17" in sql


def test_migration_preflights_role_administration_capability() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "rolcreaterole" in sql
    assert "m.admin_option" in sql
    assert "requires ADMIN OPTION on inntris_api" in sql
    assert "requires ADMIN OPTION on existing inntris_tenant_login" in sql
    assert "CI superusers would otherwise hide" in sql


def test_login_receives_no_direct_table_or_sequence_grants() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public" in sql
    assert "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public" in sql
    assert "REVOKE CREATE ON SCHEMA public" in sql
    assert "REVOKE CREATE ON SCHEMA app" in sql
    assert "GRANT SELECT" not in sql
    assert "GRANT INSERT" not in sql
    assert "GRANT UPDATE" not in sql
    assert "GRANT DELETE" not in sql


def test_role_guardrails_and_search_path_are_pinned() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "SET search_path TO pg_catalog, public" in sql
    assert "SET statement_timeout TO '30s'" in sql
    assert "SET idle_in_transaction_session_timeout TO '15s'" in sql
    assertions = _ASSERTIONS.read_text(encoding="utf-8")
    assert "tenant_connlimit <> 20" in assertions
    assert "search_path=pg_catalog, public" in assertions


def test_force_rls_preflights_owner_and_documents_bypass_semantics() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "migration_super" in sql
    assert "migration_bypass" in sql
    assert "does not own public.%" in sql
    assert "reviewed SUPERUSER/BYPASSRLS migration plane" in sql
    assert "FORCE ROW LEVEL SECURITY closes the table-owner exemption only" in sql
    assert "Production" in sql and "postgres currently has BYPASSRLS" in sql


def test_assertions_cover_privileged_membership_and_alternate_paths() -> None:
    sql = _ASSERTIONS.read_text(encoding="utf-8")
    assert "pg_has_role('inntris_tenant_login', 'inntris_worker', 'MEMBER')" in sql
    assert "pg_has_role('inntris_api', 'inntris_worker', 'MEMBER')" in sql
    assert "ARRAY['service_role', 'postgres', 'supabase_admin']" in sql
    assert "safe short-circuit boundary" in sql
    assert "acl.grantee IN (0, tenant_oid)" in sql
    assert "has_table_privilege(" in sql
    assert "has_function_privilege('inntris_tenant_login'" in sql
    assert "has_function_privilege('inntris_api'" in sql
    assert "prosecdef" in sql
    assert "has_schema_privilege" in sql


def test_rls_drift_guard_is_deny_by_default() -> None:
    sql = _ASSERTIONS.read_text(encoding="utf-8")
    assert "unknown public table(s) are outside the reviewed RLS classification" in sql
    assert "c.relname <> ALL(ARRAY[" in sql
    assert "relforcerowsecurity" in sql
    for table in (
        "administrative_audit_events",
        "agent_key_history",
        "agent_policies",
        "agents",
        "alembic_version",
        "api_keys",
        "approval_token_consumptions",
        "audit_logs",
        "erasure_requests",
        "merkle_proofs",
        "organizations",
        "policy_rules",
        "rate_limit_windows",
        "security_alerts",
        "spend_reservations",
        "verify_request_idempotency",
        "webhook_deliveries",
    ):
        assert f"'{table}'" in sql


def test_security_definer_guard_is_a_standing_assertion() -> None:
    sql = _ASSERTIONS.read_text(encoding="utf-8")
    assert "reachable_definer_count" in sql
    assert "n.nspname IN ('public', 'app')" in sql
    assert "p.prosecdef" in sql
    assert "tenant authority can execute SECURITY DEFINER" in sql


def test_downgrade_is_forward_only() -> None:
    module = _load_revision()
    with pytest.raises(NotImplementedError):
        module.downgrade()
