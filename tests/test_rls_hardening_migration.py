from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("alembic")

_REPO = Path(__file__).resolve().parents[1]
_REVISION = _REPO / "alembic" / "versions" / "0016_rls_hardening.py"
_SQL = _REPO / "database" / "migrations" / "020_rls_hardening.sql"


def _load_revision():
    spec = importlib.util.spec_from_file_location("alembic_0016_rls_hardening", _REVISION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision_is_wired_after_anchor_submission_state() -> None:
    module = _load_revision()
    assert module.revision == "0016_rls_hardening"
    assert module.down_revision == "0015_anchor_submission_state"
    assert module._SQL_FILE == _SQL
    assert module._SQL_FILE.is_file()


def test_sensitive_tables_enable_rls_and_revoke_client_roles() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    tables = (
        "agents",
        "audit_logs",
        "merkle_proofs",
        "administrative_audit_events",
        "approval_token_consumptions",
    )

    for table in tables:
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;" in sql
        assert f"REVOKE ALL PRIVILEGES ON TABLE {table} FROM anon, authenticated;" in sql


def test_worker_bypass_is_precondition_not_created_by_migration() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "rolname = 'inntris_worker'" in sql
    assert "rolbypassrls" in sql
    assert "CREATE ROLE inntris_worker" not in sql
    assert "ALTER ROLE inntris_worker" not in sql


def test_future_postgres_tables_do_not_inherit_public_client_grants() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public" in sql
    assert "REVOKE ALL ON TABLES FROM anon, authenticated;" in sql


def test_existing_tenant_policies_are_asserted() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "agents_tenant_scope" in sql
    assert "audit_logs_tenant_scope" in sql
    assert "'inntris_api' = ANY(roles)" in sql


def test_downgrade_is_forward_only() -> None:
    module = _load_revision()
    with pytest.raises(NotImplementedError):
        module.downgrade()
