from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("alembic")

from alembic.config import Config  # noqa: E402
from alembic.script import ScriptDirectory  # noqa: E402

_REPO = Path(__file__).resolve().parents[1]
_REVISION = _REPO / "alembic" / "versions" / "0018_merkle_anchor_visibility.py"
_SQL = _REPO / "database" / "migrations" / "022_merkle_proof_tenant_visibility.sql"


def _load_revision():
    spec = importlib.util.spec_from_file_location(
        "alembic_0018_merkle_anchor_visibility", _REVISION
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision_follows_tenant_login_isolation() -> None:
    module = _load_revision()
    assert module.revision == "0018_merkle_anchor_visibility"
    assert module.down_revision == "0017_tenant_login_isolation"
    assert module._SQL_FILE == _SQL


def test_alembic_has_exactly_one_head() -> None:
    config = Config(str(_REPO / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO / "alembic"))
    assert ScriptDirectory.from_config(config).get_heads() == [
        "0018_merkle_anchor_visibility"
    ]


def test_policy_is_tenant_scoped_and_read_only() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "CREATE POLICY merkle_proofs_tenant_anchor_read" in sql
    assert "FOR SELECT" in sql
    assert "TO inntris_api" in sql
    assert "al.merkle_root_id = merkle_proofs.id" in sql
    assert "a.org_id = app.current_tenant()" in sql
    assert "FOR INSERT" not in sql
    assert "FOR UPDATE" not in sql
    assert "FOR DELETE" not in sql


def test_policy_keeps_rls_forced_and_browser_roles_closed() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "ALTER TABLE public.merkle_proofs ENABLE ROW LEVEL SECURITY" in sql
    assert "ALTER TABLE public.merkle_proofs FORCE ROW LEVEL SECURITY" in sql
    assert "GRANT SELECT ON TABLE public.merkle_proofs TO inntris_api" in sql
    assert "REVOKE ALL PRIVILEGES ON TABLE public.merkle_proofs" in sql
    assert "ARRAY['anon', 'authenticated']" in sql
    assert "GRANT SELECT ON TABLE public.merkle_proofs TO anon" not in sql
    assert "GRANT SELECT ON TABLE public.merkle_proofs TO authenticated" not in sql


def test_migration_contains_fail_closed_postconditions() -> None:
    sql = _SQL.read_text(encoding="utf-8")
    assert "has_table_privilege('inntris_api', 'public.merkle_proofs', 'SELECT')" in sql
    assert "merkle_proofs_tenant_anchor_read policy is missing" in sql
    assert "direct anon/authenticated Merkle proof privilege remains" in sql


def test_downgrade_is_forward_only() -> None:
    module = _load_revision()
    with pytest.raises(NotImplementedError):
        module.downgrade()
