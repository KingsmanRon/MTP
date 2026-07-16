"""Phase 1D.1 — sanity checks on the Alembic baseline.

We cannot run ``alembic upgrade head`` in CI without a Postgres instance,
but we CAN verify the migration tree is structurally sound: revision IDs
match, the baseline's referenced SQL files exist, the module imports, and
``downgrade`` raises the expected guard rather than silently dropping
tables. These checks catch accidental breakage (renamed SQL files, missing
revision metadata) before they reach an operator.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

# Alembic is a dev-only dependency. Environments that install only the
# runtime requirements (``pip install .`` without ``[dev]``) cannot import
# the baseline module because it does ``from alembic import op``. Skip the
# whole file rather than hard-fail in that posture.
pytest.importorskip("alembic")

_REPO = Path(__file__).resolve().parents[1]
_BASELINE = _REPO / "alembic" / "versions" / "0001_baseline.py"
_WRAPPER_REVISIONS = [
    (
        _REPO / "alembic" / "versions" / "0003_audit_log_grant_tightening.py",
        "0003_audit_log_grant_tightening",
        "0002_gdpr_erasure",
        "007_audit_log_grant_tightening.sql",
    ),
    (
        _REPO / "alembic" / "versions" / "0004_supabase_compat.py",
        "0004_supabase_compat",
        "0003_audit_log_grant_tightening",
        "008_supabase_compat.sql",
    ),
    (
        _REPO / "alembic" / "versions" / "0005_ci_guard_invariants.py",
        "0005_ci_guard_invariants",
        "0004_supabase_compat",
        "009_ci_guard_security_invariants.sql",
    ),
    (
        _REPO / "alembic" / "versions" / "0008_gdpr_erasure_guard.py",
        "0008_gdpr_erasure_guard",
        "0007_agent_key_rotation",
        "012_gdpr_erasure_guard.sql",
    ),
    (
        _REPO / "alembic" / "versions" / "0009_webhook_security.py",
        "0009_webhook_security",
        "0008_gdpr_erasure_guard",
        "013_webhook_security.sql",
    ),
    (
        _REPO / "alembic" / "versions" / "0010_agent_production_approval.py",
        "0010_agent_prod_approval",
        "0009_webhook_security",
        "014_agent_production_approval.sql",
    ),
    (
        _REPO / "alembic" / "versions" / "0011_durable_security_state.py",
        "0011_durable_security_state",
        "0010_agent_prod_approval",
        "015_durable_security_state.sql",
    ),
    (
        _REPO / "alembic" / "versions" / "0012_gdpr_erasure_idempotency.py",
        "0012_erasure_idempotency",
        "0011_durable_security_state",
        "016_gdpr_erasure_idempotency.sql",
    ),
]


def _load_baseline():
    spec = importlib.util.spec_from_file_location("alembic_0001_baseline", _BASELINE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_revision(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_baseline_file_exists() -> None:
    assert _BASELINE.is_file(), "Alembic baseline revision is missing"


def test_baseline_revision_metadata() -> None:
    module = _load_baseline()
    assert module.revision == "0001_baseline"
    assert module.down_revision is None
    assert callable(module.upgrade)
    assert callable(module.downgrade)


def test_baseline_sql_sources_exist() -> None:
    """If an operator renames a SQL file, we want the failure loud & local."""
    module = _load_baseline()
    for sql_path in module._SQL_FILES:
        assert sql_path.is_file(), f"baseline references missing SQL: {sql_path}"


def test_raw_sql_wrapper_revisions_are_wired() -> None:
    for path, revision, down_revision, sql_name in _WRAPPER_REVISIONS:
        module = _load_revision(path)
        assert module.revision == revision
        assert module.down_revision == down_revision
        assert module._SQL_FILE.name == sql_name
        assert module._SQL_FILE.is_file()


def test_revision_ids_fit_alembic_version_column() -> None:
    """Alembic stores revision ids in alembic_version.version_num VARCHAR(32).

    A longer slug overflows that column and breaks ``alembic upgrade head``
    against a real Postgres (CI never catches it without a live DB).
    """
    versions_dir = _REPO / "alembic" / "versions"
    for path in versions_dir.glob("0*.py"):
        module = _load_revision(path)
        assert len(module.revision) <= 32, (
            f"{path.name}: revision id '{module.revision}' is {len(module.revision)} chars (max 32)"
        )


def test_downgrade_refuses_to_drop_forensic_data() -> None:
    """Guard against accidental ``alembic downgrade base``.

    The baseline creates audit_logs and merkle_proofs. Auto-downgrading
    would destroy forensic evidence, so we require downgrade() to raise.
    """
    module = _load_baseline()
    with pytest.raises(NotImplementedError):
        module.downgrade()


def test_alembic_ini_points_at_alembic_dir() -> None:
    ini = (_REPO / "alembic.ini").read_text(encoding="utf-8")
    assert "script_location = alembic" in ini
    # DSN must stay blank — env.py pulls it from DATABASE_URL.
    assert "sqlalchemy.url =" in ini
    assert "sqlalchemy.url = postgres" not in ini


def test_env_py_resolves_asyncpg_dsn_as_psycopg2() -> None:
    """Operators reuse DATABASE_URL; asyncpg form must be translated for sync Alembic."""
    env_src = (_REPO / "alembic" / "env.py").read_text(encoding="utf-8")
    # The translation logic must be present; if someone removes it, Alembic
    # will silently try to load the asyncpg driver synchronously and fail.
    assert "postgresql+psycopg2://" in env_src
