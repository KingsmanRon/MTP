"""Add the isolated tenant login database identity.

Revision ID: 0017_tenant_login_isolation
Revises: 0016_rls_hardening
Create Date: 2026-08-31
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0017_tenant_login_isolation"
down_revision: str | None = "0016_rls_hardening"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROOT = Path(__file__).resolve().parents[2]
_SQL_FILE = _ROOT / "database" / "migrations" / "021_tenant_login_isolation.sql"
_ASSERTIONS_FILE = _ROOT / "database" / "migrations" / "021_tenant_login_assertions.sql"


def _execute_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"migration source missing: {path}")
    op.execute(path.read_text(encoding="utf-8"))


def upgrade() -> None:
    _execute_file(_SQL_FILE)
    _execute_file(_ASSERTIONS_FILE)


def downgrade() -> None:
    raise NotImplementedError(
        "Tenant login isolation is a forward-only security boundary. "
        "Write a reviewed forward migration instead."
    )
