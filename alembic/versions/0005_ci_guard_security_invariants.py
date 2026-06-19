"""ci guard security invariants.

Revision ID: 0005_ci_guard_security_invariants
Revises: 0004_supabase_compat
Create Date: 2026-06-16
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0005_ci_guard_security_invariants"
down_revision: Union[str, None] = "0004_supabase_compat"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database" / "migrations" / "009_ci_guard_security_invariants.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError("Write a targeted trigger rollback revision instead.")
