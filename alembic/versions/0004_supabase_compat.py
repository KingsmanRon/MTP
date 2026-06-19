"""supabase role compatibility.

Revision ID: 0004_supabase_compat
Revises: 0003_audit_log_grant_tightening
Create Date: 2026-06-16
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0004_supabase_compat"
down_revision: Union[str, None] = "0003_audit_log_grant_tightening"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database" / "migrations" / "008_supabase_compat.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError("Write a targeted role attribute rollback revision instead.")
