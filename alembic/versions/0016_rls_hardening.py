"""Harden production row-level security and direct table privileges.

Revision ID: 0016_rls_hardening
Revises: 0015_anchor_submission_state
Create Date: 2026-08-29
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0016_rls_hardening"
down_revision: str | None = "0015_anchor_submission_state"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "020_rls_hardening.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "RLS hardening is a forward-only security boundary. "
        "Write a reviewed forward migration instead."
    )
