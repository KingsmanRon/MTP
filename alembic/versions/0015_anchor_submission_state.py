"""Add durable Base submission and reconciliation state.

Revision ID: 0015_anchor_submission_state
Revises: 0014_highnote_core_authority
Create Date: 2026-08-26
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0015_anchor_submission_state"
down_revision: str | None = "0014_highnote_core_authority"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "019_anchor_submission_state.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Submission identity and reconciliation evidence are forensic data. "
        "Write a forward migration instead."
    )
