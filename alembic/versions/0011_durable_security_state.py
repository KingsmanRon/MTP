"""Durable token, admin, and audit chain security state.

Revision ID: 0011_durable_security_state
Revises: 0010_agent_prod_approval
Create Date: 2026-07-13
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0011_durable_security_state"
down_revision: str | None = "0010_agent_prod_approval"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "015_durable_security_state.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Token consumption and administrative audit state are forensic evidence. "
        "Write a forward migration instead of deleting them."
    )
