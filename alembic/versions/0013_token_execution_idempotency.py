"""Bind approval token consumption to a stable execution reference.

Revision ID: 0013_token_execution_idempotency
Revises: 0012_erasure_idempotency
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0013_token_execution_idempotency"
down_revision: str | None = "0012_erasure_idempotency"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "017_token_execution_idempotency.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Token consumption evidence must be preserved. Write a forward migration instead."
    )
