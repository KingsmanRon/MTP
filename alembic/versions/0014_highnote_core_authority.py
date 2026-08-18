"""Add durable verify idempotency and expiring spend reservations.

Revision ID: 0014_highnote_core_authority
Revises: 0013_token_execution_idempotency
Create Date: 2026-08-17
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0014_highnote_core_authority"
down_revision: str | None = "0013_token_execution_idempotency"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "018_highnote_core_authority.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Verification idempotency and spend reservation evidence must be preserved. "
        "Write a forward migration instead."
    )
