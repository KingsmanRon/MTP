"""Make guarded erasure retries idempotent.

Revision ID: 0012_erasure_idempotency
Revises: 0011_durable_security_state
Create Date: 2026-07-16
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0012_erasure_idempotency"
down_revision: str | None = "0011_durable_security_state"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "016_gdpr_erasure_idempotency.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Erasure ledger integrity must be preserved. Write a forward migration instead."
    )
