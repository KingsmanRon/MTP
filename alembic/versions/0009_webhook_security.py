"""Tenant webhook secrets and durable delivery state.

Revision ID: 0009_webhook_security
Revises: 0008_gdpr_erasure_guard
Create Date: 2026-07-11
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0009_webhook_security"
down_revision: str | None = "0008_gdpr_erasure_guard"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "013_webhook_security.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Webhook delivery history and tenant secret state are operational evidence. "
        "Write a forward migration instead of deleting them."
    )
