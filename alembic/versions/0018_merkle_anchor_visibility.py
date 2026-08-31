"""Restore tenant-safe Merkle anchor visibility for admin audit routes.

Revision ID: 0018_merkle_anchor_visibility
Revises: 0017_tenant_login_isolation
Create Date: 2026-08-31
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0018_merkle_anchor_visibility"
down_revision: str | None = "0017_tenant_login_isolation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "022_merkle_proof_tenant_visibility.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Merkle proof tenant visibility is a forward-only security boundary. "
        "Write a reviewed forward migration instead."
    )
