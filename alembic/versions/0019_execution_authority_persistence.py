"""Persist execution authority grants and their issuance identity.

Revision ID: 0019_authority_persistence
Revises: 0018_merkle_anchor_visibility
Create Date: 2026-09-09
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

# Kept within alembic_version.version_num, which is VARCHAR(32).
revision: str = "0019_authority_persistence"
down_revision: str | None = "0018_merkle_anchor_visibility"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "023_execution_authority_persistence.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Execution authority grants record what was authorised and whether it "
        "was spent. Dropping them would destroy the evidence that gated real "
        "executions. Write a reviewed forward migration instead."
    )
