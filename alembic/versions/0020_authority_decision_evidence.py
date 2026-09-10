"""Erasure-safe authority decision evidence.

Revision ID: 0020_authority_evidence
Revises: 0019_authority_persistence
Create Date: 2026-09-10
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

# Kept within alembic_version.version_num, which is VARCHAR(32).
revision: str = "0020_authority_evidence"
down_revision: str | None = "0019_authority_persistence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "024_authority_decision_evidence.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Authority decision evidence is the forensic record that a decision "
        "was made, and it is what a published v3 receipt refers to. Dropping "
        "it would destroy evidence that erasure deliberately does not remove. "
        "Write a reviewed forward migration instead."
    )
