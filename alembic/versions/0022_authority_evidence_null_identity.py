"""Forensic identity CHECKs must fail closed on missing or null values.

Revision ID: 0022_authority_evidence_nn
Revises: 0021_authority_evidence_int
Create Date: 2026-09-10
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

# Kept within alembic_version.version_num, which is VARCHAR(32).
revision: str = "0022_authority_evidence_nn"
down_revision: str | None = "0021_authority_evidence_int"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "026_authority_evidence_null_identity.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Reverting these constraints would re-admit forensic evidence whose "
        "body cannot say which decision, agent or organisation it describes. "
        "Write a reviewed forward migration instead."
    )
