"""Make authority decision evidence identities unable to contradict.

Revision ID: 0021_authority_evidence_int
Revises: 0020_authority_evidence
Create Date: 2026-09-10
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

# Kept within alembic_version.version_num, which is VARCHAR(32).
revision: str = "0021_authority_evidence_int"
down_revision: str | None = "0020_authority_evidence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "025_authority_evidence_integrity.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "These constraints are what stop forensic authority evidence from "
        "contradicting itself. Dropping them would silently re-admit rows "
        "whose identities disagree. Write a reviewed forward migration."
    )
