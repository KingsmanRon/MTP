"""Server-controlled delegated-authority requirement and kill switches.

Revision ID: 0023_authority_requirement
Revises: 0022_authority_evidence_nn
Create Date: 2026-09-11
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

# Kept within alembic_version.version_num, which is VARCHAR(32).
revision: str = "0023_authority_requirement"
down_revision: str | None = "0022_authority_evidence_nn"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "027_authority_requirement_rollout.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "authority_requirements records which organisations deliberately "
        "required delegated authority, and authority_controls records when a "
        "kill switch was pulled and by whom. Dropping either would destroy "
        "the evidence for decisions that gated real executions. Write a "
        "reviewed forward migration instead."
    )
