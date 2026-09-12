"""Authority configuration changes serialise against fresh consumption.

Revision ID: 0025_authority_config_lin
Revises: 0024_authority_config_hard
Create Date: 2026-09-12
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

# Kept within alembic_version.version_num, which is VARCHAR(32).
revision: str = "0025_authority_config_lin"
down_revision: str | None = "0024_authority_config_hard"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "029_authority_configuration_linearisation.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Dropping these triggers would let a configuration change commit "
        "while a fresh consumption is mid-decision, so a spend could commit "
        "under a configuration that is no longer current. Write a reviewed "
        "forward migration instead."
    )
