"""The global configuration lock ranks above the per-organisation one.

Revision ID: 0026_authority_config_glob
Revises: 0025_authority_config_lin
Create Date: 2026-09-13
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

# Kept within alembic_version.version_num, which is VARCHAR(32).
revision: str = "0026_authority_config_glob"
down_revision: str | None = "0025_authority_config_lin"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "030_authority_configuration_global_hierarchy.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Reverting to the 029 trigger would let a platform-wide issuance "
        "halt commit underneath an issuance already in flight, so a grant "
        "could be issued under a halt that was already in force. Write a "
        "reviewed forward migration instead."
    )
