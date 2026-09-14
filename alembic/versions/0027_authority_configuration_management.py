"""A trusted identity for authority-configuration changes, and a platform audit scope.

Revision ID: 0027_authority_config_mgmt
Revises: 0026_authority_config_glob
Create Date: 2026-09-14
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

# Kept within alembic_version.version_num, which is VARCHAR(32).
revision: str = "0027_authority_config_mgmt"
down_revision: str | None = "0026_authority_config_glob"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "031_authority_configuration_management.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Dropping the management role would leave no identity able to change "
        "authority configuration together with its audit record, and the only "
        "way to restore one would be to give the write back to the runtime "
        "role. Write a reviewed forward migration instead."
    )
