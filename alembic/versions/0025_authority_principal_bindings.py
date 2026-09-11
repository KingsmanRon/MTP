"""Server-only binding from a principal to its external issuer identity.

Revision ID: 0025_authority_binding
Revises: 0024_authority_revocation
Create Date: 2026-09-11
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

# Kept within alembic_version.version_num, which is VARCHAR(32).
revision: str = "0025_authority_binding"
down_revision: str | None = "0024_authority_revocation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "029_authority_principal_bindings.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "These rows are what tie a verified external delegation to the "
        "principal it actually belongs to. Dropping them would leave "
        "delegations verifying against no principal at all. Write a reviewed "
        "forward migration instead."
    )
