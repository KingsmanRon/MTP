"""Runtime revocation of issuers, keys and delegations.

Revision ID: 0024_authority_revocation
Revises: 0023_authority_requirement
Create Date: 2026-09-11
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

# Kept within alembic_version.version_num, which is VARCHAR(32).
revision: str = "0024_authority_revocation"
down_revision: str | None = "0023_authority_requirement"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "028_authority_trust_revocations.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Dropping this table would silently re-trust every issuer, key and "
        "delegation an operator has revoked. Write a reviewed forward "
        "migration instead."
    )
