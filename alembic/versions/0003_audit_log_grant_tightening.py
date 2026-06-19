"""audit log grant tightening.

Revision ID: 0003_audit_log_grant_tightening
Revises: 0002_gdpr_erasure
Create Date: 2026-06-16
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0003_audit_log_grant_tightening"
down_revision: Union[str, None] = "0002_gdpr_erasure"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database" / "migrations" / "007_audit_log_grant_tightening.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError("Write a targeted grant rollback revision instead.")
