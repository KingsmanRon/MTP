"""agent signing-key rotation + history.

Revision ID: 0007_agent_key_rotation
Revises: 0006_agent_policies
Create Date: 2026-06-20

NOTE: the revision id is kept <= 32 chars because Alembic stores it in
alembic_version.version_num VARCHAR(32). A longer slug overflows that
column and breaks ``alembic upgrade head`` on a real Postgres.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0007_agent_key_rotation"
down_revision: Union[str, None] = "0006_agent_policies"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database" / "migrations" / "011_agent_key_rotation.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS agent_key_history")
    op.execute("ALTER TABLE agents DROP COLUMN IF EXISTS key_rotated_at")
    op.execute("ALTER TABLE agents DROP COLUMN IF EXISTS key_version")
