"""authorised GDPR erasure guard.

Revision ID: 0008_gdpr_erasure_guard
Revises: 0007_agent_key_rotation
Create Date: 2026-07-11

This is a forward repair for migration 006. Applied migrations remain
unchanged so existing databases and clean replays converge on the same
guarded erasure function and audit trigger.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0008_gdpr_erasure_guard"
down_revision: str | None = "0007_agent_key_rotation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2] / "database" / "migrations" / "012_gdpr_erasure_guard.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "The previous erasure function is unsafe on the current schema. "
        "Write a new forward repair instead of restoring it."
    )
