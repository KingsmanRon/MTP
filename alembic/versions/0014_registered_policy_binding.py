"""Record the registered policy version and hash on each audit row.

A receipt could prove an action was allowed, but not which registered policy
version allowed it. Written at decision time rather than joined at read time,
so historical receipts are not re-labelled by later policy changes.

Revision ID: 0014_registered_policy_binding
Revises: 0013_effective_controls_hash
Create Date: 2026-07-25
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0014_registered_policy_binding"
down_revision: str | None = "0013_effective_controls_hash"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "018_registered_policy_binding.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    # Dropping these columns discards the only record of which policy version
    # each decision was evaluated under. That evidence cannot be reconstructed
    # afterwards. Write a forward migration instead.
    raise NotImplementedError(
        "Registered policy binding is forensic evidence and is not reversible. "
        "Write a forward migration instead."
    )
