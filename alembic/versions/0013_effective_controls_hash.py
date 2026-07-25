"""Rename audit_logs.policy_hash to effective_controls_hash.

The column holds a hash of the agent's effective controls at decision time,
never a policy document hash. Disambiguating it from the registered
.inntris.yml hash on agent_policies.policy_hash.

Revision ID: 0013_effective_controls_hash
Revises: 0012_erasure_idempotency
Create Date: 2026-07-25
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0013_effective_controls_hash"
down_revision: str | None = "0012_erasure_idempotency"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "017_effective_controls_hash.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(f"migration source missing: {_SQL_FILE}")
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    # Reversible in principle, but every receipt fingerprint issued after this
    # revision commits to the new key name. Rolling the column back would
    # silently invalidate them. Write a forward migration instead.
    raise NotImplementedError(
        "Receipt fingerprints issued under schema v3 commit to "
        "effective_controls_hash. Write a forward migration instead."
    )
