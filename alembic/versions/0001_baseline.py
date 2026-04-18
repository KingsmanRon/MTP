"""baseline — import schemas.sql + migrations 002-005 (Phase 1D.1).

Revision ID: 0001_baseline
Revises:
Create Date: 2026-04-18

This is the anchor point for Alembic-managed migrations. It replays the
same DDL that ``database/schemas.sql`` + ``database/migrations/002-005``
already apply, so a fresh database ends up in the same state whether the
operator runs the legacy ``psql -f`` path or ``alembic upgrade head``.

Idempotency:
  * schemas.sql uses ``CREATE ... IF NOT EXISTS`` / ``CREATE OR REPLACE``
    throughout, so re-applying it against an existing deployment is safe.
  * Migrations 002-005 use ``CREATE OR REPLACE`` / ``DROP POLICY IF EXISTS``
    guards for the same reason.

So for operators who already applied the raw-SQL files, running
``alembic stamp 0001_baseline`` records the revision without re-running
the DDL. Greenfield deployments run ``alembic upgrade head`` and get the
full schema in one step.

The downgrade is intentionally unimplemented. Schema destruction is not a
routine operation and requires operator-driven data migration; we refuse
to auto-drop tables that may contain forensic audit data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# The raw-SQL files are checked in next to the Alembic tree. Resolving
# relative to __file__ keeps this robust against the working directory the
# operator happened to run ``alembic`` from.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SQL_FILES = [
    _REPO_ROOT / "database" / "schemas.sql",
    _REPO_ROOT / "database" / "migrations" / "002_fix_audit_trigger_nonce.sql",
    _REPO_ROOT / "database" / "migrations" / "003_add_policy_hash.sql",
    _REPO_ROOT / "database" / "migrations" / "004_merkle_proof_dead_letter.sql",
    _REPO_ROOT / "database" / "migrations" / "005_rls_policies.sql",
]


def upgrade() -> None:
    for sql_path in _SQL_FILES:
        if not sql_path.is_file():
            raise FileNotFoundError(
                f"baseline migration source missing: {sql_path}. "
                "The baseline revision pins specific files under database/; "
                "do not move or rename them without also updating this migration."
            )
        op.execute(sql_path.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Downgrading the baseline would drop audit_logs and merkle_proofs, which "
        "contain forensic evidence. Write a targeted Alembic revision instead."
    )
