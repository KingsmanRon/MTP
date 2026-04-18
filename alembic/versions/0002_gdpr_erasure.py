"""gdpr erasure — forensic-integrity-preserving redaction (Phase 4B).

Revision ID: 0002_gdpr_erasure
Revises: 0001_baseline
Create Date: 2026-04-18

Adds ``erasure_requests`` ledger and ``app.erase_personal_data(...)``
function. See ``database/migrations/006_gdpr_erasure.sql`` for the
rationale — this revision is a thin wrapper that re-runs that SQL via
Alembic so greenfield deployments pick it up automatically.

Downgrade is unimplemented for the same reason as 0001: dropping the
erasure ledger would lose the record of past redactions, which is
itself evidence of compliant behavior.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0002_gdpr_erasure"
down_revision: Union[str, None] = "0001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_SQL_FILE = (
    Path(__file__).resolve().parents[2]
    / "database" / "migrations" / "006_gdpr_erasure.sql"
)


def upgrade() -> None:
    if not _SQL_FILE.is_file():
        raise FileNotFoundError(
            f"migration source missing: {_SQL_FILE}. "
            "0002_gdpr_erasure pins database/migrations/006_gdpr_erasure.sql; "
            "do not move or rename it without also updating this revision."
        )
    op.execute(_SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    raise NotImplementedError(
        "Dropping erasure_requests would lose the record of past erasures, "
        "which is the evidence we relied on the Art. 17(3)(e) carve-out. "
        "Write a targeted Alembic revision instead."
    )
