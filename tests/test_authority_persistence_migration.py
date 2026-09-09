"""Phase 3 — structural checks on the execution-authority migration.

These run without a database. They pin the revision chain, the fail-closed
constraints, the lifecycle guard and the tenant policy as *source*, so a
later edit that quietly loosens one shows up here rather than in
production.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("alembic")

from alembic.config import Config  # noqa: E402
from alembic.script import ScriptDirectory  # noqa: E402

_REPO = Path(__file__).resolve().parents[1]
_REVISION = _REPO / "alembic" / "versions" / "0019_execution_authority_persistence.py"
_SQL = _REPO / "database" / "migrations" / "023_execution_authority_persistence.sql"
_REVISION_ID = "0019_authority_persistence"


def _load_revision():
    spec = importlib.util.spec_from_file_location("alembic_0019_authority", _REVISION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestRevisionChain:
    def test_revision_follows_the_prior_head(self) -> None:
        module = _load_revision()
        assert module.revision == _REVISION_ID
        assert module.down_revision == "0018_merkle_anchor_visibility"
        assert module._SQL_FILE == _SQL

    def test_revision_id_fits_the_alembic_version_column(self) -> None:
        """``alembic_version.version_num`` is VARCHAR(32).

        A longer id applies the DDL and then fails when stamping the
        version, leaving the database migrated but unrecorded.
        """
        assert len(_REVISION_ID) <= 32

    def test_this_revision_is_the_single_head(self) -> None:
        config = Config(str(_REPO / "alembic.ini"))
        config.set_main_option("script_location", str(_REPO / "alembic"))
        assert ScriptDirectory.from_config(config).get_heads() == [_REVISION_ID]

    def test_downgrade_refuses_rather_than_dropping_evidence(self) -> None:
        module = _load_revision()
        with pytest.raises(NotImplementedError):
            module.downgrade()

    def test_the_sql_source_exists(self) -> None:
        assert _SQL.is_file()


class TestReusesExistingMechanisms:
    """The migration must not grow a second authority system beside the first."""

    def test_it_claims_single_use_through_the_existing_token_table(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "approval_token_id TEXT NOT NULL UNIQUE" in sql
        assert "approval_token_consumptions" in sql

    def test_it_holds_capacity_through_the_existing_reservation_table(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "spend_reservation_id UUID REFERENCES spend_reservations(id)" in sql

    def test_it_does_not_define_its_own_consumption_table(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        created = [
            line for line in sql.splitlines() if line.startswith("CREATE TABLE")
        ]
        assert created == ["CREATE TABLE IF NOT EXISTS execution_authority_grants ("]


class TestFailClosedConstraints:
    def test_single_use_is_a_database_constraint(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "CONSTRAINT execution_authority_single_use_only CHECK (single_use)" in sql
        # The word appears once, in the comment explaining its absence. What
        # must not exist is a column.
        assert "max_consumptions " not in sql
        assert "max_consumptions INT" not in sql

    def test_issuance_identity_is_unique_per_agent(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "uq_execution_authority_grants_issuance" in sql
        assert "ON execution_authority_grants(agent_id, issuance_ref)" in sql

    @pytest.mark.parametrize(
        "column",
        [
            "issuance_digest",
            "execution_action_hash",
            "policy_hash",
            "executor_binding_digest",
        ],
    )
    def test_every_digest_column_is_format_checked(self, column: str) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert f"{column} ~ '^[a-f0-9]{{64}}$'" in sql

    def test_the_validity_window_cannot_be_empty(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "CHECK (expires_at > issued_at)" in sql

    def test_a_consumed_grant_must_name_its_receipt(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "AND consumption_audit_id IS NOT NULL" in sql

    def test_the_action_type_is_carried_for_revalidation(self) -> None:
        """Without it, current policy cannot be re-derived at consumption."""
        sql = _SQL.read_text(encoding="utf-8")
        assert "action_type VARCHAR(100) NOT NULL" in sql

    def test_the_delegated_scope_digest_is_carried(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "authority_scope_digest VARCHAR(64)" in sql


class TestLifecycleGuard:
    def test_terminal_states_cannot_transition(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "IF OLD.status <> 'active' AND NEW.status <> OLD.status THEN" in sql
        assert "cannot transition to" in sql

    @pytest.mark.parametrize(
        "column",
        [
            "execution_action_hash",
            "policy_hash",
            "executor_binding_digest",
            "approval_token_id",
            "amount_usd",
            "issuance_digest",
            "action_type",
        ],
    )
    def test_the_act_and_its_binding_are_immutable(self, column: str) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert f"NEW.{column} <> OLD.{column}" in sql

    def test_grants_cannot_be_deleted(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "protect_execution_authority_delete" in sql
        assert "prevent_security_state_modification" in sql


class TestTenantIsolation:
    def test_row_level_security_is_enabled(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "ALTER TABLE execution_authority_grants ENABLE ROW LEVEL SECURITY" in sql

    def test_the_policy_scopes_to_the_current_tenant_both_ways(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "CREATE POLICY execution_authority_grants_tenant_scope" in sql
        assert sql.count("a.org_id = app.current_tenant()") == 2, "USING and WITH CHECK"

    def test_public_holds_no_privileges(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "REVOKE ALL ON TABLE execution_authority_grants FROM PUBLIC" in sql
