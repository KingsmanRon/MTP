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
        # Keyed on the grant's own org_id rather than a join. The composite
        # foreign key guarantees that column equals the agent's owner, so this
        # is the same predicate with no subquery to influence.
        assert sql.count("org_id = app.current_tenant()") == 2, "USING and WITH CHECK"

    def test_public_holds_no_privileges(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "REVOKE ALL ON TABLE execution_authority_grants FROM PUBLIC" in sql


class TestCompositeOwnership:
    def test_the_grant_carries_its_organisation(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "org_id UUID NOT NULL REFERENCES organizations(id)" in sql

    def test_ownership_is_enforced_by_a_composite_foreign_key(self) -> None:
        """A grant cannot name an organisation that does not own the agent."""
        sql = _SQL.read_text(encoding="utf-8")
        assert "FOREIGN KEY (agent_id, org_id)" in sql
        assert "REFERENCES agents(id, org_id)" in sql

    def test_the_referencable_unique_key_is_created_first(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "ADD CONSTRAINT agents_id_org_unique UNIQUE (id, org_id)" in sql
        assert sql.index("agents_id_org_unique") < sql.index("FOREIGN KEY (agent_id, org_id)")

    def test_the_tenant_policy_keys_on_the_grants_own_column(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "USING (org_id = app.current_tenant())" in sql
        assert "WITH CHECK (org_id = app.current_tenant())" in sql

    def test_the_owning_organisation_is_immutable(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "NEW.org_id <> OLD.org_id" in sql


class TestGrantLifetimeBound:
    def test_a_grant_cannot_outlive_its_delegated_authority(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "CONSTRAINT execution_authority_within_delegated_validity" in sql
        assert "expires_at <= authority_expires_at" in sql

    def test_the_validity_window_is_immutable_after_issuance(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "NEW.expires_at <> OLD.expires_at" in sql
        assert (
            "NEW.authority_expires_at IS DISTINCT FROM OLD.authority_expires_at" in sql
        )


class TestOutcomeStateMachine:
    def test_the_outcome_states_are_the_documented_four(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert (
            "outcome_state IN ('pending', 'succeeded', 'failed_final', 'outcome_unknown')"
            in sql
        )

    def test_an_outcome_only_exists_for_spent_authority(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "CONSTRAINT execution_authority_outcome_requires_consumption" in sql

    def test_an_unknown_outcome_may_only_be_resolved_forward(self) -> None:
        """A timeout is never quietly cleared back to pending."""
        sql = _SQL.read_text(encoding="utf-8")
        assert "OLD.outcome_state = 'outcome_unknown'" in sql
        assert "NEW.outcome_state IN ('succeeded', 'failed_final')" in sql
        assert "outcome % cannot transition to %" in sql


class TestSecurityConventions:
    def test_browser_roles_are_conditionally_revoked(self) -> None:
        """Portable across Supabase and plain PostgreSQL, as 020 established."""
        sql = _SQL.read_text(encoding="utf-8")
        assert "ARRAY['anon', 'authenticated']" in sql
        assert "EXISTS (SELECT 1 FROM pg_roles WHERE rolname = client_role)" in sql

    def test_the_migration_asserts_its_own_posture(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "RLS is not enabled on public.execution_authority_grants" in sql
        assert (
            "direct anon/authenticated privilege remains on "
            "public.execution_authority_grants" in sql
        )
        assert "execution_authority_grants_tenant_scope policy is missing" in sql

    def test_the_trigger_function_pins_its_search_path(self) -> None:
        sql = _SQL.read_text(encoding="utf-8")
        assert "SET search_path = pg_catalog, public;" in sql
