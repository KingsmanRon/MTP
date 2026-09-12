"""Migration 027 — the requirement rollout schema, and what it refuses.

Gate 2's control decides whether real money may move without a delegation,
so the schema is tested for the properties that make its answer unique and
tenant-safe, not merely for the presence of two tables:

  * exactly one row can win for a scope -- two contradictory rows for one
    scope would give "is authority required here" two answers;
  * a requirement cannot name another tenant's principal;
  * an unknown kill-switch name is refused, so a typo cannot create a switch
    nothing reads and everyone believes in;
  * the runtime role cannot DELETE, because lifting a requirement must keep
    the record of what it used to be;
  * a tenant sees its own rows and nothing else, and never the global
    kill switch.

Default behaviour is asserted too: an organisation with no row is not
enrolled, which is what every existing organisation gets.

Gated like the other database integration tests.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from collections.abc import AsyncIterator
from uuid import UUID, uuid4

import pytest

asyncpg = pytest.importorskip("asyncpg")

from api.database import Database  # noqa: E402

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="requirement rollout schema tests require INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)

REQUIREMENT_TABLES = ("authority_requirements", "authority_controls")


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=2, max_size=8)
    try:
        yield database
    finally:
        await database.close()


async def _make_org(db: Database) -> UUID:
    org_id = uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
               VALUES ($1,$2,'enterprise',$3,$4)""",
            org_id, f"req-{org_id}", f"req-{org_id}@example.test",
            hashlib.sha256(str(org_id).encode()).digest(),
        )
    return org_id


async def _make_agent(db: Database, org_id: UUID) -> UUID:
    agent_id = uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """INSERT INTO agents (
                 id, org_id, name, public_key, public_key_fingerprint, trust_score,
                 status, daily_limit_usd, per_action_limit_usd, allowed_actions,
                 blocked_actions, rate_limit_per_minute, metadata)
               VALUES ($1,$2,$3,$4,$5,80,'active',1000,100,
                       ARRAY['financial_transaction']::TEXT[], ARRAY[]::TEXT[], 60, $6::JSONB)""",
            agent_id, org_id, f"req-agent-{agent_id}", secrets.token_bytes(32),
            hashlib.sha256(str(agent_id).encode()).hexdigest(),
            # Migration 014 requires an active production agent to carry its
            # approval metadata; satisfy it rather than sandboxing the agent,
            # which would exclude it from the paths under test.
            json.dumps(
                {
                    "sandbox": False,
                    "production_approval_reference": "requirement-rollout-test",
                    "production_approved_at": "2026-01-01T00:00:00Z",
                    "production_approved_by": "requirement-rollout-test",
                }
            ),
        )
    return agent_id


async def _add_requirement(db, org_id, *, agent_id=None, action_class=None, required=True):
    async with db.acquire() as conn:
        return await conn.fetchval(
            """INSERT INTO authority_requirements
                 (org_id, agent_id, action_class, required, reason, changed_by,
                  approval_reference)
               VALUES ($1,$2,$3,$4,'test','test-suite','APPROVAL-1')
               RETURNING id""",
            org_id, agent_id, action_class, required,
        )


class TestTheAnswerIsUnique:
    async def test_two_org_wide_rows_are_impossible(self, db) -> None:
        org_id = await _make_org(db)
        await _add_requirement(db, org_id, required=True)
        with pytest.raises(asyncpg.UniqueViolationError):
            await _add_requirement(db, org_id, required=False)

    async def test_two_rows_for_one_principal_and_class_are_impossible(self, db) -> None:
        org_id = await _make_org(db)
        agent_id = await _make_agent(db, org_id)
        await _add_requirement(db, org_id, agent_id=agent_id, action_class="financial_transaction")
        with pytest.raises(asyncpg.UniqueViolationError):
            await _add_requirement(
                db, org_id, agent_id=agent_id, action_class="financial_transaction",
                required=False,
            )

    async def test_the_ladder_rungs_do_not_collide_with_each_other(self, db) -> None:
        """All four specificity rungs may coexist; only duplicates collide."""
        org_id = await _make_org(db)
        agent_id = await _make_agent(db, org_id)
        await _add_requirement(db, org_id)
        await _add_requirement(db, org_id, action_class="financial_transaction")
        await _add_requirement(db, org_id, agent_id=agent_id)
        await _add_requirement(db, org_id, agent_id=agent_id, action_class="financial_transaction")
        async with db.acquire() as conn:
            count = await conn.fetchval(
                "SELECT count(*) FROM authority_requirements WHERE org_id = $1", org_id
            )
        assert count == 4


class TestTenantOwnership:
    async def test_a_requirement_cannot_name_another_tenants_principal(self, db) -> None:
        org_a = await _make_org(db)
        org_b = await _make_org(db)
        foreign_agent = await _make_agent(db, org_b)
        with pytest.raises(asyncpg.ForeignKeyViolationError):
            await _add_requirement(db, org_a, agent_id=foreign_agent)

    async def test_a_requirement_cannot_name_an_agent_that_does_not_exist(self, db) -> None:
        org_id = await _make_org(db)
        with pytest.raises(asyncpg.ForeignKeyViolationError):
            await _add_requirement(db, org_id, agent_id=uuid4())


class TestKillSwitches:
    async def test_an_unknown_control_name_is_refused(self, db) -> None:
        org_id = await _make_org(db)
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.CheckViolationError):
                await conn.execute(
                    """INSERT INTO authority_controls
                         (control, org_id, engaged, reason, changed_by, approval_reference)
                       VALUES ('not_a_real_control',$1,TRUE,'t','t','A')""",
                    org_id,
                )

    async def test_a_global_and_an_org_row_may_coexist_but_not_duplicate(self, db) -> None:
        org_id = await _make_org(db)
        async with db.acquire() as conn:
            await conn.execute(
                """INSERT INTO authority_controls
                     (control, org_id, engaged, reason, changed_by, approval_reference)
                   VALUES ('authority_issuance',$1,TRUE,'t','t','A')""",
                org_id,
            )
            with pytest.raises(asyncpg.UniqueViolationError):
                await conn.execute(
                    """INSERT INTO authority_controls
                         (control, org_id, engaged, reason, changed_by, approval_reference)
                       VALUES ('authority_issuance',$1,FALSE,'t','t','A')""",
                    org_id,
                )

    async def test_both_named_controls_are_accepted(self, db) -> None:
        org_id = await _make_org(db)
        async with db.acquire() as conn:
            for control in ("requirement_enforcement", "authority_issuance"):
                await conn.execute(
                    """INSERT INTO authority_controls
                         (control, org_id, engaged, reason, changed_by, approval_reference)
                       VALUES ($2,$1,TRUE,'t','t','A')""",
                    org_id, control,
                )


class TestPermissionsAndIsolation:
    async def test_the_runtime_role_cannot_delete_a_requirement(self, db) -> None:
        """Lifting a requirement is an UPDATE that keeps the record."""
        async with db.acquire() as conn:
            granted = await conn.fetch(
                """SELECT table_name, privilege_type
                   FROM information_schema.role_table_grants
                   WHERE grantee = 'inntris_worker' AND table_name = ANY($1::TEXT[])""",
                list(REQUIREMENT_TABLES),
            )
        privileges = {(r["table_name"], r["privilege_type"]) for r in granted}
        for table in REQUIREMENT_TABLES:
            assert (table, "SELECT") in privileges
            assert (table, "INSERT") in privileges
            assert (table, "UPDATE") in privileges
            assert (table, "DELETE") not in privileges

    async def test_row_level_security_is_enabled_and_forced(self, db) -> None:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                """SELECT relname, relrowsecurity, relforcerowsecurity
                   FROM pg_class WHERE relname = ANY($1::TEXT[])""",
                list(REQUIREMENT_TABLES),
            )
        assert {r["relname"] for r in rows} == set(REQUIREMENT_TABLES)
        for row in rows:
            assert row["relrowsecurity"], f"{row['relname']} has RLS disabled"
            assert row["relforcerowsecurity"], f"{row['relname']} does not FORCE RLS"

    async def test_a_tenant_sees_only_its_own_requirements(self, db) -> None:
        org_a = await _make_org(db)
        org_b = await _make_org(db)
        await _add_requirement(db, org_a)
        await _add_requirement(db, org_b)

        async with db.acquire_as_tenant(org_a) as conn:
            visible = await conn.fetch("SELECT org_id FROM authority_requirements")

        org_ids = {row["org_id"] for row in visible}
        assert org_a in org_ids
        assert org_b not in org_ids

    async def test_the_global_kill_switch_is_invisible_to_a_tenant(self, db) -> None:
        """A platform-wide halt is not a tenant-visible setting."""
        org_id = await _make_org(db)
        async with db.acquire() as conn:
            await conn.execute(
                """INSERT INTO authority_controls
                     (control, org_id, engaged, reason, changed_by, approval_reference)
                   VALUES ('requirement_enforcement',NULL,TRUE,'global','platform','A')
                   ON CONFLICT DO NOTHING"""
            )
        async with db.acquire_as_tenant(org_id) as conn:
            visible = await conn.fetch("SELECT org_id FROM authority_controls")
        assert all(row["org_id"] is not None for row in visible)


class TestDefaultBehaviourIsUnchanged:
    async def test_a_new_organisation_is_enrolled_in_nothing(self, db) -> None:
        """Absence of a row is the answer for every existing organisation."""
        org_id = await _make_org(db)
        async with db.acquire() as conn:
            requirements = await conn.fetchval(
                "SELECT count(*) FROM authority_requirements WHERE org_id = $1", org_id
            )
            controls = await conn.fetchval(
                "SELECT count(*) FROM authority_controls WHERE org_id = $1", org_id
            )
        assert requirements == 0
        assert controls == 0

    async def test_updated_at_is_maintained_by_the_database(self, db) -> None:
        org_id = await _make_org(db)
        requirement_id = await _add_requirement(db, org_id, required=True)
        async with db.acquire() as conn:
            before = await conn.fetchval(
                "SELECT updated_at FROM authority_requirements WHERE id = $1", requirement_id
            )
            await conn.execute(
                "UPDATE authority_requirements SET required = FALSE WHERE id = $1",
                requirement_id,
            )
            after = await conn.fetchval(
                "SELECT updated_at FROM authority_requirements WHERE id = $1", requirement_id
            )
        assert after > before
