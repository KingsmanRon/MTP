"""The effective authority configuration: one snapshot, database only.

Three questions decide an operation -- is issuance halted, which
requirement wins, is enforcement suspended -- and they are answered by one
statement against one snapshot. These tests pin that, and pin the things
that must never happen: an environment variable contributing to a
decision, a configuration failure resolving to "not required", a second
read inside one decision, or the two HTTP surfaces disagreeing.
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

from api.core.authority.decision import DecisionReason  # noqa: E402
from api.database import Database  # noqa: E402
from api.persistence.authority_configuration import (  # noqa: E402
    AuthorityConfigurationUnavailable,
    resolve_authority_configuration,
)
from api.services import authority_service as authority_service_module  # noqa: E402
from api.services.authority_service import (  # noqa: E402
    AUTHORITY_REQUIRED_ORGS_ENV,
    LegacyAuthorityEnrolmentError,
    assert_legacy_authority_enrolment_decommissioned,
    legacy_authority_gate,
)

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")
MIGRATOR_URL = os.getenv("ALEMBIC_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="runtime configuration tests require INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)

ACTION = "financial_transaction"


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=2, max_size=8)
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
async def seed() -> AsyncIterator[asyncpg.Connection]:
    if not MIGRATOR_URL:
        pytest.skip("seeding authority configuration requires ALEMBIC_DATABASE_URL")
    conn = await asyncpg.connect(MIGRATOR_URL)
    try:
        yield conn
    finally:
        # Never leave a GLOBAL control behind: it halts every other test.
        await conn.execute("DELETE FROM authority_controls WHERE org_id IS NULL")
        await conn.close()


@pytest.fixture
async def principal(db: Database) -> tuple[UUID, UUID]:
    org_id, agent_id = uuid4(), uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """INSERT INTO organizations (id,name,billing_tier,contact_email,api_key_hash)
               VALUES ($1,$2,'enterprise',$3,$4)""",
            org_id, f"cfg-{org_id}", f"cfg-{org_id}@example.test",
            hashlib.sha256(str(org_id).encode()).digest(),
        )
        await conn.execute(
            """INSERT INTO agents (id,org_id,name,public_key,public_key_fingerprint,
                 trust_score,status,daily_limit_usd,per_action_limit_usd,allowed_actions,
                 blocked_actions,rate_limit_per_minute,metadata)
               VALUES ($1,$2,$3,$4,$5,80,'active',1000,100,
                       ARRAY['financial_transaction']::TEXT[],ARRAY[]::TEXT[],60,$6::JSONB)""",
            agent_id, org_id, f"cfg-agent-{agent_id}", secrets.token_bytes(32),
            hashlib.sha256(str(agent_id).encode()).hexdigest(),
            json.dumps({"sandbox": False,
                        "production_approval_reference": "cfg-test",
                        "production_approved_at": "2026-01-01T00:00:00Z",
                        "production_approved_by": "cfg-test"}),
        )
    return org_id, agent_id


async def _require(seed, org_id, *, agent_id=None, action_class=None, required=True):
    await seed.execute(
        """INSERT INTO authority_requirements
             (org_id,agent_id,action_class,required,reason,changed_by,approval_reference)
           VALUES ($1,$2,$3,$4,'t','test-suite','A')""",
        org_id, agent_id, action_class, required,
    )


async def _control(seed, control, *, org_id=None, engaged=True):
    await seed.execute(
        """INSERT INTO authority_controls
             (control,org_id,engaged,reason,changed_by,approval_reference)
           VALUES ($1,$2,$3,'t','test-suite','A')""",
        control, org_id, engaged,
    )


async def _resolve(db, principal):
    org_id, agent_id = principal
    return await resolve_authority_configuration(
        db, organisation_id=org_id, principal_id=agent_id, action_class=ACTION
    )


class TestSpecificityLadder:
    async def test_no_row_means_not_required(self, db, principal) -> None:
        config = await _resolve(db, principal)
        assert config.configured_required is False
        assert config.effective_required is False
        assert config.requirement_scope is None

    async def test_a_more_specific_row_can_tighten(self, db, seed, principal) -> None:
        org_id, agent_id = principal
        await _require(seed, org_id, required=False)
        await _require(seed, org_id, agent_id=agent_id, required=True)
        config = await _resolve(db, principal)
        assert config.effective_required is True
        assert config.requirement_scope == "agent"

    async def test_a_more_specific_row_can_also_loosen(self, db, seed, principal) -> None:
        """Both directions -- an org-wide requirement lifted for one principal."""
        org_id, agent_id = principal
        await _require(seed, org_id, required=True)
        await _require(seed, org_id, agent_id=agent_id, required=False)
        config = await _resolve(db, principal)
        assert config.effective_required is False
        assert config.requirement_scope == "agent"

    async def test_agent_and_class_outranks_agent_alone(self, db, seed, principal) -> None:
        org_id, agent_id = principal
        await _require(seed, org_id, agent_id=agent_id, required=False)
        await _require(seed, org_id, agent_id=agent_id, action_class=ACTION, required=True)
        config = await _resolve(db, principal)
        assert config.effective_required is True
        assert config.requirement_scope == "agent+class"

    async def test_a_class_row_outranks_the_organisation_row(self, db, seed, principal) -> None:
        org_id, _agent = principal
        await _require(seed, org_id, required=False)
        await _require(seed, org_id, action_class=ACTION, required=True)
        config = await _resolve(db, principal)
        assert config.effective_required is True
        assert config.requirement_scope == "class"

    async def test_a_row_for_another_action_class_does_not_apply(
        self, db, seed, principal
    ) -> None:
        org_id, _agent = principal
        await _require(seed, org_id, action_class="some_other_action", required=True)
        config = await _resolve(db, principal)
        assert config.effective_required is False


class TestScopeIsolation:
    async def test_another_organisation_is_unaffected(self, db, seed, principal) -> None:
        org_id, _agent = principal
        await _require(seed, org_id, required=True)
        other = await resolve_authority_configuration(
            db, organisation_id=uuid4(), principal_id=uuid4(), action_class=ACTION
        )
        assert other.effective_required is False

    async def test_another_principal_in_the_same_org_is_unaffected(
        self, db, seed, principal
    ) -> None:
        org_id, agent_id = principal
        await _require(seed, org_id, agent_id=agent_id, required=True)
        other = await resolve_authority_configuration(
            db, organisation_id=org_id, principal_id=uuid4(), action_class=ACTION
        )
        assert other.effective_required is False


class TestControls:
    async def test_a_global_issuance_halt_applies(self, db, seed, principal) -> None:
        await _control(seed, "authority_issuance", org_id=None, engaged=True)
        config = await _resolve(db, principal)
        assert config.issuance_halted is True
        assert config.issuance_halt_is_global is True

    async def test_an_org_issuance_halt_applies(self, db, seed, principal) -> None:
        org_id, _agent = principal
        await _control(seed, "authority_issuance", org_id=org_id, engaged=True)
        config = await _resolve(db, principal)
        assert config.issuance_halted is True
        assert config.issuance_halt_is_global is False

    async def test_an_org_row_cannot_cancel_a_global_halt(self, db, seed, principal) -> None:
        org_id, _agent = principal
        await _control(seed, "authority_issuance", org_id=None, engaged=True)
        await _control(seed, "authority_issuance", org_id=org_id, engaged=False)
        config = await _resolve(db, principal)
        assert config.issuance_halted is True, "a tenant must not opt out of a platform halt"
        assert config.issuance_halt_is_global is True

    async def test_enforcement_suspension_suppresses_only_the_requirement(
        self, db, seed, principal
    ) -> None:
        org_id, _agent = principal
        await _require(seed, org_id, required=True)
        await _control(seed, "requirement_enforcement", org_id=org_id, engaged=True)
        config = await _resolve(db, principal)
        assert config.configured_required is True, "the configured answer is retained"
        assert config.enforcement_suspended is True
        assert config.effective_required is False

    async def test_suspension_does_not_lift_an_issuance_halt(
        self, db, seed, principal
    ) -> None:
        org_id, _agent = principal
        await _control(seed, "requirement_enforcement", org_id=org_id, engaged=True)
        await _control(seed, "authority_issuance", org_id=org_id, engaged=True)
        config = await _resolve(db, principal)
        assert config.issuance_halted is True

    async def test_suspension_is_not_a_generic_fail_open(self, db, seed, principal) -> None:
        """With nothing configured, suspension changes nothing."""
        org_id, _agent = principal
        await _control(seed, "requirement_enforcement", org_id=org_id, engaged=True)
        config = await _resolve(db, principal)
        assert config.configured_required is False
        assert config.effective_required is False


class TestFailsClosed:
    async def test_an_unreadable_configuration_raises_rather_than_defaulting(
        self, principal
    ) -> None:
        org_id, agent_id = principal
        broken = await Database.create(DATABASE_URL, min_size=1, max_size=2)
        await broken.close()
        with pytest.raises(AuthorityConfigurationUnavailable):
            await resolve_authority_configuration(
                broken, organisation_id=org_id, principal_id=agent_id, action_class=ACTION
            )

    async def test_the_legacy_gate_reports_unavailable_not_not_required(
        self, principal
    ) -> None:
        org_id, agent_id = principal
        broken = await Database.create(DATABASE_URL, min_size=1, max_size=2)
        await broken.close()
        reason = await legacy_authority_gate(
            broken, organisation_id=org_id, principal_id=agent_id, action_type=ACTION
        )
        assert reason is DecisionReason.AUTHORITY_CONFIGURATION_UNAVAILABLE
        assert reason is not None, "an unreadable configuration must never mean 'allowed'"


class TestEnvironmentVariableIsDecommissioned:
    def test_an_empty_value_is_fine(self, monkeypatch) -> None:
        monkeypatch.delenv(AUTHORITY_REQUIRED_ORGS_ENV, raising=False)
        assert_legacy_authority_enrolment_decommissioned(environment="production")

    def test_a_non_empty_value_refuses_to_start_in_production(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(uuid4()))
        with pytest.raises(LegacyAuthorityEnrolmentError) as raised:
            assert_legacy_authority_enrolment_decommissioned(environment="production")
        assert "authority_requirements" in str(raised.value)

    def test_a_non_empty_value_only_warns_outside_production(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(uuid4()))
        assert_legacy_authority_enrolment_decommissioned(environment="ci")

    async def test_it_never_contributes_to_a_decision(
        self, db, principal, monkeypatch
    ) -> None:
        org_id, agent_id = principal
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(org_id))
        config = await resolve_authority_configuration(
            db, organisation_id=org_id, principal_id=agent_id, action_class=ACTION
        )
        assert config.effective_required is False


class TestOneSnapshotPerDecision:
    async def test_the_configuration_is_resolved_exactly_once(
        self, db, principal, monkeypatch
    ) -> None:
        """A second read inside one decision could disagree with the first."""
        pytest.importorskip("api.routes.authority")
        from api.services.authority_service import AuthorityEvaluationService
        from tests.test_authority_endpoints import (  # noqa: PLC0415
            SERVER_SECRET,
            executor,
            payment_payload,
        )

        org_id, agent_id = principal
        agent = await db.get_agent_by_id(agent_id)
        assert agent is not None

        calls = 0
        real = authority_service_module.resolve_authority_configuration

        async def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return await real(*args, **kwargs)

        monkeypatch.setattr(
            authority_service_module, "resolve_authority_configuration", counting
        )
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref=f"one-snapshot-{uuid4().hex[:8]}",
        )
        assert calls == 1, f"the configuration was read {calls} times in one decision"

    async def test_a_concurrent_change_cannot_split_one_decision(
        self, db, seed, principal
    ) -> None:
        """The snapshot is immutable once taken.

        A change committed after resolution must not retroactively alter the
        configuration this decision is using -- otherwise half the decision
        is judged under the old configuration and half under the new.
        """
        org_id, agent_id = principal
        await _require(seed, org_id, required=False)

        config = await _resolve(db, principal)
        assert config.effective_required is False

        # Operator tightens the requirement AFTER the snapshot was taken.
        await seed.execute(
            "UPDATE authority_requirements SET required = TRUE WHERE org_id = $1", org_id
        )

        assert config.effective_required is False, (
            "the resolved snapshot must not change under a concurrent write"
        )
        # ...and the NEXT decision sees the new value.
        assert (await _resolve(db, principal)).effective_required is True


class TestBothSurfacesAgree:
    async def test_verify_and_evaluate_get_the_same_requirement_answer(
        self, db, seed, principal
    ) -> None:
        org_id, agent_id = principal
        await _require(seed, org_id, agent_id=agent_id, action_class=ACTION, required=True)

        gate = await legacy_authority_gate(
            db, organisation_id=org_id, principal_id=agent_id, action_type=ACTION
        )
        config = await _resolve(db, principal)

        assert gate is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING
        assert config.effective_required is True

    async def test_both_surfaces_agree_when_suspended(self, db, seed, principal) -> None:
        org_id, agent_id = principal
        await _require(seed, org_id, required=True)
        await _control(seed, "requirement_enforcement", org_id=org_id, engaged=True)

        gate = await legacy_authority_gate(
            db, organisation_id=org_id, principal_id=agent_id, action_type=ACTION
        )
        config = await _resolve(db, principal)

        assert gate is None
        assert config.effective_required is False
