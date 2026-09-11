"""Phase 7A, Gate 2 — the delegated-authority requirement as a real control.

What these tests are for
------------------------
The requirement decides whether an organisation's money can move without a
delegation. Gate 2 requires it to be server-controlled, off by default,
narrowable, audited, reversible by a kill switch, and impossible to bypass
through the legacy route. Each of those is a property somebody could break
without noticing, so each has a test that fails when they do.

Everything here runs against a real PostgreSQL: the specificity ladder, the
uniqueness of a scope and the immutability of the audit trail are database
behaviour, and a fake would only prove that the fake agrees with itself.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID, uuid4

import asyncpg
import pytest

from api.core.authority.decision import Decision, DecisionReason
from api.database import Database
from api.persistence.authority_requirements import (
    CONTROL_AUTHORITY_ISSUANCE,
    CONTROL_REQUIREMENT_ENFORCEMENT,
    EVENT_CONTROL_SET,
    EVENT_REQUIREMENT_CLEARED,
    EVENT_REQUIREMENT_SET,
    SOURCE_NOT_DEPLOYED,
    SOURCE_SUPPRESSED,
    SOURCE_UNAVAILABLE,
    SOURCE_UNCONFIGURED,
    FailClosedRequirementResolver,
    RequirementResolutionUnavailable,
    RequirementRow,
    RequirementSnapshot,
    clear_requirement,
    list_controls,
    list_requirements,
    load_requirement_snapshot,
    resolve_requirement_context,
    set_control,
    set_requirement,
)
from api.services.authority_service import (
    AUTHORITY_REQUIRED_ORGS_ENV,
    AuthorityEvaluationService,
    legacy_authority_gate,
    requirement_resolver_for,
)
from api.services.executor_context import (
    AuthenticatedExecutorContext,
    executor_binding_digest,
)

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="requirement rollout tests require INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)

SERVER_SECRET = b"phase-7a-gate-2-test-secret-not-a-production-value"
ACTION = "financial_transaction"
OTHER_ACTION = "code_release"


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=2, max_size=8)
    try:
        yield database
    finally:
        await database.close()


async def _make_org_and_agent(db: Database) -> tuple[UUID, UUID]:
    org_id, agent_id = uuid4(), uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
            VALUES ($1, $2, 'enterprise', $3, sha256($4::BYTEA))
            """,
            org_id,
            f"gate2-{org_id}",
            f"gate2-{org_id}@invalid.test",
            str(org_id).encode(),
        )
        await conn.execute(
            """
            INSERT INTO agents (
                id, org_id, name, public_key, public_key_fingerprint, trust_score,
                status, daily_limit_usd, per_action_limit_usd, allowed_actions,
                blocked_actions, rate_limit_per_minute, metadata
            ) VALUES (
                $1, $2, $3, decode(repeat('00', 32), 'hex'), $4, 95, 'active',
                10000, 10000, ARRAY['financial_transaction']::TEXT[],
                ARRAY[]::TEXT[], 600, '{"sandbox": true}'::JSONB
            )
            """,
            agent_id,
            org_id,
            f"gate2-agent-{agent_id}",
            uuid4().hex + uuid4().hex,
        )
    return org_id, agent_id


@pytest.fixture
async def org_and_agent(db: Database) -> tuple[UUID, UUID]:
    return await _make_org_and_agent(db)


def executor(org_id: UUID) -> AuthenticatedExecutorContext:
    key_id = "gate2-executor-key"
    return AuthenticatedExecutorContext(
        organisation_id=org_id,
        api_key_id=key_id,
        scopes=frozenset({"write"}),
        binding_digest=executor_binding_digest(organisation_id=org_id, api_key_id=key_id),
    )


def payment_payload(amount: str = "12.00") -> dict[str, object]:
    return {
        "amount": amount,
        "currency": "USD",
        "recipient": "0x" + "ab" * 20,
        "chain": "base",
    }


# =============================================================================
# Safe default
# =============================================================================


class TestSafeDefault:
    """An organisation nobody configured behaves exactly as it does today."""

    async def test_an_unconfigured_organisation_is_not_required(
        self, db, org_and_agent, monkeypatch
    ) -> None:
        monkeypatch.delenv(AUTHORITY_REQUIRED_ORGS_ENV, raising=False)
        org_id, agent_id = org_and_agent
        snapshot = await load_requirement_snapshot(
            db, organisation_id=org_id, principal_id=agent_id
        )
        answer = snapshot.requirement(str(org_id), str(agent_id), ACTION)
        assert answer.required is False
        assert answer.source == SOURCE_UNCONFIGURED

    async def test_an_unconfigured_organisation_still_gets_a_grant(
        self, db, org_and_agent, monkeypatch
    ) -> None:
        monkeypatch.delenv(AUTHORITY_REQUIRED_ORGS_ENV, raising=False)
        org_id, agent_id = org_and_agent
        agent = await db.get_agent_by_id(agent_id)
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        result = await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref=f"unconfigured-{uuid4()}",
        )
        assert result.decision is Decision.ALLOW
        assert result.authority_token is not None


# =============================================================================
# Scoping — the specificity ladder
# =============================================================================


class TestScoping:
    """Per-organisation, per-principal and per-action-class configuration."""

    async def test_an_organisation_wide_row_applies_to_every_principal(
        self, db, org_and_agent
    ) -> None:
        org_id, agent_id = org_and_agent
        await set_requirement(
            db,
            organisation_id=org_id,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-1",
            reason="organisation-wide rollout",
        )
        snapshot = await load_requirement_snapshot(
            db, organisation_id=org_id, principal_id=agent_id
        )
        assert snapshot.requirement(str(org_id), str(agent_id), ACTION).required is True
        assert snapshot.requirement(str(org_id), str(agent_id), OTHER_ACTION).required is True

    async def test_an_action_class_row_binds_only_that_class(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        await set_requirement(
            db,
            organisation_id=org_id,
            action_class=ACTION,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-2",
            reason="payments first",
        )
        snapshot = await load_requirement_snapshot(
            db, organisation_id=org_id, principal_id=agent_id
        )
        assert snapshot.requirement(str(org_id), str(agent_id), ACTION).required is True
        assert snapshot.requirement(str(org_id), str(agent_id), OTHER_ACTION).required is False

    async def test_a_principal_row_binds_only_that_principal(self, db) -> None:
        org_id, agent_id = await _make_org_and_agent(db)
        other_agent = uuid4()
        async with db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO agents (
                    id, org_id, name, public_key, public_key_fingerprint, trust_score,
                    status, daily_limit_usd, per_action_limit_usd, allowed_actions,
                    blocked_actions, rate_limit_per_minute, metadata
                ) VALUES (
                    $1, $2, $3, decode(repeat('00', 32), 'hex'), $4, 95, 'active',
                    10000, 10000, ARRAY['financial_transaction']::TEXT[],
                    ARRAY[]::TEXT[], 600, '{"sandbox": true}'::JSONB
                )
                """,
                other_agent,
                org_id,
                f"gate2-other-{other_agent}",
                uuid4().hex + uuid4().hex,
            )
        await set_requirement(
            db,
            organisation_id=org_id,
            agent_id=agent_id,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-3",
            reason="one principal first",
        )

        configured = await load_requirement_snapshot(
            db, organisation_id=org_id, principal_id=agent_id
        )
        untouched = await load_requirement_snapshot(
            db, organisation_id=org_id, principal_id=other_agent
        )
        assert configured.requirement(str(org_id), str(agent_id), ACTION).required
        assert not untouched.requirement(str(org_id), str(other_agent), ACTION).required

    async def test_the_narrower_row_wins_in_both_directions(self, db, org_and_agent) -> None:
        """A rollout must be reversible for one principal without deleting
        the organisation-wide row and losing what it used to say."""
        org_id, agent_id = org_and_agent
        await set_requirement(
            db,
            organisation_id=org_id,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-4",
            reason="organisation-wide",
        )
        await set_requirement(
            db,
            organisation_id=org_id,
            agent_id=agent_id,
            action_class=ACTION,
            required=False,
            changed_by="gate2-test",
            approval_reference="CHG-5",
            reason="this principal is not ready",
        )
        snapshot = await load_requirement_snapshot(
            db, organisation_id=org_id, principal_id=agent_id
        )
        # Narrowest row exempts this exact act ...
        assert snapshot.requirement(str(org_id), str(agent_id), ACTION).required is False
        # ... and the organisation-wide row still governs everything else.
        assert snapshot.requirement(str(org_id), str(agent_id), OTHER_ACTION).required is True

    async def test_a_scope_cannot_hold_two_contradictory_answers(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        await set_requirement(
            db,
            organisation_id=org_id,
            agent_id=agent_id,
            action_class=ACTION,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-6",
            reason="first",
        )
        await set_requirement(
            db,
            organisation_id=org_id,
            agent_id=agent_id,
            action_class=ACTION,
            required=False,
            changed_by="gate2-test",
            approval_reference="CHG-7",
            reason="second",
        )
        rows = await list_requirements(db, organisation_id=org_id)
        matching = [
            row for row in rows if row["agent_id"] == agent_id and row["action_class"] == ACTION
        ]
        assert len(matching) == 1
        assert matching[0]["required"] is False

    async def test_a_row_cannot_name_another_tenants_principal(self, db) -> None:
        org_a, _agent_a = await _make_org_and_agent(db)
        _org_b, agent_b = await _make_org_and_agent(db)
        with pytest.raises(asyncpg.ForeignKeyViolationError):
            await set_requirement(
                db,
                organisation_id=org_a,
                agent_id=agent_b,
                required=True,
                changed_by="gate2-test",
                approval_reference="CHG-8",
                reason="cross-tenant attempt",
            )


# =============================================================================
# Audit trail
# =============================================================================


class TestAuditTrail:
    async def test_enabling_writes_immutable_audit_evidence(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        await set_requirement(
            db,
            organisation_id=org_id,
            agent_id=agent_id,
            action_class=ACTION,
            required=True,
            changed_by="release-engineer@inntris.test",
            approval_reference="CHG-2026-0001",
            reason="Gate 2 rollout",
        )
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT event_type, actor, approval_reference, details
                FROM administrative_audit_events
                WHERE org_id = $1 AND event_type = $2
                ORDER BY created_at DESC LIMIT 1
                """,
                org_id,
                EVENT_REQUIREMENT_SET,
            )
        assert row is not None
        assert row["actor"] == "release-engineer@inntris.test"
        assert row["approval_reference"] == "CHG-2026-0001"

    async def test_disabling_is_recorded_too(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        await set_requirement(
            db,
            organisation_id=org_id,
            agent_id=agent_id,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-9",
            reason="on",
        )
        existed = await clear_requirement(
            db,
            organisation_id=org_id,
            agent_id=agent_id,
            changed_by="gate2-test",
            approval_reference="CHG-10",
            reason="off",
        )
        assert existed is True
        async with db.acquire() as conn:
            count = await conn.fetchval(
                """
                SELECT COUNT(*) FROM administrative_audit_events
                WHERE org_id = $1 AND event_type = $2
                """,
                org_id,
                EVENT_REQUIREMENT_CLEARED,
            )
        assert count == 1

    async def test_the_audit_row_cannot_be_rewritten(self, db, org_and_agent) -> None:
        org_id, _agent_id = org_and_agent
        await set_requirement(
            db,
            organisation_id=org_id,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-11",
            reason="on",
        )
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.PostgresError):
                await conn.execute(
                    """
                    UPDATE administrative_audit_events SET actor = 'someone-else'
                    WHERE org_id = $1 AND event_type = $2
                    """,
                    org_id,
                    EVENT_REQUIREMENT_SET,
                )

    async def test_a_requirement_write_needs_an_actor_and_an_approval(
        self, db, org_and_agent
    ) -> None:
        org_id, _agent_id = org_and_agent
        for bad in ({"changed_by": "  "}, {"approval_reference": ""}, {"reason": ""}):
            kwargs: dict[str, object] = {
                "organisation_id": org_id,
                "required": True,
                "changed_by": "gate2-test",
                "approval_reference": "CHG-12",
                "reason": "on",
            }
            kwargs.update(bad)
            with pytest.raises(asyncpg.PostgresError):
                await set_requirement(db, **kwargs)  # type: ignore[arg-type]


# =============================================================================
# Kill switches
# =============================================================================


class TestKillSwitches:
    async def test_the_enforcement_switch_undoes_a_requirement(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        await set_requirement(
            db,
            organisation_id=org_id,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-13",
            reason="rolled out too wide",
        )
        await set_control(
            db,
            control=CONTROL_REQUIREMENT_ENFORCEMENT,
            organisation_id=org_id,
            engaged=True,
            changed_by="incident-commander",
            approval_reference="INC-1",
            reason="rollback",
        )
        snapshot = await load_requirement_snapshot(
            db, organisation_id=org_id, principal_id=agent_id
        )
        answer = snapshot.requirement(str(org_id), str(agent_id), ACTION)
        assert answer.required is False
        assert answer.source == SOURCE_SUPPRESSED

    async def test_releasing_the_switch_restores_the_requirement(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        await set_requirement(
            db,
            organisation_id=org_id,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-14",
            reason="on",
        )
        await set_control(
            db,
            control=CONTROL_REQUIREMENT_ENFORCEMENT,
            organisation_id=org_id,
            engaged=True,
            changed_by="incident-commander",
            approval_reference="INC-2",
            reason="rollback",
        )
        await set_control(
            db,
            control=CONTROL_REQUIREMENT_ENFORCEMENT,
            organisation_id=org_id,
            engaged=False,
            changed_by="incident-commander",
            approval_reference="INC-3",
            reason="resolved",
        )
        snapshot = await load_requirement_snapshot(
            db, organisation_id=org_id, principal_id=agent_id
        )
        assert snapshot.requirement(str(org_id), str(agent_id), ACTION).required is True

    async def test_the_issuance_switch_stops_new_grants(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        agent = await db.get_agent_by_id(agent_id)
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)

        before = await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref=f"before-halt-{uuid4()}",
        )
        assert before.decision is Decision.ALLOW

        await set_control(
            db,
            control=CONTROL_AUTHORITY_ISSUANCE,
            organisation_id=org_id,
            engaged=True,
            changed_by="incident-commander",
            approval_reference="INC-4",
            reason="suspected issuer compromise",
        )
        after = await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref=f"after-halt-{uuid4()}",
        )
        assert after.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_ISSUANCE_HALTED in after.reasons
        assert after.authority_token is None
        assert after.grant_id is None

    async def test_a_global_halt_reaches_an_organisation_with_no_row(
        self, db, org_and_agent
    ) -> None:
        org_id, agent_id = org_and_agent
        await set_control(
            db,
            control=CONTROL_AUTHORITY_ISSUANCE,
            organisation_id=None,
            engaged=True,
            changed_by="platform-operator",
            approval_reference="INC-5",
            reason="platform-wide halt",
        )
        try:
            resolver = await requirement_resolver_for(
                db, organisation_id=org_id, principal_id=agent_id
            )
            assert resolver.issuance_halted is True
        finally:
            await set_control(
                db,
                control=CONTROL_AUTHORITY_ISSUANCE,
                organisation_id=None,
                engaged=False,
                changed_by="platform-operator",
                approval_reference="INC-6",
                reason="released",
            )

    async def test_a_typo_cannot_create_a_switch_nothing_reads(self, db) -> None:
        with pytest.raises(ValueError, match="unknown authority control"):
            await set_control(
                db,
                control="requirement_enforcment",
                engaged=True,
                changed_by="gate2-test",
                approval_reference="CHG-15",
                reason="typo",
            )

    async def test_engaging_a_switch_writes_audit_evidence(self, db, org_and_agent) -> None:
        org_id, _agent_id = org_and_agent
        await set_control(
            db,
            control=CONTROL_AUTHORITY_ISSUANCE,
            organisation_id=org_id,
            engaged=True,
            changed_by="incident-commander",
            approval_reference="INC-7",
            reason="halt",
        )
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT actor, approval_reference FROM administrative_audit_events
                WHERE org_id = $1 AND event_type = $2
                ORDER BY created_at DESC LIMIT 1
                """,
                org_id,
                EVENT_CONTROL_SET,
            )
        assert row is not None
        assert row["approval_reference"] == "INC-7"

    async def test_controls_are_listed_with_the_global_row(self, db, org_and_agent) -> None:
        org_id, _agent_id = org_and_agent
        await set_control(
            db,
            control=CONTROL_AUTHORITY_ISSUANCE,
            organisation_id=org_id,
            engaged=False,
            changed_by="gate2-test",
            approval_reference="CHG-16",
            reason="listed",
        )
        rows = await list_controls(db, organisation_id=org_id)
        assert any(row["org_id"] == org_id for row in rows)


# =============================================================================
# The legacy route cannot bypass an enabled requirement
# =============================================================================


class TestLegacyRouteCannotBypass:
    """Gate 2's explicit acceptance test.

    ``/verify`` has no field in which to present delegated authority. An
    organisation that has deliberately enabled the requirement must not be
    able to obtain an approval token through it — otherwise the control is
    decorative and the older, wider route is the way around it.
    """

    async def test_the_legacy_gate_blocks_an_enabled_organisation(
        self, db, org_and_agent, monkeypatch
    ) -> None:
        monkeypatch.delenv(AUTHORITY_REQUIRED_ORGS_ENV, raising=False)
        org_id, agent_id = org_and_agent
        assert (
            await legacy_authority_gate(
                database=db,
                organisation_id=org_id,
                principal_id=agent_id,
                action_type=ACTION,
            )
            is None
        )
        await set_requirement(
            db,
            organisation_id=org_id,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-17",
            reason="enabled",
        )
        assert (
            await legacy_authority_gate(
                database=db,
                organisation_id=org_id,
                principal_id=agent_id,
                action_type=ACTION,
            )
            is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING
        )

    async def test_the_legacy_gate_respects_the_action_class_scope(
        self, db, org_and_agent, monkeypatch
    ) -> None:
        monkeypatch.delenv(AUTHORITY_REQUIRED_ORGS_ENV, raising=False)
        org_id, agent_id = org_and_agent
        await set_requirement(
            db,
            organisation_id=org_id,
            action_class=ACTION,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-18",
            reason="payments only",
        )
        assert (
            await legacy_authority_gate(
                database=db,
                organisation_id=org_id,
                principal_id=agent_id,
                action_type=ACTION,
            )
            is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING
        )
        assert (
            await legacy_authority_gate(
                database=db,
                organisation_id=org_id,
                principal_id=agent_id,
                action_type=OTHER_ACTION,
            )
            is None
        )

    async def test_the_http_verify_route_blocks_an_enabled_organisation(
        self, db, org_and_agent, monkeypatch
    ) -> None:
        """The property that matters is on the wire, not in the helper."""
        monkeypatch.delenv(AUTHORITY_REQUIRED_ORGS_ENV, raising=False)
        org_id, agent_id = org_and_agent
        from api.services.core_evaluation import CorePolicyInputs, evaluate_core_policy

        agent = await db.get_agent_by_id(agent_id)

        # Baseline: core policy itself permits this act, so a later BLOCK can
        # only be the requirement gate.
        baseline = evaluate_core_policy(
            CorePolicyInputs(
                agent=agent,
                action_type=ACTION,
                payload=payment_payload(),
                timestamp=datetime.now(UTC),
                daily_spend=Decimal("0"),
                minute_request_count=0,
                registered_policy=None,
                client_policy_hash=None,
            )
        )
        assert baseline.allowed is True

        await set_requirement(
            db,
            organisation_id=org_id,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-19",
            reason="enabled",
        )
        gap = await legacy_authority_gate(
            database=db,
            organisation_id=org_id,
            principal_id=agent_id,
            action_type=ACTION,
        )
        assert gap is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING

    async def test_the_authority_surface_blocks_without_a_delegation(
        self, db, org_and_agent, monkeypatch
    ) -> None:
        monkeypatch.delenv(AUTHORITY_REQUIRED_ORGS_ENV, raising=False)
        org_id, agent_id = org_and_agent
        await set_requirement(
            db,
            organisation_id=org_id,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-20",
            reason="enabled",
        )
        agent = await db.get_agent_by_id(agent_id)
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        result = await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref=f"required-{uuid4()}",
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING in result.reasons
        assert result.authority_token is None


# =============================================================================
# The environment variable can only add
# =============================================================================


class TestEnvironmentEnrolmentIsAdditive:
    async def test_the_variable_can_turn_a_requirement_on(
        self, db, org_and_agent, monkeypatch
    ) -> None:
        org_id, agent_id = org_and_agent
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(org_id))
        resolver = await requirement_resolver_for(db, organisation_id=org_id, principal_id=agent_id)
        assert resolver.requirement(str(org_id), str(agent_id), ACTION).required is True

    async def test_the_variable_cannot_turn_a_requirement_off(
        self, db, org_and_agent, monkeypatch
    ) -> None:
        """An environment variable must not silently disable a control an
        organisation deliberately configured."""
        org_id, agent_id = org_and_agent
        await set_requirement(
            db,
            organisation_id=org_id,
            required=True,
            changed_by="gate2-test",
            approval_reference="CHG-21",
            reason="configured on",
        )
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(uuid4()))
        resolver = await requirement_resolver_for(db, organisation_id=org_id, principal_id=agent_id)
        assert resolver.requirement(str(org_id), str(agent_id), ACTION).required is True

    async def test_the_kill_switch_beats_the_variable(self, db, org_and_agent, monkeypatch) -> None:
        """A break-glass variable set last month must not defeat the control
        an operator is pulling now."""
        org_id, agent_id = org_and_agent
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(org_id))
        await set_control(
            db,
            control=CONTROL_REQUIREMENT_ENFORCEMENT,
            organisation_id=org_id,
            engaged=True,
            changed_by="incident-commander",
            approval_reference="INC-8",
            reason="rollback",
        )
        resolver = await requirement_resolver_for(db, organisation_id=org_id, principal_id=agent_id)
        assert resolver.requirement(str(org_id), str(agent_id), ACTION).required is False


# =============================================================================
# The three answers, and which of them fails closed
# =============================================================================


class TestResolutionFailureModes:
    def test_an_unreadable_configuration_fails_closed(self) -> None:
        org, principal = uuid4(), uuid4()
        resolver = FailClosedRequirementResolver(
            organisation_id=str(org), principal_id=str(principal)
        )
        answer = resolver.requirement(str(org), str(principal), ACTION)
        assert answer.required is True
        assert answer.source == SOURCE_UNAVAILABLE
        # It could not read the switches either, so it must not claim
        # issuance is permitted.
        assert resolver.issuance_halted is True

    async def test_a_read_failure_becomes_the_fail_closed_resolver(self) -> None:
        class BrokenDatabase:
            def acquire(self):  # noqa: ANN201 - test double
                raise asyncpg.PostgresConnectionError("connection reset")

        resolver = await resolve_requirement_context(
            BrokenDatabase(), organisation_id=uuid4(), principal_id=uuid4()
        )
        assert isinstance(resolver, FailClosedRequirementResolver)

    async def test_a_missing_relation_means_nobody_was_enrolled(self) -> None:
        """The mixed-version window: new code, pre-0023 schema.

        A relation that does not exist is proof that nothing was enrolled,
        not an inability to find out. Failing closed here would block every
        organisation over a deployment-ordering fault.
        """

        class MissingTableDatabase:
            def acquire(self):  # noqa: ANN201 - test double
                raise asyncpg.UndefinedTableError(
                    'relation "authority_requirements" does not exist'
                )

        org, principal = uuid4(), uuid4()
        snapshot = await load_requirement_snapshot(
            MissingTableDatabase(), organisation_id=org, principal_id=principal
        )
        answer = snapshot.requirement(str(org), str(principal), ACTION)
        assert answer.required is False
        assert answer.source == SOURCE_NOT_DEPLOYED

    async def test_a_programming_fault_is_not_turned_into_a_policy_answer(
        self,
    ) -> None:
        """A bug must not be laundered into "authority is required".

        Failing closed on a ``TypeError`` would refuse every request with
        "delegated authority is required and was not presented" — a control
        giving a false reason, on organisations that never enrolled. The
        fault propagates instead: visible, attributable and fixable.
        """

        class BuggyDatabase:
            def acquire(self):  # noqa: ANN201 - test double
                raise AttributeError("acquire is not a thing here")

        with pytest.raises(AttributeError):
            await resolve_requirement_context(
                BuggyDatabase(), organisation_id=uuid4(), principal_id=uuid4()
            )

    def test_a_snapshot_refuses_to_answer_for_another_subject(self) -> None:
        org, principal = uuid4(), uuid4()
        snapshot = RequirementSnapshot(organisation_id=str(org), principal_id=str(principal))
        with pytest.raises(RequirementResolutionUnavailable):
            snapshot.requirement(str(org), str(uuid4()), ACTION)


class TestSpecificityLadder:
    """The ordering itself, without a database in the way."""

    def test_specificity_is_strictly_ordered(self) -> None:
        agent = uuid4()
        org_wide = RequirementRow(None, None, True, "r", "a", "c")
        action_only = RequirementRow(None, ACTION, True, "r", "a", "c")
        agent_only = RequirementRow(agent, None, True, "r", "a", "c")
        both = RequirementRow(agent, ACTION, True, "r", "a", "c")
        assert (
            org_wide.specificity
            < action_only.specificity
            < agent_only.specificity
            < both.specificity
        )

    def test_a_non_matching_principal_row_is_ignored(self) -> None:
        org, principal, other = uuid4(), uuid4(), uuid4()
        snapshot = RequirementSnapshot(
            organisation_id=str(org),
            principal_id=str(principal),
            rows=(RequirementRow(other, ACTION, True, "r", "a", "c"),),
        )
        assert snapshot.requirement(str(org), str(principal), ACTION).required is False
