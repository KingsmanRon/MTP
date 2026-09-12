"""Fresh consumption respects the CURRENT authority requirement.

The threat: a grant issued while delegation was optional must not keep a
permanent right to bypass a stricter configuration.

    T0  effective_required = FALSE, authority issued without delegation
    T1  operator sets the requirement to TRUE
    T2  the old, unconsumed grant is presented

At T2 a FRESH consume must refuse. What must NOT change is recovery: an
already-committed consumption is a historical fact, and tightening the
requirement afterwards cannot turn reading that record back into a new
decision.

The durable proof that a grant was issued under a VERIFIED delegation is
``authority_scope_digest``. The policy refuses to ALLOW an unverified
delegation and a non-ALLOW never reaches issuance, so the column is
non-NULL only for a grant whose delegation was checked.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

asyncpg = pytest.importorskip("asyncpg")

from api.core.authority.decision import DecisionReason  # noqa: E402
from api.core.authority.lifecycle import ConsumptionOutcome  # noqa: E402
from api.database import Database  # noqa: E402
from api.persistence.authority_store import AuthorityStore  # noqa: E402

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")
MIGRATOR_URL = os.getenv("ALEMBIC_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="consume-time requirement tests require INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)

POLICY_HASH = "b" * 64
BINDING = "c" * 64
FORMAT = "inntris-payment-authority-policy-v1"
SCOPE_DIGEST = "d" * 64
ACTION = "financial_transaction"


def action_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _static_policy():
    def resolver(_agent, _action_type, _domain):
        return POLICY_HASH, "revision-1"

    return resolver


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=2, max_size=10)
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
        await conn.execute("DELETE FROM authority_controls WHERE org_id IS NULL")
        await conn.close()


@pytest.fixture
async def store(db: Database) -> AuthorityStore:
    return AuthorityStore(db, current_policy_resolver=_static_policy())


@pytest.fixture
async def principal(db: Database) -> tuple[UUID, UUID]:
    org_id, agent_id = uuid4(), uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """INSERT INTO organizations (id,name,billing_tier,contact_email,api_key_hash)
               VALUES ($1,$2,'enterprise',$3,$4)""",
            org_id, f"cc-{org_id}", f"cc-{org_id}@example.test",
            hashlib.sha256(str(org_id).encode()).digest(),
        )
        await conn.execute(
            """INSERT INTO agents (id,org_id,name,public_key,public_key_fingerprint,
                 trust_score,status,daily_limit_usd,per_action_limit_usd,allowed_actions,
                 blocked_actions,rate_limit_per_minute,metadata)
               VALUES ($1,$2,$3,$4,$5,95,'active',1000000,1000000,
                       ARRAY['financial_transaction']::TEXT[],ARRAY[]::TEXT[],100000,$6::JSONB)""",
            agent_id, org_id, f"cc-agent-{agent_id}", secrets.token_bytes(32),
            hashlib.sha256(str(agent_id).encode()).hexdigest(),
            json.dumps({"sandbox": False,
                        "production_approval_reference": "cc-test",
                        "production_approved_at": "2026-01-01T00:00:00Z",
                        "production_approved_by": "cc-test"}),
        )
    return org_id, agent_id


async def issue(store, org_id, agent_id, ref, *, scope_digest=None):
    now = datetime.now(UTC)
    return await store.issue(
        agent_id=agent_id, organisation_id=org_id, issuance_ref=ref,
        execution_action_hash=action_hash(ref), policy_hash=POLICY_HASH,
        policy_snapshot_format=FORMAT, policy_revision="revision-1",
        executor_binding_digest=BINDING, domain="payment", action_type=ACTION,
        minute_start=now.replace(second=0, microsecond=0),
        day_start=now.replace(hour=0, minute=0, second=0, microsecond=0),
        rate_limit_per_minute=100000, daily_limit_usd=Decimal("1000000"),
        amount_usd=Decimal("1"), authority_scope_digest=scope_digest,
    )


async def consume(store, ref, grant, *, execution_ref=None, evidence=None):
    return await store.consume(
        grant_id=grant.grant_id,
        execution_action_hash=action_hash(ref),
        executor_binding_digest=BINDING,
        execution_ref=execution_ref or f"exec-{ref}",
        authority_evidence=evidence,
    )


async def require(seed, org_id, *, required=True):
    await seed.execute(
        """INSERT INTO authority_requirements
             (org_id,agent_id,action_class,required,reason,changed_by,approval_reference)
           VALUES ($1,NULL,NULL,$2,'t','test-suite','A')
           ON CONFLICT (org_id, scope_key) DO UPDATE SET required = EXCLUDED.required""",
        org_id, required,
    )


async def suspend(seed, org_id, *, engaged=True):
    await seed.execute(
        """INSERT INTO authority_controls
             (control,org_id,engaged,reason,changed_by,approval_reference)
           VALUES ('requirement_enforcement',$1,$2,'t','test-suite','A')""",
        org_id, engaged,
    )


def _evidence(*, revoked=False, expires_at=None):
    from api.persistence.authority_store import ResolvedAuthorityEvidence

    return ResolvedAuthorityEvidence(
        scope_digest=SCOPE_DIGEST, revoked=revoked, expires_at=expires_at
    )


class TestFreshConsumeHonoursTheCurrentRequirement:
    async def test_A_a_grant_without_delegation_is_refused_once_required(
        self, db, seed, store, principal
    ) -> None:
        """The exploit: issued while optional, presented after tightening."""
        org_id, agent_id = principal
        grant = await issue(store, org_id, agent_id, "case-a")
        assert grant.grant_id is not None

        # T1 -- the operator tightens the requirement.
        await require(seed, org_id, required=True)

        result = await consume(store, "case-a", grant)
        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.rejection_reason is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING

        # Nothing was spent.
        async with db.acquire() as conn:
            status = await conn.fetchval(
                "SELECT status FROM execution_authority_grants WHERE id = $1", grant.grant_id
            )
        assert status == "active"

    async def test_B_an_org_suspension_restores_the_configured_behaviour(
        self, seed, store, principal
    ) -> None:
        org_id, agent_id = principal
        grant = await issue(store, org_id, agent_id, "case-b")
        await require(seed, org_id, required=True)
        await suspend(seed, org_id, engaged=True)

        result = await consume(store, "case-b", grant)
        assert result.outcome is ConsumptionOutcome.AUTHORISED

    async def test_C_a_grant_issued_under_verified_delegation_still_consumes(
        self, seed, store, principal
    ) -> None:
        org_id, agent_id = principal
        grant = await issue(store, org_id, agent_id, "case-c", scope_digest=SCOPE_DIGEST)
        await require(seed, org_id, required=True)

        result = await consume(store, "case-c", grant, evidence=_evidence())
        assert result.outcome is ConsumptionOutcome.AUTHORISED

    async def test_D_a_revoked_delegation_is_refused(
        self, seed, store, principal
    ) -> None:
        org_id, agent_id = principal
        grant = await issue(store, org_id, agent_id, "case-d", scope_digest=SCOPE_DIGEST)
        await require(seed, org_id, required=True)

        result = await consume(store, "case-d", grant, evidence=_evidence(revoked=True))
        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.rejection_reason is DecisionReason.AUTHORITY_REVOKED

    async def test_E_an_unreadable_configuration_refuses_the_fresh_spend(
        self, principal
    ) -> None:
        org_id, agent_id = principal
        working = await Database.create(DATABASE_URL, min_size=1, max_size=4)
        working_store = AuthorityStore(working, current_policy_resolver=_static_policy())
        grant = await issue(working_store, org_id, agent_id, "case-e")
        await working.close()

        broken_store = AuthorityStore(working, current_policy_resolver=_static_policy())
        with pytest.raises(Exception):  # noqa: B017 - a dead pool raises before the check
            await consume(broken_store, "case-e", grant)

    async def test_E2_a_configuration_read_failure_is_reported_as_unavailable(
        self, store, principal, monkeypatch
    ) -> None:
        """The configuration read itself failing must refuse, not allow."""
        org_id, agent_id = principal
        grant = await issue(store, org_id, agent_id, "case-e2")

        from api.persistence import authority_store as store_module
        from api.persistence.authority_configuration import (
            AuthorityConfigurationUnavailable,
        )

        async def unavailable(*_a, **_kw):
            raise AuthorityConfigurationUnavailable("simulated outage")

        monkeypatch.setattr(
            store_module, "resolve_authority_configuration_on", unavailable
        )
        result = await consume(store, "case-e2", grant)
        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.rejection_reason is DecisionReason.AUTHORITY_CONFIGURATION_UNAVAILABLE


class TestRecoveryIsNotReAuthorised:
    async def test_F_same_execution_ref_still_recovers_after_tightening(
        self, db, seed, store, principal
    ) -> None:
        """A committed consumption is a historical fact, not a new decision."""
        org_id, agent_id = principal
        grant = await issue(store, org_id, agent_id, "case-f")

        first = await consume(store, "case-f", grant, execution_ref="ref-f")
        assert first.outcome is ConsumptionOutcome.AUTHORISED

        # The requirement tightens AFTER the spend.
        await require(seed, org_id, required=True)

        again = await consume(store, "case-f", grant, execution_ref="ref-f")
        assert again.outcome is ConsumptionOutcome.RECOVERED
        assert again.consumption_audit_id == first.consumption_audit_id

        # Exactly one consumption exists: nothing was executed a second time.
        async with db.acquire() as conn:
            claims = await conn.fetchval(
                "SELECT count(*) FROM approval_token_consumptions WHERE token_id = $1",
                grant.approval_token_id,
            )
        assert claims == 1

    async def test_G_a_different_execution_ref_remains_rejected(
        self, seed, store, principal
    ) -> None:
        org_id, agent_id = principal
        grant = await issue(store, org_id, agent_id, "case-g")
        first = await consume(store, "case-g", grant, execution_ref="ref-g1")
        assert first.outcome is ConsumptionOutcome.AUTHORISED

        await require(seed, org_id, required=True)

        replay = await consume(store, "case-g", grant, execution_ref="ref-g2")
        assert replay.outcome is ConsumptionOutcome.REJECTED
        assert replay.rejection_reason in {
            DecisionReason.GRANT_ALREADY_CONSUMED,
            DecisionReason.EXECUTION_REF_CONFLICT,
        }


class TestIssuanceControlStaysIssuanceOnly:
    async def test_an_issuance_halt_does_not_invalidate_an_existing_grant(
        self, seed, store, principal
    ) -> None:
        """Halting issuance must not strand an executor mid-flight."""
        org_id, agent_id = principal
        grant = await issue(store, org_id, agent_id, "case-halt")
        await seed.execute(
            """INSERT INTO authority_controls
                 (control,org_id,engaged,reason,changed_by,approval_reference)
               VALUES ('authority_issuance',$1,TRUE,'t','test-suite','A')""",
            org_id,
        )
        result = await consume(store, "case-halt", grant)
        assert result.outcome is ConsumptionOutcome.AUTHORISED


class TestConcurrentConfigurationChange:
    """H and I: no commit under a configuration that is no longer current.

    The property under test is: *if consumption commits, it was valid under
    one coherent current authority configuration*. The checkable form of
    that is -- once a tightening has COMMITTED, no later fresh consume is
    authorised; and whatever happened while the write was in flight left no
    torn state behind.
    """

    @staticmethod
    async def _assert_no_torn_state(db, grants) -> None:
        token_ids = [g.approval_token_id for g in grants]
        grant_ids = [g.grant_id for g in grants]
        async with db.acquire() as conn:
            duplicate = await conn.fetchval(
                """SELECT COUNT(*) FROM (
                     SELECT token_id FROM approval_token_consumptions
                     WHERE token_id = ANY($1::TEXT[])
                     GROUP BY token_id HAVING COUNT(*) > 1) s""",
                token_ids,
            )
            orphan = await conn.fetchval(
                """SELECT COUNT(*) FROM execution_authority_grants g
                   WHERE g.id = ANY($1::UUID[]) AND g.status = 'consumed'
                     AND NOT EXISTS (SELECT 1 FROM approval_token_consumptions c
                                     WHERE c.token_id = g.approval_token_id)""",
                grant_ids,
            )
            contradiction = await conn.fetchval(
                """SELECT COUNT(*) FROM execution_authority_grants g
                   JOIN approval_token_consumptions c ON c.token_id = g.approval_token_id
                   WHERE g.id = ANY($1::UUID[]) AND g.status = 'active'""",
                grant_ids,
            )
        assert duplicate == 0, "a token was spent more than once"
        assert orphan == 0, "a grant reads consumed with no consumption record"
        assert contradiction == 0, "a token was claimed while its grant reads active"

    async def test_H_tightening_races_fresh_consume_without_a_stale_commit(
        self, db, seed, store, principal
    ) -> None:
        import asyncio

        org_id, agent_id = principal
        await require(seed, org_id, required=False)
        grants = [
            await issue(store, org_id, agent_id, f"race-h-{i}") for i in range(12)
        ]

        async def flip():
            await asyncio.sleep(0.01)
            await require(seed, org_id, required=True)

        results = await asyncio.wait_for(
            asyncio.gather(
                *(consume(store, f"race-h-{i}", g) for i, g in enumerate(grants)),
                flip(),
            ),
            timeout=60.0,
        )
        outcomes = list(results[:-1])
        for outcome in outcomes:
            if outcome.outcome is not ConsumptionOutcome.AUTHORISED:
                assert outcome.rejection_reason is (
                    DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING
                )
        await self._assert_no_torn_state(db, grants)

        # The tightening is now definitively committed: nothing more may pass.
        after = await issue(store, org_id, agent_id, "race-h-after")
        late = await consume(store, "race-h-after", after)
        assert late.outcome is ConsumptionOutcome.REJECTED
        assert late.rejection_reason is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING

    async def test_I_lifting_a_suspension_races_fresh_consume(
        self, db, seed, store, principal
    ) -> None:
        import asyncio

        org_id, agent_id = principal
        await require(seed, org_id, required=True)
        await suspend(seed, org_id, engaged=True)
        grants = [
            await issue(store, org_id, agent_id, f"race-i-{i}") for i in range(12)
        ]

        async def lift():
            await asyncio.sleep(0.01)
            await seed.execute(
                """UPDATE authority_controls SET engaged = FALSE
                   WHERE control = 'requirement_enforcement' AND org_id = $1""",
                org_id,
            )

        results = await asyncio.wait_for(
            asyncio.gather(
                *(consume(store, f"race-i-{i}", g) for i, g in enumerate(grants)),
                lift(),
            ),
            timeout=60.0,
        )
        for outcome in results[:-1]:
            if outcome.outcome is not ConsumptionOutcome.AUTHORISED:
                assert outcome.rejection_reason is (
                    DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING
                )
        await self._assert_no_torn_state(db, grants)

        # With the suspension lifted the requirement is in force again.
        after = await issue(store, org_id, agent_id, "race-i-after")
        late = await consume(store, "race-i-after", after)
        assert late.outcome is ConsumptionOutcome.REJECTED
        assert late.rejection_reason is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING
