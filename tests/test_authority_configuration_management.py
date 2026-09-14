"""A configuration change and its audit record commit together, or not at all.

Invariant 7. There must be no state in which the configuration changed and
no audit exists, or an audit claims a change that rolled back.

These are deterministic: failures are forced with real database triggers and
real constraint violations, not by mocking the application, and every
ordering claim is read out of ``pg_locks`` or proved from inside the
transaction by a trigger that can see what has been written so far.
"""

from __future__ import annotations

import asyncio
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

from api.core.authority.lifecycle import ConsumptionOutcome  # noqa: E402
from api.database import Database  # noqa: E402
from api.persistence.authority_configuration import (  # noqa: E402
    resolve_authority_configuration_on,
)
from api.persistence.authority_configuration_management import (  # noqa: E402
    CONTROL_EVENT,
    REQUIREMENT_EVENT,
    AuthorityConfigurationManagementError,
    apply_authority_configuration_change,
    apply_authority_configuration_change_on,
)
from api.persistence.authority_store import AuthorityStore, IssueOutcome  # noqa: E402

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")
MIGRATOR_URL = os.getenv("ALEMBIC_DATABASE_URL", "")
MANAGEMENT_URL = os.getenv("AUTHORITY_MANAGEMENT_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL and MIGRATOR_URL and MANAGEMENT_URL),
    reason="management atomicity tests need INNTRIS_DB_INTEGRATION=1, "
    "DATABASE_URL, ALEMBIC_DATABASE_URL and AUTHORITY_MANAGEMENT_DATABASE_URL",
)

POLICY_HASH = "b" * 64
BINDING = "c" * 64
FORMAT = "inntris-payment-authority-policy-v1"
ACTION = "financial_transaction"
BLOCKED_FOR = 1.5

ACTOR = "ops@inntris.test"
REASON = "gate 2 invariant 7"


def action_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


# --- Fixtures --------------------------------------------------------------


def _static_policy():
    def resolver(_agent, _action_type, _domain):
        return POLICY_HASH, "revision-1"

    return resolver


@pytest.fixture
def approval() -> str:
    """A fresh approval reference per test.

    administrative_audit_events is append only and never cleaned between
    tests, so a shared reference would make every "exactly one event"
    assertion cumulative -- and would pass or fail depending on test order.
    """
    return f"CHG-{uuid4().hex[:12].upper()}"


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=2, max_size=12)
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
async def management() -> AsyncIterator[asyncpg.Pool]:
    """The trusted management pool: inntris_authority_admin, nothing else."""
    pool = await asyncpg.create_pool(MANAGEMENT_URL, min_size=1, max_size=4)
    try:
        yield pool
    finally:
        await pool.close()


@pytest.fixture
async def writer() -> AsyncIterator[asyncpg.Connection]:
    conn = await asyncpg.connect(MIGRATOR_URL)
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture
async def observer() -> AsyncIterator[asyncpg.Connection]:
    conn = await asyncpg.connect(MIGRATOR_URL)
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture
async def store(db: Database) -> AuthorityStore:
    return AuthorityStore(db, current_policy_resolver=_static_policy())


@pytest.fixture(autouse=True)
async def global_halt_cleanup(writer) -> AsyncIterator[None]:
    """A leaked platform-wide halt would refuse issuance for every other test."""
    try:
        yield
    finally:
        await writer.execute(
            "DELETE FROM authority_controls "
            "WHERE org_id IS NULL AND control = 'authority_issuance'"
        )


async def make_principal(conn) -> tuple[UUID, UUID]:
    """Seed an organisation and one active agent on a privileged CONNECTION."""
    org_id, agent_id = uuid4(), uuid4()
    await conn.execute(
        """INSERT INTO organizations (id,name,billing_tier,contact_email,api_key_hash)
           VALUES ($1,$2,'enterprise',$3,$4)""",
        org_id, f"mgmt-{org_id}", f"mgmt-{org_id}@example.test",
        hashlib.sha256(str(org_id).encode()).digest(),
    )
    await conn.execute(
        """INSERT INTO agents (id,org_id,name,public_key,public_key_fingerprint,
             trust_score,status,daily_limit_usd,per_action_limit_usd,allowed_actions,
             blocked_actions,rate_limit_per_minute,metadata)
           VALUES ($1,$2,$3,$4,$5,95,'active',1000000,1000000,
                   ARRAY['financial_transaction']::TEXT[],ARRAY[]::TEXT[],100000,$6::JSONB)""",
        agent_id, org_id, f"mgmt-agent-{agent_id}", secrets.token_bytes(32),
        hashlib.sha256(str(agent_id).encode()).hexdigest(),
        json.dumps({"sandbox": False,
                    "production_approval_reference": "mgmt",
                    "production_approved_at": "2026-01-01T00:00:00Z",
                    "production_approved_by": "mgmt"}),
    )
    return org_id, agent_id


async def issue(store, org_id, agent_id, ref):
    now = datetime.now(UTC)
    return await store.issue(
        agent_id=agent_id, organisation_id=org_id, issuance_ref=ref,
        execution_action_hash=action_hash(ref), policy_hash=POLICY_HASH,
        policy_snapshot_format=FORMAT, policy_revision="revision-1",
        executor_binding_digest=BINDING, domain="payment", action_type=ACTION,
        minute_start=now.replace(second=0, microsecond=0),
        day_start=now.replace(hour=0, minute=0, second=0, microsecond=0),
        rate_limit_per_minute=100000, daily_limit_usd=Decimal("1000000"),
        amount_usd=Decimal("1"),
    )


async def consume(store, ref, grant):
    return await store.consume(
        grant_id=grant.grant_id,
        execution_action_hash=action_hash(ref),
        executor_binding_digest=BINDING,
        execution_ref=f"exec-{ref}",
    )


async def blocks_for(task: asyncio.Task, seconds: float = BLOCKED_FOR) -> bool:
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=seconds)
    except TimeoutError:
        return True
    return False


async def audit_events(conn, approval: str) -> list:
    return await conn.fetch(
        "SELECT * FROM administrative_audit_events WHERE approval_reference = $1",
        approval,
    )


async def requirement_rows(conn, org_id) -> list:
    return await conn.fetch(
        "SELECT * FROM authority_requirements WHERE org_id = $1", org_id
    )


# --- Lock observation ------------------------------------------------------

_CONFIG_LOCK_IDS = """
SELECT hashtext(authority_config_lock_namespace())::OID  AS classid,
       hashtext(authority_config_lock_key(NULL))::OID    AS global_objid,
       hashtext(authority_config_lock_key($1))::OID      AS org_objid
"""


async def config_locks(observer, pid: int, org_id: UUID) -> dict[str, set[str]]:
    ids = await observer.fetchrow(_CONFIG_LOCK_IDS, org_id)
    rows = await observer.fetch(
        """SELECT objid, mode, granted FROM pg_locks
           WHERE locktype = 'advisory' AND pid = $1 AND objsubid = 2
             AND classid = $2""",
        pid, ids["classid"],
    )
    out: dict[str, set[str]] = {
        "global": set(), "org": set(), "waiting_global": set(), "waiting_org": set(),
    }
    for row in rows:
        if row["objid"] == ids["global_objid"]:
            key = "global" if row["granted"] else "waiting_global"
        elif row["objid"] == ids["org_objid"]:
            key = "org" if row["granted"] else "waiting_org"
        else:
            continue
        out[key].add(row["mode"])
    return out


async def holds_any_chain_lock(observer, pid: int) -> bool:
    """Any ONE-int advisory lock -- the forensic chain uses that form."""
    return bool(
        await observer.fetchval(
            """SELECT COUNT(*) FROM pg_locks
               WHERE locktype = 'advisory' AND pid = $1 AND granted
                 AND objsubid = 1""",
            pid,
        )
    )


async def park_issuance(store, org_id, agent_id, ref):
    """Leave an issuance in flight past both configuration locks."""
    parker = await asyncpg.connect(DATABASE_URL)
    tx = parker.transaction()
    await tx.start()
    await parker.fetchrow("SELECT id FROM agents WHERE id = $1 FOR UPDATE", agent_id)
    task = asyncio.create_task(issue(store, org_id, agent_id, ref))
    assert await blocks_for(task), "issuance did not park on the principal row"

    async def unpark():
        await tx.rollback()
        await parker.close(timeout=5)

    return task, unpark


async def park_consumption(store, grant, ref):
    """Leave a consumption in flight holding CONFIG_ORG and the forensic chain.

    ``consume()`` reaches the grant row after CONFIG_ORG, the chain lock and
    the principal row, so holding the grant row parks it with exactly the
    locks this contention test is about.
    """
    parker = await asyncpg.connect(DATABASE_URL)
    tx = parker.transaction()
    await tx.start()
    await parker.fetchrow(
        "SELECT id FROM execution_authority_grants WHERE id = $1 FOR UPDATE",
        grant.grant_id,
    )
    task = asyncio.create_task(consume(store, ref, grant))
    assert await blocks_for(task), "consumption did not park on the grant row"

    async def unpark():
        await tx.rollback()
        await parker.close(timeout=5)

    return task, unpark


# --- A1-A3: the change and its audit commit together ----------------------


class TestCommittedTogether:
    async def test_A1_requirement_change_and_audit_commit_together(
        self, management, writer, approval
    ) -> None:
        org_id, _agent = await make_principal(writer)

        change = await apply_authority_configuration_change(
            management, setting="requirement", new_value=True,
            organisation_id=org_id, actor=ACTOR, reason=REASON,
            approval_reference=approval,
        )

        rows = await requirement_rows(writer, org_id)
        assert len(rows) == 1
        assert rows[0]["required"] is True
        assert rows[0]["id"] == change.configuration_row_id
        assert rows[0]["changed_by"] == ACTOR
        assert rows[0]["approval_reference"] == approval

        events = await audit_events(writer, approval)
        assert len(events) == 1, "exactly one audit event per change"
        event = events[0]
        assert event["id"] == change.audit_event_id
        assert event["event_type"] == REQUIREMENT_EVENT
        assert event["scope"] == "organisation"
        assert event["org_id"] == org_id
        assert event["actor"] == ACTOR
        details = json.loads(event["details"])
        assert details["configuration_table"] == "authority_requirements"
        assert details["configuration_row_id"] == str(change.configuration_row_id)
        assert details["old_value"] is None, "no row existed; the change created it"
        assert details["new_value"] is True
        assert details["reason"] == REASON
        assert details["correlation_id"] == str(change.audit_event_id)

    async def test_A2_org_control_change_and_audit_commit_together(
        self, management, writer, approval
    ) -> None:
        org_id, _agent = await make_principal(writer)

        change = await apply_authority_configuration_change(
            management, setting="requirement_enforcement", new_value=True,
            organisation_id=org_id, actor=ACTOR, reason=REASON,
            approval_reference=approval,
        )

        row = await writer.fetchrow(
            "SELECT * FROM authority_controls WHERE id = $1",
            change.configuration_row_id,
        )
        assert row is not None
        assert row["control"] == "requirement_enforcement"
        assert row["engaged"] is True
        assert row["org_id"] == org_id

        events = await audit_events(writer, approval)
        assert len(events) == 1
        assert events[0]["event_type"] == CONTROL_EVENT
        assert events[0]["scope"] == "organisation"
        details = json.loads(events[0]["details"])
        assert details["setting"] == "requirement_enforcement"
        assert details["configuration_table"] == "authority_controls"

    async def test_A3_global_issuance_halt_and_audit_commit_together(
        self, management, writer, approval
    ) -> None:
        change = await apply_authority_configuration_change(
            management, setting="authority_issuance", new_value=True,
            actor=ACTOR, reason="platform incident", approval_reference=approval,
        )
        assert change.scope == "platform"
        assert change.organisation_id is None

        row = await writer.fetchrow(
            "SELECT * FROM authority_controls WHERE id = $1",
            change.configuration_row_id,
        )
        assert row is not None
        assert row["org_id"] is None
        assert row["engaged"] is True

        events = await audit_events(writer, approval)
        assert len(events) == 1
        assert events[0]["scope"] == "platform"
        assert events[0]["org_id"] is None, (
            "a platform change has no tenant; recording one would be a lie"
        )

    async def test_a_platform_requirement_enforcement_suspension_is_refused(
        self, management, writer
    ) -> None:
        """Migration 028's rule, enforced where the caller can see why."""
        with pytest.raises(AuthorityConfigurationManagementError, match="platform-wide"):
            await apply_authority_configuration_change(
                management, setting="requirement_enforcement", new_value=True,
                actor=ACTOR, reason=REASON, approval_reference="CHG-BAD",
            )
        assert not await audit_events(writer, "CHG-BAD")


# --- A4, A5, A6, A14: neither, or both ------------------------------------


class TestAtomicity:
    async def _fail_audit_inserts(self, writer, sentinel: str) -> None:
        await writer.execute(
            f"""
            CREATE OR REPLACE FUNCTION test_fail_admin_audit()
            RETURNS TRIGGER AS $t$
            BEGIN
                IF NEW.approval_reference = '{sentinel}' THEN
                    RAISE EXCEPTION 'forced administrative audit failure';
                END IF;
                RETURN NEW;
            END;
            $t$ LANGUAGE plpgsql;
            DROP TRIGGER IF EXISTS test_fail_admin_audit ON administrative_audit_events;
            CREATE TRIGGER test_fail_admin_audit
                BEFORE INSERT ON administrative_audit_events
                FOR EACH ROW EXECUTE FUNCTION test_fail_admin_audit();
            """
        )

    async def _restore_audit_inserts(self, writer) -> None:
        await writer.execute(
            "DROP TRIGGER IF EXISTS test_fail_admin_audit ON administrative_audit_events;"
            "DROP FUNCTION IF EXISTS test_fail_admin_audit();"
        )

    async def test_A4_audit_failure_rolls_back_the_configuration_change(
        self, management, writer
    ) -> None:
        org_id, _agent = await make_principal(writer)
        sentinel = "CHG-AUDIT-FAILS"

        # An existing committed state, so "unchanged" is a real assertion and
        # not just "nothing there".
        await apply_authority_configuration_change(
            management, setting="requirement", new_value=False,
            organisation_id=org_id, actor=ACTOR, reason=REASON,
            approval_reference="CHG-BASE",
        )

        await self._fail_audit_inserts(writer, sentinel)
        try:
            with pytest.raises(asyncpg.PostgresError, match="forced administrative"):
                await apply_authority_configuration_change(
                    management, setting="requirement", new_value=True,
                    organisation_id=org_id, actor=ACTOR, reason=REASON,
                    approval_reference=sentinel,
                )
        finally:
            await self._restore_audit_inserts(writer)

        rows = await requirement_rows(writer, org_id)
        assert len(rows) == 1
        assert rows[0]["required"] is False, (
            "the configuration change survived an audit failure; there is now "
            "a policy change with no record of who made it"
        )
        assert rows[0]["approval_reference"] == "CHG-BASE"
        assert not await audit_events(writer, sentinel)

    async def test_A14_an_audit_failure_cannot_become_a_successful_change(
        self, management, writer, db
    ) -> None:
        """The rolled-back change must not reach the decision path either."""
        org_id, agent_id = await make_principal(writer)
        sentinel = "CHG-AUDIT-FAILS-14"

        await self._fail_audit_inserts(writer, sentinel)
        try:
            with pytest.raises(asyncpg.PostgresError):
                await apply_authority_configuration_change(
                    management, setting="requirement", new_value=True,
                    organisation_id=org_id, actor=ACTOR, reason=REASON,
                    approval_reference=sentinel,
                )
        finally:
            await self._restore_audit_inserts(writer)

        async with db.acquire() as conn:
            configuration = await resolve_authority_configuration_on(
                conn, organisation_id=org_id, principal_id=agent_id,
                action_class=ACTION,
            )
        assert configuration.effective_required is False, (
            "a change whose audit failed is being enforced; the failure was "
            "converted into a successful configuration change"
        )
        assert configuration.requirement_id is None

    async def test_A5_a_configuration_failure_creates_no_audit_event(
        self, management, writer
    ) -> None:
        """A principal from another organisation: 027's composite foreign key."""
        org_id, _agent = await make_principal(writer)
        _other_org, other_agent = await make_principal(writer)
        approval = "CHG-CONFIG-FAILS"

        with pytest.raises(asyncpg.PostgresError):
            await apply_authority_configuration_change(
                management, setting="requirement", new_value=True,
                organisation_id=org_id, principal_id=other_agent,
                actor=ACTOR, reason=REASON, approval_reference=approval,
            )

        assert not await requirement_rows(writer, org_id)
        assert not await audit_events(writer, approval), (
            "an audit event records a configuration change that was refused"
        )

    async def test_A6_rolling_back_the_transaction_leaves_neither(
        self, management, writer
    ) -> None:
        org_id, _agent = await make_principal(writer)
        approval = "CHG-ROLLED-BACK"

        async with management.acquire() as conn:
            tx = conn.transaction()
            await tx.start()
            change = await apply_authority_configuration_change_on(
                conn, setting="requirement", new_value=True,
                organisation_id=org_id, actor=ACTOR, reason=REASON,
                approval_reference=approval,
            )
            # Both rows exist inside the transaction...
            assert await conn.fetchval(
                "SELECT COUNT(*) FROM authority_requirements WHERE id = $1",
                change.configuration_row_id,
            ) == 1
            assert await conn.fetchval(
                "SELECT COUNT(*) FROM administrative_audit_events WHERE id = $1",
                change.audit_event_id,
            ) == 1
            await tx.rollback()

        # ...and neither survives it.
        assert not await requirement_rows(writer, org_id)
        assert not await audit_events(writer, approval)


# --- A7: configuration first, and the chain is never taken ----------------


class TestOrdering:
    async def test_A7_the_configuration_row_exists_before_the_audit_insert(
        self, management, writer, approval
    ) -> None:
        """Proved from inside the transaction, by the database.

        A trigger on the audit table refuses the insert unless the
        configuration row it names is already written in this transaction. If
        the audit row were written first there would be nothing to find.
        """
        org_id, _agent = await make_principal(writer)
        await writer.execute(
            """
            CREATE OR REPLACE FUNCTION test_audit_requires_config()
            RETURNS TRIGGER AS $t$
            BEGIN
                IF NEW.event_type = 'authority.configuration.requirement_changed'
                   AND NOT EXISTS (
                        SELECT 1 FROM authority_requirements
                         WHERE id = (NEW.details->>'configuration_row_id')::UUID
                           AND required = (NEW.details->>'new_value')::BOOLEAN
                   ) THEN
                    RAISE EXCEPTION
                        'the audit record was written before its configuration row';
                END IF;
                RETURN NEW;
            END;
            $t$ LANGUAGE plpgsql;
            DROP TRIGGER IF EXISTS test_audit_requires_config ON administrative_audit_events;
            CREATE TRIGGER test_audit_requires_config
                BEFORE INSERT ON administrative_audit_events
                FOR EACH ROW EXECUTE FUNCTION test_audit_requires_config();
            """
        )
        try:
            change = await apply_authority_configuration_change(
                management, setting="requirement", new_value=True,
                organisation_id=org_id, actor=ACTOR, reason=REASON,
                approval_reference=approval,
            )
            assert change.new_value is True
        finally:
            await writer.execute(
                "DROP TRIGGER IF EXISTS test_audit_requires_config "
                "ON administrative_audit_events;"
                "DROP FUNCTION IF EXISTS test_audit_requires_config();"
            )

    async def test_A7_the_management_transaction_never_takes_the_forensic_chain(
        self, management, writer, observer, approval
    ) -> None:
        """No CONFIG -> CHAIN edge exists on this path, so none can invert."""
        org_id, _agent = await make_principal(writer)

        async with management.acquire() as conn:
            pid = await conn.fetchval("SELECT pg_backend_pid()")
            tx = conn.transaction()
            await tx.start()
            await apply_authority_configuration_change_on(
                conn, setting="requirement", new_value=True,
                organisation_id=org_id, actor=ACTOR, reason=REASON,
                approval_reference=approval,
            )
            # Measured with both rows written and the transaction still open.
            seen = await config_locks(observer, pid, org_id)
            assert "ExclusiveLock" in seen["global"], (
                f"the management transaction does not hold CONFIG_GLOBAL: {seen}"
            )
            assert "ExclusiveLock" in seen["org"], (
                f"the management transaction does not hold CONFIG_ORG: {seen}"
            )
            assert not await holds_any_chain_lock(observer, pid), (
                "the management transaction holds a forensic-chain lock while "
                "holding the configuration locks -- CONFIG -> CHAIN, which "
                "inverts against consumption"
            )
            await tx.commit()


# --- A8, A9, A10: contention ----------------------------------------------


class TestContention:
    async def test_A8_management_waits_for_in_flight_issuance_global_then_org(
        self, management, store, writer, observer, approval
    ) -> None:
        org_id, agent_id = await make_principal(writer)
        task, unpark = await park_issuance(store, org_id, agent_id, "a8")
        try:
            async with management.acquire() as conn:
                pid = await conn.fetchval("SELECT pg_backend_pid()")
                tx = conn.transaction()
                await tx.start()
                pending = asyncio.create_task(
                    apply_authority_configuration_change_on(
                        conn, setting="authority_issuance", new_value=True,
                        organisation_id=org_id, actor=ACTOR, reason=REASON,
                        approval_reference=approval,
                    )
                )
                assert await blocks_for(pending), (
                    "a management change committed while an issuance was in "
                    "flight for that organisation"
                )
                seen = await config_locks(observer, pid, org_id)
                assert seen["waiting_global"], (
                    f"the management change is stalled elsewhere: {seen}"
                )
                assert not seen["org"], (
                    "it holds CONFIG_ORG while waiting for CONFIG_GLOBAL -- "
                    f"the one inversion the hierarchy forbids: {seen}"
                )

                await unpark()
                result = await asyncio.wait_for(task, timeout=20.0)
                assert result.outcome is IssueOutcome.ISSUED

                await asyncio.wait_for(pending, timeout=20.0)
                seen = await config_locks(observer, pid, org_id)
                assert seen["global"] and seen["org"]
                await tx.commit()
        finally:
            if not task.done():
                await unpark()
                await asyncio.wait_for(task, timeout=20.0)

        events = await audit_events(writer, approval)
        assert len(events) == 1, "the change committed without its audit record"

    async def test_A9_management_waits_for_in_flight_consumption_no_inversion(
        self, management, store, writer, observer, approval
    ) -> None:
        org_id, agent_id = await make_principal(writer)
        grant = await issue(store, org_id, agent_id, "a9")
        task, unpark = await park_consumption(store, grant, "a9")
        try:
            async with management.acquire() as conn:
                pid = await conn.fetchval("SELECT pg_backend_pid()")
                tx = conn.transaction()
                await tx.start()
                pending = asyncio.create_task(
                    apply_authority_configuration_change_on(
                        conn, setting="requirement", new_value=True,
                        organisation_id=org_id, actor=ACTOR, reason=REASON,
                        approval_reference=approval,
                    )
                )
                assert await blocks_for(pending), (
                    "a management change committed while a consumption held "
                    "the organisation configuration lock"
                )
                seen = await config_locks(observer, pid, org_id)
                assert seen["waiting_org"], f"stalled elsewhere: {seen}"
                assert seen["global"], (
                    "it is waiting for CONFIG_ORG without holding "
                    f"CONFIG_GLOBAL; the hierarchy is not total: {seen}"
                )
                assert not await holds_any_chain_lock(observer, pid), (
                    "the management change holds a forensic-chain lock while "
                    "waiting for the configuration lock -- the CONFIG/CHAIN "
                    "inversion Gate 7 was opened to remove"
                )

                await unpark()
                spent = await asyncio.wait_for(task, timeout=20.0)
                assert spent.outcome is ConsumptionOutcome.AUTHORISED

                await asyncio.wait_for(pending, timeout=20.0)
                await tx.commit()
        finally:
            if not task.done():
                await unpark()
                await asyncio.wait_for(task, timeout=20.0)

        assert len(await audit_events(writer, approval)) == 1

    async def test_A10_two_management_writers_of_different_shapes_do_not_deadlock(
        self, writer, approval
    ) -> None:
        """Opposite scope orders in one transaction each. No cycle exists."""
        org_a, _a = await make_principal(writer)
        org_b, _b = await make_principal(writer)
        first_approval, second_approval = f"{approval}-W1", f"{approval}-W2"

        first = await asyncpg.connect(MANAGEMENT_URL)
        second = await asyncpg.connect(MANAGEMENT_URL)
        try:
            tx1 = first.transaction()
            await tx1.start()
            # Organisation first, then platform.
            await apply_authority_configuration_change_on(
                first, setting="requirement", new_value=True,
                organisation_id=org_a, actor=ACTOR, reason=REASON,
                approval_reference=first_approval,
            )

            tx2 = second.transaction()
            await tx2.start()

            async def platform_then_org():
                # Platform first, then a different organisation.
                await apply_authority_configuration_change_on(
                    second, setting="authority_issuance", new_value=False,
                    actor=ACTOR, reason=REASON, approval_reference=second_approval,
                )
                await apply_authority_configuration_change_on(
                    second, setting="requirement", new_value=True,
                    organisation_id=org_b, actor=ACTOR, reason=REASON,
                    approval_reference=second_approval,
                )

            pending = asyncio.create_task(platform_then_org())
            assert await blocks_for(pending), (
                "the second management writer did not serialise on the "
                "platform configuration lock"
            )

            await apply_authority_configuration_change_on(
                first, setting="authority_issuance", new_value=False,
                actor=ACTOR, reason=REASON, approval_reference=first_approval,
            )
            await tx1.commit()

            # No 40P01: there is no CONFIG_ORG -> CONFIG_GLOBAL edge to close
            # a cycle with.
            await asyncio.wait_for(pending, timeout=20.0)
            await tx2.commit()
        finally:
            await first.close(timeout=5)
            await second.close(timeout=5)

        assert len(await audit_events(writer, first_approval)) == 2
        assert len(await audit_events(writer, second_approval)) == 2


# --- A11, A12, A13: the record, and who may write it ----------------------


class TestRecordAndAuthority:
    async def test_A11_old_and_new_values_match_the_committed_transition(
        self, management, writer
    ) -> None:
        org_id, _agent = await make_principal(writer)

        created = await apply_authority_configuration_change(
            management, setting="requirement", new_value=False,
            organisation_id=org_id, actor=ACTOR, reason="initial",
            approval_reference="CHG-T1",
        )
        assert created.old_value is None and created.created_configuration
        assert created.new_value is False

        changed = await apply_authority_configuration_change(
            management, setting="requirement", new_value=True,
            organisation_id=org_id, actor=ACTOR, reason="tightened",
            approval_reference="CHG-T2",
        )
        assert changed.old_value is False
        assert changed.new_value is True
        assert changed.configuration_row_id == created.configuration_row_id, (
            "the second change created a second row instead of replacing one"
        )

        row = await writer.fetchrow(
            "SELECT required FROM authority_requirements WHERE id = $1",
            changed.configuration_row_id,
        )
        assert row["required"] is True

        details = json.loads((await audit_events(writer, "CHG-T2"))[0]["details"])
        assert details["old_value"] is False
        assert details["new_value"] is True
        assert details["new_value"] == row["required"], (
            "the audit record names a transition the table does not show"
        )

        # A no-op change is still a recorded decision, and still says so.
        repeated = await apply_authority_configuration_change(
            management, setting="requirement", new_value=True,
            organisation_id=org_id, actor=ACTOR, reason="reaffirmed",
            approval_reference="CHG-T3",
        )
        assert repeated.old_value is True and repeated.new_value is True

    @pytest.mark.parametrize("field", ["actor", "reason", "approval_reference"])
    @pytest.mark.parametrize("value", [None, "", "   "])
    async def test_A12_the_contract_fields_cannot_be_silently_absent(
        self, management, writer, field, value
    ) -> None:
        org_id, _agent = await make_principal(writer)
        arguments = {
            "setting": "requirement", "new_value": True,
            "organisation_id": org_id, "actor": ACTOR, "reason": REASON,
            "approval_reference": "CHG-MISSING",
        }
        arguments[field] = value

        with pytest.raises(AuthorityConfigurationManagementError, match=field):
            await apply_authority_configuration_change(management, **arguments)

        assert not await requirement_rows(writer, org_id), (
            "a change was written without a complete management contract"
        )
        assert not await audit_events(writer, "CHG-MISSING")

    async def test_A13_the_runtime_role_cannot_invoke_the_primitive(
        self, db, writer
    ) -> None:
        org_id, _agent = await make_principal(writer)
        approval = "CHG-RUNTIME"

        with pytest.raises(asyncpg.PostgresError) as refused:
            await apply_authority_configuration_change(
                db, setting="requirement", new_value=True,
                organisation_id=org_id, actor=ACTOR, reason=REASON,
                approval_reference=approval,
            )
        assert "permission denied" in str(refused.value).lower()

        assert not await requirement_rows(writer, org_id)
        assert not await audit_events(writer, approval)

    async def test_A13_the_runtime_role_cannot_write_the_tables_directly(
        self, db, writer
    ) -> None:
        org_id, _agent = await make_principal(writer)
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.execute(
                    """INSERT INTO authority_requirements
                         (org_id,agent_id,action_class,required,reason,
                          changed_by,approval_reference)
                       VALUES ($1,NULL,NULL,TRUE,'direct','direct','direct')""",
                    org_id,
                )
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.execute(
                    """INSERT INTO authority_controls
                         (control,org_id,engaged,reason,changed_by,approval_reference)
                       VALUES ('authority_issuance',$1,TRUE,'d','d','d')""",
                    org_id,
                )
        assert not await requirement_rows(writer, org_id)

    async def test_A13_the_tenant_role_reaches_none_of_it(self, writer) -> None:
        privileges = await writer.fetchrow(
            """SELECT
                 has_table_privilege('inntris_api','authority_requirements','INSERT') AS req_ins,
                 has_table_privilege('inntris_api','authority_requirements','UPDATE') AS req_upd,
                 has_table_privilege('inntris_api','authority_controls','INSERT') AS ctl_ins,
                 has_table_privilege('inntris_api','authority_controls','UPDATE') AS ctl_upd,
                 has_table_privilege('inntris_api','administrative_audit_events','SELECT') AS audit_sel,
                 has_table_privilege('inntris_api','administrative_audit_events','INSERT') AS audit_ins"""
        )
        assert not any(privileges.values()), (
            f"the tenant role reaches authority management: {dict(privileges)}"
        )

        # ...and the management role is not a second superuser.
        role = await writer.fetchrow(
            "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb "
            "FROM pg_roles WHERE rolname = 'inntris_authority_admin'"
        )
        assert role is not None
        assert not any(role.values()), (
            f"the management role has privileged attributes: {dict(role)}"
        )
