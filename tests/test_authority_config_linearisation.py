"""Configuration changes are linearised against fresh consumption.

The acceptance statement:

    If a configuration change commits before a fresh consumption commits,
    that consumption either observed the new configuration, or was already
    linearised before the change because it held the shared configuration
    lock that prevented the change from committing.

These are deterministic interleavings driven from two connections, not
timing loops: each test blocks on the lock it is asserting about and
verifies the other side genuinely cannot proceed.
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

from api.core.authority.decision import DecisionReason  # noqa: E402
from api.core.authority.lifecycle import ConsumptionOutcome  # noqa: E402
from api.database import Database  # noqa: E402
from api.persistence.authority_store import AuthorityStore  # noqa: E402

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")
MIGRATOR_URL = os.getenv("ALEMBIC_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL and MIGRATOR_URL),
    reason="linearisation tests need INNTRIS_DB_INTEGRATION=1, DATABASE_URL and "
    "ALEMBIC_DATABASE_URL",
)

POLICY_HASH = "b" * 64
BINDING = "c" * 64
FORMAT = "inntris-payment-authority-policy-v1"
ACTION = "financial_transaction"
#: Long enough that a wait is unambiguous, short enough to keep tests quick.
BLOCKED_FOR = 1.5


def action_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


#: Take the shared lock exactly as production does -- through the same
#: central helper. A test that built the key itself would pass while the
#: application addressed a different lock, which is the failure mode these
#: tests exist to catch.
async def hold_shared_config_lock(conn, org_id) -> None:
    from api.persistence.authority_configuration import (
        lock_authority_configuration_shared,
    )

    await lock_authority_configuration_shared(conn, organisation_id=org_id)


def _static_policy():
    def resolver(_agent, _action_type, _domain):
        return POLICY_HASH, "revision-1"

    return resolver


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=4, max_size=16)
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
async def writer() -> AsyncIterator[asyncpg.Connection]:
    conn = await asyncpg.connect(MIGRATOR_URL)
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture
async def store(db: Database) -> AuthorityStore:
    return AuthorityStore(db, current_policy_resolver=_static_policy())


async def make_principal(db: Database) -> tuple[UUID, UUID]:
    org_id, agent_id = uuid4(), uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """INSERT INTO organizations (id,name,billing_tier,contact_email,api_key_hash)
               VALUES ($1,$2,'enterprise',$3,$4)""",
            org_id, f"lin-{org_id}", f"lin-{org_id}@example.test",
            hashlib.sha256(str(org_id).encode()).digest(),
        )
        await conn.execute(
            """INSERT INTO agents (id,org_id,name,public_key,public_key_fingerprint,
                 trust_score,status,daily_limit_usd,per_action_limit_usd,allowed_actions,
                 blocked_actions,rate_limit_per_minute,metadata)
               VALUES ($1,$2,$3,$4,$5,95,'active',1000000,1000000,
                       ARRAY['financial_transaction']::TEXT[],ARRAY[]::TEXT[],100000,$6::JSONB)""",
            agent_id, org_id, f"lin-agent-{agent_id}", secrets.token_bytes(32),
            hashlib.sha256(str(agent_id).encode()).hexdigest(),
            json.dumps({"sandbox": False,
                        "production_approval_reference": "lin",
                        "production_approved_at": "2026-01-01T00:00:00Z",
                        "production_approved_by": "lin"}),
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


async def set_required(conn, org_id, required):
    await conn.execute(
        """INSERT INTO authority_requirements
             (org_id,agent_id,action_class,required,reason,changed_by,approval_reference)
           VALUES ($1,NULL,NULL,$2,'t','lin','A')
           ON CONFLICT (org_id, scope_key) DO UPDATE SET required = EXCLUDED.required""",
        org_id, required,
    )


async def set_suspension(conn, org_id, engaged):
    await conn.execute(
        """INSERT INTO authority_controls
             (control,org_id,engaged,reason,changed_by,approval_reference)
           VALUES ('requirement_enforcement',$1,$2,'t','lin','A')
           ON CONFLICT (control, scope_key) DO UPDATE SET engaged = EXCLUDED.engaged""",
        org_id, engaged,
    )


async def blocks_for(task: asyncio.Task, seconds: float = BLOCKED_FOR) -> bool:
    """True if the task is still waiting after `seconds`."""
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=seconds)
    except TimeoutError:
        return True
    return False


class TestWriterWaitsForAnInFlightConsumption:
    """H1 / I1 -- the consumption is linearised BEFORE the change."""

    async def _writer_blocked_by_shared_holder(self, writer, org_id, mutate):
        """Hold the shared lock as a consumer would; the writer must wait."""
        holder = await asyncpg.connect(DATABASE_URL)
        try:
            tx = holder.transaction()
            await tx.start()
            await hold_shared_config_lock(holder, org_id)

            writer_tx = writer.transaction()
            await writer_tx.start()
            task = asyncio.create_task(mutate(writer))
            assert await blocks_for(task), (
                "the configuration writer committed while a consumption held "
                "the shared lock; the change is not linearised"
            )

            # The consumption commits; only now may the writer proceed.
            await tx.rollback()
            await asyncio.wait_for(task, timeout=20.0)
            await writer_tx.commit()
        finally:
            await holder.close(timeout=5)

    async def test_H1_a_tightening_cannot_commit_under_a_live_consumption(
        self, db, writer, store
    ) -> None:
        org_id, agent_id = await make_principal(db)
        await set_required(writer, org_id, False)
        grant = await issue(store, org_id, agent_id, "h1")

        await self._writer_blocked_by_shared_holder(
            writer, org_id, lambda c: set_required(c, org_id, True)
        )

        # After the change is committed, a fresh consume observes it.
        later = await consume(store, "h1", grant)
        assert later.outcome is ConsumptionOutcome.REJECTED
        assert later.rejection_reason is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING

    async def test_I1_lifting_a_suspension_cannot_commit_under_a_live_consumption(
        self, db, writer, store
    ) -> None:
        org_id, agent_id = await make_principal(db)
        await set_required(writer, org_id, True)
        await set_suspension(writer, org_id, True)
        grant = await issue(store, org_id, agent_id, "i1")

        await self._writer_blocked_by_shared_holder(
            writer, org_id, lambda c: set_suspension(c, org_id, False)
        )

        later = await consume(store, "i1", grant)
        assert later.outcome is ConsumptionOutcome.REJECTED
        assert later.rejection_reason is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING


class TestConsumptionWaitsForAnInFlightWriter:
    """H2 / I2 -- the consumption is linearised AFTER the change."""

    async def _consumer_blocked_then_observes(self, writer, store, grant, mutate):
        writer_tx = writer.transaction()
        await writer_tx.start()
        await mutate(writer)  # holds the EXCLUSIVE lock, uncommitted

        task = asyncio.create_task(consume(store, "blocked", grant))
        assert await blocks_for(task), (
            "the consumption proceeded while a configuration change held the "
            "exclusive lock; it could have observed stale configuration"
        )

        await writer_tx.commit()
        return await asyncio.wait_for(task, timeout=20.0)

    async def test_H2_a_consumer_waits_for_a_tightening_and_then_sees_it(
        self, db, writer, store
    ) -> None:
        org_id, agent_id = await make_principal(db)
        await set_required(writer, org_id, False)
        grant = await issue(store, org_id, agent_id, "blocked")

        result = await self._consumer_blocked_then_observes(
            writer, store, grant, lambda c: set_required(c, org_id, True)
        )
        assert result.outcome is ConsumptionOutcome.REJECTED, (
            "the consumer resumed but did not observe the committed tightening"
        )
        assert result.rejection_reason is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING

    async def test_I2_a_consumer_waits_for_a_lifted_suspension_and_then_sees_it(
        self, db, writer, store
    ) -> None:
        org_id, agent_id = await make_principal(db)
        await set_required(writer, org_id, True)
        await set_suspension(writer, org_id, True)
        grant = await issue(store, org_id, agent_id, "blocked")

        result = await self._consumer_blocked_then_observes(
            writer, store, grant, lambda c: set_suspension(c, org_id, False)
        )
        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.rejection_reason is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING


class TestSharedLockDoesNotSerialiseConsumers:
    async def test_two_consumers_in_one_org_both_hold_the_shared_lock(
        self, db
    ) -> None:
        org_id, _agent = await make_principal(db)
        a = await asyncpg.connect(DATABASE_URL)
        b = await asyncpg.connect(DATABASE_URL)
        try:
            ta, tb = a.transaction(), b.transaction()
            await ta.start()
            await tb.start()
            await hold_shared_config_lock(a, org_id)
            # The second must NOT wait: shared holders are compatible.
            await asyncio.wait_for(hold_shared_config_lock(b, org_id), timeout=5.0)
            await ta.rollback()
            await tb.rollback()
        finally:
            await a.close(timeout=5)
            await b.close(timeout=5)

    async def test_a_writer_waits_for_both_shared_holders(self, db, writer) -> None:
        org_id, _agent = await make_principal(db)
        a = await asyncpg.connect(DATABASE_URL)
        b = await asyncpg.connect(DATABASE_URL)
        try:
            ta, tb = a.transaction(), b.transaction()
            await ta.start()
            await tb.start()
            for conn in (a, b):
                await hold_shared_config_lock(conn, org_id)

            writer_tx = writer.transaction()
            await writer_tx.start()
            task = asyncio.create_task(set_required(writer, org_id, True))
            assert await blocks_for(task)

            await ta.rollback()
            assert await blocks_for(task), "the writer proceeded with one reader still live"

            await tb.rollback()
            await asyncio.wait_for(task, timeout=20.0)
            await writer_tx.commit()
        finally:
            await a.close(timeout=5)
            await b.close(timeout=5)

    async def test_a_different_organisation_is_not_blocked(self, db, writer, store) -> None:
        """Different organisations use different keys and never interact."""
        blocked_org, _a = await make_principal(db)
        other_org, other_agent = await make_principal(db)
        grant = await issue(store, other_org, other_agent, "cross-org")

        writer_tx = writer.transaction()
        await writer_tx.start()
        await set_required(writer, blocked_org, True)  # holds blocked_org exclusive
        try:
            result = await asyncio.wait_for(consume(store, "cross-org", grant), timeout=15.0)
        finally:
            await writer_tx.rollback()
        assert result.outcome is ConsumptionOutcome.AUTHORISED


class TestNoDeadlockWithTheForensicChain:
    async def test_concurrent_consumes_and_a_config_write_do_not_deadlock(
        self, db, writer, store
    ) -> None:
        """The config lock precedes the chain lock, so no ABBA is possible."""
        org_id, agent_id = await make_principal(db)
        await set_required(writer, org_id, False)
        grants = [await issue(store, org_id, agent_id, f"nd-{i}") for i in range(12)]

        async def flip():
            await asyncio.sleep(0.01)
            conn = await asyncpg.connect(MIGRATOR_URL)
            try:
                await set_required(conn, org_id, True)
            finally:
                await conn.close()

        results = await asyncio.wait_for(
            asyncio.gather(
                *(consume(store, f"nd-{i}", g) for i, g in enumerate(grants)),
                flip(),
                return_exceptions=True,
            ),
            timeout=90.0,
        )
        deadlocks = [
            r for r in results
            if isinstance(r, BaseException) and getattr(r, "sqlstate", None) == "40P01"
        ]
        assert not deadlocks, f"{len(deadlocks)} deadlock(s) under config contention"
        other = [
            r for r in results
            if isinstance(r, BaseException) and getattr(r, "sqlstate", None) != "40P01"
        ]
        assert not other, f"unexpected failures: {other[:2]}"


class TestIssuanceIsLinearisedToo:
    """Part 2 -- the counterexample on the ISSUANCE side.

        T1  evaluation reads: issuance not halted, requirement permissive
        T2  operator engages the halt (or tightens) and COMMITS
        T1  the grant is then committed under the configuration read before T2

    The evaluating service reads the configuration on its own connection, so
    that read is a different transaction from the one that writes the grant.
    ``issue`` therefore takes the shared configuration lock and RE-READS on
    its own connection: the read that gates issuance shares its lifetime
    with the INSERT that commits the grant.
    """

    async def test_J1_issuance_waits_for_a_committing_halt_and_then_refuses(
        self, db, writer, store
    ) -> None:
        org_id, agent_id = await make_principal(db)

        writer_tx = writer.transaction()
        await writer_tx.start()
        await writer.execute(
            """INSERT INTO authority_controls
                 (control,org_id,engaged,reason,changed_by,approval_reference)
               VALUES ('authority_issuance',$1,TRUE,'t','lin','A')""",
            org_id,
        )  # holds the EXCLUSIVE lock, uncommitted

        task = asyncio.create_task(issue(store, org_id, agent_id, "j1"))
        assert await blocks_for(task), (
            "issuance proceeded while a halt held the exclusive configuration "
            "lock; it could have committed a grant under stale configuration"
        )

        await writer_tx.commit()
        result = await asyncio.wait_for(task, timeout=20.0)
        assert result.grant_id is None, "a grant was issued after the halt committed"
        assert result.reason is DecisionReason.AUTHORITY_ISSUANCE_HALTED

    async def test_J2_a_committing_tightening_cannot_outrun_issuance(
        self, db, writer, store
    ) -> None:
        org_id, agent_id = await make_principal(db)
        await set_required(writer, org_id, False)

        # Hold the shared lock as an in-flight issuance does.
        holder = await asyncpg.connect(DATABASE_URL)
        try:
            tx = holder.transaction()
            await tx.start()
            await hold_shared_config_lock(holder, org_id)

            writer_tx = writer.transaction()
            await writer_tx.start()
            task = asyncio.create_task(set_required(writer, org_id, True))
            assert await blocks_for(task), (
                "a tightening committed while an issuance held the shared lock"
            )
            await tx.rollback()
            await asyncio.wait_for(task, timeout=20.0)
            await writer_tx.commit()
        finally:
            await holder.close(timeout=5)

        # Now that the tightening is committed, issuance without delegation
        # must be refused rather than written under the older configuration.
        refused = await issue(store, org_id, agent_id, "j2")
        assert refused.grant_id is None
        assert refused.reason is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING

    async def test_J3_a_global_halt_also_stops_issuance(
        self, db, writer, store
    ) -> None:
        org_id, agent_id = await make_principal(db)
        try:
            await writer.execute(
                """INSERT INTO authority_controls
                     (control,org_id,engaged,reason,changed_by,approval_reference)
                   VALUES ('authority_issuance',NULL,TRUE,'t','lin','A')
                   ON CONFLICT (control, scope_key) DO UPDATE SET engaged = TRUE"""
            )
            result = await issue(store, org_id, agent_id, "j3")
            assert result.grant_id is None
            assert result.reason is DecisionReason.AUTHORITY_ISSUANCE_HALTED
        finally:
            await writer.execute(
                "DELETE FROM authority_controls WHERE org_id IS NULL"
            )

    async def test_J4_a_halt_does_not_invalidate_an_already_issued_grant(
        self, db, writer, store
    ) -> None:
        """The halt is issuance-only; consumption of existing authority stands."""
        org_id, agent_id = await make_principal(db)
        grant = await issue(store, org_id, agent_id, "j4")
        assert grant.grant_id is not None

        await writer.execute(
            """INSERT INTO authority_controls
                 (control,org_id,engaged,reason,changed_by,approval_reference)
               VALUES ('authority_issuance',$1,TRUE,'t','lin','A')""",
            org_id,
        )
        result = await consume(store, "j4", grant)
        assert result.outcome is ConsumptionOutcome.AUTHORISED


class TestAdversarial:
    """Attempts to defeat the linearisation rather than demonstrate it."""

    async def test_the_python_and_postgres_keys_are_the_same_lock(
        self, db, writer
    ) -> None:
        """The failure that would look like serialisation and provide none.

        If the application derived its key differently from the trigger, both
        sides would take a lock and neither would block the other. Proven by
        comparing what each actually registers in pg_locks.
        """
        org_id, _agent = await make_principal(db)

        reader = await asyncpg.connect(DATABASE_URL)
        try:
            rtx = reader.transaction()
            await rtx.start()
            await hold_shared_config_lock(reader, org_id)
            app_lock = await reader.fetchrow(
                """SELECT classid, objid, objsubid, mode FROM pg_locks
                   WHERE locktype = 'advisory' AND pid = pg_backend_pid()
                     AND granted AND mode = 'ShareLock'"""
            )
            assert app_lock is not None, "the application took no shared advisory lock"

            wtx = writer.transaction()
            await wtx.start()
            # The trigger fires on this INSERT and takes the EXCLUSIVE form.
            task = asyncio.create_task(set_required(writer, org_id, True))
            assert await blocks_for(task), (
                "the writer did not block: application and trigger are "
                "addressing different advisory locks"
            )
            await rtx.rollback()
            await asyncio.wait_for(task, timeout=20.0)
            trigger_lock = await writer.fetchrow(
                """SELECT classid, objid, objsubid FROM pg_locks
                   WHERE locktype = 'advisory' AND pid = pg_backend_pid()
                     AND granted AND mode = 'ExclusiveLock'"""
            )
            await wtx.rollback()
        finally:
            await reader.close(timeout=5)

        assert trigger_lock is not None
        assert (app_lock["classid"], app_lock["objid"], app_lock["objsubid"]) == (
            trigger_lock["classid"],
            trigger_lock["objid"],
            trigger_lock["objsubid"],
        ), "the application and the trigger addressed different advisory keys"

    async def test_a_direct_sql_delete_still_takes_the_lock(self, db, writer) -> None:
        """DELETE is covered even though the runtime role cannot DELETE."""
        org_id, _agent = await make_principal(db)
        await set_required(writer, org_id, False)

        reader = await asyncpg.connect(DATABASE_URL)
        try:
            rtx = reader.transaction()
            await rtx.start()
            await hold_shared_config_lock(reader, org_id)

            wtx = writer.transaction()
            await wtx.start()
            task = asyncio.create_task(
                writer.execute(
                    "DELETE FROM authority_requirements WHERE org_id = $1", org_id
                )
            )
            assert await blocks_for(task), "a DELETE bypassed the configuration lock"
            await rtx.rollback()
            await asyncio.wait_for(task, timeout=20.0)
            await wtx.commit()
        finally:
            await reader.close(timeout=5)

    async def test_moving_a_row_between_organisations_is_refused(
        self, db, writer
    ) -> None:
        """Two organisations would mean two locks governing one statement."""
        org_a, _a = await make_principal(db)
        org_b, _b = await make_principal(db)
        await set_required(writer, org_a, False)

        with pytest.raises(asyncpg.PostgresError, match="between organisations"):
            await writer.execute(
                "UPDATE authority_requirements SET org_id = $2 WHERE org_id = $1",
                org_a, org_b,
            )

    async def test_a_rolled_back_writer_releases_the_lock(self, db, writer) -> None:
        """A transaction-scoped lock must not survive its transaction."""
        org_id, _agent = await make_principal(db)

        wtx = writer.transaction()
        await wtx.start()
        await set_required(writer, org_id, True)
        await wtx.rollback()

        # The lock is gone, so a reader must not wait at all.
        reader = await asyncpg.connect(DATABASE_URL)
        try:
            rtx = reader.transaction()
            await rtx.start()
            await asyncio.wait_for(hold_shared_config_lock(reader, org_id), timeout=5.0)
            await rtx.rollback()
        finally:
            await reader.close(timeout=5)

        # ...and the rolled-back change did not take effect.
        async with db.acquire() as conn:
            rows = await conn.fetchval(
                "SELECT count(*) FROM authority_requirements WHERE org_id = $1", org_id
            )
        assert rows == 0

    async def test_no_path_takes_the_forensic_chain_before_the_config_lock(self) -> None:
        """The Gate-7 ABBA shape, asserted against the source itself.

        Consumption takes CONFIG then CHAIN. A path that took CHAIN first and
        CONFIG second would close the cycle Gate 7 was opened to remove, and
        it would only show up under production contention.
        """
        from pathlib import Path

        source = Path("api/persistence/authority_store.py").read_text(encoding="utf-8")
        config_at = source.index("lock_authority_configuration_shared(\n                conn")
        chain_at = source.index('str(discovered["agent_id"]),')
        assert config_at < chain_at, (
            "consumption acquires the forensic-chain lock before the "
            "configuration lock; that is the Gate-7 inversion"
        )
