"""The global configuration lock ranks above the per-organisation one.

029 gave every configuration scope its own advisory key. Independent review
found what that still left open::

    issuance for organisation A       takes  authority-config:<A>  SHARED
    a GLOBAL authority_issuance halt  takes  authority-config:global EXCLUSIVE

Those keys do not conflict -- yet the effective configuration for A consults
the global row. A halt could therefore commit while issuance for A was in
flight, and that issuance still wrote its grant.

The acceptance statement these tests hold the code to:

    If a configuration change commits before an issuance commits, that
    issuance either observed the change, or was already linearised before it
    because it held a lock the change had to wait for.

and the hierarchy that buys it::

    ISSUANCE    CONFIG_GLOBAL shared -> CONFIG_ORG shared -> principal ...
    CONSUMPTION CONFIG_ORG shared -> forensic chain -> principal -> grant
    WRITER      CONFIG_GLOBAL exclusive -> CONFIG_ORG exclusive (org rows)

Every case below is a deterministic interleaving driven from separate
connections. Nothing waits on a race to happen: each test parks one side on
a lock it genuinely cannot pass, then reads ``pg_locks`` to show which lock
that is and which locks the parked side does and does not already hold.
Order is proved that way -- "blocked on GLOBAL while holding no ORG lock"
is only possible if GLOBAL is taken first.
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
from api.persistence.authority_store import AuthorityStore, IssueOutcome  # noqa: E402

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")
MIGRATOR_URL = os.getenv("ALEMBIC_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL and MIGRATOR_URL),
    reason="global linearisation tests need INNTRIS_DB_INTEGRATION=1, "
    "DATABASE_URL and ALEMBIC_DATABASE_URL",
)

POLICY_HASH = "b" * 64
BINDING = "c" * 64
FORMAT = "inntris-payment-authority-policy-v1"
ACTION = "financial_transaction"
#: Long enough that a wait is unambiguous, short enough to keep tests quick.
BLOCKED_FOR = 1.5


def action_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


# --- Keys ------------------------------------------------------------------
# Every key below is derived by the SAME PostgreSQL functions the write
# trigger and the application call. A test that built a key itself would
# pass while production addressed a different lock -- exactly the drift
# this mechanism exists to prevent, and the one bug such a test could never
# see.

_CONFIG_LOCK_IDS = """
SELECT hashtext(authority_config_lock_namespace())::OID  AS classid,
       hashtext(authority_config_lock_key(NULL))::OID    AS global_objid,
       hashtext(authority_config_lock_key($1))::OID      AS org_objid
"""

#: The forensic-chain lock is the ONE-int advisory form, so PostgreSQL
#: reports it split across classid/objid with objsubid = 1.
_CHAIN_LOCK_IDS = """
SELECT ((hashtext($1)::BIGINT >> 32) & 4294967295)::OID AS classid,
       (hashtext($1)::BIGINT & 4294967295)::OID         AS objid
"""

_TAKE_EXCLUSIVE = """
SELECT pg_advisory_xact_lock(
    hashtext(authority_config_lock_namespace()),
    hashtext(authority_config_lock_key($1)))
"""


async def hold_shared_org_lock(conn, org_id) -> None:
    """Take the org lock exactly as production does -- same helper."""
    from api.persistence.authority_configuration import (
        lock_authority_configuration_shared,
    )

    await lock_authority_configuration_shared(conn, organisation_id=org_id)


async def hold_shared_global_lock(conn) -> None:
    """Take the global lock exactly as production does -- same helper."""
    from api.persistence.authority_configuration import (
        lock_authority_configuration_global_shared,
    )

    await lock_authority_configuration_global_shared(conn)


async def take_exclusive(conn, org_id: UUID | None) -> None:
    """Hold a configuration lock exclusively without writing a row.

    The trigger is the only exclusive taker in production, so tests that can
    write a row do; this exists for the cases that must hold the lock
    without one.
    """
    await conn.execute(_TAKE_EXCLUSIVE, org_id)


# --- Lock observation ------------------------------------------------------


async def config_locks(observer, pid: int, org_id: UUID) -> dict[str, set[str]]:
    """What a backend holds and waits for on the configuration keys.

    Returns ``{"global": {...modes}, "org": {...}, "waiting_global": {...},
    "waiting_org": {...}}`` so a test can say precisely which lock a backend
    is parked on and which it has not reached yet.
    """
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


async def config_lock_count(observer, pid: int) -> int:
    """Every granted configuration lock this backend holds, of any scope."""
    return await observer.fetchval(
        """SELECT COUNT(*) FROM pg_locks
           WHERE locktype = 'advisory' AND pid = $1 AND granted AND objsubid = 2
             AND classid = hashtext(authority_config_lock_namespace())::OID""",
        pid,
    )


async def holds_chain_lock(observer, pid: int, agent_id: UUID) -> bool:
    ids = await observer.fetchrow(_CHAIN_LOCK_IDS, str(agent_id))
    return bool(
        await observer.fetchval(
            """SELECT COUNT(*) FROM pg_locks
               WHERE locktype = 'advisory' AND pid = $1 AND granted
                 AND objsubid = 1 AND classid = $2 AND objid = $3""",
            pid, ids["classid"], ids["objid"],
        )
    )


async def global_shared_holders(observer) -> int:
    return await observer.fetchval(
        """SELECT COUNT(*) FROM pg_locks
           WHERE locktype = 'advisory' AND granted AND objsubid = 2
             AND mode = 'ShareLock'
             AND classid = hashtext(authority_config_lock_namespace())::OID
             AND objid = hashtext(authority_config_lock_key(NULL))::OID"""
    )


async def blocks_for(task: asyncio.Task, seconds: float = BLOCKED_FOR) -> bool:
    """True if the task is still waiting after `seconds`."""
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=seconds)
    except TimeoutError:
        return True
    return False


# --- Fixtures --------------------------------------------------------------


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
async def pinned() -> AsyncIterator[tuple[Database, int]]:
    """A pool of exactly one connection, and that connection's backend pid.

    Order proofs have to read ``pg_locks`` for the backend the code under
    test is actually running on. Pinning the pool to one connection is what
    makes that backend knowable.
    """
    database = await Database.create(DATABASE_URL, min_size=1, max_size=1)
    try:
        async with database.acquire() as conn:
            pid = await conn.fetchval("SELECT pg_backend_pid()")
        yield database, pid
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
    """A leaked global halt would block issuance for every other test."""
    try:
        yield
    finally:
        await writer.execute(
            "DELETE FROM authority_controls "
            "WHERE org_id IS NULL AND control = 'authority_issuance'"
        )


async def make_principal(db: Database) -> tuple[UUID, UUID]:
    org_id, agent_id = uuid4(), uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """INSERT INTO organizations (id,name,billing_tier,contact_email,api_key_hash)
               VALUES ($1,$2,'enterprise',$3,$4)""",
            org_id, f"glob-{org_id}", f"glob-{org_id}@example.test",
            hashlib.sha256(str(org_id).encode()).digest(),
        )
        await conn.execute(
            """INSERT INTO agents (id,org_id,name,public_key,public_key_fingerprint,
                 trust_score,status,daily_limit_usd,per_action_limit_usd,allowed_actions,
                 blocked_actions,rate_limit_per_minute,metadata)
               VALUES ($1,$2,$3,$4,$5,95,'active',1000000,1000000,
                       ARRAY['financial_transaction']::TEXT[],ARRAY[]::TEXT[],100000,$6::JSONB)""",
            agent_id, org_id, f"glob-agent-{agent_id}", secrets.token_bytes(32),
            hashlib.sha256(str(agent_id).encode()).hexdigest(),
            json.dumps({"sandbox": False,
                        "production_approval_reference": "glob",
                        "production_approved_at": "2026-01-01T00:00:00Z",
                        "production_approved_by": "glob"}),
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


async def engage_global_halt(conn, engaged: bool = True) -> None:
    """Write the GLOBAL authority_issuance control, as an operator would."""
    await conn.execute(
        """INSERT INTO authority_controls
             (control,org_id,engaged,reason,changed_by,approval_reference)
           VALUES ('authority_issuance',NULL,$1,'global linearisation','glob','A')
           ON CONFLICT (control, scope_key) DO UPDATE SET engaged = EXCLUDED.engaged""",
        engaged,
    )


async def write_org_requirement(conn, org_id, required: bool = True) -> None:
    await conn.execute(
        """INSERT INTO authority_requirements
             (org_id,agent_id,action_class,required,reason,changed_by,approval_reference)
           VALUES ($1,NULL,NULL,$2,'t','glob','A')
           ON CONFLICT (org_id, scope_key) DO UPDATE SET required = EXCLUDED.required""",
        org_id, required,
    )


async def park_issuance(store, org_id, agent_id, ref):
    """Start an issuance and leave it parked past both configuration locks.

    ``issue()`` takes the entry lock, then CONFIG_GLOBAL, then CONFIG_ORG,
    then the principal row FOR SHARE. Holding that row FOR UPDATE on another
    connection parks the issuance at the principal -- in flight, holding both
    configuration locks, with no timing involved.

    Returns the still-pending task and an ``unpark`` coroutine.
    """
    parker = await asyncpg.connect(DATABASE_URL)
    tx = parker.transaction()
    await tx.start()
    await parker.fetchrow("SELECT id FROM agents WHERE id = $1 FOR UPDATE", agent_id)

    task = asyncio.create_task(issue(store, org_id, agent_id, ref))
    assert await blocks_for(task), (
        "issuance did not park on the principal row; the interleaving this "
        "test depends on did not happen"
    )

    async def unpark():
        await tx.rollback()
        await parker.close(timeout=5)

    return task, unpark


class TestJ5GlobalHaltCannotCommitUnderLiveIssuance:
    """The defect, and the property that removes it."""

    async def test_J5_counterexample_the_org_lock_alone_lets_a_global_halt_commit(
        self, db, writer
    ) -> None:
        """Why the organisation key was not enough -- the shape of the bug.

        This is the pre-fix behaviour stated as a property of the keys
        themselves: a holder of ``authority-config:<A>`` does not conflict
        with a writer of ``authority-config:global``. It was true before this
        change and is still true; what changed is that issuance no longer
        holds only that key.
        """
        org_id, _agent = await make_principal(db)
        holder = await asyncpg.connect(DATABASE_URL)
        try:
            tx = holder.transaction()
            await tx.start()
            await hold_shared_org_lock(holder, org_id)

            writer_tx = writer.transaction()
            await writer_tx.start()
            # No wait at all: the global writer sails past the org-scoped
            # holder. An issuance holding only this lock is not protected.
            await asyncio.wait_for(engage_global_halt(writer), timeout=5.0)
            await writer_tx.commit()
            await tx.rollback()
        finally:
            await holder.close(timeout=5)

    async def test_J5_a_global_halt_cannot_commit_under_an_in_flight_issuance(
        self, db, store, writer, observer
    ) -> None:
        """The regression. Fails on 0837b2d: the halt is not blocked there."""
        org_id, agent_id = await make_principal(db)
        task, unpark = await park_issuance(store, org_id, agent_id, "j5")
        try:
            writer_pid = await writer.fetchval("SELECT pg_backend_pid()")
            writer_tx = writer.transaction()
            await writer_tx.start()
            halt = asyncio.create_task(engage_global_halt(writer))

            assert await blocks_for(halt), (
                "a GLOBAL authority_issuance halt committed while an issuance "
                "was already in flight; that issuance can still write a grant "
                "under a halt that is already in force"
            )
            seen = await config_locks(observer, writer_pid, org_id)
            assert seen["waiting_global"], (
                "the halt is stalled, but not on the global configuration "
                f"lock; observed {seen}"
            )

            # The issuance finishes first, and only then may the halt commit.
            await unpark()
            result = await asyncio.wait_for(task, timeout=20.0)
            assert result.outcome is IssueOutcome.ISSUED, (
                "the issuance that began before the halt must still succeed"
            )
            await asyncio.wait_for(halt, timeout=20.0)
            await writer_tx.commit()
        finally:
            if not task.done():
                await unpark()
                await asyncio.wait_for(task, timeout=20.0)

        # ...and everything after the halt is refused.
        after = await issue(store, org_id, agent_id, "j5-after")
        assert after.outcome is IssueOutcome.REFUSED
        assert after.reason is DecisionReason.AUTHORITY_ISSUANCE_HALTED


class TestJ6IssuanceWaitsForAnInFlightGlobalHalt:
    async def test_J6_issuance_waits_then_observes_the_committed_halt(
        self, db, store, writer
    ) -> None:
        org_id, agent_id = await make_principal(db)

        writer_tx = writer.transaction()
        await writer_tx.start()
        await engage_global_halt(writer)  # holds CONFIG_GLOBAL, uncommitted

        task = asyncio.create_task(issue(store, org_id, agent_id, "j6"))
        assert await blocks_for(task), (
            "issuance proceeded while a global halt held the exclusive global "
            "configuration lock; it could have issued under stale configuration"
        )

        await writer_tx.commit()
        result = await asyncio.wait_for(task, timeout=20.0)
        assert result.outcome is IssueOutcome.REFUSED, (
            "issuance resumed but did not observe the committed global halt"
        )
        assert result.reason is DecisionReason.AUTHORITY_ISSUANCE_HALTED


class TestJ7GlobalLockDoesNotSerialiseIssuance:
    async def test_J7_two_organisations_hold_the_global_lock_at_once(
        self, db, store, observer
    ) -> None:
        """Shared holders are compatible: the hierarchy costs no throughput."""
        org_a, agent_a = await make_principal(db)
        org_b, agent_b = await make_principal(db)

        task_a, unpark_a = await park_issuance(store, org_a, agent_a, "j7a")
        task_b, unpark_b = await park_issuance(store, org_b, agent_b, "j7b")
        try:
            assert await global_shared_holders(observer) >= 2, (
                "two issuances in different organisations did not hold the "
                "global configuration lock simultaneously"
            )

            # A writer, however, must wait for both of them.
            blocker = await asyncpg.connect(DATABASE_URL)
            try:
                btx = blocker.transaction()
                await btx.start()
                pending = asyncio.create_task(take_exclusive(blocker, None))
                assert await blocks_for(pending), (
                    "an exclusive global writer did not wait for the shared "
                    "holders already in flight"
                )
                await unpark_a()
                await asyncio.wait_for(task_a, timeout=20.0)
                assert await blocks_for(pending), (
                    "the writer proceeded while a second issuance still held "
                    "the shared global lock"
                )
                await unpark_b()
                await asyncio.wait_for(task_b, timeout=20.0)
                await asyncio.wait_for(pending, timeout=20.0)
                await btx.rollback()
            finally:
                await blocker.close(timeout=5)
        finally:
            for task, unpark in ((task_a, unpark_a), (task_b, unpark_b)):
                if not task.done():
                    await unpark()
                    await asyncio.wait_for(task, timeout=20.0)

        assert task_a.result().outcome is IssueOutcome.ISSUED
        assert task_b.result().outcome is IssueOutcome.ISSUED


class TestJ8OrgWriterTakesGlobalFirst:
    async def test_J8_an_org_scoped_write_blocks_on_global_holding_no_org_lock(
        self, db, writer, observer
    ) -> None:
        """The order proof.

        Parked on GLOBAL *while holding no ORG lock* is only reachable if
        GLOBAL is acquired first. Had the trigger taken ORG first it would be
        holding ORG and waiting on GLOBAL -- which is the inversion.
        """
        org_id, _agent = await make_principal(db)
        writer_pid = await writer.fetchval("SELECT pg_backend_pid()")

        holder = await asyncpg.connect(DATABASE_URL)
        try:
            htx = holder.transaction()
            await htx.start()
            await hold_shared_global_lock(holder)

            writer_tx = writer.transaction()
            await writer_tx.start()
            task = asyncio.create_task(write_org_requirement(writer, org_id))
            assert await blocks_for(task), (
                "an organisation-scoped configuration write proceeded while "
                "the global configuration lock was held; it never took it"
            )

            seen = await config_locks(observer, writer_pid, org_id)
            assert seen["waiting_global"], (
                f"the write is stalled but not on the global lock: {seen}"
            )
            assert not seen["org"], (
                "the write already holds the organisation lock while waiting "
                "for the global one -- CONFIG_ORG -> CONFIG_GLOBAL, the exact "
                f"inversion the hierarchy forbids: {seen}"
            )

            await htx.rollback()
            await asyncio.wait_for(task, timeout=20.0)

            seen = await config_locks(observer, writer_pid, org_id)
            assert seen["global"] and seen["org"], (
                f"an org-scoped write must end up holding both locks: {seen}"
            )
            await writer_tx.commit()
        finally:
            await holder.close(timeout=5)


class TestJ9DirectSqlGlobalWriteObeysTheGlobalLock:
    async def test_J9_a_direct_global_halt_waits_and_takes_only_the_global_lock(
        self, writer, observer
    ) -> None:
        writer_pid = await writer.fetchval("SELECT pg_backend_pid()")
        holder = await asyncpg.connect(DATABASE_URL)
        try:
            htx = holder.transaction()
            await htx.start()
            await hold_shared_global_lock(holder)

            writer_tx = writer.transaction()
            await writer_tx.start()
            # Raw SQL, no application code in the path: the database alone
            # has to impose the hierarchy.
            task = asyncio.create_task(engage_global_halt(writer))
            assert await blocks_for(task), (
                "a direct SQL global halt bypassed the global configuration "
                "lock; a writer outside the application can defeat it"
            )

            await htx.rollback()
            await asyncio.wait_for(task, timeout=20.0)

            assert await config_lock_count(observer, writer_pid) == 1, (
                "a global configuration row must take the global lock and "
                "nothing else"
            )
            await writer_tx.rollback()
        finally:
            await holder.close(timeout=5)


class TestJ10DirectSqlOrgWriteObeysGlobalThenOrg:
    async def _blocked_on_org_while_holding_global(
        self, writer, observer, org_id, mutate
    ) -> None:
        writer_pid = await writer.fetchval("SELECT pg_backend_pid()")
        holder = await asyncpg.connect(DATABASE_URL)
        try:
            htx = holder.transaction()
            await htx.start()
            await hold_shared_org_lock(holder, org_id)

            writer_tx = writer.transaction()
            await writer_tx.start()
            task = asyncio.create_task(mutate())
            assert await blocks_for(task), (
                "an organisation-scoped configuration write proceeded while "
                "the organisation lock was held"
            )

            seen = await config_locks(observer, writer_pid, org_id)
            assert seen["global"], (
                "the write is waiting for the organisation lock without "
                f"holding the global one; the hierarchy is not total: {seen}"
            )
            assert seen["waiting_org"], f"stalled somewhere else: {seen}"

            await htx.rollback()
            await asyncio.wait_for(task, timeout=20.0)
            await writer_tx.commit()
        finally:
            await holder.close(timeout=5)

    async def test_J10_a_direct_update_takes_global_then_org(
        self, db, writer, observer
    ) -> None:
        org_id, _agent = await make_principal(db)
        await write_org_requirement(writer, org_id, required=False)
        await self._blocked_on_org_while_holding_global(
            writer, observer, org_id,
            lambda: writer.execute(
                "UPDATE authority_requirements SET required = TRUE WHERE org_id = $1",
                org_id,
            ),
        )

    async def test_J10_a_direct_delete_takes_global_then_org(
        self, db, writer, observer
    ) -> None:
        org_id, _agent = await make_principal(db)
        await write_org_requirement(writer, org_id, required=True)
        await self._blocked_on_org_while_holding_global(
            writer, observer, org_id,
            lambda: writer.execute(
                "DELETE FROM authority_requirements WHERE org_id = $1", org_id
            ),
        )


class TestJ11NoConfigurationToForensicChainInversion:
    async def test_J11_consumption_does_not_take_the_global_lock(
        self, db, store
    ) -> None:
        """Halting new issuance must not stall spending of existing authority."""
        org_id, agent_id = await make_principal(db)
        grant = await issue(store, org_id, agent_id, "j11-global")

        blocker = await asyncpg.connect(MIGRATOR_URL)
        try:
            btx = blocker.transaction()
            await btx.start()
            await take_exclusive(blocker, None)  # CONFIG_GLOBAL, exclusive

            result = await asyncio.wait_for(
                consume(store, "j11-global", grant), timeout=10.0
            )
            assert result.outcome is ConsumptionOutcome.AUTHORISED, (
                "consumption did not complete while the global configuration "
                "lock was held; it is taking a lock it must not take"
            )
            await btx.rollback()
        finally:
            await blocker.close(timeout=5)

    async def test_J11_consumption_takes_configuration_before_the_forensic_chain(
        self, pinned, observer
    ) -> None:
        """CONFIG -> CHAIN, still. The Gate-7 inversion must not return."""
        database, pid = pinned
        store = AuthorityStore(database, current_policy_resolver=_static_policy())
        org_id, agent_id = await make_principal(database)
        grant = await issue(store, org_id, agent_id, "j11-order")

        blocker = await asyncpg.connect(MIGRATOR_URL)
        try:
            btx = blocker.transaction()
            await btx.start()
            await take_exclusive(blocker, org_id)  # CONFIG_ORG, exclusive

            task = asyncio.create_task(consume(store, "j11-order", grant))
            assert await blocks_for(task), (
                "consumption proceeded while the organisation configuration "
                "lock was held exclusively"
            )

            seen = await config_locks(observer, pid, org_id)
            assert seen["waiting_org"], f"stalled somewhere else: {seen}"
            assert not await holds_chain_lock(observer, pid, agent_id), (
                "consumption holds the forensic-chain lock while waiting for "
                "the configuration lock -- CHAIN -> CONFIG, the ABBA shape "
                "Gate 7 was opened to remove"
            )
            assert not seen["global"], (
                "consumption took the global configuration lock; every spend "
                "on the platform would serialise behind one key"
            )

            await btx.rollback()
            result = await asyncio.wait_for(task, timeout=20.0)
            assert result.outcome is ConsumptionOutcome.AUTHORISED
        finally:
            await blocker.close(timeout=5)


class TestJ12GlobalHaltDoesNotInvalidateIssuedAuthority:
    async def test_J12_an_existing_grant_is_still_consumable_under_a_global_halt(
        self, db, store, writer
    ) -> None:
        org_id, agent_id = await make_principal(db)
        grant = await issue(store, org_id, agent_id, "j12")

        await engage_global_halt(writer)

        refused = await issue(store, org_id, agent_id, "j12-new")
        assert refused.outcome is IssueOutcome.REFUSED
        assert refused.reason is DecisionReason.AUTHORITY_ISSUANCE_HALTED

        spent = await consume(store, "j12", grant)
        assert spent.outcome is ConsumptionOutcome.AUTHORISED, (
            "a global issuance halt revoked authority that was already "
            "issued; it halts NEW issuance only"
        )


class TestJ13RollbackReleasesTheConfigurationLocks:
    async def test_J13_rolling_back_a_reader_releases_both_shared_locks(
        self, db
    ) -> None:
        org_id, _agent = await make_principal(db)
        reader = await asyncpg.connect(DATABASE_URL)
        other = await asyncpg.connect(MIGRATOR_URL)
        try:
            rtx = reader.transaction()
            await rtx.start()
            await hold_shared_global_lock(reader)
            await hold_shared_org_lock(reader, org_id)
            await rtx.rollback()

            otx = other.transaction()
            await otx.start()
            await asyncio.wait_for(take_exclusive(other, None), timeout=5.0)
            await asyncio.wait_for(take_exclusive(other, org_id), timeout=5.0)
            await otx.rollback()
        finally:
            await reader.close(timeout=5)
            await other.close(timeout=5)

    async def test_J13_rolling_back_a_writer_releases_the_locks_the_trigger_took(
        self, db, writer
    ) -> None:
        org_id, _agent = await make_principal(db)
        writer_tx = writer.transaction()
        await writer_tx.start()
        await write_org_requirement(writer, org_id)
        await writer_tx.rollback()

        other = await asyncpg.connect(DATABASE_URL)
        try:
            otx = other.transaction()
            await otx.start()
            await asyncio.wait_for(take_exclusive(other, None), timeout=5.0)
            await asyncio.wait_for(take_exclusive(other, org_id), timeout=5.0)
            await otx.rollback()
        finally:
            await other.close(timeout=5)


class TestJ14MultiRowMutationNeverInvertsTheHierarchy:
    async def test_J14_an_org_row_written_first_still_takes_global_first(
        self, db, writer, observer
    ) -> None:
        """Statement order does not decide lock order; the trigger does."""
        org_id, _agent = await make_principal(db)
        writer_pid = await writer.fetchval("SELECT pg_backend_pid()")

        holder = await asyncpg.connect(DATABASE_URL)
        try:
            htx = holder.transaction()
            await htx.start()
            await hold_shared_global_lock(holder)

            writer_tx = writer.transaction()
            await writer_tx.start()

            async def both_rows():
                await write_org_requirement(writer, org_id)  # org row FIRST
                await engage_global_halt(writer, engaged=False)

            task = asyncio.create_task(both_rows())
            assert await blocks_for(task)

            seen = await config_locks(observer, writer_pid, org_id)
            assert seen["waiting_global"] and not seen["org"], (
                "writing an organisation row first built CONFIG_ORG -> "
                f"CONFIG_GLOBAL; the hierarchy is not total: {seen}"
            )

            await htx.rollback()
            await asyncio.wait_for(task, timeout=20.0)
            seen = await config_locks(observer, writer_pid, org_id)
            assert seen["global"] and seen["org"]
            await writer_tx.commit()
        finally:
            await holder.close(timeout=5)

    async def test_J14_a_global_row_written_first_needs_no_second_global_wait(
        self, db, writer, observer
    ) -> None:
        org_id, _agent = await make_principal(db)
        writer_pid = await writer.fetchval("SELECT pg_backend_pid()")

        writer_tx = writer.transaction()
        await writer_tx.start()
        await engage_global_halt(writer, engaged=False)  # global row FIRST
        await asyncio.wait_for(write_org_requirement(writer, org_id), timeout=5.0)

        seen = await config_locks(observer, writer_pid, org_id)
        assert seen["global"] and seen["org"], (
            f"one transaction touching both scopes must hold both keys: {seen}"
        )
        await writer_tx.commit()

    async def test_J14_opposite_statement_orders_do_not_deadlock(
        self, db, writer
    ) -> None:
        """The cycle the hierarchy makes unconstructible, attempted directly."""
        org_a, _a = await make_principal(db)
        org_b, _b = await make_principal(db)

        second = await asyncpg.connect(MIGRATOR_URL)
        try:
            # W1 goes org-then-global and gets both keys.
            w1 = writer.transaction()
            await w1.start()
            await write_org_requirement(writer, org_a)

            # W2 goes global-then-org, and must simply queue.
            w2 = second.transaction()
            await w2.start()

            async def global_then_org():
                await engage_global_halt(second, engaged=False)
                await write_org_requirement(second, org_b)

            task = asyncio.create_task(global_then_org())
            assert await blocks_for(task), (
                "the second writer did not serialise on the global key"
            )

            await engage_global_halt(writer, engaged=False)
            await w1.commit()

            # No 40P01: there is no edge for a cycle to close on.
            await asyncio.wait_for(task, timeout=20.0)
            await w2.commit()
        finally:
            await second.close(timeout=5)
