"""The migration transaction model: one revision per transaction, one session lock.

Gate 1 failed because Alembic ran the whole revision series in ONE
transaction. A transaction-scoped advisory lock taken by migration 029
survived into 030, whose drift guard correctly refused when it found a lock
it had not taken. ``alembic upgrade head`` -- the command Railway actually
runs -- could therefore upgrade an empty database but not a deployed one.

These tests hold the model to its contract:

* M1-M4  ``alembic upgrade head`` reaches head in ONE invocation from the
         deployed revision, from two later revisions, and from empty;
* M5     each revision commits on its own, observably;
* M6     two concurrent migrators are safe: one migrates, one no-ops;
* M7     a migrator that dies mid-series releases the lock and leaves the
         database at the last committed revision;
* M8     nothing migrates while another runner holds the session lock.

They run real ``alembic`` subprocesses against real throwaway databases.
Nothing here is mocked: the command under test is the command that deploys.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import pytest

asyncpg = pytest.importorskip("asyncpg")

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
MIGRATOR_URL = os.getenv("ALEMBIC_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and MIGRATOR_URL),
    reason="migration-model tests need INNTRIS_DB_INTEGRATION=1 and "
    "ALEMBIC_DATABASE_URL pointing at a role that may CREATE DATABASE",
)

REPO = Path(__file__).resolve().parents[1]
DEPLOYED = "0018_merkle_anchor_visibility"
HEAD = "0027_authority_config_mgmt"
#: env.py's invocation lock. Named here so a test can hold it, not recomputed.
MIGRATION_LOCK_KEY = 4_803_921_115_399_370_837


def _with_database(dsn: str, name: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit(parts._replace(path=f"/{name}"))


def alembic(database: str, *args: str, timeout: float = 300.0):
    """Run the real command, against one database."""
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=str(REPO), capture_output=True, text=True, timeout=timeout,
        env={**os.environ, "ALEMBIC_DATABASE_URL": _with_database(MIGRATOR_URL, database)},
    )


@pytest.fixture
def scratch() -> Iterator[str]:
    """A throwaway database, dropped however the test ends."""
    name = f"inntris_mm_{uuid4().hex[:10]}"
    admin = _with_database(MIGRATOR_URL, "postgres")

    async def run(sql: str) -> None:
        conn = await asyncpg.connect(admin)
        try:
            await conn.execute(sql)
        finally:
            await conn.close(timeout=5)

    asyncio.run(run(f'CREATE DATABASE "{name}"'))
    try:
        yield name
    finally:
        asyncio.run(run(
            f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            f"WHERE datname = '{name}' AND pid <> pg_backend_pid()"))
        asyncio.run(run(f'DROP DATABASE IF EXISTS "{name}"'))


@pytest.fixture
async def connect():
    """Open connections to a named database and close them at teardown."""
    opened: list[asyncpg.Connection] = []

    async def _connect(database: str) -> asyncpg.Connection:
        conn = await asyncpg.connect(_with_database(MIGRATOR_URL, database))
        opened.append(conn)
        return conn

    try:
        yield _connect
    finally:
        for conn in opened:
            await conn.close(timeout=5)


async def revision_of(conn) -> str | None:
    if not await conn.fetchval("SELECT to_regclass('public.alembic_version')"):
        return None
    return await conn.fetchval("SELECT version_num FROM alembic_version")


async def session_lock_holders(conn) -> int:
    """How many backends hold or await env.py's invocation lock."""
    return await conn.fetchval(
        """SELECT count(*) FROM pg_locks
           WHERE locktype = 'advisory' AND objsubid = 1
             AND ((classid::BIGINT << 32) | objid::BIGINT) = $1""",
        MIGRATION_LOCK_KEY,
    )


async def granted_session_lock(conn) -> int:
    return await conn.fetchval(
        """SELECT count(*) FROM pg_locks
           WHERE locktype = 'advisory' AND objsubid = 1 AND granted
             AND ((classid::BIGINT << 32) | objid::BIGINT) = $1""",
        MIGRATION_LOCK_KEY,
    )


def ran_any_migration(result) -> bool:
    return "Running upgrade" in (result.stdout + result.stderr)


# --- M1-M4: one invocation reaches head -----------------------------------


class TestSingleInvocationReachesHead:
    """The primary regression. M1 fails on the model this replaced."""

    @pytest.mark.parametrize(
        "start",
        [
            pytest.param(DEPLOYED, id="M1_from_deployed_revision"),
            pytest.param("0022_authority_evidence_nn", id="M2_from_0022"),
            pytest.param("0024_authority_config_hard", id="M3_from_0024"),
            pytest.param(None, id="M4_from_empty"),
        ],
    )
    async def test_upgrade_head_in_one_invocation(self, scratch, connect, start):
        if start is not None:
            staged = alembic(scratch, "upgrade", start)
            assert staged.returncode == 0, staged.stdout + staged.stderr

        result = alembic(scratch, "upgrade", "head")
        assert result.returncode == 0, (
            "`alembic upgrade head` -- the command deployment runs -- could not "
            f"reach head from {start or 'an empty database'}:\n"
            + (result.stdout + result.stderr)[-1500:]
        )
        conn = await connect(scratch)
        assert await revision_of(conn) == HEAD

    async def test_M4_the_historical_begin_commit_migration_still_applies(
        self, scratch, connect
    ):
        """0002 contains its own BEGIN/COMMIT and is not to be rewritten."""
        result = alembic(scratch, "upgrade", "head")
        assert result.returncode == 0, (result.stdout + result.stderr)[-1500:]
        conn = await connect(scratch)
        assert await revision_of(conn) == HEAD
        assert await conn.fetchval(
            "SELECT to_regprocedure('app.erase_personal_data(uuid,uuid,text,text,text)') "
            "IS NOT NULL"
        ), "migration 0002's function is missing; its BEGIN/COMMIT was mishandled"


# --- M5: each revision commits on its own ---------------------------------


class TestRevisionsCommitIndependently:
    async def test_M5_an_outside_reader_observes_intermediate_revisions(
        self, scratch, connect
    ):
        """One transaction for the series would show only start and end.

        Seeing the version row move through intermediate revisions is direct
        proof that each migration committed before the next began -- which is
        what releases a transaction-scoped advisory lock taken by one
        migration before the next one runs.
        """
        conn = await connect(scratch)
        seen: set[str] = set()
        done = asyncio.Event()

        async def watch() -> None:
            while not done.is_set():
                current = await revision_of(conn)
                if current:
                    seen.add(current)
                await asyncio.sleep(0.002)

        watcher = asyncio.create_task(watch())
        result = await asyncio.to_thread(alembic, scratch, "upgrade", "head")
        done.set()
        await watcher

        assert result.returncode == 0, (result.stdout + result.stderr)[-1500:]
        assert await revision_of(conn) == HEAD
        intermediate = seen - {HEAD}
        assert len(intermediate) >= 3, (
            "an outside reader never observed the version row at an "
            "intermediate revision, so the series looks like one transaction; "
            f"observed {sorted(seen)}"
        )

    async def test_M5_no_configuration_lock_survives_into_the_next_revision(
        self, scratch, connect
    ):
        """029 -> 030 is the pair that proved this, so assert it directly.

        030's drift guard counts the authority-config advisory locks its own
        write took. It can only pass if 029's transaction -- and the lock its
        write trigger took -- ended first.
        """
        staged = alembic(scratch, "upgrade", "0024_authority_config_hard")
        assert staged.returncode == 0, staged.stdout + staged.stderr

        result = alembic(scratch, "upgrade", "0026_authority_config_glob")
        assert result.returncode == 0, (
            "030's drift guard refused: a configuration lock from 029 was "
            "still held when 030 ran\n" + (result.stdout + result.stderr)[-800:]
        )
        conn = await connect(scratch)
        assert await revision_of(conn) == "0026_authority_config_glob"


# --- M6 / M8: concurrent migrators -----------------------------------------


class TestConcurrentMigrators:
    async def test_M6_two_concurrent_upgrades_one_migrates_one_no_ops(
        self, scratch, connect
    ):
        """Both Railway services run the same command. Exactly one may work."""
        staged = alembic(scratch, "upgrade", DEPLOYED)
        assert staged.returncode == 0, staged.stdout + staged.stderr

        first, second = await asyncio.gather(
            asyncio.to_thread(alembic, scratch, "upgrade", "head"),
            asyncio.to_thread(alembic, scratch, "upgrade", "head"),
        )

        for label, result in (("first", first), ("second", second)):
            assert result.returncode == 0, (
                f"the {label} concurrent migrator failed:\n"
                + (result.stdout + result.stderr)[-1200:]
            )
        migrators = [r for r in (first, second) if ran_any_migration(r)]
        assert len(migrators) == 1, (
            f"{len(migrators)} of 2 concurrent invocations applied migrations; "
            "the invocation lock did not serialise them"
        )

        conn = await connect(scratch)
        assert await revision_of(conn) == HEAD
        assert await conn.fetchval("SELECT count(*) FROM alembic_version") == 1, (
            "the version table has more than one row -- the invocations raced"
        )
        combined = "".join(r.stdout + r.stderr for r in (first, second))
        assert "deadlock detected" not in combined

    async def test_M8_nothing_migrates_while_another_runner_holds_the_lock(
        self, scratch, connect
    ):
        """Held by a stand-in for the other deployment's migrator."""
        staged = alembic(scratch, "upgrade", DEPLOYED)
        assert staged.returncode == 0, staged.stdout + staged.stderr

        holder = await connect(scratch)
        observer = await connect(scratch)
        await holder.execute("SELECT pg_advisory_lock($1)", MIGRATION_LOCK_KEY)

        pending = asyncio.create_task(
            asyncio.to_thread(alembic, scratch, "upgrade", "head"))
        try:
            # It must wait, and it must be waiting on THIS lock.
            await asyncio.sleep(2.5)
            assert not pending.done(), (
                "a migrator ran while another runner held the invocation lock"
            )
            assert await revision_of(observer) == DEPLOYED
            assert await session_lock_holders(observer) >= 2, (
                "the migrator is stalled somewhere other than the invocation "
                "lock"
            )
            assert await granted_session_lock(observer) == 1
        finally:
            await holder.execute("SELECT pg_advisory_unlock($1)", MIGRATION_LOCK_KEY)

        result = await asyncio.wait_for(pending, timeout=300)
        assert result.returncode == 0, (result.stdout + result.stderr)[-1200:]
        assert await revision_of(observer) == HEAD
        assert await granted_session_lock(observer) == 0, (
            "the invocation lock was not released after the migrator finished"
        )


# --- M7: a migrator that dies mid-series ----------------------------------


class TestMidSeriesFailure:
    async def test_M7_failure_releases_the_lock_and_leaves_a_committed_revision(
        self, scratch, connect
    ):
        """Injected the way it happens: a live query holds a lock 0021 needs."""
        staged = alembic(scratch, "upgrade", "0020_authority_evidence")
        assert staged.returncode == 0, staged.stdout + staged.stderr

        admin = await connect(scratch)
        await admin.execute(f'ALTER DATABASE "{scratch}" SET lock_timeout = \'2s\'')

        blocker = await connect(scratch)
        tx = blocker.transaction()
        await tx.start()
        await blocker.fetchval("SELECT count(*) FROM audit_logs WHERE 1=0")
        try:
            failed = await asyncio.to_thread(alembic, scratch, "upgrade", "head")
        finally:
            await tx.rollback()

        assert failed.returncode != 0, (
            "0021 was expected to time out against a held lock but succeeded"
        )
        observer = await connect(scratch)
        assert await revision_of(observer) == "0020_authority_evidence", (
            "the database is not at the last revision that committed"
        )
        assert await granted_session_lock(observer) == 0, (
            "a failed migrator left the invocation lock held; the next "
            "deployment would block forever"
        )

        # ...and the next invocation simply continues.
        await admin.execute(f'ALTER DATABASE "{scratch}" RESET lock_timeout')
        retry = alembic(scratch, "upgrade", "head")
        assert retry.returncode == 0, (retry.stdout + retry.stderr)[-1200:]
        assert await revision_of(observer) == HEAD
