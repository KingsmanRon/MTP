"""Gate 1: rehearse the upgrade from the deployed revision to head, measured.

This runs the command deployment actually runs -- ONE ``alembic upgrade
head`` -- not a stepwise workaround. Per-revision timings come from watching
``alembic_version`` move, which is only possible because each revision now
commits on its own; under the previous single-transaction model an outside
reader saw nothing until the whole series finished.

Recorded: total and per-revision wall clock, the ACCESS EXCLUSIVE locks each
revision takes, whether any table is rewritten, and how long a concurrent
reader is blocked. The reader is the honest measure of impact: it is what a
live API process does while the pre-deploy migration runs.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

import asyncpg

MIGRATOR_URL = os.environ["ALEMBIC_DATABASE_URL"]
DEPLOYED = "0018_merkle_anchor_visibility"
HEAD = "0027_authority_config_mgmt"
#: Tables that exist at the deployed revision and carry real rows. A lock on
#: one of these is what blocks production traffic.
WATCHED = ["audit_logs", "agents", "administrative_audit_events",
           "approval_token_consumptions", "merkle_proofs", "organizations"]


async def filenodes(conn) -> dict[str, int]:
    rows = await conn.fetch(
        "SELECT relname, relfilenode FROM pg_class "
        "WHERE relname = ANY($1::TEXT[]) AND relkind = 'r'", WATCHED)
    return {r["relname"]: r["relfilenode"] for r in rows}


async def revision_of(conn) -> str | None:
    if not await conn.fetchval("SELECT to_regclass('public.alembic_version')"):
        return None
    return await conn.fetchval("SELECT version_num FROM alembic_version")


async def watcher(stop: asyncio.Event, timeline: list) -> None:
    """Record when the version row moves. Each move is a revision commit."""
    conn = await asyncpg.connect(MIGRATOR_URL)
    try:
        current = await revision_of(conn)
        timeline.append((current, time.perf_counter()))
        while not stop.is_set():
            latest = await revision_of(conn)
            if latest != current:
                current = latest
                timeline.append((current, time.perf_counter()))
            await asyncio.sleep(0.002)
    finally:
        await conn.close(timeout=5)


async def sampler(stop: asyncio.Event, seen: dict, timeline: list) -> None:
    """Every strong lock, attributed to the revision in force at that moment."""
    conn = await asyncpg.connect(MIGRATOR_URL)
    try:
        while not stop.is_set():
            rows = await conn.fetch(
                """SELECT c.relname, l.mode, l.granted
                     FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
                     JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND l.pid <> pg_backend_pid()
                      AND l.mode IN ('AccessExclusiveLock','ShareRowExclusiveLock',
                                     'ShareLock','ExclusiveLock')""")
            during = timeline[-1][0] if timeline else "?"
            for row in rows:
                key = f"{row['relname']}:{row['mode']}"
                seen.setdefault(during, {}).setdefault(
                    key, {"granted": 0, "waiting": 0}
                )["granted" if row["granted"] else "waiting"] += 1
            blocked = await conn.fetchval(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE datname = current_database() AND wait_event_type = 'Lock' "
                "AND pid <> pg_backend_pid()")
            if blocked:
                seen.setdefault(during, {}).setdefault(
                    "_blocked_samples", {"granted": 0, "waiting": 0}
                )["waiting"] += blocked
            await asyncio.sleep(0.02)
    finally:
        await conn.close(timeout=5)


async def reader(stop: asyncio.Event, worst: dict, timeline: list) -> None:
    """A live reader. Its worst latency IS the operator-visible impact."""
    conn = await asyncpg.connect(MIGRATOR_URL)
    probes = {
        "audit_logs": "SELECT count(*) FROM audit_logs WHERE chain_sequence = 1",
        "agents": "SELECT count(*) FROM agents WHERE status = 'active'",
        "administrative_audit_events":
            "SELECT count(*) FROM administrative_audit_events WHERE actor IS NOT NULL",
    }
    try:
        while not stop.is_set():
            for table, sql in probes.items():
                during = timeline[-1][0] if timeline else "?"
                began = time.perf_counter()
                try:
                    await conn.fetchval(sql)
                except Exception as exc:  # a blocked read that errored still counts
                    worst.setdefault("_errors", []).append(f"{table}: {exc}")
                waited = time.perf_counter() - began
                bucket = worst.setdefault(during, {})
                if waited > bucket.get(table, 0.0):
                    bucket[table] = waited
            await asyncio.sleep(0.01)
    finally:
        await conn.close(timeout=5)


async def main() -> int:
    conn = await asyncpg.connect(MIGRATOR_URL)
    start_revision = await revision_of(conn)
    before_nodes = await filenodes(conn)
    before_counts = {t: await conn.fetchval(f"SELECT count(*) FROM {t}")
                     for t in WATCHED}
    await conn.close(timeout=5)

    if start_revision != DEPLOYED:
        print(f"refusing: database is at {start_revision}, expected {DEPLOYED}")
        return 2

    stop = asyncio.Event()
    timeline: list = []
    locks: dict = {}
    worst: dict = {}
    watchers = [
        asyncio.create_task(watcher(stop, timeline)),
        asyncio.create_task(sampler(stop, locks, timeline)),
        asyncio.create_task(reader(stop, worst, timeline)),
    ]
    await asyncio.sleep(0.2)

    # THE COMMAND DEPLOYMENT RUNS. One invocation, no stepwise workaround.
    began = time.perf_counter()
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "alembic", "upgrade", "head",
        cwd=str(Path(__file__).resolve().parents[2]),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await proc.communicate()
    total = time.perf_counter() - began

    await asyncio.sleep(0.1)
    stop.set()
    await asyncio.gather(*watchers, return_exceptions=True)

    conn = await asyncpg.connect(MIGRATOR_URL)
    end_revision = await revision_of(conn)
    after_nodes = await filenodes(conn)
    after_counts = {t: await conn.fetchval(f"SELECT count(*) FROM {t}")
                    for t in WATCHED}
    await conn.close(timeout=5)

    # Per-revision durations, from the moments the version row moved.
    #
    # ATTRIBUTION. While revision N is executing, the version row still shows
    # N-1: the row only moves when N commits. So samples recorded under the
    # label N-1 belong to the work of N, and are shifted accordingly. Without
    # this every lock and every reader stall is reported against the
    # migration before the one that caused it.
    steps = []
    for index, (revision, at) in enumerate(timeline):
        if revision in (None, start_revision):
            continue
        previous_revision, previous_at = timeline[index - 1]
        during = locks.get(previous_revision, {})
        stalls = worst.get(previous_revision, {})
        steps.append({
            "revision": revision,
            "seconds": round(at - previous_at, 3),
            "strong_locks": {k: v for k, v in during.items()
                             if not k.startswith("_")},
            "blocked_samples": during.get("_blocked_samples", {}).get("waiting", 0),
            "worst_reader_latency_s": {k: round(v, 3) for k, v in stalls.items()},
        })

    result = {
        "command": "alembic upgrade head (ONE invocation)",
        "start_revision": start_revision,
        "end_revision": end_revision,
        "returncode": proc.returncode,
        "total_seconds": round(total, 3),
        "revisions_observed": [r for r, _ in timeline],
        "steps": steps,
        "tables_rewritten": [t for t in WATCHED
                             if before_nodes.get(t) != after_nodes.get(t)],
        "row_counts_changed": {t: [before_counts[t], after_counts[t]]
                               for t in WATCHED
                               if before_counts[t] != after_counts[t]},
        "reader_errors": worst.get("_errors", [])[:3],
        "output_tail": (out or b"").decode().strip().splitlines()[-1:],
    }
    Path(sys.argv[1]).write_text(json.dumps(result, indent=2))

    flag = "OK " if proc.returncode == 0 and end_revision == HEAD else "FAIL"
    print(f"[{flag}] alembic upgrade head: {start_revision} -> {end_revision} "
          f"in {total:.3f}s (ONE invocation)")
    for step in steps:
        ae = [k for k in step["strong_locks"] if k.endswith(":AccessExclusiveLock")]
        print(f"   {step['revision']:<30} {step['seconds']:>6.3f}s  "
              f"AE={len(ae)}  worst_read="
              f"{max(step['worst_reader_latency_s'].values(), default=0):.3f}s")
    print(f"   tables rewritten: {result['tables_rewritten'] or 'NONE'}")
    print(f"   row counts changed: {result['row_counts_changed'] or 'none'}")
    return 0 if proc.returncode == 0 and end_revision == HEAD else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
