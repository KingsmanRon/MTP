"""Gate 1: rehearse the upgrade from the deployed revision to head, measured.

For every migration step this records wall-clock duration, the ACCESS
EXCLUSIVE locks it takes, whether any table is rewritten, and -- the number
an operator actually needs -- how long a concurrent reader is blocked.

The reader is the honest measure of impact: it is what a live API process
does while the pre-deploy migration runs.
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
CHAIN = [
    "0019_authority_persistence",
    "0020_authority_evidence",
    "0021_authority_evidence_int",
    "0022_authority_evidence_nn",
    "0023_authority_requirement",
    "0024_authority_config_hard",
    "0025_authority_config_lin",
    "0026_authority_config_glob",
    "0027_authority_config_mgmt",
]
#: Tables that exist at the deployed revision and carry real rows. A lock on
#: one of these is what blocks production traffic.
WATCHED = ["audit_logs", "agents", "administrative_audit_events",
           "approval_token_consumptions", "merkle_proofs", "organizations"]


async def filenodes(conn) -> dict[str, int]:
    rows = await conn.fetch(
        "SELECT relname, relfilenode FROM pg_class "
        "WHERE relname = ANY($1::TEXT[]) AND relkind = 'r'",
        WATCHED,
    )
    return {r["relname"]: r["relfilenode"] for r in rows}


async def sampler(stop: asyncio.Event, seen: dict) -> None:
    """Record every ACCESS EXCLUSIVE lock and every waiting session."""
    conn = await asyncpg.connect(MIGRATOR_URL)
    try:
        while not stop.is_set():
            rows = await conn.fetch(
                """SELECT c.relname, l.mode, l.granted, l.pid
                     FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
                     JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND l.pid <> pg_backend_pid()
                      AND l.mode IN ('AccessExclusiveLock','ShareRowExclusiveLock',
                                     'ShareLock','ExclusiveLock')"""
            )
            for r in rows:
                key = f"{r['relname']}:{r['mode']}"
                entry = seen.setdefault(key, {"granted": 0, "waiting": 0})
                entry["granted" if r["granted"] else "waiting"] += 1
            waiting = await conn.fetch(
                "SELECT pid, wait_event_type, state, LEFT(query, 60) AS q "
                "FROM pg_stat_activity WHERE datname = current_database() "
                "AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()"
            )
            for w in waiting:
                seen.setdefault("_blocked_sessions", []).append(dict(w))
            await asyncio.sleep(0.02)
    finally:
        await conn.close(timeout=5)


async def reader(stop: asyncio.Event, worst: dict) -> None:
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
                began = time.perf_counter()
                try:
                    await conn.fetchval(sql)
                except Exception as exc:  # a blocked read that errored still counts
                    worst.setdefault("_errors", []).append(f"{table}: {exc}")
                waited = time.perf_counter() - began
                if waited > worst.get(table, 0.0):
                    worst[table] = waited
            await asyncio.sleep(0.01)
    finally:
        await conn.close(timeout=5)


async def run_step(revision: str) -> dict:
    conn = await asyncpg.connect(MIGRATOR_URL)
    before_nodes = await filenodes(conn)
    before_counts = {
        t: await conn.fetchval(f"SELECT count(*) FROM {t}") for t in WATCHED
    }
    await conn.close(timeout=5)

    stop = asyncio.Event()
    locks: dict = {}
    worst: dict = {}
    watchers = [
        asyncio.create_task(sampler(stop, locks)),
        asyncio.create_task(reader(stop, worst)),
    ]
    await asyncio.sleep(0.2)  # let the watchers settle

    began = time.perf_counter()
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "alembic", "upgrade", revision,
        cwd=str(Path(__file__).resolve().parents[2]),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate()
    duration = time.perf_counter() - began

    stop.set()
    await asyncio.gather(*watchers, return_exceptions=True)

    conn = await asyncpg.connect(MIGRATOR_URL)
    after_nodes = await filenodes(conn)
    after_counts = {
        t: await conn.fetchval(f"SELECT count(*) FROM {t}") for t in WATCHED
    }
    indexes = await conn.fetchval(
        "SELECT count(*) FROM pg_indexes WHERE schemaname = 'public'"
    )
    await conn.close(timeout=5)

    rewritten = [t for t in WATCHED
                 if before_nodes.get(t) != after_nodes.get(t)]
    return {
        "revision": revision,
        "returncode": proc.returncode,
        "seconds": round(duration, 3),
        "access_exclusive": sorted(
            k for k in locks if k.endswith(":AccessExclusiveLock")
        ),
        "other_strong_locks": sorted(
            k for k in locks
            if not k.startswith("_") and not k.endswith(":AccessExclusiveLock")
        ),
        "blocked_sessions": len(locks.get("_blocked_sessions", [])),
        "worst_reader_latency_s": {k: round(v, 3) for k, v in worst.items()
                                   if not k.startswith("_")},
        "reader_errors": worst.get("_errors", [])[:3],
        "tables_rewritten": rewritten,
        "row_counts_changed": {
            t: [before_counts[t], after_counts[t]]
            for t in WATCHED if before_counts[t] != after_counts[t]
        },
        "total_indexes_after": indexes,
        "output_tail": (out or b"").decode().strip().splitlines()[-1:],
    }


async def main() -> int:
    results = []
    for revision in CHAIN:
        step = await run_step(revision)
        results.append(step)
        flag = "OK " if step["returncode"] == 0 else "FAIL"
        print(
            f"[{flag}] {step['revision']:<30} {step['seconds']:>7.3f}s  "
            f"AE={len(step['access_exclusive']):<2} "
            f"rewrite={step['tables_rewritten'] or '-'}  "
            f"worst_read={max(step['worst_reader_latency_s'].values(), default=0):.3f}s",
            flush=True,
        )
        if step["returncode"] != 0:
            print("\n".join(step["output_tail"]))
            break
    Path(sys.argv[1]).write_text(json.dumps(results, indent=2))
    return 0 if all(s["returncode"] == 0 for s in results) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
