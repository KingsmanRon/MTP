"""Phase 7A, Gate 1 — rehearse the production migration on populated data.

A migration that has only ever run on an empty schema has not been tested.
This builds a database at a configurable data volume, upgrades it from the
revision production is actually on to head, and measures and checks what a
release decision needs to know.

What it answers
---------------
1. **Does the upgrade complete**, from the current production revision?
2. **How long does each migration take**, individually, on this volume?
3. **Which locks does it take, and for how long?** An ACCESS EXCLUSIVE lock
   on a hot table blocks every reader for its duration; that is the number
   a maintenance-window decision turns on.
4. **Is existing data still readable** afterwards?
5. **Do existing unconsumed legacy approval tokens still behave** as the
   documented mixed-version bridge says?
6. **Does tenant isolation still hold?**
7. **Was anything rewritten destructively?** Table rewrites are detected by
   comparing each relation's file node before and after: a changed filenode
   means the table was rewritten, which on a large table is the difference
   between seconds and hours.

Usage
-----
    ADMIN_DATABASE_URL=postgresql://...   # may CREATE DATABASE
    python -m scripts.staging_migration_rehearsal \\
        --from-revision 0018_merkle_anchor_visibility \\
        --agents 200 --audit-rows 50000 --json evidence.json

``--from-revision`` should be the revision production is on right now. The
default is the last revision before the v0.5 authority work, which is what
this release upgrades from.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse
from uuid import UUID, uuid4

import asyncpg

PROJECT_ROOT = Path(__file__).resolve().parents[1]

#: The last revision before the v0.5 authority migrations. Production is
#: expected to be at or before this when this release deploys.
DEFAULT_FROM_REVISION = "0018_merkle_anchor_visibility"

#: Relations whose rewrite would be expensive, and whose locks matter.
WATCHED_TABLES: tuple[str, ...] = (
    "agents",
    "audit_logs",
    "organizations",
    "approval_token_consumptions",
    "spend_reservations",
    "api_keys",
    "merkle_proofs",
)


def _with_database(dsn: str, database: str) -> str:
    parsed = urlparse(dsn)
    return urlunparse(parsed._replace(path=f"/{database}"))


class AtHead(RuntimeError):
    """``upgrade +1`` had nothing left to apply. Not a failure."""


def _alembic(dsn: str, *args: str) -> tuple[float, str]:
    started = time.perf_counter()
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=PROJECT_ROOT,
        env={**os.environ, "ALEMBIC_DATABASE_URL": dsn},
        capture_output=True,
        text=True,
        timeout=7200,
    )
    combined = result.stdout + result.stderr
    if result.returncode != 0:
        # Alembic reports "already at head" for a relative upgrade the same
        # way it reports a real failure. Distinguished here so the loop
        # below can stop rather than report a migration error that is not one.
        if "didn't produce 1 migrations" in combined:
            raise AtHead()
        raise RuntimeError(f"alembic {' '.join(args)} failed:\n{combined}")
    return time.perf_counter() - started, combined


async def populate(dsn: str, *, agents: int, audit_rows: int) -> dict[str, Any]:
    """Build a realistic tenant/principal/audit graph.

    Deliberately many organisations rather than one: the RLS graph and the
    per-agent audit chains are both per-tenant, and a single-tenant fixture
    would not exercise either.
    """
    conn = await asyncpg.connect(dsn)
    started = time.perf_counter()
    try:
        organisations = max(1, agents // 5)
        org_ids = [uuid4() for _ in range(organisations)]
        await conn.executemany(
            """
            INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
            VALUES ($1, $2, 'enterprise', $3, sha256($4::BYTEA))
            """,
            [
                (org, f"rehearsal-{org}", f"rehearsal-{org}@invalid.test", str(org).encode())
                for org in org_ids
            ],
        )

        agent_ids: list[tuple[UUID, UUID]] = []
        rows = []
        for index in range(agents):
            org = org_ids[index % organisations]
            agent = uuid4()
            agent_ids.append((org, agent))
            rows.append(
                (
                    agent,
                    org,
                    f"rehearsal-agent-{agent}",
                    bytes(32),
                    f"{index:064x}",
                    json.dumps(
                        {
                            "sandbox": False,
                            "production_approval_reference": "rehearsal",
                            "production_approved_at": "2026-01-01T00:00:00Z",
                            "production_approved_by": "rehearsal",
                        }
                    ),
                )
            )
        await conn.executemany(
            """
            INSERT INTO agents (
                id, org_id, name, public_key, public_key_fingerprint, trust_score,
                status, daily_limit_usd, per_action_limit_usd, allowed_actions,
                blocked_actions, rate_limit_per_minute, metadata
            ) VALUES (
                $1, $2, $3, $4, $5, 80, 'active', 10000, 10000,
                ARRAY['financial_transaction']::TEXT[], ARRAY[]::TEXT[], 1000, $6::JSONB
            )
            """,
            rows,
        )

        # Audit rows carry the per-agent hash chain, so they are inserted
        # through the same trigger production uses rather than bulk-loaded
        # with a precomputed sequence. That makes the volume realistic and
        # the chain genuine.
        per_agent = max(1, audit_rows // max(1, len(agent_ids)))
        audit_batch = []
        for _org, agent in agent_ids:
            for sequence in range(per_agent):
                audit_batch.append(
                    (
                        agent,
                        "financial_transaction",
                        f"{(hash((agent, sequence)) & (2**256 - 1)):064x}"[:64],
                        json.dumps({"amount": "10.00", "currency": "USD"}),
                        "approved",
                        "rehearsal fixture",
                        bytes(64),
                        True,
                        80,
                    )
                )
        await conn.executemany(
            """
            INSERT INTO audit_logs (
                agent_id, action_type, action_hash, payload, verdict,
                verdict_reason, signature, signature_valid, trust_score_at_time
            ) VALUES ($1, $2, $3, $4::JSONB, $5, $6, $7, $8, $9)
            """,
            audit_batch,
        )

        # Unconsumed legacy approval tokens: the mixed-version bridge is
        # about exactly these, so the rehearsal must have some.
        legacy_tokens = []
        for _org, agent in agent_ids[: min(len(agent_ids), 50)]:
            token_id = f"legacy-token-{uuid4()}"
            legacy_tokens.append(
                (
                    agent,
                    f"{(hash(token_id) & (2**256 - 1)):064x}"[:64],
                    token_id,
                    "10.00",
                    datetime.now(UTC) + timedelta(hours=1),
                )
            )
        await conn.executemany(
            """
            INSERT INTO spend_reservations (
                agent_id, action_hash, approval_token_id, amount_usd, expires_at
            ) VALUES ($1, $2, $3, $4::NUMERIC, $5)
            """,
            legacy_tokens,
        )

        await conn.execute("ANALYZE")
        sizes = await conn.fetch("""
            SELECT relname, n_live_tup,
                   pg_size_pretty(pg_total_relation_size(relid)) AS size
            FROM pg_stat_user_tables
            WHERE n_live_tup > 0
            ORDER BY n_live_tup DESC
            """)
    finally:
        await conn.close()

    return {
        "seconds": round(time.perf_counter() - started, 3),
        "organisations": organisations,
        "agents": agents,
        "tables": [
            {"table": r["relname"], "rows": r["n_live_tup"], "size": r["size"]} for r in sizes
        ],
    }


async def relation_filenodes(dsn: str) -> dict[str, int]:
    """Each watched table's file node. A change means it was rewritten."""
    conn = await asyncpg.connect(dsn)
    try:
        rows = await conn.fetch(
            """
            SELECT c.relname, c.relfilenode
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relname = ANY($1::TEXT[])
            """,
            list(WATCHED_TABLES),
        )
    finally:
        await conn.close()
    return {row["relname"]: row["relfilenode"] for row in rows}


async def watch_locks(dsn: str, stop: asyncio.Event) -> list[dict[str, Any]]:
    """Sample the locks the migration holds while it runs.

    Polling rather than instrumenting the migration, because the question
    is what an OBSERVER would have seen -- which is exactly what a blocked
    application connection experiences.
    """
    observed: dict[tuple[str, str], dict[str, Any]] = {}
    conn = await asyncpg.connect(dsn)
    try:
        while not stop.is_set():
            rows = await conn.fetch("""
                SELECT c.relname, l.mode, l.granted
                FROM pg_locks l
                JOIN pg_class c ON c.oid = l.relation
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND l.mode IN ('AccessExclusiveLock', 'ExclusiveLock', 'ShareRowExclusiveLock')
                """)
            now = time.perf_counter()
            for row in rows:
                key = (row["relname"], row["mode"])
                entry = observed.setdefault(
                    key,
                    {
                        "table": row["relname"],
                        "mode": row["mode"],
                        "first_seen": now,
                        "last_seen": now,
                    },
                )
                entry["last_seen"] = now
            await asyncio.sleep(0.05)
    except asyncio.CancelledError:
        pass
    finally:
        # The connection may be mid-operation when cancelled; terminate
        # rather than close, which would try to finish that operation.
        conn.terminate()

    return [
        {
            "table": entry["table"],
            "mode": entry["mode"],
            "held_at_least_seconds": round(entry["last_seen"] - entry["first_seen"], 3),
        }
        for entry in sorted(observed.values(), key=lambda e: -(e["last_seen"] - e["first_seen"]))
    ]


async def check_data_readable(dsn: str) -> dict[str, Any]:
    conn = await asyncpg.connect(dsn)
    try:
        counts = {}
        for table in ("organizations", "agents", "audit_logs", "spend_reservations"):
            counts[table] = await conn.fetchval(f"SELECT COUNT(*) FROM {table}")
        # The audit chain must still be intact: every agent's sequence runs
        # 1..n with no gaps. A migration that renumbered it would break every
        # existing receipt's provenance.
        broken = await conn.fetchval("""
            SELECT COUNT(*) FROM (
                SELECT agent_id, COUNT(*) AS rows, MAX(chain_sequence) AS top
                FROM audit_logs GROUP BY agent_id
            ) s WHERE s.rows <> s.top
            """)
        return {"row_counts": counts, "agents_with_broken_chain": broken}
    finally:
        await conn.close()


async def check_legacy_tokens(dsn: str) -> dict[str, Any]:
    """The mixed-version bridge, on real pre-existing rows.

    A legacy approval token is simply a token with no grant row. After the
    upgrade it must still be exactly that: unconsumed, unreferenced by any
    grant, and claimable through the same uniqueness that always governed
    it. Nothing is converted and nothing is backfilled.
    """
    conn = await asyncpg.connect(dsn)
    try:
        reserved = await conn.fetchval(
            "SELECT COUNT(*) FROM spend_reservations WHERE status = 'reserved'"
        )
        orphaned = await conn.fetchval("""
            SELECT COUNT(*) FROM spend_reservations r
            WHERE r.status = 'reserved'
              AND NOT EXISTS (
                SELECT 1 FROM execution_authority_grants g
                WHERE g.approval_token_id = r.approval_token_id
              )
            """)
        consumed = await conn.fetchval("SELECT COUNT(*) FROM approval_token_consumptions")
        return {
            "unconsumed_legacy_reservations": reserved,
            "still_without_a_grant_row": orphaned,
            "no_backfill_occurred": reserved == orphaned,
            "consumption_records": consumed,
        }
    finally:
        await conn.close()


async def check_tenant_isolation(dsn: str) -> dict[str, Any]:
    """RLS forced on every table carrying tenant data, after the upgrade."""
    conn = await asyncpg.connect(dsn)
    try:
        rows = await conn.fetch("""
            SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r'
              AND c.relname IN (
                'agents', 'audit_logs', 'organizations', 'merkle_proofs',
                'execution_authority_grants', 'authority_decision_evidence',
                'authority_requirements', 'authority_controls',
                'authority_trust_revocations', 'authority_principal_bindings',
                'approval_token_consumptions', 'administrative_audit_events'
              )
            """)
    finally:
        await conn.close()
    unprotected = [
        r["relname"] for r in rows if not (r["relrowsecurity"] and r["relforcerowsecurity"])
    ]
    return {
        "tables_checked": len(rows),
        "without_forced_rls": unprotected,
        "ok": not unprotected,
    }


async def rehearse(args: argparse.Namespace) -> dict[str, Any]:
    admin_dsn = os.getenv("ADMIN_DATABASE_URL", "").strip()
    if not admin_dsn:
        raise SystemExit("ADMIN_DATABASE_URL is required")

    name = args.database or f"staging_rehearsal_{datetime.now(UTC):%Y%m%d%H%M%S}"
    dsn = _with_database(admin_dsn, name)

    admin = await asyncpg.connect(admin_dsn)
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
    finally:
        await admin.close()

    findings: dict[str, Any] = {"database": name, "from_revision": args.from_revision}
    try:
        # 1. Bring the database to the revision production is on.
        baseline_seconds, _ = _alembic(dsn, "upgrade", args.from_revision)
        findings["baseline_upgrade_seconds"] = round(baseline_seconds, 3)

        # 2. Populate it.
        findings["population"] = await populate(dsn, agents=args.agents, audit_rows=args.audit_rows)

        before = await relation_filenodes(dsn)

        # 3. Upgrade to head, one revision at a time so each is timed
        #    separately, while sampling the locks an observer would see.
        stop = asyncio.Event()
        watcher = asyncio.create_task(watch_locks(dsn, stop))

        per_revision: list[dict[str, Any]] = []
        total_started = time.perf_counter()
        while True:
            try:
                seconds, output = _alembic(dsn, "upgrade", "+1")
            except AtHead:
                break
            applied = [line.strip() for line in output.splitlines() if "Running upgrade" in line]
            if not applied:
                break
            per_revision.append({"revision": applied[0], "seconds": round(seconds, 3)})
        total_seconds = time.perf_counter() - total_started

        stop.set()
        try:
            findings["locks_observed"] = await asyncio.wait_for(watcher, timeout=10)
        except (TimeoutError, Exception) as exc:  # noqa: BLE001
            watcher.cancel()
            findings["locks_observed"] = {
                "error": f"lock sampling ended early: {type(exc).__name__}"
            }

        after = await relation_filenodes(dsn)
        rewritten = sorted(
            table for table, node in before.items() if after.get(table) not in (None, node)
        )

        findings.update(
            {
                "upgrade": {
                    "total_seconds": round(total_seconds, 3),
                    "per_revision": per_revision,
                    "revisions_applied": len(per_revision),
                },
                "destructive_rewrites": {
                    "tables_rewritten": rewritten,
                    "none": not rewritten,
                    "method": "pg_class.relfilenode compared before and after",
                },
                "data_readable": await check_data_readable(dsn),
                "legacy_token_bridge": await check_legacy_tokens(dsn),
                "tenant_isolation": await check_tenant_isolation(dsn),
            }
        )

        problems: list[str] = []
        if rewritten:
            problems.append(f"tables rewritten: {rewritten}")
        if findings["data_readable"]["agents_with_broken_chain"]:
            problems.append("an agent's audit hash chain has gaps after the upgrade")
        if not findings["legacy_token_bridge"]["no_backfill_occurred"]:
            problems.append("legacy approval tokens were modified by the upgrade")
        if not findings["tenant_isolation"]["ok"]:
            problems.append(
                f"RLS not forced on {findings['tenant_isolation']['without_forced_rls']}"
            )
        findings["problems"] = problems
        findings["ready"] = not problems
        findings["recovery"] = {
            "downgrade_supported": False,
            "mechanism": "reviewed forward repair",
            "detail": (
                "Every authority migration raises on downgrade(): grants record "
                "what was authorised and whether it was spent, and dropping them "
                "would destroy the evidence that gated real executions. If the "
                "application is rolled back, the new tables are inert -- nothing "
                "in the old code path reads or writes them -- so no repair is "
                "needed to run the old version. Rolling forward again needs one "
                "reconciliation: grants whose approval_token_id appears in "
                "approval_token_consumptions while the grant still reads "
                "'active'. See docs/EXECUTION_AUTHORITY_PERSISTENCE.md."
            ),
        }
    finally:
        if not args.keep:
            admin = await asyncpg.connect(admin_dsn)
            try:
                await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            finally:
                await admin.close()

    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="staging_migration_rehearsal", description=__doc__)
    parser.add_argument("--from-revision", default=DEFAULT_FROM_REVISION)
    parser.add_argument("--agents", type=int, default=200)
    parser.add_argument("--audit-rows", type=int, default=20000)
    parser.add_argument("--database", default=None)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--json", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    findings = asyncio.run(rehearse(args))
    rendered = json.dumps(findings, indent=2, default=str)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if findings.get("ready") else 1


if __name__ == "__main__":
    sys.exit(main())
