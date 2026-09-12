"""Phase 7A, Gate 8 — rehearse restoring from backup, and check what matters.

A backup nobody has restored is a hope, not a control. This script restores
one into a scratch database and then asks the questions that actually decide
whether the restore is usable — not "did pg_restore exit 0", which it will
even when the security properties are gone.

What it checks, and why each one
--------------------------------
**The migration revision.** A restore at an older head means the application
would run against a schema it does not expect. Compared, not assumed.

**Row counts on the security-critical tables.** A restore missing
``approval_token_consumptions`` rows is the worst possible outcome: every
already-spent single-use authority would appear unspent, and a replayed
token would be honoured. This is checked first among the counts.

**Append-only triggers.** ``pg_restore`` can succeed while leaving a trigger
behind. It is not enough that the rows came back; the rules that stop them
being rewritten have to come back too. So the restored database is *made to
refuse* an UPDATE, rather than being inspected for a trigger's name.

**Row level security.** Same reasoning: RLS enabled AND forced on every
table that carries tenant data, checked as a property of the restored
catalog.

**Spent authority stays spent.** The end of the chain: a grant recorded as
consumed must still be unspendable after the restore.

Usage
-----
    SOURCE_DATABASE_URL=postgresql://...      # what to back up
    TARGET_ADMIN_URL=postgresql://...         # a server we may create a DB on
    python -m scripts.backup_restore_rehearsal --json evidence.json

The target database is created fresh and dropped afterwards unless
``--keep`` is passed. Nothing is written to the source.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import asyncpg

#: Restoring fewer rows than the source had in any of these is a failure,
#: not a warning. approval_token_consumptions is first deliberately: it is
#: the single-use authority record, and losing it re-opens every spent token.
CRITICAL_TABLES: tuple[str, ...] = (
    "approval_token_consumptions",
    "execution_authority_grants",
    "authority_decision_evidence",
    "administrative_audit_events",
    "audit_logs",
    "spend_reservations",
    "authority_requirements",
    "authority_controls",
    "authority_trust_revocations",
    "authority_principal_bindings",
    "agents",
    "organizations",
)

#: Tables whose rows must be impossible to rewrite after a restore.
APPEND_ONLY_TABLES: tuple[str, ...] = (
    "approval_token_consumptions",
    "administrative_audit_events",
)


class RehearsalError(RuntimeError):
    """The restore is not usable. Always fatal — a caveat is not a result."""


def _require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def _with_database(dsn: str, database: str) -> str:
    parsed = urlparse(dsn)
    return urlunparse(parsed._replace(path=f"/{database}"))


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise SystemExit(
            f"{name} is not on PATH. The rehearsal needs the PostgreSQL client "
            "tools; install postgresql-client matching the server version."
        )
    return path


def run_dump(source_dsn: str, dump_path: Path) -> float:
    started = time.perf_counter()
    subprocess.run(
        [
            _require_tool("pg_dump"),
            "--format=custom",
            "--no-owner",
            "--no-privileges",
            f"--file={dump_path}",
            source_dsn,
        ],
        check=True,
        timeout=3600,
    )
    return time.perf_counter() - started


def run_restore(target_dsn: str, dump_path: Path) -> float:
    started = time.perf_counter()
    result = subprocess.run(
        [
            _require_tool("pg_restore"),
            "--no-owner",
            "--no-privileges",
            f"--dbname={target_dsn}",
            str(dump_path),
        ],
        capture_output=True,
        text=True,
        timeout=3600,
    )
    # pg_restore exits non-zero for ignorable ownership/extension notices on a
    # scratch target. The checks below are what decide usability, so a
    # non-zero exit is reported rather than silently fatal -- but its stderr
    # is carried into the evidence so nobody has to guess what it said.
    if result.returncode != 0:
        print(
            "NOTE: pg_restore exited "
            f"{result.returncode}; the property checks below decide usability",
            file=sys.stderr,
        )
        print(result.stderr[-4000:], file=sys.stderr)
    return time.perf_counter() - started


async def table_counts(dsn: str) -> dict[str, int | None]:
    counts: dict[str, int | None] = {}
    conn = await asyncpg.connect(dsn)
    try:
        for table in CRITICAL_TABLES:
            exists = await conn.fetchval("SELECT to_regclass($1)", f"public.{table}")
            if exists is None:
                counts[table] = None
                continue
            counts[table] = await conn.fetchval(f"SELECT COUNT(*) FROM {table}")
    finally:
        await conn.close()
    return counts


async def alembic_revision(dsn: str) -> str | None:
    conn = await asyncpg.connect(dsn)
    try:
        if await conn.fetchval("SELECT to_regclass('public.alembic_version')") is None:
            return None
        return await conn.fetchval("SELECT version_num FROM alembic_version LIMIT 1")
    finally:
        await conn.close()


async def check_append_only(dsn: str) -> dict[str, str]:
    """Prove the restored database REFUSES a rewrite, table by table."""
    results: dict[str, str] = {}
    conn = await asyncpg.connect(dsn)
    try:
        for table in APPEND_ONLY_TABLES:
            if await conn.fetchval("SELECT to_regclass($1)", f"public.{table}") is None:
                results[table] = "absent"
                continue
            if await conn.fetchval(f"SELECT COUNT(*) FROM {table}") == 0:
                # Nothing to attempt a rewrite of. Fall back to the catalog,
                # and say so rather than reporting a check that did not run.
                present = await conn.fetchval(
                    """
                    SELECT COUNT(*) FROM pg_trigger t
                    JOIN pg_class c ON c.oid = t.tgrelid
                    WHERE c.relname = $1 AND NOT t.tgisinternal
                    """,
                    table,
                )
                results[table] = f"no rows to test; {present} trigger(s) present in catalog"
                continue
            # Update a column to ITSELF, chosen from the catalog. A hardcoded
            # column name would differ per table, and an UPDATE that fails
            # because the column does not exist looks exactly like an UPDATE
            # the trigger refused -- a false pass on the check that matters
            # most here.
            column = await conn.fetchval(
                """
                SELECT attname FROM pg_attribute
                WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped
                ORDER BY attnum LIMIT 1
                """,
                f"public.{table}",
            )
            if column is None:
                results[table] = "FAILED: no column to attempt an update on"
                continue
            try:
                async with conn.transaction():
                    await conn.execute(f'UPDATE {table} SET "{column}" = "{column}"')
                results[table] = "FAILED: an update was accepted"
            except asyncpg.UndefinedColumnError:
                results[table] = "FAILED: the update could not even be attempted"
            except asyncpg.PostgresError as exc:
                results[table] = f"refused ({type(exc).__name__})"
    finally:
        await conn.close()
    return results


async def check_row_level_security(dsn: str) -> dict[str, Any]:
    conn = await asyncpg.connect(dsn)
    try:
        rows = await conn.fetch(
            """
            SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r'
              AND c.relname = ANY($1::TEXT[])
            """,
            list(CRITICAL_TABLES),
        )
    finally:
        await conn.close()

    unprotected = [
        row["relname"] for row in rows if not (row["relrowsecurity"] and row["relforcerowsecurity"])
    ]
    return {
        "tables_checked": len(rows),
        "without_forced_rls": unprotected,
        "ok": not unprotected,
    }


async def check_spent_authority_stays_spent(dsn: str) -> dict[str, Any]:
    """The end of the chain: a consumed token must still be unclaimable.

    Attempts to insert a duplicate consumption for a token that is already
    recorded as spent. If the restore lost the uniqueness that makes
    single-use authority single-use, this is where it shows.
    """
    conn = await asyncpg.connect(dsn)
    try:
        if await conn.fetchval("SELECT to_regclass('public.approval_token_consumptions')") is None:
            return {"checked": False, "reason": "table absent"}
        row = await conn.fetchrow("""
            SELECT token_id, token_digest, agent_id, action_hash, audit_log_id
            FROM approval_token_consumptions LIMIT 1
            """)
        if row is None:
            return {"checked": False, "reason": "no consumed tokens in the backup"}
        try:
            async with conn.transaction():
                await conn.execute(
                    """
                    INSERT INTO approval_token_consumptions (
                        token_id, token_digest, agent_id, action_hash, audit_log_id
                    ) VALUES ($1, $2, $3, $4, $5)
                    """,
                    row["token_id"],
                    row["token_digest"],
                    row["agent_id"],
                    row["action_hash"],
                    row["audit_log_id"],
                )
            return {
                "checked": True,
                "ok": False,
                "detail": "a spent token was accepted a second time",
            }
        except asyncpg.PostgresError as exc:
            return {"checked": True, "ok": True, "refused_with": type(exc).__name__}
    finally:
        await conn.close()


async def rehearse(args: argparse.Namespace) -> dict[str, Any]:
    source_dsn = _require_env("SOURCE_DATABASE_URL")
    admin_dsn = _require_env("TARGET_ADMIN_URL")
    target_name = args.target_database or (
        f"restore_rehearsal_{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
    )
    target_dsn = _with_database(admin_dsn, target_name)

    source_counts = await table_counts(source_dsn)
    source_revision = await alembic_revision(source_dsn)

    admin = await asyncpg.connect(admin_dsn)
    try:
        await admin.execute(f'CREATE DATABASE "{target_name}"')
    finally:
        await admin.close()

    findings: dict[str, Any] = {}
    try:
        with tempfile.TemporaryDirectory() as workdir:
            dump_path = Path(workdir) / "backup.dump"
            dump_seconds = run_dump(source_dsn, dump_path)
            dump_bytes = dump_path.stat().st_size
            restore_seconds = run_restore(target_dsn, dump_path)

        restored_counts = await table_counts(target_dsn)
        restored_revision = await alembic_revision(target_dsn)

        missing_rows = {
            table: {"source": source_counts[table], "restored": restored_counts[table]}
            for table in CRITICAL_TABLES
            if source_counts.get(table) is not None
            and (restored_counts.get(table) or 0) < source_counts[table]
        }

        findings = {
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "target_database": target_name,
            "dump": {
                "seconds": round(dump_seconds, 3),
                "bytes": dump_bytes,
            },
            "restore": {"seconds": round(restore_seconds, 3)},
            "migration_revision": {
                "source": source_revision,
                "restored": restored_revision,
                "match": source_revision == restored_revision,
            },
            "row_counts": {
                "source": source_counts,
                "restored": restored_counts,
                "tables_with_missing_rows": missing_rows,
            },
            "append_only_triggers": await check_append_only(target_dsn),
            "row_level_security": await check_row_level_security(target_dsn),
            "spent_authority_stays_spent": await check_spent_authority_stays_spent(target_dsn),
        }

        problems: list[str] = []
        if not findings["migration_revision"]["match"]:
            problems.append("restored migration revision differs from the source")
        if missing_rows:
            problems.append(f"rows missing after restore: {sorted(missing_rows)}")
        if not findings["row_level_security"]["ok"]:
            problems.append(
                "row level security is not forced on: "
                f"{findings['row_level_security']['without_forced_rls']}"
            )
        for table, outcome in findings["append_only_triggers"].items():
            if outcome.startswith("FAILED"):
                problems.append(f"{table} accepted an update after restore")
        spent = findings["spent_authority_stays_spent"]
        if spent.get("checked") and not spent.get("ok"):
            problems.append("a spent single-use token was accepted again after restore")

        findings["problems"] = problems
        findings["usable"] = not problems
    finally:
        if not args.keep:
            admin = await asyncpg.connect(admin_dsn)
            try:
                await admin.execute(f'DROP DATABASE IF EXISTS "{target_name}" WITH (FORCE)')
            finally:
                await admin.close()

    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="backup_restore_rehearsal", description=__doc__)
    parser.add_argument("--target-database", default=None)
    parser.add_argument("--keep", action="store_true", help="Leave the restored database in place")
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
    # Non-zero on an unusable restore: a rehearsal that reports a problem and
    # exits 0 will be run by CI and ignored.
    return 0 if findings.get("usable") else 1


if __name__ == "__main__":
    sys.exit(main())
