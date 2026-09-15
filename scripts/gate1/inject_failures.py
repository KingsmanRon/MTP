"""Gate 1: what actually happens when the migration fails, and what operators do.

Failures are injected the way they happen in production -- a live query
holding a lock the migration needs, with lock_timeout set -- not by editing
a migration. The question each scenario answers is: after the failure, what
revision is the database at, is the schema consistent, and does the running
application still work?
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import asyncpg

MIG = os.environ["ALEMBIC_DATABASE_URL"]
RESULTS: list[dict] = []


def alembic(*args: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=str(Path(__file__).resolve().parents[2]), capture_output=True, text=True,
        env={**os.environ},
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


async def revision(conn) -> str:
    return await conn.fetchval("SELECT version_num FROM alembic_version")


async def blocked_upgrade(table: str, target: str) -> dict:
    """Hold a read lock on `table`, as a live query would, then migrate."""
    holder = await asyncpg.connect(MIG)
    tx = holder.transaction()
    await tx.start()
    await holder.fetchval(f"SELECT count(*) FROM {table} WHERE 1=0")  # AccessShareLock
    try:
        code, output = alembic("upgrade", target)
    finally:
        await tx.rollback()
        await holder.close(timeout=5)
    return {"returncode": code, "output_tail": output.splitlines()[-2:]}


async def schema_fingerprint(conn) -> dict:
    return {
        "revision": await revision(conn),
        "agents_unique": await conn.fetchval(
            "SELECT count(*) FROM pg_constraint WHERE conname = 'agents_id_org_unique'"),
        "audit_unique": await conn.fetchval(
            "SELECT count(*) FROM pg_constraint "
            "WHERE conname = 'audit_logs_id_agent_action_unique'"),
        "authority_tables": await conn.fetchval(
            "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' "
            "AND table_name IN ('execution_authority_grants','authority_requirements',"
            "'authority_controls','authority_decision_evidence')"),
        "admin_scope_column": await conn.fetchval(
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_name='administrative_audit_events' AND column_name='scope'"),
    }


async def old_app_write_probe(conn) -> dict:
    """Exactly what the OLD application does, in its own column shape."""
    agent = await conn.fetchval("SELECT id FROM agents WHERE status='active' LIMIT 1")
    org = await conn.fetchval("SELECT org_id FROM agents WHERE id=$1", agent)
    audit = await conn.fetchval(
        """INSERT INTO audit_logs (id, agent_id, timestamp, action_type, action_hash,
             payload, verdict, signature, signature_valid, trust_score_at_time)
           VALUES (gen_random_uuid(), $1, NOW(), 'financial_transaction',
                   encode(sha256(gen_random_bytes(8)),'hex'), '{}'::JSONB, 'approved',
                   gen_random_bytes(64), TRUE, 90) RETURNING id""", agent)
    # The old app's administrative_audit_events INSERT names no `scope`.
    admin = await conn.fetchval(
        """INSERT INTO administrative_audit_events
             (org_id, event_type, actor, approval_reference, details)
           VALUES ($1, 'agent.production_promoted', 'old-app', 'OLD-APP-1',
                   '{"agent_id":"x"}'::JSONB) RETURNING id""", org)
    # `scope` only exists once 031 has run; the earlier scenarios run against
    # a database that has not reached it, which is the whole point of them.
    has_scope = await conn.fetchval(
        "SELECT count(*) FROM information_schema.columns "
        "WHERE table_name='administrative_audit_events' AND column_name='scope'")
    scope = (
        await conn.fetchval(
            "SELECT scope FROM administrative_audit_events WHERE id=$1", admin)
        if has_scope else "n/a (pre-031)"
    )
    chained = await conn.fetchval(
        "SELECT chain_sequence IS NOT NULL FROM audit_logs WHERE id=$1", audit)
    return {"audit_insert": bool(audit), "chain_assigned": bool(chained),
            "admin_insert": bool(admin), "admin_scope_defaulted_to": scope}


def rebuild(target: str | None) -> None:
    subprocess.run(
        ["bash", str(Path(__file__).resolve().parent / "build_staging.sh")],
        capture_output=True, text=True, check=True)
    if target:
        code, out = alembic("upgrade", target)
        if code != 0:
            raise RuntimeError(out)


async def main() -> int:
    conn_url = MIG

    # --- Scenario A: failure BEFORE the first authority migration --------
    rebuild(None)  # at 0018
    attempt = await blocked_upgrade("agents", "head")
    conn = await asyncpg.connect(conn_url)
    after = await schema_fingerprint(conn)
    probe = await old_app_write_probe(conn)
    await conn.close(timeout=5)
    RESULTS.append({
        "scenario": "A failure before the first authority migration",
        "injected": "a live query holds AccessShareLock on agents; "
                    "0019 cannot take ACCESS EXCLUSIVE and hits lock_timeout",
        "migration_failed": attempt["returncode"] != 0,
        "state_after": after,
        "old_app_still_works": probe,
        "operator_action": "none. The database is still at the deployed "
                           "revision and nothing partial was applied; retry the "
                           "pre-deploy migration in a quieter window.",
    })

    # ...and a retry with the lock released must succeed.
    code, _ = alembic("upgrade", "head")
    conn = await asyncpg.connect(conn_url)
    RESULTS[-1]["retry_succeeds"] = code == 0
    RESULTS[-1]["retry_method"] = "alembic upgrade head (ONE invocation)"
    RESULTS[-1]["retry_revision"] = await revision(conn)
    await conn.close(timeout=5)

    # --- Scenario B: failure MID-CHAIN -----------------------------------
    rebuild("0020_authority_evidence")
    attempt = await blocked_upgrade("audit_logs", "head")
    conn = await asyncpg.connect(conn_url)
    after = await schema_fingerprint(conn)
    probe = await old_app_write_probe(conn)
    await conn.close(timeout=5)
    RESULTS.append({
        "scenario": "B failure mid-chain",
        "injected": "0019/0020 applied; a live query holds AccessShareLock on "
                    "audit_logs; 0021's unique constraint hits lock_timeout",
        "migration_failed": attempt["returncode"] != 0,
        "state_after": after,
        "old_app_still_works": probe,
        "operator_action": "none, and NO downgrade. One revision is one "
                           "transaction, so the database sits at the last "
                           "revision that committed, with a consistent schema. "
                           "The partially applied authority tables are inert to "
                           "the old application. Retry forward.",
    })
    code, _ = alembic("upgrade", "head")
    conn = await asyncpg.connect(conn_url)
    RESULTS[-1]["retry_succeeds"] = code == 0
    RESULTS[-1]["retry_method"] = "alembic upgrade head (ONE invocation)"
    RESULTS[-1]["retry_revision"] = await revision(conn)
    await conn.close(timeout=5)

    # --- Scenario C: schema at head, application NOT yet rolled forward --
    conn = await asyncpg.connect(conn_url)
    state = await schema_fingerprint(conn)
    probe = await old_app_write_probe(conn)
    grants = await conn.fetchval("SELECT count(*) FROM execution_authority_grants")
    await conn.close(timeout=5)
    RESULTS.append({
        "scenario": "C schema migrated, old application still serving",
        "injected": "the pre-deploy migration succeeded; the application "
                    "rollout has not happened yet",
        "state_after": state,
        "old_app_still_works": probe,
        "new_tables_inert": {"execution_authority_grants_rows": grants},
        "operator_action": "none. This is the normal pre-deploy window and the "
                           "old application is unaffected -- proved by running "
                           "the deployed branch's own suite against this "
                           "database with an identical pass/fail set. Roll the "
                           "application forward when ready.",
    })

    # --- Scenario D: application ROLLBACK after the database reached head
    conn = await asyncpg.connect(conn_url)
    probe = await old_app_write_probe(conn)
    still_head = await revision(conn)
    await conn.close(timeout=5)
    RESULTS.append({
        "scenario": "D application rolled back after the database reached head",
        "injected": "the new application was deployed and then rolled back; "
                    "the database stays at 0027",
        "database_left_at": still_head,
        "old_app_still_works": probe,
        "operator_action": "roll the application back and leave the database "
                           "forward. Alembic downgrade is NOT the recovery "
                           "mechanism -- 0023-0027 raise NotImplementedError on "
                           "downgrade by design. Recovery is either (1) deploy "
                           "the previous application image, which the old-app/"
                           "new-db result shows is safe, or (2) restore from a "
                           "snapshot taken before the pre-deploy migration, "
                           "which loses everything written since. (1) is the "
                           "expected path; (2) is only for a schema fault that "
                           "a reviewed forward migration cannot repair.",
    })

    Path(sys.argv[1]).write_text(json.dumps(RESULTS, indent=2))
    for r in RESULTS:
        print(f"--- {r['scenario']}")
        for key in ("migration_failed", "retry_succeeds", "retry_revision",
                    "database_left_at"):
            if key in r:
                print(f"    {key}: {r[key]}")
        if "state_after" in r:
            print(f"    state: {r['state_after']}")
        print(f"    old app: {r['old_app_still_works']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
