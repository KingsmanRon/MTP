"""Gate 1: what must still be true after the staging upgrade reaches 0027.

Run against the migrated staging database. Every check is a statement about
data or behaviour that existed before the migration, or about behaviour the
migration is supposed to add -- nothing is asserted from the migration's own
success.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import asyncpg

from api.core.authority.decision import DecisionReason
from api.core.authority.lifecycle import ConsumptionOutcome
from api.database import Database
from api.persistence.authority_configuration import (
    resolve_authority_configuration_on,
)
from api.persistence.authority_configuration_management import (
    apply_authority_configuration_change,
)
from api.persistence.authority_store import AuthorityStore, IssueOutcome

MIGRATOR_URL = os.environ["ALEMBIC_DATABASE_URL"]
RUNTIME_URL = os.environ["DATABASE_URL"]
MANAGEMENT_URL = os.environ["AUTHORITY_MANAGEMENT_DATABASE_URL"]

POLICY_HASH = "b" * 64
BINDING = "c" * 64
RESULTS: list[dict] = []


def check(name: str, ok: bool, detail: str) -> None:
    RESULTS.append({"check": name, "pass": bool(ok), "detail": detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}", flush=True)


def action_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


async def main() -> int:
    mig = await asyncpg.connect(MIGRATOR_URL)
    db = await Database.create(RUNTIME_URL, min_size=2, max_size=8)
    mgmt = await asyncpg.create_pool(MANAGEMENT_URL, min_size=1, max_size=3)
    store = AuthorityStore(
        db, current_policy_resolver=lambda _agent, _action, _domain: (POLICY_HASH, "revision-1")
    )

    # --- 1. pre-existing data is still readable --------------------------
    counts = {}
    for table in ("organizations", "agents", "audit_logs",
                  "approval_token_consumptions", "merkle_proofs",
                  "administrative_audit_events"):
        counts[table] = await mig.fetchval(f"SELECT count(*) FROM {table}")
    check("1 pre-existing data readable",
          all(v > 0 for v in counts.values()), json.dumps(counts))

    # --- 2. the forensic chain survived ----------------------------------
    broken = await mig.fetchval("""
        WITH chk AS (
          SELECT chain_sequence, chain_previous_hash,
                 LAG(action_hash) OVER (PARTITION BY agent_id ORDER BY chain_sequence) AS expected,
                 ROW_NUMBER() OVER (PARTITION BY agent_id ORDER BY chain_sequence) AS ordinal
          FROM audit_logs)
        SELECT count(*) FROM chk
         WHERE chain_sequence <> ordinal OR chain_previous_hash IS DISTINCT FROM expected
    """)
    check("2 historical audit chain intact", broken == 0,
          f"{counts['audit_logs']} rows, {broken} broken links or sequence gaps")

    # --- 3. receipt v1/v2 semantics unchanged ----------------------------
    # The discriminator is a non-NULL policy_hash on the audit row
    # (api/legacy_main.py). Seeded history has none, so it stays v1; the
    # migration must not have invented one.
    v2_rows = await mig.fetchval(
        "SELECT count(*) FROM audit_logs WHERE policy_hash IS NOT NULL")
    seeded_v1 = await mig.fetchval(
        "SELECT count(*) FROM audit_logs WHERE metadata->>'seeded' = 'true'"
        " AND policy_hash IS NULL")
    check("3 legacy receipt version semantics unchanged",
          v2_rows == 0 and seeded_v1 == counts["audit_logs"],
          f"{seeded_v1} historical rows still classify v1 (policy_hash NULL); "
          f"{v2_rows} rows gained a policy_hash")

    # --- 4/5. the legacy token bridge ------------------------------------
    grants_after_migration = await mig.fetchval(
        "SELECT count(*) FROM execution_authority_grants")
    check("5 no legacy token became a v0.5 grant", grants_after_migration == 0,
          f"{counts['approval_token_consumptions']} historical token "
          f"consumptions, {grants_after_migration} grant rows -- no conversion, "
          "no backfill")

    # An UNCONSUMED legacy token is a token with no consumption row and no
    # grant. Claiming it the legacy way must still work, and must not create
    # a grant.
    legacy_agent = await mig.fetchval(
        "SELECT id FROM agents WHERE status = 'active' LIMIT 1")
    legacy_audit = await mig.fetchval(
        """INSERT INTO audit_logs (id, agent_id, timestamp, action_type, action_hash,
             payload, verdict, signature, signature_valid, trust_score_at_time)
           VALUES (gen_random_uuid(), $1, NOW(), 'financial_transaction', $2,
                   '{}'::JSONB, 'approved', gen_random_bytes(64), TRUE, 90)
           RETURNING id""",
        legacy_agent, action_hash("legacy-unconsumed"))
    token_id = f"legacy-unconsumed-{uuid4()}"
    await mig.execute(
        """INSERT INTO approval_token_consumptions
             (token_id, token_digest, agent_id, action_hash, audit_log_id, execution_ref)
           VALUES ($1, $2, $3, $4, $5, $6)""",
        token_id, hashlib.sha256(token_id.encode()).digest()[:32],
        legacy_agent, action_hash("legacy-unconsumed"), legacy_audit,
        f"legacy-exec-{token_id}")
    reused = False
    try:
        await mig.execute(
            """INSERT INTO approval_token_consumptions
                 (token_id, token_digest, agent_id, action_hash, audit_log_id, execution_ref)
               VALUES ($1, $2, $3, $4, $5, $6)""",
            token_id, hashlib.sha256(token_id.encode()).digest()[:32],
            legacy_agent, action_hash("legacy-unconsumed"), legacy_audit,
            f"other-{token_id}")
        reused = True
    except asyncpg.UniqueViolationError:
        pass
    grants_now = await mig.fetchval(
        "SELECT count(*) FROM execution_authority_grants")
    check("4 unconsumed legacy token claims once, creates no grant",
          not reused and grants_now == 0,
          "single-use still enforced by approval_token_consumptions; "
          f"{grants_now} grant rows created by the legacy claim")

    # --- 14/15. administrative audit scope -------------------------------
    org_scoped = await mig.fetchval(
        "SELECT count(*) FROM administrative_audit_events "
        "WHERE scope = 'organisation' AND org_id IS NOT NULL")
    mis_scoped = await mig.fetchval(
        "SELECT count(*) FROM administrative_audit_events "
        "WHERE (scope = 'organisation') <> (org_id IS NOT NULL)")
    check("14 existing administrative rows defaulted to organisation scope",
          org_scoped == counts["administrative_audit_events"] and mis_scoped == 0,
          f"{org_scoped}/{counts['administrative_audit_events']} organisation "
          f"scope, {mis_scoped} inconsistent")

    # --- 6/7/8/9. the new lifecycle works --------------------------------
    org_id = await mig.fetchval("SELECT id FROM organizations LIMIT 1")
    principal = await mig.fetchrow(
        "SELECT id, rate_limit_per_minute, daily_limit_usd FROM agents "
        "WHERE org_id = $1 AND status = 'active' LIMIT 1",
        org_id)
    agent_id = principal["id"]
    now = datetime.now(UTC)

    async def issue(ref: str):
        # The limits come from the principal's own row. The store refuses an
        # issuance whose supplied limits disagree with trusted state, which
        # is the point -- a caller inventing its own ceiling is the attack.
        return await store.issue(
            agent_id=agent_id, organisation_id=org_id, issuance_ref=ref,
            execution_action_hash=action_hash(ref), policy_hash=POLICY_HASH,
            policy_snapshot_format="inntris-payment-authority-policy-v1",
            policy_revision="revision-1", executor_binding_digest=BINDING,
            domain="payment", action_type="financial_transaction",
            minute_start=now.replace(second=0, microsecond=0),
            day_start=now.replace(hour=0, minute=0, second=0, microsecond=0),
            rate_limit_per_minute=int(principal["rate_limit_per_minute"]),
            daily_limit_usd=Decimal(principal["daily_limit_usd"]),
            amount_usd=Decimal("1"))

    ref = f"stage-{uuid4()}"
    issued = await issue(ref)
    check("6 new grant issuance works",
          issued.outcome is IssueOutcome.ISSUED, f"outcome={issued.outcome}")

    spent = await store.consume(
        grant_id=issued.grant_id, execution_action_hash=action_hash(ref),
        executor_binding_digest=BINDING, execution_ref=f"exec-{ref}")
    check("7 new consumption works",
          spent.outcome is ConsumptionOutcome.AUTHORISED,
          f"outcome={spent.outcome}")

    again = await store.consume(
        grant_id=issued.grant_id, execution_action_hash=action_hash(ref),
        executor_binding_digest=BINDING, execution_ref=f"exec-{ref}")
    check("8 same-ref recovery works",
          again.outcome is ConsumptionOutcome.RECOVERED,
          f"outcome={again.outcome}")

    other = await store.consume(
        grant_id=issued.grant_id, execution_action_hash=action_hash(ref),
        executor_binding_digest=BINDING, execution_ref=f"different-{ref}")
    check("9 different-ref reuse refused",
          other.outcome is ConsumptionOutcome.REJECTED
          and other.rejection_reason is DecisionReason.EXECUTION_REF_CONFLICT,
          f"outcome={other.outcome}, reason={other.rejection_reason}")

    # --- 10. Gate-2 configuration works on migrated data -----------------
    change = await apply_authority_configuration_change(
        mgmt, setting="requirement", new_value=True, organisation_id=org_id,
        actor="gate1@stage", reason="gate 1 rehearsal",
        approval_reference=f"GATE1-{uuid4().hex[:8]}")
    async with db.acquire() as conn:
        configuration = await resolve_authority_configuration_on(
            conn, organisation_id=org_id, principal_id=agent_id,
            action_class="financial_transaction")
    audit_row = await mig.fetchrow(
        "SELECT scope, org_id FROM administrative_audit_events WHERE id = $1",
        change.audit_event_id)
    check("10 Gate-2 requirement configuration works after migration",
          configuration.effective_required and audit_row is not None,
          f"effective_required={configuration.effective_required}, "
          f"audit event {change.audit_event_id} scope={audit_row['scope']}")

    # ...and the requirement is actually enforced on a fresh issuance.
    refused = await issue(f"stage-required-{uuid4()}")
    check("10b the new requirement is enforced, not merely stored",
          refused.outcome is IssueOutcome.REFUSED
          and refused.reason is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING,
          f"outcome={refused.outcome}, reason={refused.reason}")

    # --- 15. a platform-scoped administrative event ----------------------
    platform = await apply_authority_configuration_change(
        mgmt, setting="authority_issuance", new_value=False,
        actor="gate1@stage", reason="gate 1 rehearsal",
        approval_reference=f"GATE1-PLATFORM-{uuid4().hex[:8]}")
    platform_row = await mig.fetchrow(
        "SELECT scope, org_id FROM administrative_audit_events WHERE id = $1",
        platform.audit_event_id)
    check("15 platform administrative events representable",
          platform_row["scope"] == "platform" and platform_row["org_id"] is None,
          f"scope={platform_row['scope']}, org_id={platform_row['org_id']}")

    # --- 11. tenant isolation --------------------------------------------
    other_org = await mig.fetchval(
        "SELECT id FROM organizations WHERE id <> $1 LIMIT 1", org_id)
    async with db.acquire_as_tenant(org_id) as tconn:
        visible_agents = await tconn.fetchval(
            "SELECT count(*) FROM agents WHERE org_id = $1", other_org)
        own_agents = await tconn.fetchval(
            "SELECT count(*) FROM agents WHERE org_id = $1", org_id)
        own_reqs = await tconn.fetchval(
            "SELECT count(*) FROM authority_requirements")
        try:
            admin_visible = await tconn.fetchval(
                "SELECT count(*) FROM administrative_audit_events")
            admin_error = None
        except asyncpg.PostgresError as exc:
            admin_visible, admin_error = None, type(exc).__name__
        try:
            await tconn.execute(
                """INSERT INTO authority_requirements
                     (org_id, agent_id, action_class, required, reason,
                      changed_by, approval_reference)
                   VALUES ($1, NULL, NULL, TRUE, 't', 't', 't')""", org_id)
            tenant_wrote = True
        except asyncpg.PostgresError:
            tenant_wrote = False
    check("11 tenant isolation holds after migration",
          visible_agents == 0 and own_agents > 0 and own_reqs == 1
          and not tenant_wrote and (admin_visible in (0, None)),
          f"other-org agents visible={visible_agents}, own={own_agents}, "
          f"own requirements={own_reqs}, admin audit visible={admin_visible}"
          f"{f' ({admin_error})' if admin_error else ''}, "
          f"tenant configuration write accepted={tenant_wrote}")

    # --- 12. runtime role -------------------------------------------------
    runtime = await asyncpg.connect(RUNTIME_URL)
    runtime_blocked = {}
    for table in ("authority_requirements", "authority_controls"):
        for verb, sql in (
            ("INSERT", f"INSERT INTO {table} DEFAULT VALUES"),
            ("UPDATE", f"UPDATE {table} SET reason = 'x'"),
            ("DELETE", f"DELETE FROM {table}"),
        ):
            try:
                async with runtime.transaction():
                    await runtime.execute(sql)
                runtime_blocked[f"{table}.{verb}"] = "ACCEPTED"
            except asyncpg.InsufficientPrivilegeError:
                runtime_blocked[f"{table}.{verb}"] = "denied"
            except asyncpg.PostgresError as exc:
                runtime_blocked[f"{table}.{verb}"] = f"other:{type(exc).__name__}"
    await runtime.close(timeout=5)
    check("12 runtime role cannot mutate authority configuration",
          all(v == "denied" for v in runtime_blocked.values()),
          json.dumps(runtime_blocked))

    # --- 13. management role ---------------------------------------------
    role = await mig.fetchrow(
        "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolcanlogin "
        "FROM pg_roles WHERE rolname = 'inntris_authority_admin'")
    privs = await mig.fetchrow("""
        SELECT has_table_privilege('inntris_authority_admin','authority_requirements','INSERT') AS req_ins,
               has_table_privilege('inntris_authority_admin','authority_requirements','UPDATE') AS req_upd,
               has_table_privilege('inntris_authority_admin','authority_requirements','DELETE') AS req_del,
               has_table_privilege('inntris_authority_admin','authority_controls','INSERT') AS ctl_ins,
               has_table_privilege('inntris_authority_admin','authority_controls','UPDATE') AS ctl_upd,
               has_table_privilege('inntris_authority_admin','authority_controls','DELETE') AS ctl_del,
               has_table_privilege('inntris_authority_admin','administrative_audit_events','INSERT') AS aud_ins,
               has_table_privilege('inntris_authority_admin','administrative_audit_events','DELETE') AS aud_del,
               has_table_privilege('inntris_authority_admin','audit_logs','INSERT') AS forensic_ins""")
    expected = (
        role["rolcanlogin"] and not role["rolsuper"] and not role["rolbypassrls"]
        and not role["rolcreaterole"] and not role["rolcreatedb"]
        and privs["req_ins"] and privs["req_upd"] and privs["ctl_ins"]
        and privs["ctl_upd"] and privs["aud_ins"]
        and not privs["req_del"] and not privs["ctl_del"]
        and not privs["aud_del"] and not privs["forensic_ins"]
    )
    check("13 management role has exactly the accepted privileges", expected,
          json.dumps({**dict(role), **dict(privs)}, default=str))

    await mgmt.close()
    await db.close()
    await mig.close(timeout=5)

    Path(sys.argv[1]).write_text(json.dumps(RESULTS, indent=2))
    failed = [r for r in RESULTS if not r["pass"]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
