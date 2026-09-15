"""NEW APP against an OLD (0018) database. Classify what actually happens."""
import asyncio
import hashlib
from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import asyncpg

from api.database import Database
from api.persistence.authority_configuration import (
    AuthorityConfigurationUnavailable,
    resolve_authority_configuration,
)
from api.persistence.authority_store import AuthorityStore

OLD = "postgresql://inntris_worker:stagepw_gate1_0123456789abcdefgh@127.0.0.1:5432/inntris_mixed_old"
MIG = "postgresql://postgres:gate2pw@127.0.0.1:5432/inntris_mixed_old"

async def main():
    mig = await asyncpg.connect(MIG)
    org = await mig.fetchval("SELECT id FROM organizations LIMIT 1")
    p = await mig.fetchrow("SELECT id, rate_limit_per_minute, daily_limit_usd FROM agents WHERE org_id=$1 AND status='active' LIMIT 1", org)
    await mig.close(timeout=5)
    db = await Database.create(OLD, min_size=1, max_size=4)
    store = AuthorityStore(db, current_policy_resolver=lambda _agent, _action, _domain: ("b" * 64, "revision-1"))

    # 1. The configuration reader the new app depends on.
    try:
        await resolve_authority_configuration(db, organisation_id=org, principal_id=p["id"], action_class="financial_transaction")
        print("config_read: SUCCEEDED (unexpected)")
    except AuthorityConfigurationUnavailable as exc:
        print(f"config_read: AuthorityConfigurationUnavailable -> fail-closed ({exc})")
    except Exception as exc:
        print(f"config_read: {type(exc).__name__}: {str(exc)[:90]}")

    # 2. Issuance.
    now = datetime.now(UTC)
    ref = f"na-od-{uuid4()}"
    try:
        r = await store.issue(agent_id=p["id"], organisation_id=org, issuance_ref=ref,
            execution_action_hash=hashlib.sha256(ref.encode()).hexdigest(),
            policy_hash="b"*64, policy_snapshot_format="inntris-payment-authority-policy-v1",
            policy_revision="revision-1", executor_binding_digest="c"*64,
            domain="payment", action_type="financial_transaction",
            minute_start=now.replace(second=0,microsecond=0),
            day_start=now.replace(hour=0,minute=0,second=0,microsecond=0),
            rate_limit_per_minute=int(p["rate_limit_per_minute"]),
            daily_limit_usd=Decimal(p["daily_limit_usd"]), amount_usd=Decimal("1"))
        print(f"issue: outcome={r.outcome} reason={getattr(r,'reason',None)}")
    except Exception as exc:
        print(f"issue: {type(exc).__name__}: {str(exc)[:110]}")

    # 3. Which of the tables the new app needs are actually missing?
    mig = await asyncpg.connect(MIG)
    missing = []
    for t in ("execution_authority_grants","authority_decision_evidence",
              "authority_requirements","authority_controls"):
        if not await mig.fetchval("SELECT to_regclass('public.'||$1) IS NOT NULL", t):
            missing.append(t)
    fn = await mig.fetchval("SELECT to_regproc('authority_config_lock_key(uuid)') IS NOT NULL")
    role = await mig.fetchval("SELECT count(*) FROM pg_roles WHERE rolname='inntris_authority_admin'")
    print(f"missing_tables: {missing}")
    print(f"authority_config_lock_key present: {bool(fn)} | management role present: {role==1}")
    await mig.close(timeout=5)
    await db.close()

asyncio.run(main())
