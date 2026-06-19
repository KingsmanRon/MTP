# Inntris Deploy Runbook

How the production system is wired and the exact steps to ship a change safely.

## Topology

| Piece | Hosts | Notes |
|-------|-------|-------|
| **Vercel** | Frontend (Next.js in `frontend/`) | Root Directory **must** be `frontend`. Production branch = the repo default branch. |
| **Railway `web`** | FastAPI API (`Procfile: web`) | Runs `alembic upgrade head` as a pre-deploy step (see `railway.json`). |
| **Railway `worker`** | Anchor worker (`Procfile: worker`) | Should use `railway.worker.json` so it does **not** also run migrations. |
| **Railway `redis`** | Nonce dedup + cache | Managed Railway Redis; no repo build. |
| **Supabase** | PostgreSQL | Schema is **Alembic-managed** (`alembic/versions/`). |

A push to the default branch auto-deploys **both** Vercel and Railway. The frontend
is safe to deploy independently of the backend (it only calls existing endpoints).

## Config-as-code (`railway.json` / `railway.worker.json`)

Railway config-as-code **overrides dashboard settings** for any field it declares,
and a root `railway.json` applies to **every** service on the default config path.
These files therefore declare *only* the pre-deploy command and a restart policy —
**no `startCommand` and no `build`** — so each service keeps its existing start
command and builder.

- **`web` service** → config path `railway.json` (default). Adds
  `preDeployCommand: alembic upgrade head`.
- **`worker` service** → set its **Config file path** to `railway.worker.json`
  (Service → Settings → Config-as-code). This omits the migration so `web` and
  `worker` never race to run the same migration. If you skip this, the worker will
  also run `alembic upgrade head`; today that is a harmless no-op (DB is at head),
  but a *future* migration could fail the worker deploy on a concurrent run.

### Migrations need a non-transaction-pooler connection
The pre-deploy `alembic upgrade head` uses `ALEMBIC_DATABASE_URL` if set, else the
service's `DATABASE_URL` (`alembic/env.py` rewrites `postgresql://` →
`postgresql+psycopg2://`). Point it at the Supabase **direct connection** or
**session pooler (port 5432)** — **not** the transaction pooler on **6543**, which
breaks DDL / multi-statement migrations.

### Migrations need a privileged role — not the RLS app role
The runtime app connects as **`inntris_worker`** (locked-down, `NOSUPERUSER`, RLS-
enforced — see `database/migrations/005_rls_policies.sql` and `api/database.py`).
That role **cannot** run DDL or even read `alembic_version` (owned by the Supabase
`postgres` role from the manual bootstrap below). If the pre-deploy migration uses
the same `DATABASE_URL`, it fails with `permission denied for table alembic_version`.

Fix: set **`ALEMBIC_DATABASE_URL`** on the `web` service to the Supabase **`postgres`**
direct/session-pooler URI (5432), and keep `DATABASE_URL` pointed at `inntris_worker`.
`alembic/env.py` prefers `ALEMBIC_DATABASE_URL` for migrations only. One-time unblock
for an already-deployed DB (run as `postgres` in the Supabase SQL editor):

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.alembic_version TO inntris_worker;
```

## Environment variables (Railway `web`)

| Var | Value |
|-----|-------|
| `DATABASE_URL` | Supabase direct / session-pooler URI (5432), not 6543 — `inntris_worker` role (RLS-enforced runtime) |
| `ALEMBIC_DATABASE_URL` | Same host (5432, not 6543) but the `postgres` (owner) role — used **only** by the pre-deploy `alembic upgrade head` |
| `REDIS_URL` | Railway Redis URL |
| `SERVER_SECRET` | HMAC secret for approval tokens (required in prod) |
| `ALLOWED_ORIGINS` | `https://inntris.com,https://www.inntris.com` — exact-match, no `*`, no trailing slash. Add your `*.vercel.app` preview if you test from it. |
| `ENVIRONMENT` | `production` |
| `MASTER_ADMIN_KEY` | only set while provisioning a new org; otherwise leave unset |
| anchor vars | `ANCHOR_CONTRACT_ADDRESS`, RPC URL, signer key, `ANCHOR_INTERVAL_MINUTES`, `ANCHOR_MAX_GAS_PRICE_GWEI` (worker) |

CORS is exact-match: if the admin UI loads on `www.inntris.com`, an apex-only
`ALLOWED_ORIGINS` will block its API calls even with a valid key.

## API-key scopes (the 403 gotcha)

Admin endpoints enforce scopes (`require_api_scope`). A key must carry `admin`
(or the matching `read`/`write`) or those endpoints return **403**. Bootstrap keys
created via `POST /admin/organizations` already get `["admin","read","write","verify"]`.
Check before a cutover:

```sql
select id, name, scopes, is_active, last_used_at from api_keys order by last_used_at desc nulls last;
```

The key the console actually uses is the one with the most recent `last_used_at`.
If it lacks `admin`:

```sql
update api_keys set scopes = array['admin','read','write','verify'] where id = '<key-id>';
```

## Standard deploy (after this runbook is in place)

1. Merge/push to the default branch.
2. Railway `web` builds → runs `alembic upgrade head` (pre-deploy) → starts the API.
   Railway `worker` builds and starts (no migration). Vercel builds `frontend/`.
3. Smoke test (below).

## First-time / un-stamped database (one-off — already done for current prod)

The production DB predates Alembic (set up via `database/schemas.sql`), so it had no
`alembic_version` table. Bringing such a DB under Alembic management:

1. **Detect** current state (read-only, Supabase SQL editor):
   ```sql
   select to_regclass('public.alembic_version');                 -- null => not yet managed
   select
     to_regclass('public.erasure_requests') is not null as has_006,
     exists (select 1 from pg_proc
             where proname='create_signature_failure_alert'
               and pg_get_functiondef(oid) ilike '%non_cryptographic%') as has_009;
   ```
2. **Apply** the missing migrations (the `.sql` files are idempotent; guard role-
   dependent ones like 007 with `IF EXISTS (SELECT 1 FROM pg_roles WHERE ...)`).
3. **Stamp** Alembic at head so future `upgrade head` is a clean no-op:
   ```sql
   create table if not exists alembic_version (
       version_num varchar(32) not null,
       constraint alembic_version_pkc primary key (version_num)
   );
   delete from alembic_version;
   insert into alembic_version (version_num) values ('0005_ci_guard_invariants');
   ```
   (Or, with a direct DSN: `DATABASE_URL=<direct> alembic stamp <rev>` then `alembic upgrade head`.)

## Smoke test (every deploy)

- **API**: `GET /health` returns 200.
- **Admin UI**: loads, lists agents, and a save/suspend succeeds (proves CORS +
  scopes + new build).
- **Anchoring**: the next anchor batch populates `tx_hash` on a `merkle_proofs`
  row — confirms the worker still writes proofs (migration 007 narrowed its
  `audit_logs` grants to `merkle_root_id` / `merkle_leaf_index` only).

## Gotchas / invariants

- **Revision ids ≤ 32 chars.** Alembic stores them in `alembic_version.version_num
  VARCHAR(32)`. A longer slug breaks `alembic upgrade head` on real Postgres
  (`tests/test_alembic_baseline.py` guards this).
- **Downgrades are intentionally `NotImplementedError`** — schema/forensic-data
  destruction is never automatic. Write a targeted forward revision instead.
- **Frontend lives in `frontend/`**, not the repo root — Vercel Root Directory
  must reflect that.
