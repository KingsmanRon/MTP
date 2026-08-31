# PR 2 — tenant route database boundary

## Acceptance question

**Can any tenant-facing path still obtain BYPASSRLS access?**

**Expected answer after CI/security and the outstanding production merge gates: NO.**

Tenant-facing handlers receive an organisation-bound `TenantScopedDatabase` whose only acquisition path enters `TenantDatabase.tenant(trusted_org_id)`. The adapter has no worker pool, cannot create one, and rejects attempts to rebind to another organisation. The privileged `Database` object is retained only in SYSTEM code for authentication/bootstrap/system operations and is never passed to tenant handlers.

## Database call-site classification

Classification is based on the current repository tree at the PR-2 branch. `TENANT` means customer/partner data access that must execute through `inntris_tenant_login -> SET ROLE inntris_api` with RLS. `SYSTEM` means a reviewed operation that genuinely needs the `inntris_worker` identity or is a non-tenant operational/authentication function. `MIGRATION` means schema/role deployment code using the migration identity.

| Call site / surface | Class | Database identity / primitive | Reason / boundary |
|---|---|---|---|
| `api/tenant_runtime.py` | TENANT | `TENANT_DATABASE_URL` -> `TenantDatabase.create()` | Owns the web-only restricted pool. No worker pool is exposed. |
| `api/tenant_database.py:TenantDatabase.create` | TENANT | `asyncpg.create_pool`, `statement_cache_size=0`, max 5 | Only constructor for tenant connections; validates exact login identity and worker-role non-reachability. |
| `api/tenant_database.py:TenantDatabase.tenant` | TENANT | restricted pool + transaction-local `inntris_api`/`app.current_org_id` | Only tenant connection primitive. There is no generic public `TenantDatabase.acquire()`. |
| `api/tenant_database.py:assert_safe_identity/health_check` | TENANT | restricted pool, no customer-supplied org | Connection/canary checks only; raw connection never leaves the class. |
| `api/tenant_boundary.py` | TENANT boundary | `TenantDatabase` only; no import of `api.database.Database` | Replaces direct handler `get_db` dependencies after trusted auth resolves the organisation. |
| `api/system_tenant_adapter.py` | SYSTEM adapter | Reuses `Database` method implementations but contains no worker pool | Compatibility bridge only. `_pool`, `create()` and `close()` fail closed; `acquire*` always delegates to `TenantDatabase.tenant(trusted_org_id)`. |
| `api/legacy_main.py:get_db/get_db_optional` | SYSTEM | `DATABASE_URL` -> `Database` (`inntris_worker`) | System pool provider. It is not supplied directly to classified tenant handlers after PR 2. |
| `api/legacy_main.py:verify_api_key` | SYSTEM authentication | `Database.acquire()` | API-key hash lookup must occur before tenant identity is known. Returns trusted server-side `org_id`; the system DB object is discarded at the boundary. |
| `api/legacy_main.py:_verify_bearer_token` | SYSTEM authentication | `Database.acquire()` | Resolves bearer/API-key identity before `/v1/events` tenant work. |
| `/v1/events` | TENANT | organisation-bound tenant adapter | Partner event ingestion is tenant-facing. Request/body UUIDs cannot replace the authenticated organisation context. |
| `/admin/test-verify` | TENANT | organisation-bound tenant adapter | Authenticated customer test surface. |
| `/admin/usage` | TENANT | organisation-bound tenant adapter | Organisation-scoped usage read. |
| `/admin/agents` and `/admin/agents/*` | TENANT | organisation-bound tenant adapter | Agent list/create/update/status/policy/key/promotion operations are RLS-scoped to authenticated org. `database.create_agent` executes through tenant acquisition; its `org_id` is the trusted authenticated org. |
| `/admin/audit/*` | TENANT | organisation-bound tenant adapter | Tenant audit reads/exports are RLS-scoped. |
| `/admin/alerts` and children | TENANT | organisation-bound tenant adapter | Tenant security-alert access. |
| `/admin/api-keys` and children | TENANT | organisation-bound tenant adapter | Tenant API-key lifecycle after the caller's organisation has been authenticated. The initial caller API-key lookup remains SYSTEM authentication. |
| `/admin/organization` and children | TENANT | organisation-bound tenant adapter | Singular organisation self-service surface is scoped to the authenticated org. |
| `/admin/webhook*` / organisation webhook configuration | TENANT | organisation-bound tenant adapter | Tenant-owned webhook configuration/delivery history. Network delivery itself is outside tenant DB transactions. |
| `/admin/organizations` (plural) | SYSTEM | `Database` / `inntris_worker` | MASTER_ADMIN_KEY operator provisioning, not a tenant self-service route. Explicitly excluded from tenant route matcher. |
| `/verify` | SYSTEM | `Database` / `inntris_worker` | Security decision path requires cross-table/system authority; semantics unchanged. |
| `/verify-token` | SYSTEM | `Database` / `inntris_worker` | Approval-token consumption/security path; semantics unchanged. |
| approval-token consumption paths | SYSTEM | `Database` / `inntris_worker` | System authority and existing atomicity preserved. |
| spend reservation / release / consumption used by verification | SYSTEM | `Database` / `inntris_worker` | Part of system authorisation flow; not moved for architectural neatness. |
| verify idempotency paths | SYSTEM | `Database` / `inntris_worker` | System authorisation/idempotency semantics preserved. |
| public receipt/proof verification endpoints | SYSTEM | `Database` / `inntris_worker` or read-only system lookup | Public verification has no authenticated tenant context and must preserve existing evidence semantics. |
| agent fingerprint/signature/policy lookup used by `/verify` | SYSTEM | `Database` / `inntris_worker` | Verification requires trusted system lookup independent of caller-supplied tenant identity. |
| health/readiness checks using system DB | SYSTEM | `Database` / `inntris_worker` | Operational health, not tenant data access. Tenant pool has its own restricted identity canary. |
| `api/webhooks.py` delivery/recovery protocol | SYSTEM delivery + TENANT configuration | DB object supplied by caller; outbound HTTP/DNS outside DB methods | Tenant configuration/history uses tenant-scoped route DB. Background due-delivery recovery remains SYSTEM because it scans across organisations. |
| webhook recovery task created by web startup | SYSTEM | `Database` / `inntris_worker` | Cross-organisation recovery loop; genuinely requires system scope. |
| `workers/anchor_worker.py` | SYSTEM | `DATABASE_URL`, direct `asyncpg` | Cross-organisation Merkle batching/reconciliation and Base anchoring. Worker has no `TENANT_DATABASE_URL`. |
| Merkle proof creation/reconciliation | SYSTEM | worker DB | Cross-tenant batch/evidence infrastructure; remains BYPASSRLS. |
| Base RPC/Web3 anchoring | SYSTEM | no tenant DB primitive | External chain I/O belongs to worker; no tenant transaction is held. |
| `api/database.py:Database.create` | SYSTEM | `DATABASE_URL`, `asyncpg.create_pool` | Privileged runtime constructor. Not a tenant primitive. |
| `api/database.py:Database.acquire` | SYSTEM | worker pool | Generic privileged acquisition; static route test prevents direct tenant-handler dependency on it. |
| `api/database.py:Database.acquire_as_tenant` | SYSTEM legacy implementation | worker pool + tenant context | Retained for existing system/legacy methods; tenant adapter overrides it and rejects org rebind. Tenant routes do not receive the worker-backed implementation. |
| direct `Database` methods used by public/system verification | SYSTEM | worker pool | Preserved intentionally. |
| `alembic/env.py` | MIGRATION | `ALEMBIC_DATABASE_URL` | Alembic schema/role deployment. |
| `alembic/versions/*` | MIGRATION | Alembic connection | Versioned schema/role migrations. |
| `database/migrations/*` | MIGRATION | executed by Alembic/operator migration path | SQL migration sources; 021 assertions retain FORCE RLS, role and SECURITY DEFINER checks. |
| `scripts/configure_runtime_role.py` | MIGRATION | `ALEMBIC_DATABASE_URL` via `psycopg2` | Provisions/rotates locked-down `inntris_worker`; validates migration/runtime DSN separation. |
| `scripts/verify_tenant_role.py` | SYSTEM security verification | reviewed DB verification connection | Read-only/assertion utility for tenant role postconditions; not an application tenant path. |
| `scripts/production_readback.py` | SYSTEM operator | `DATABASE_URL` via `psycopg2`, read-only session | Cross-organisation production trust/readback checks. |
| `scripts/seed_production.py` | SYSTEM admin utility | `DATABASE_URL`, direct `asyncpg.connect` | Explicit privileged bootstrap/seed utility; not reachable from tenant HTTP requests. |
| `scripts/provision_demo_agent.py` and demo/admin provisioning utilities | SYSTEM admin utility | privileged/runtime DB or Core admin surface | Operator/demo bootstrap, not tenant request execution. |
| tests using `DATABASE_URL` | SYSTEM test harness | worker identity | Fixture/setup and system-semantic tests. |
| tests using `ALEMBIC_DATABASE_URL` | MIGRATION test harness | migration identity | Schema setup and ephemeral tenant-login credential provisioning in CI. |
| `tests/test_tenant_login_integration.py` | TENANT security test | `TENANT_DATABASE_URL`, `TenantDatabase(min_size=1,max_size=1)` | Real PostgreSQL isolation/reuse tests. |
| `tests/test_tenant_route_boundary.py` | TENANT static test | dependency graph inspection, no DB connection | Fails if tenant route can directly acquire `legacy_main.get_db`; also forbids `Database` import in tenant boundary module. |
| frontend `src/app/api/admin/*` | No direct DB callsite | HTTP proxy to Core | Does not create a PostgreSQL/Supabase/PostgREST client; DB identity is enforced inside Core. |
| Supabase/PostgREST client / `SUPABASE_SERVICE_ROLE_KEY` | No inspected runtime callsite | none identified | Runtime persistence in the inspected tree is direct PostgreSQL. No tenant route is authorised through a Supabase service-role client. |

## Exact tenant/system boundary

1. `api/legacy_main.py` owns established application behaviour and the privileged SYSTEM pool.
2. SYSTEM authentication (`verify_api_key` / bearer resolution) may use `inntris_worker` only long enough to authenticate the credential and resolve its organisation.
3. `api/tenant_boundary.py` takes only the resulting trusted `org_id`; it does not accept an authoritative request body/query/header organisation id.
4. The handler receives `TenantScopedDatabase`, whose acquisitions enter `TenantDatabase.tenant(trusted_org_id)`.
5. `TenantDatabase` authenticates as `inntris_tenant_login`, then transaction-locally sets role `inntris_api` and `app.current_org_id`.
6. Background, public and cross-organisation system operations remain on `inntris_worker`.

The compatibility adapter is classified SYSTEM because it imports the legacy `Database` class solely to reuse query method implementations. It never calls `Database.__init__`, has no system pool, rejects raw-pool access, cannot construct a pool, and overrides both acquisition methods. Tenant route code itself does not import `Database`.

## Trusted organisation resolution

For admin tenant routes, the authoritative organisation is `verify_api_key(...)["org_id"]`, resolved server-side from the API-key hash using the SYSTEM authentication resolver. For `/v1/events`, `_verify_bearer_token` resolves the organisation from the bearer credential before a tenant DB object is constructed.

Request-supplied UUIDs remain object identifiers only. They do not alter `app.current_org_id`. The scoped adapter rejects `acquire_as_tenant(other_org)` even if a caller attempts to pass a different UUID. Real PostgreSQL tests prove that an org-A scope cannot read/update/delete org-B rows or insert a child row beneath an org-B agent.

## Tenant transaction setup

Tenant context is installed in one PostgreSQL round trip and is transaction-local:

```sql
SELECT
  set_config('role','inntris_api',true),
  set_config('search_path','pg_catalog, public',true),
  set_config('statement_timeout','30s',true),
  set_config('idle_in_transaction_session_timeout','15s',true),
  set_config('app.current_org_id',$1,true);
```

`statement_cache_size=0` remains enabled for Supavisor transaction-pool compatibility. Real PostgreSQL tests use `min_size=1/max_size=1` where reuse matters and assert both commit and rollback clear tenant context.

## Transaction lifetime audit

Tenant transactions are acquired at individual database-method boundaries. The route is not wrapped in one long-lived request transaction. This prevents DNS, HTTP/webhook delivery, Base RPC/Web3 calls, signing or response serialisation from idling inside the 15-second tenant transaction timeout.

In particular:

- admin/audit reads fetch database rows within tenant DB methods; response/export processing happens after the acquisition closes;
- webhook URL resolution and outbound HTTP occur outside the tenant DB transaction; delivery state transitions are separate short DB operations;
- background webhook recovery remains SYSTEM and is not moved onto the tenant pool;
- Merkle batching and Base anchoring remain SYSTEM worker operations;
- no timeout increase is introduced.

## RLS/security drift

The standing migration-0017/SQL-021 assertions remain unchanged. They continue to require:

- exact `inntris_tenant_login` role attributes and connection limit;
- no reachability to `inntris_worker`, `postgres`, `service_role` or `supabase_admin`;
- no direct/effective table privileges before `SET ROLE`;
- no tenant-reachable `SECURITY DEFINER` function in `public`/`app`;
- all 17 reviewed public tables explicitly classified;
- ENABLE + FORCE RLS on every public table;
- `inntris_api` policy coverage on every tenant-policy table.

Any new public table therefore fails the standing drift guard until it is explicitly classified.

## Connection budget

Production `inntris_tenant_login` has `CONNECTION LIMIT 20`. The Railway production web service currently has **1 replica**. PR 2 sets `TenantDatabase max_size = 5`.

Current arithmetic:

- application tenant pool: `5 × 1 web replica = 5`;
- planning allowance for Supavisor/server-side transaction-pool overhead: approximately `2` server connections;
- expected current total: approximately `7 / 20`;
- deliberate headroom: approximately `13` connections.

Scaling check using the same planning allowance:

- 2 web replicas: `5 × 2 + 2 = 12 / 20`;
- 3 web replicas: `5 × 3 + 2 = 17 / 20`.

The `+2` overhead is a planning assumption, not a Supavisor guarantee. **Merge gate C requires confirming the actual production server-connection behaviour/headroom before PR 2 may merge.** Do not raise `max_size` merely because the login limit is 20.

## Required production rollout gates — still outstanding

PR 2 must remain draft/unmerged until all of these are captured.

### A. Final production tenant URI authentication

Using the final edited `TENANT_DATABASE_URL` (Supavisor transaction pool, port 6543), prove:

- `session_user = inntris_tenant_login`;
- `current_user = inntris_tenant_login`;
- `superuser = false`;
- `bypassrls = false`;
- `inntris_worker` is unreachable;
- after `SET ROLE inntris_api` with no org context, `SELECT count(*) FROM agents;` returns `0`.

### B. Production smoke

- `/verify`;
- `/verify-token`;
- public receipt endpoint;
- anchor worker health;
- no unexpected unresolved Merkle proofs.

### C. Connection budget

Confirm production replica count and realistic Supavisor/server connection overhead keep deliberate headroom below the 20-connection login cap.

Note: production web deployments run `alembic upgrade head` through the repository root `railway.json` pre-deploy command. Railway dashboard service configuration does not surface config-as-code overrides, so do not infer migration behaviour from the dashboard snapshot alone.

## CI/security evidence required before review completion

The PR is not merge-ready until full CI/security on PostgreSQL 17.6 is green with no weakened test. The PR-1 baseline was 676 passed, 7 warnings, Ruff clean and full CI/security green.

Required real-PostgreSQL coverage in this PR includes:

- org A reads A; org B reads B;
- A cannot read B; B cannot read A;
- cross-tenant UPDATE blocked;
- cross-tenant DELETE blocked;
- cross-tenant child INSERT blocked;
- no org context returns zero tenant rows;
- forged/rebound org id rejected;
- authenticated org A + org B object UUID cannot cross the boundary;
- A -> B reuse through the same pooled connection;
- rollback clears context;
- commit clears context;
- tenant login cannot `SET ROLE inntris_worker`;
- tenant route cannot acquire the privileged pool;
- standing RLS/table/security assertions remain active.

## Merge answer

Once CI/security and production gates A-C are green, the evidence-backed answer to **“Can any tenant-facing path still obtain BYPASSRLS access?”** is **NO**.

Until those gates are captured, this PR must remain draft and must not be deployed or merged.
