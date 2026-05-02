# /verify audit — 2026-05-02

Scope: read-only audit of the `/verify` endpoint on branch
`claude/verify-endpoint-demo-KffoU` ahead of cold outreach to Monavate, Baanx
and MoonPay. No code or config was modified during this phase.

## Summary

- Blockers: **2**
- Harden items: **6**
- OK items: **3**
- Demo-ready verdict: **CONDITIONAL** — the public verification *page* (the
  `/verify/{id}` route showing the canonical Base mainnet receipt
  `3030c27c-…` and `d8dd0902-…`) is reachable and correct, and *that* is
  what the InMail wording promises. However, the live signed `POST /verify`
  endpoint cannot be exercised by a stranger in 60 seconds, and two items
  flagged in your context (DB password rotation, dev-mode auth bypass) need
  external verification before the link is shared.

## Findings

### Check 1 — Endpoint reachability and shape
**Severity: HARDEN**

- Route handler: `api/main.py:880-1164` — `@app.post("/verify")` defined as
  `verify_action(...)`.
- Request shape: `VerifyActionRequest` at `api/models.py:49-152`. Required
  fields: `agent_id`, `action_type`, `payload`, `signature` (Ed25519 b64),
  `nonce`, `timestamp` (ISO 8601 string), optional `policy_hash` and
  `sig_version` (1/2/3, default 2).
- Response shape: `VerifyActionResponse` at `api/models.py:275-295`. Returns
  `verdict`, `verdict_reason`, `approval_token` (HMAC over server secret),
  `trust_score`, `audit_id`, `timestamp`, `limits_remaining`.
- Auth: `/verify` itself does **not** require an API key — authentication is
  the Ed25519 signature over the action hash (`api/main.py:929-940`). The
  agent must already exist in the DB. A cold tester cannot use `/verify`
  directly without first registering an agent.
- A cold tester *could* in theory:
  1. POST `/public/agents/register` (`api/main.py:463-535`, no API key,
     5/hr/IP rate limit).
  2. Sign an action with their generated Ed25519 private key.
  3. POST `/verify`.
  This path is **not documented** for external testers — `README.md:230-274`
  documents `/verify` shape but the only example flow (`scripts/demo_verification.py:154-155`)
  takes `--api-key` as a required argument and calls `/admin/agents`, an
  authenticated route.
- Public read of an existing receipt is at `GET /public/verify/{record_id}`
  (`api/main.py:616-783`) — completely unauthenticated, no rate limit.
- Auth dev backdoor: `api/main.py:231-238` accepts any `X-API-Key`
  starting with `dev_` or `test_` when `ENVIRONMENT=development`. Public
  endpoints (`/verify`, `/public/verify/*`, `/public/agents/register`) do
  not depend on `verify_api_key`, so this only matters for `/admin/*`
  routes. Verify externally that `ENVIRONMENT=production` (or any non-`development`
  value) is set in Railway.

**Recommendation:** publish a one-step cold-tester path — either a curl
example for `/public/verify/{CANONICAL_RECEIPT_ID}` or a short SDK snippet
that uses `/public/agents/register` + `/verify`. Confirm
`ENVIRONMENT != development` in the deployed env.

---

### Check 2 — Happy path correctness
**Severity: OK** (with one HARDEN sub-finding)

Trace, all in `api/main.py`:

1. `verify_action` fetches the agent (`906`), computes the action hash
   via `CryptoService.compute_action_hash` (`919-926`), and verifies the
   Ed25519 signature (`929-933`).
2. Replay protection via Redis nonce (`988-1013`) — fail-closed if Redis
   is down (returns 503, does **not** silently approve).
3. Policy evaluation (`1015-1100`) using `PolicyEngine` over current rate
   counters and daily spend.
4. Audit log insert via `database.insert_audit_log(...)` (`1120`).
5. Approval token via HMAC over `SERVER_SECRET` (`1136-1141`).

The receipt as defined in `PublicVerificationRecord` (`api/models.py:313-358`)
includes:

- Agent decision event (`verdict`, `verdict_reason`, `action_type`, `payload`-derived `risk_level`/`violations`).
- Action hash (`action_hash`), Ed25519 signature validity flag.
- Merkle root (`merkle_root`) and Merkle proof via separate
  `GET /public/verify/{audit_id}/proof` (`api/main.py:786-873`).
- Anchor reference: `tx_hash`, `block_number`, `chain_id` (default 8453),
  `anchored_at`. The proof endpoint computes the Merkle proof path with
  `compute_merkle_proof` from `workers/anchor_worker.py:852` (good — same
  function used at anchoring time).
- Receipt fingerprint (SHA-256 over a fixed-order canonical subset),
  `schema_version` (v2 if `policy_hash` present), `integrity_status`
  (`verified` / `pending_anchor`).

No mocks, stubs, fake-data branches or TODO/FIXME markers were found in the
hot path of `verify_action`, `get_public_verification_record`, or
`get_public_proof`. The only `placeholder_*` items
(`api/main.py:503-505`, `586`) are random-bytes placeholders for the
`api_key_hash NOT NULL` column on auto-created public-registration orgs —
they do not affect receipts.

Sub-finding: **`/admin/test-verify`** (`api/main.py:1167-1290`) is a
playground bypass that runs policy evaluation **without** signature
verification and inserts a test_request marker. It is correctly labelled
NOT proof-eligible and is auth-gated (`Depends(verify_api_key)`). No
production-reachable path uses it. Worth keeping out of any external
docs to avoid CEOs accidentally landing there.

**Recommendation:** none for the happy path itself; ensure the canonical
receipts (`d8dd0902-…`, `3030c27c-…`) referenced by
`frontend/src/app/page.tsx:61-62` are still present and anchored on
Base mainnet — verify externally that
`tx 0x3f86eea4328d00fbd968181f5f188aee95dea65ea690273f229534edd68ecd84`
(per `docs/INNTRIS_CONTEXT.md:46`) resolves on basescan.org.

---

### Check 3 — Failure modes & error leakage
**Severity: HARDEN**

| Failure | Location | Behaviour |
|---|---|---|
| Bad input shape | FastAPI/pydantic at `VerifyActionRequest` | Returns 422 with field-level validation messages. Pydantic-default; no internal state leaks. |
| Agent not found | `api/main.py:907-911` | 404, `Agent {id} not found`. OK. |
| Bad signature | `api/main.py:938-986` | 401, `Ed25519 signature verification failed. Potential attack detected.` Audit log + security alert created. OK. |
| Redis down | `api/main.py:990-1013` | 503, generic `Verification service temporarily unavailable. Please retry.` — **no internal detail leaked**. OK. |
| Nonce replay | `api/main.py:1000-1007` | 401, `Nonce already used - possible replay attack`. OK. |
| Policy violation / rate-limit | `api/main.py:1090-1100` | 429 or 403 with `verdict_reason`. Reason text comes from `PolicyEngine` and is human-safe. OK. |
| Catch-all | `api/main.py:1160-1164` | Generic 500 `Internal server error`; full exception logged via `logger.exception`. OK. |
| Public verify, DB privilege error | `api/main.py:676-685` | **LEAKS** infrastructure detail: response body literally says *"Run migration 005 and ensure the runtime DATABASE_URL role can SELECT from merkle_proofs (recommended: inntris_worker)."* This reveals the migration scheme, role names and table names to any unauthenticated caller. |
| Admin agent registration error | `api/main.py:1519-1521` | `raise HTTPException(status_code=400, detail=str(e))` — leaks raw exception text (DB constraint names, asyncpg error strings). Authenticated admin only, but still HARDEN. |

No stack traces, no env-var names other than `DATABASE_URL` in the public
verify error message. Exception logging uses `logger.exception` which is
correctly server-side only.

**Recommendation:** replace the body at `api/main.py:678-685` with a
generic 503 (`Verification temporarily unavailable.`) and log the
operator-facing detail server-side. Replace `detail=str(e)` at
`api/main.py:1521` with a fixed string.

---

### Check 4 — Base mainnet enforcement
**Severity: OK** (with one HARDEN sub-finding)

- Public verify rejects non-mainnet receipts with HTTP 410 at
  `api/main.py:690-705` — the test guard for this is
  `tests/test_mainnet_guard.py:42-52`.
- `PublicVerificationRecord.chain_id` defaults to 8453
  (`api/models.py:345`); `get_public_verification_record` and
  `get_public_proof` both fall back to 8453 when DB chain_id is NULL
  (`api/main.py:778, 866`) — meaning unanchored receipts surface as
  mainnet-eligible by default. Acceptable for the demo path.
- Anchor worker pins `BASE_CHAIN_ID = int(os.getenv("BLOCKCHAIN_CHAIN_ID", "8453"))`
  at `workers/anchor_worker.py:89` and verifies `eth.chain_id` against it
  before every batch submit (`workers/anchor_worker.py:291-306, 332`). A
  misconfigured RPC fails closed.
- Default RPC: `BLOCKCHAIN_PROVIDER_URL=https://base-rpc.publicnode.com`
  (`workers/anchor_worker.py:53`, `.env.production.template:42`). Per
  `docs/INNTRIS_CONTEXT.md:18`, the official Base RPC blocks Railway
  egress IPs, so PublicNode is the required choice — there is no
  Cloudflare/Anthropic endpoint anywhere in the codebase.
- Mainnet contract: `0x0600eA15802c8d2EA429371b2EB0aacCFe321480`
  (`docs/INNTRIS_CONTEXT.md:19`,
  `scripts/windows_verify_basescan.py:28`). `0x2300Fc9eff12ff5ca39621259B121fa3417773bf`
  is the deployer/admin EOA (`docs/INNTRIS_CONTEXT.md:20`). The
  `ANCHOR_CONTRACT_ADDRESS` is read from env at `workers/anchor_worker.py:54`;
  verify externally that the Railway worker has it set to the mainnet
  address above.
- 84532 / sepolia references found are **not** in any production-reachable
  code path:
  - `tests/test_mainnet_guard.py:43-46` — proves the 410 guard works.
  - `scripts/windows_verify_basescan.py:31-36` — explicitly labelled
    `_base_sepolia_dev_only` and the script defaults to `base_mainnet`
    (`scripts/windows_verify_basescan.py:40`).
  - `.env.example:49-50`, `.env.production.template:41` — commented out.
  - `docs/INNTRIS_CONTEXT.md:21`, `docs/THREAT_MODEL.md`, etc. — narrative.

Sub-finding (HARDEN): the same address
`0x0600ea15802c8d2ea429371b2eb0aaccfe321480` is listed for both Base
mainnet and Base Sepolia in
`scripts/windows_verify_basescan.py:28,34`. Plausible (deterministic
deploy under same nonce) but means the basescan link in
`scripts/windows_verify_basescan.py:131` points at sepolia.basescan.org —
only the dev script, not production code, but it could confuse a CEO
shown the script.

**Recommendation:** spot-check externally that the deployed
`ANCHOR_CONTRACT_ADDRESS` env var is the mainnet address, and remove
the `_base_sepolia_dev_only` block from
`scripts/windows_verify_basescan.py` if the script is ever shared
externally.

---

### Check 5 — RLS and grants on audit_logs
**Severity: OK**

- `audit_logs` defined in `database/schemas.sql` with RLS enabled
  in `database/migrations/005_rls_policies.sql:122-141` —
  policy `audit_logs_tenant_scope` filters by
  `agents.org_id = app.current_tenant()` for both `USING` and
  `WITH CHECK`.
- Grants on `audit_logs`:
  - `inntris_api`: **`SELECT, INSERT` only**
    (`database/migrations/005_rls_policies.sql:225`). UPDATE/DELETE are
    not granted. The user's prior concern that "inntris_api write grants
    on audit_logs may be too permissive" is **already mitigated** — only
    INSERT is granted.
  - `inntris_worker`: `SELECT, INSERT, UPDATE, DELETE`
    (`database/migrations/005_rls_policies.sql:242-245`). Worker has
    `BYPASSRLS`. UPDATE is needed for the anchor flow (writing
    `merkle_root_id` / `merkle_leaf_index`).
- Tamper-evidence enforcement is via the
  `prevent_audit_log_modification` trigger in
  `database/schemas.sql:315-365` (attached at lines 357-365). DELETE is
  always rejected; UPDATE is allowed only when the only changed columns
  are `merkle_root_id` / `merkle_leaf_index` and they were previously
  NULL. The trigger fires regardless of role, including `inntris_worker`
  with BYPASSRLS — triggers are not bypassed by row security.
- `merkle_proofs` table grants: worker has full CRUD; `inntris_api`
  is not granted any access to `merkle_proofs`
  (`database/migrations/005_rls_policies.sql:240-245`). Public verify
  reads `merkle_proofs` — confirm externally that the API process's
  `DATABASE_URL` connects as `inntris_worker` (the migration comment at
  `005_rls_policies.sql:39-41` describes exactly this expected wiring,
  and the privilege-error message at `api/main.py:678-685` confirms it
  is the operative assumption).

Sub-finding (informational, not a finding): `inntris_worker` has DELETE
grant on `audit_logs`; tamper-evidence relies on the trigger rather than
revocation. Defence-in-depth would also revoke DELETE from the worker
role, but this is not a blocker — superuser/owner can disable the
trigger anyway, and the trigger is the documented control.

**Recommendation:** none required for the demo. Optional future
hardening: `REVOKE UPDATE, DELETE ON audit_logs FROM inntris_worker;`
and grant only on the two anchor columns
(`GRANT UPDATE (merkle_root_id, merkle_leaf_index) ON audit_logs TO inntris_worker`).

---

### Check 6 — Secret hygiene
**Severity: BLOCKER** (rotation)

Repository scan — no real secrets checked in:

- `.gitignore` excludes `.env`, `.env.local`, `.env.*.local`, `*.pem`,
  `*.key`, `secrets/`, `.secrets/` (`.gitignore:8-14`). Confirmed via
  `git ls-files | grep ^\.env` returning only `.env.example` and
  `.env.production.template`.
- `.env.example` and `.env.production.template` contain only placeholders
  (`your_secure_password_here`, `REPLACE_WITH_DEPLOYED_CONTRACT_ADDRESS`,
  `0xREPLACE_WITH_YOUR_PRIVATE_KEY_64_HEX_CHARS`,
  `your_base64_encoded_ed25519_private_key`).
- The hardcoded `postgresql://postgres:password@db:5432/inntris` at
  `api/main.py:86` and `postgresql://postgres:postgres@localhost:5432/inntris`
  at `workers/anchor_worker.py:49` are **dev fallback defaults** used only
  when `DATABASE_URL` is unset; in production the env var must override.
  In production, `SERVER_SECRET` (`api/main.py:88-95`) and (per migration
  005) the worker DB role must be set, so a missing `DATABASE_URL` would
  also be caught at boot.
- Demo doc transaction hash `0x517853a7…` at `frontend/src/app/docs/page.tsx:323`
  is a documentation fixture, not a secret.
- No hardcoded Ed25519 private keys, JWT secrets, RPC API keys, or
  wallet keys present in the repo (grep across `.py`, `.ts`, `.tsx`,
  `.json`, `.md`, `.yml`, `.yaml`, `.template`, `.example`, `.sql`, `.sh`,
  `Dockerfile*` — nothing matches realistic-secret patterns).

**However** — flagged out of band per the task brief, **must verify
externally** before the link is shared:

1. **Rotation owed.** Two database passwords (`inntris_worker`,
   `inntris_api`) were exposed in conversation prior to this audit and
   were *not* rotated. Until they are rotated and the new value is set
   in Railway env, a credential leak from past chats remains live. This
   is a BLOCKER for cold outreach because the only thing standing between
   a leaked password and unauthenticated DB access is Supabase's network
   layer.
2. **Railway env keys to confirm present** (do not dump values):
   `DATABASE_URL`, `REDIS_URL`, `SERVER_SECRET`, `BLOCKCHAIN_PROVIDER_URL`,
   `BLOCKCHAIN_CHAIN_ID` (or default 8453), `ANCHOR_CONTRACT_ADDRESS`,
   `BLOCKCHAIN_PRIVATE_KEY`, `ALLOWED_ORIGINS`, `ENVIRONMENT=production`
   (or staging). The CORS guard at `api/main.py:147-174` will fail-closed
   at boot if `ENVIRONMENT != development` and `ALLOWED_ORIGINS` is unset
   — this is good but means a missing env var manifests as a 502 on the
   demo URL.

**Recommendation:** rotate both DB roles in Supabase, push new values to
Railway, redeploy, and verify externally before sharing the demo link.

---

### Check 7 — Cold-tester demo readiness
**Severity: BLOCKER** for live `POST /verify`; **OK** for receipt page
(`/verify/{id}`)

What a stranger landing on `https://www.inntris.com` *can* do today:

- Click the "View receipt" CTA on the homepage
  (`frontend/src/app/page.tsx:182, 336, 395`) and land on
  `/verify/d8dd0902-4750-42d2-9516-92bf6362e815` or
  `/verify/3030c27c-87c4-4464-b4af-605fbe638e0e`. These hit
  `GET /public/verify/{record_id}` (no auth) and render the canonical
  Base mainnet receipt: verdict, agent, policy hash, action hash, Merkle
  root, tx hash, block number, anchored_at, receipt fingerprint,
  integrity_status (`api/main.py:760-783`).
- Use the search box at `frontend/src/app/verify/page.tsx:44-53` to look
  up any audit ID or 0x-prefixed tx hash.
- Independently verify the on-chain root via the public schema at
  `GET /schema/receipt/v1.json` (`api/main.py:424-427`) and BaseScan.

This satisfies a literal reading of "a working /verify demo available in
advance." A CEO clicking through will see a real receipt anchored on
Base mainnet within seconds.

What a stranger **cannot** do:

- POST to `/verify` and get back their own receipt within 60 seconds.
  The on-ramp requires generating an Ed25519 keypair, hitting
  `/public/agents/register`, computing the canonical action hash exactly
  (matching `api/crypto.py` byte-for-byte, including
  `sig_version` envelope semantics), signing it, and POSTing. There is
  **no public curl example or hosted playground** for this in the repo:
  - `README.md:230-274` shows the request shape but not a runnable
    end-to-end example.
  - `scripts/demo_verification.py` is the closest thing but requires
    `--api-key` (`scripts/demo_verification.py:155`) and uses
    `/admin/agents` (authenticated), not `/public/agents/register`.
  - `frontend/src/app/portal` exists ("Agent Portal: Developer
    dashboard, credentials, verification playground" per
    `README.md:108`) but is gated behind `/login`. A stranger cannot
    use it without being onboarded.
  - There is no `scripts/cold_tester_demo.py` or hosted `/playground`
    route.

If your message wording is the literal "a working /verify demo available
in advance" and you mean the receipt-viewing page, you're fine. If a CEO
expects to *generate* a receipt against your endpoint by themselves,
they will fail. The honest read is: this is a CONDITIONAL pass — the
demo is real, but the InMail wording sets a "they can use it" expectation
the codebase doesn't fulfil for unaided strangers.

**Recommendation:** add a single curl example to `README.md` for
`/public/verify/{CANONICAL_RECEIPT_ID}` that returns a real mainnet
receipt in one call, **and**/**or** publish a 30-line
`scripts/cold_tester_demo.py` that uses `/public/agents/register` to
sign + POST `/verify` end-to-end, no API key required. Either of these
would convert the receipt page from "look at this" to "click and run".

---

## Proposed fixes, ranked

1. **BLOCKER — Rotate the two exposed DB passwords** (`inntris_api`,
   `inntris_worker`) in Supabase, push to Railway env, redeploy, then
   verify `/health` is green and the canonical receipt page still
   loads. — effort: **S**.
2. **BLOCKER — Cold-tester on-ramp.** Either (a) add a 5-line curl
   example to `README.md` against `/public/verify/{CANONICAL_RECEIPT_ID}`
   so the link in the InMail is one copy-paste from a real receipt, or
   (b) ship `scripts/cold_tester_demo.py` exercising
   `/public/agents/register` → `/verify` end-to-end with no API key. — effort: **S** (curl example) / **M** (full script).
3. **HARDEN — Stop leaking infra detail in public verify error path.**
   Replace `api/main.py:678-685` 503 body with a generic
   "Verification temporarily unavailable" string; keep the operator
   detail in server logs. — effort: **S**.
4. **HARDEN — Stop leaking exception text from admin agent registration.**
   Replace `detail=str(e)` at `api/main.py:1521` with a fixed string;
   log the original `e` server-side. — effort: **S**.
5. **HARDEN — Verify production env vars in Railway.** Confirm
   `ENVIRONMENT` is not `development` (otherwise the
   `dev_*`/`test_*` API-key bypass at `api/main.py:231-238` is live),
   and that `ANCHOR_CONTRACT_ADDRESS`, `BLOCKCHAIN_CHAIN_ID=8453`,
   `BLOCKCHAIN_PROVIDER_URL`, `SERVER_SECRET`, `ALLOWED_ORIGINS` are
   all set. — effort: **S**.
6. **HARDEN — Externally verify canonical mainnet receipts still
   resolve.** Confirm
   `tx 0x3f86eea4328d00fbd968181f5f188aee95dea65ea690273f229534edd68ecd84`
   on basescan.org and that `/public/verify/3030c27c-…` returns a
   `verified` integrity_status against
   `https://api.inntris.com`. — effort: **S**.
7. **HARDEN — Defence-in-depth grant tightening.** `REVOKE UPDATE,
   DELETE ON audit_logs FROM inntris_worker;` and re-grant
   `UPDATE (merkle_root_id, merkle_leaf_index) ON audit_logs TO inntris_worker`.
   The trigger already enforces this; this is belt-and-braces. — effort: **S**.
8. **HARDEN — Remove `_base_sepolia_dev_only` block from
   `scripts/windows_verify_basescan.py`** so the script cannot be shared
   externally with a sepolia.basescan.org link. — effort: **S**.

## What I did NOT touch

- I did not run any code, migrations, or RPC calls. Nothing was written
  to the DB, the blockchain, or external services.
- I did not enumerate Railway env-var keys directly (no credentials
  available in this session) — every "verify externally" item depends
  on you doing that lookup.
- I did not check whether the canonical receipts
  (`d8dd0902-…`, `3030c27c-…`) and tx
  `0x3f86eea4…` are actually present and indexed on Base mainnet right
  now — that requires a live RPC / basescan query.
- I did not test that `https://api.inntris.com/health`,
  `https://api.inntris.com/public/verify/3030c27c-87c4-4464-b4af-605fbe638e0e`,
  and `https://www.inntris.com/verify/3030c27c-…` are actually reachable
  from a fresh browser on a different network — same reason.
- I did not audit `mcp_server/`, `trust_widget/`, or
  `frontend/src/app/admin` / `audit` / `portal` routes; they are out of
  scope for the `/verify` cold-tester surface.
- I did not run `pip`/`npm install`, did not modify lockfiles, and did
  not edit any source file.
