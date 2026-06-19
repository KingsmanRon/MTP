# INNTRIS SYSTEM BRIEF
**Authoritative technical briefing for product and go-to-market decisions**
*Compiled 2026-06-16 from direct code inspection. All claims are cited to file + line.*

---

## PLAIN-ENGLISH SUMMARY (5 sentences)

Inntris is a real-time control and audit layer that sits between an AI agent and its most dangerous actions — money transfers, external emails, deploys, data exports, and admin operations. Before any such action executes, the agent must call Inntris's `/verify` endpoint with a cryptographic signature; Inntris evaluates the action against a policy (trust thresholds, spend caps, rate limits, action allowlists) and returns either an approval token or a hard block. Every decision — approve or block — is recorded in an append-only audit log, whose SHA-256 hashes are periodically bundled into a keccak256 Merkle tree and anchored on Base Mainnet via a smart contract, producing a tamper-evident public receipt that anyone can verify. There is a working Next.js admin portal where operators can see live agent state, toggle individual action types, change spend caps, and hit a "Suspend agent" button that makes every subsequent request fail closed immediately. The critical limitation to disclose in every customer conversation: **Inntris only blocks if the customer's runtime actually calls `/verify` first — agents that skip the call are invisible to the system**, so the guarantee is self-enforcing only when the customer correctly wires the integration.

---

## ⚠️ CORRECTIONS TO THE STATED MODEL

The two-plane model (Control + Proof) is **confirmed and accurately described**, with the following specific corrections or clarifications:

| Claim | Verdict | Notes |
|---|---|---|
| Blocking in real time | **Confirmed** | `/verify` is synchronous; HTTP 403/401/429 returned before action executes |
| "inntris-verify" GitHub Action | **NOT FOUND** | No `action.yml` exists in this repo; only referenced in `.claude/agents/` description text |
| Enforce=self-enforcing | **Partially correct** | Self-enforcing only if customer calls `/verify` first; no proxy or kernel hook forces it |
| Ed25519 signing | **Confirmed** | `api/crypto.py:234-291` |
| keccak256 Merkle tree | **Confirmed** | `workers/anchor_worker.py:174-247` |
| Base Mainnet anchoring | **Confirmed** | chain_id=8453; contract `0x0600eA15802c8d2EA429371b2EB0aacCFe321480` (from `scripts/windows_verify_basescan.py:28`) |
| Admin frontend is Next.js | **Confirmed** | `frontend/` directory, Next.js App Router |
| FastAPI backend | **Confirmed** | `api/main.py` |

---

## 1. ENFORCEMENT MODEL

**Verdict: Synchronous and blocking on Inntris's side; self-enforcing only if the customer wires correctly.**

### The request path

When a customer-integrated agent wants to take a high-risk action, the sequence is:

1. Agent calls **`POST /verify`** with: `agent_id`, `action_type`, `payload`, Ed25519 `signature`, `nonce`, `timestamp`.
2. Inntris verifies the signature, checks the nonce (Redis), evaluates all policies (see §3), and atomically reserves rate/spend counters.
3. If all checks pass, Inntris returns HTTP 200 with an **approval token** (HMAC-SHA256 signed, 5-minute TTL) and the audit entry is recorded.
4. If any check fails, Inntris returns HTTP 403/429/401 with no approval token. The audit entry is still recorded.

Evidence: `api/main.py:1037-1458` (the complete `/verify` handler).

### The approval token

The token (`CryptoService.generate_approval_token`, `api/crypto.py:294-335`) is a base64-encoded JSON payload + HMAC-SHA256 signature over `SERVER_SECRET`. It binds `agent_id`, `action_hash`, `verdict`, and an expiry timestamp. The downstream system can verify it at `POST /verify-token` (`api/main.py:1460-1557`) — which requires no database lookup, only knowledge of the server secret — and optionally confirm that the token authorizes exactly this action (by recomputing the action hash).

### What physically prevents a blocked action

**Nothing in Inntris physically prevents execution.** There is no kernel hook, no proxy, no reverse-proxy intercept. The guarantee is:

- The MCP server (`mcp_server/server.py:471-506`) raises `InntrisVerificationError` with `isError=True` and `"DO NOT proceed"` text when `/verify` returns an error. An LLM agent seeing `isError=True` will not proceed (by MCP protocol convention).
- For custom API integrations, the customer's code must check `verdict == "approved"` before executing. If they skip the check, or check after the fact, nothing stops the action.

**This is the single most important go-to-market caveat**: Inntris is in the causal path only if the customer integrates it correctly. Competitors who offer an inline proxy or eBPF hook can claim a stronger guarantee.

---

## 2. SUSPEND / FAIL-CLOSED

**Verdict: Suspension alone guarantees fail-closed. The limits do NOT do the work — status does.**

The policy engine evaluates checks in strict priority order (`api/policy.py:136-195`):

```
1. _check_agent_status   ← THIS FIRES FIRST
2. _check_action_allowed
3. _check_trust_score
4. _check_timestamp
5. _check_rate_limits
6. _check_spending_limits (with atomic reservation)
```

`_check_agent_status` (`api/policy.py:197-206`) immediately returns `BLOCKED` if `agent.status != AgentStatus.ACTIVE`. A suspended or revoked agent never reaches limit checks. Spend caps and rate limits are irrelevant once status is non-active.

The admin portal's "Suspend agent" button (`frontend/src/components/admin/agent-control-panel.tsx:152-182`) calls `PATCH /admin/agents/{agent_id}/status?new_status=suspended`, which updates the DB row (`api/main.py:2210-2231` → `api/database.py:281-298`). The next `/verify` call reads the fresh row and blocks immediately.

**The code path for fail-closed on suspend:**
`PATCH /status` → `UPDATE agents SET status='suspended'` → next `/verify` → `get_agent_by_id` (reads live row) → `policy_engine.evaluate` → `_check_agent_status` → `PolicyResult(allowed=False, verdict=BLOCKED)` → HTTP 403.

---

## 3. CONTROL PLANE INVENTORY

All controls are **enforced in backend code**, not UI-only. The admin frontend (`agent-controls.ts`) mirrors the backend thresholds as advisory UI context only; the backend (`api/policy.py:TRUST_THRESHOLDS`) is the source of truth at decision time.

### Action types and their gates

| Action Type | Trust Threshold | Rate Limit | Daily Spend Cap | Per-Action Cap | Allow/Block List | Backend-Enforced? |
|---|---|---|---|---|---|---|
| `financial_transaction` | 30 | ✓ | ✓ | ✓ | ✓ | **YES** |
| `email_send` | 20 | ✓ | — | — | ✓ | **YES** |
| `api_call` | 10 | ✓ | — | — | ✓ | **YES** |
| `tool_call` | 10 | ✓ | — | — | ✓ | **YES** |
| `data_export` | 40 | ✓ | — | — | ✓ | **YES** |
| `admin_action` | 70 | ✓ | — | — | ✓ | **YES** |
| `ci_workflow_change` | 80 | ✓ | — | — | ✓ | **YES** |
| `protected_branch_merge` | 80 | ✓ | — | — | ✓ | **YES** |
| `production_deployment` | 80 | ✓ | — | — | ✓ | **YES** |
| `repo_change` | **None (attestation)** | ✓ | — | — | ✓ | **YES** |
| `promptfoo_eval` | **None (attestation)** | ✓ | — | — | ✓ | **YES** |

Attestation actions (`repo_change`, `promptfoo_eval`) bypass the trust-score gate (`api/policy.py:64-67`, `api/policy.py:244-247`). They record that something happened but do not gate a live operation on trust level.

### How spend limits work

`financial_transaction` must carry a numeric amount field (one of: `amount`, `amount_usd`, `value`, `total`) (`api/policy.py:80-81`). A malformed or missing amount on a financial action is BLOCKED, not treated as $0 (`api/policy.py:318-349`). After the policy engine's pre-check approves the amount, an atomic database transaction (`api/database.py:641-701`) increments both the minute request counter and the daily spend counter, checks them against limits, and rolls back if either trips — closing the check-then-act race under concurrent load.

### No UI-only controls

Every control visible in the admin panel has a corresponding backend gate. There are no "display-only" policy controls that the backend ignores.

---

## 4. PROOF PLANE

### Full pipeline

**Step 1 — Signing (per-event, synchronous in `/verify`)**
The agent Ed25519-signs a canonical hash of `{agent_id, action_type, payload_hash, nonce, timestamp}` using its private key before sending the request (`mcp_server/server.py:108-145`, `api/crypto.py:156-232`). The server verifies the signature with pynacl (`api/crypto.py:234-291`). Three signing envelope versions are supported for cross-SDK compatibility (v1 legacy, v2 UTC-normalized default, v3 JCS/RFC-8785 for non-Python SDKs).

**Step 2 — Audit log insertion (per-event, synchronous)**
Every `/verify` call — approved or blocked — inserts a row into `audit_logs` with the action hash, verdict, signature bytes, and a `chain_previous_hash` linking it to the prior audit entry for that agent (local per-agent hash chain). This is done under a per-agent advisory lock to prevent concurrent forks (`api/database.py:441-488`).

**Step 3 — Merkle tree construction (batched, asynchronous)**
The anchor worker (`workers/anchor_worker.py`) runs on a configurable interval (default: 60 minutes, `ANCHOR_INTERVAL_MINUTES`). It fetches up to 1,000 unanchored audit logs (excluding test-request sentinel rows) and builds a keccak256 Merkle tree from their `action_hash` values (`workers/anchor_worker.py:182-247`). Keccak-256 is used — not SHA-256 — to match the on-chain `keccak256()` function in Solidity.

**Step 4 — On-chain anchoring**
The Merkle root (bytes32) is submitted to the `AnchorRegistry` contract on Base Mainnet via `anchorBatch(merkleRoot, logCount, startTimestamp, endTimestamp)` (`contracts/AnchorRegistry.sol:159-215`). The contract stores the root immutably, emits a `BatchAnchored` event, and rejects duplicate roots. The worker verifies chain ID before submission to guard against RPC misconfiguration (`workers/anchor_worker.py:291-307`). A gas-price cap (default 50 gwei, `ANCHOR_MAX_GAS_PRICE_GWEI`) prevents ruinous fees from a broken oracle. Failed submissions retry with exponential backoff (base 60s); after 5 failures a record is moved to `dead_letter` state (`workers/anchor_worker.py:766-807`).

**Step 5 — Receipt publication**
`GET /public/verify/{audit_id}` returns a `PublicVerificationRecord` (`api/main.py:773-940`) including `tx_hash`, `block_number`, `chain_id=8453`, `merkle_root`, and a `receipt_fingerprint` (SHA-256 of canonical JSON of the 7 core receipt fields). `GET /public/verify/{audit_id}/proof` returns the full Merkle proof path (sibling hashes + positions) needed to verify inclusion (`api/main.py:943-1030`).

### What gets anchored

**Only the Merkle root** (32 bytes) is written on-chain. The full audit records stay in Postgres. A receipt is "trustlessly verifiable" in the following bounded sense: a verifier can independently confirm that (a) the Merkle root exists on-chain at the given block (fully trustless, needs only a Base RPC), and (b) the claimed action hash is a leaf in that tree (requires the sibling path, which Inntris's API serves). The sibling path is not itself on-chain, so the verifier must currently trust Inntris to serve the correct path — or store the proof path independently.

The `AnchorRegistry.verifyProof()` function (`contracts/AnchorRegistry.sol:347-380`) enables full on-chain proof verification if the caller has the proof path. The API provides all the inputs for this.

### Contract address and chain

| Parameter | Value |
|---|---|
| Contract address | `0x0600eA15802c8d2EA429371b2EB0aacCFe321480` (from `scripts/windows_verify_basescan.py:28`) |
| Chain | Base Mainnet, chain_id=8453 |
| Network check at runtime | YES — worker verifies `eth_chainId` before every submission |

*Note: The contract address appears only in a demo/verification script, not in a config file. Operators must set `ANCHOR_CONTRACT_ADDRESS` as an env var; the worker exits if unset (`workers/anchor_worker.py:832-834`).*

---

## 5. INTEGRATION / ADOPTION SURFACE

### What the customer must do

**Minimum integration for enforcement (Option A — MCP server)**
1. Register an agent: `POST /public/agents/register` with email + Ed25519 public key. Returns `agent_id`. No API key required.
2. Run `mcp_server/server.py` alongside the AI agent process, configured with `INNTRIS_AGENT_ID` and `INNTRIS_PRIVATE_KEY_B64`.
3. Instruct the agent model to call the `inntris_guard` tool before financial, email, API, data-export, and admin actions.
4. The MCP tool returns APPROVED or BLOCKED; the agent's framework treats `isError=True` as a hard stop.

Lift: **Light** — two env vars and no SDK installation beyond the MCP package.

**Minimum integration for enforcement (Option B — Direct API)**
1. Register agent (same as above).
2. Before each high-risk action: generate a nonce, compute the action hash, sign with Ed25519 private key, call `POST /verify`.
3. Check `verdict == "approved"`. If not, abort. Optionally call `POST /verify-token` downstream before the actual execution.

Lift: **Moderate** — requires implementing Ed25519 signing in the customer's language.

**Minimum integration for proof (same for both paths)**
Proof is automatic — every audit log entry is included in the next batch. The customer gets `audit_id` from the `/verify` response and can poll `/public/verify/{audit_id}` to see when `tx_hash` is populated (up to ~60 minutes after the action).

### Public API surface

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /verify` | None (uses agent Ed25519 sig) | Primary enforcement gate |
| `POST /verify-token` | None | Downstream token validation |
| `POST /public/agents/register` | None (rate-limited 5/IP/hr) | Self-serve agent bootstrap |
| `POST /public/agents/register-promptfoo` | None | Promptfoo-specific alias |
| `GET /public/agent/{agent_id}` | None | Trust badge data |
| `GET /public/verify/{record_id}` | None | Public receipt (by audit UUID or tx hash) |
| `GET /public/verify/{audit_id}/proof` | None | Merkle proof path |
| `POST /v1/events` | Bearer token | Unsigned partner event ingestion |
| `GET /admin/agents` | X-API-Key | List agents |
| `PATCH /admin/agents/{id}` | X-API-Key | Update policy |
| `PATCH /admin/agents/{id}/status` | X-API-Key | Suspend/activate |
| `GET /admin/audit/search` | X-API-Key | Search audit logs |
| `GET /admin/audit/{id}/proof` | X-API-Key | Merkle proof (authenticated) |
| `GET /admin/audit/export` | X-API-Key | Export CSV/JSON |
| `POST /admin/test-verify` | X-API-Key | Policy sandbox (no proof anchoring) |
| `GET /health` | None | Health check |
| `GET /metrics` | None | Prometheus metrics |
| `GET /schema/receipt/v1.json` | None | JSON Schema for receipt v1 |

---

## 6. IMPLEMENTED vs INCOMPLETE

### Fully implemented and wired end-to-end

1. **`POST /verify` core pipeline** — Ed25519 verification, nonce replay protection (Redis fail-closed), policy evaluation, atomic rate+spend reservation (single DB transaction, race-free), audit log insertion with per-agent hash chain, trust score adjustment, approval token issuance, webhook dispatch. (`api/main.py:1037-1458`)

2. **`POST /verify-token`** — HMAC-SHA256 token verification with optional action binding. (`api/main.py:1460-1557`)

3. **Agent management** — full CRUD: register, list, get, update policy (PATCH), suspend/activate, dashboard. (`api/main.py:1883-2231`)

4. **Trust scoring** — integer accrual (+1 per approval, -2 per policy block, -20 per invalid signature) with daily decay toward baseline 50. (`api/policy.py:371-459`)

5. **Admin frontend** — Next.js App Router with login, agents list, agent detail page with tabs (Policy / Activity), full AgentControlPanel (action toggles, spend limits, rate limits, trust score override, suspend/activate button, presets). (`frontend/src/app/admin/`, `frontend/src/components/admin/agent-control-panel.tsx`)

6. **Anchor worker** — keccak256 Merkle tree builder, Base L2 submission, exponential-backoff retry, dead-letter queue, RPC circuit breaker, gas-price sanity cap, chain-ID guard. (`workers/anchor_worker.py`)

7. **AnchorRegistry smart contract** — AccessControl-gated, Pausable, ReentrancyGuard, immutable roots, `verifyProof()` on-chain verification. (`contracts/AnchorRegistry.sol`)

8. **Public receipt and proof API** — `GET /public/verify/{id}`, `GET /public/verify/{id}/proof`, receipt fingerprint (SHA-256 of 7 canonical fields), v1/v2 schema versioning. (`api/main.py:773-1030`)

9. **MCP server** — `inntris_guard`, `inntris_check_status`, `inntris_log_audit` tools over stdio transport. Compatible with any MCP-speaking agent (Claude, Lovable, Replit, LangChain). (`mcp_server/server.py`)

10. **Partner event ingestion** — `POST /v1/events` (bearer-authenticated, unsigned, flows into Merkle pipeline with explicit `non_cryptographic` marker). (`api/main.py:1786-1876`)

11. **Webhooks** — HMAC-SHA256 signed, fire-and-forget, per-org URL, events: `verification.approved`, `verification.blocked`, `verification.rate_limited`, `verification.signature_invalid`. (`api/main.py:141-228`)

12. **Observability** — Prometheus metrics (`verify_requests_total`, `verify_latency_seconds`, `signature_failures_total`, `nonce_replays_total`, `rate_limit_trips_total`, `anchor_submissions_total`), request ID middleware, structured JSON logging. (`api/observability.py`)

13. **CI pipeline** — pytest + ruff (Python), jest + tsc + Next.js build (frontend), forge build + forge test (Solidity). Three parallel jobs. (`/.github/workflows/ci.yml`)

14. **Security scanning** — Semgrep (OWASP + security-audit), pip-audit, npm audit, Trivy (vuln + config + secret). Weekly scheduled runs. (`/.github/workflows/security.yml`)

15. **Trust badge widget** — standalone React component for embedding agent trust status on third-party sites. (`trust_widget/src/TrustBadge.tsx`)

---

### Scaffolded / stubbed / incomplete / NOT FOUND

1. **`trust_history` in agent dashboard** — `api/main.py:2041-2046` returns the current trust score repeated for the last 7 days with a comment "Would track historical values in production." There is no time-series trust history table; the chart in the admin UI shows a flat line.

2. **`inntris-verify` GitHub Action** — Referenced in `.claude/agents/inntris-integration-architect` description as "primary distribution channel" but **no `action.yml` or `action.yaml` file exists anywhere in this repository**. This is either planned or lives in a separate repo not included here. **Unverified from code.**

3. **`policy_rules` table** — The database schema (`database/schemas.sql:96+`) defines a `policy_rules` table for configurable per-org/per-agent rules. The `PolicyEngine` (`api/policy.py`) does not query this table; it uses only the `TRUST_THRESHOLDS` dict (hardcoded in Python) and the `allowed_actions`/`blocked_actions` arrays stored on the agent row. The table may exist but is not wired.

4. **`inntris_log_audit` MCP tool** — Calls `/verify` with `action_type="audit_log"` (`mcp_server/server.py:571-596`). This action type is not in any default `allowed_actions` list, so it will be BLOCKED unless the operator adds it. Functionally broken without manual agent config.

5. **TimescaleDB hypertables** — The schema attempts `CREATE EXTENSION timescaledb` with graceful fallback. There is no code that uses TimescaleDB-specific APIs. Its value in production depends on whether it was actually installed.

6. **`/admin/alerts` workflow** — The alert creation endpoint is implemented and security alerts are created on `signature_invalid` events. However, the ack/resolve endpoints appear in `api.ts` but the actual backend routes for `POST /admin/alerts/{id}/acknowledge` and `POST /admin/alerts/{id}/resolve` need verification — they are not visible in the 3100 lines of `main.py` read. **Unverified — may be complete or may be missing.**

7. **RLS (Row-Level Security)** — `database.py:102-135` implements `acquire_as_tenant()` that sets `app.current_org_id` and switches role to `inntris_api`. This is referenced as "migration 005" but the two Alembic migrations in `alembic/versions/` (0001_baseline, 0002_gdpr_erasure) do not include this. The actual admin endpoints use explicit `WHERE org_id = $1` filters rather than `acquire_as_tenant`, so the RLS path is implemented but not used in the hot path.

---

## 7. ARCHITECTURE & DATA MODEL

### Stack

```
┌─────────────────────────────────────────────────────────┐
│  Customer AI Agent                                       │
│  (LLM + tool loop)                                       │
│        │                                                 │
│  mcp_server/server.py   OR   direct API call             │
│  (MCP stdio transport)       (custom SDK)                │
└───────────────────┬─────────────────────────────────────┘
                    │ POST /verify (Ed25519-signed)
                    ▼
┌─────────────────────────────────────────────────────────┐
│  FastAPI  (api/main.py)                                  │
│  Python 3.12 / uvicorn                                   │
│  ├── pynacl (Ed25519 verify)                             │
│  ├── Redis (nonce dedup, fail-closed on unavailability)  │
│  └── asyncpg → PostgreSQL 15+                            │
└──────────┬──────────────────────────────────────────────┘
           │ async writes (audit_logs)
           ▼
┌──────────────────────────────┐
│  PostgreSQL                  │
│  tables:                     │
│  - organizations             │
│  - agents (+ public_key)     │
│  - audit_logs (append-only)  │
│  - merkle_proofs             │
│  - rate_limit_windows        │
│  - security_alerts           │
│  - api_keys                  │
└──────────┬───────────────────┘
           │ periodic poll (every 60 min)
           ▼
┌──────────────────────────────┐     ┌─────────────────────────────┐
│  workers/anchor_worker.py    │────▶│  Base Mainnet (chain 8453)  │
│  keccak256 Merkle tree       │     │  AnchorRegistry.sol          │
│  web3.py + eth_account       │     │  0x0600eA15802c8d2EA429371b │
└──────────────────────────────┘     │    2EB0aacCFe321480          │
                                     └─────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  Next.js 14 App Router  (frontend/)                      │
│  TypeScript, Tailwind CSS, shadcn/ui                     │
│  Admin portal: /admin (auth'd via X-API-Key in cookie)   │
│  Public pages: /verify/[id], /ai-pr-protection, etc.     │
└─────────────────────────────────────────────────────────┘
```

### Core data model

**`organizations`** — Tenant root. Fields: `id`, `name`, `billing_tier` (free/starter/professional/enterprise), `contact_email`, `webhook_url`, `api_key_hash` (SHA-256, stored not plaintext), `daily_limit_usd`, `monthly_limit_usd`. One org can have many agents and many API keys.

**`agents`** — Per-agent identity and policy. Fields: `id`, `org_id` (FK), `name`, `public_key` (BYTEA, 32 bytes Ed25519), `public_key_fingerprint` (SHA-256 hex), `trust_score` (0–100 int), `status` (active/suspended/revoked/pending_verification), `daily_limit_usd`, `per_action_limit_usd`, `allowed_actions` (TEXT[]), `blocked_actions` (TEXT[]), `rate_limit_per_minute`, `total_actions_count`, `total_blocked_count`. This single row is the complete policy state for an agent.

**`audit_logs`** — Append-only forensic record. Fields: `id`, `agent_id`, `action_type`, `action_hash` (SHA-256 hex), `payload` (JSONB), `verdict` (approved/blocked/rate_limited/signature_invalid), `verdict_reason`, `signature` (BYTEA), `signature_valid` (bool), `trust_score_at_time`, `chain_previous_hash` (previous row's action_hash, creating a per-agent hash chain), `policy_hash` (optional SHA-256 of customer's .inntris.yml), `merkle_root_id` (FK, null until anchored), `merkle_leaf_index`. Test-request rows are excluded from Merkle batching via `metadata->>'test_request'`.

**`merkle_proofs`** — One row per anchor batch. Fields: `id`, `root_hash` (VARCHAR 64, hex without 0x), `leaf_hashes` (TEXT[]), `start_timestamp`, `end_timestamp`, `transaction_hash`, `block_number`, `chain_id` (always 8453 in production), `status` (pending/confirmed/failed/dead_letter), `retry_count`, `next_retry_at`, `dead_lettered_at`, `submitted_by` (wallet address).

**`rate_limit_windows`** — Sliding window counters. Fields: `agent_id`, `window_type` ('minute' or 'day'), `window_start`, `request_count`, `amount_usd`. The atomic upsert in `reserve_rate_and_spend()` is the authoritative limit gate.

**`security_alerts`** — Created on `signature_invalid` events (and potentially others). Fields: `id`, `agent_id`, `org_id`, `alert_type`, `severity`, `title`, `description`, `evidence` (JSONB), `audit_log_ids` (UUID[]), `acknowledged`, `resolved`.

**`api_keys`** — Org-level keys for admin endpoints. Fields: `id`, `org_id`, `key_hash` (BYTEA SHA-256), `name`, `scopes` (TEXT[]), `is_active`, `expires_at`, `last_used_at`.

---

*End of brief. Evidence base: direct reading of `api/main.py` (3100 lines), `api/policy.py`, `api/crypto.py`, `api/database.py`, `api/models.py`, `workers/anchor_worker.py`, `contracts/AnchorRegistry.sol`, `mcp_server/server.py`, `frontend/src/components/admin/agent-control-panel.tsx`, `frontend/src/lib/agent-controls.ts`, `frontend/src/lib/api.ts`, `frontend/src/app/admin/agents/[id]/page.tsx`, `database/schemas.sql`, `.github/workflows/ci.yml`, `.github/workflows/security.yml`, `trust_widget/src/TrustBadge.tsx`, `scripts/windows_verify_basescan.py`.*
