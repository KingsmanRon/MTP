# Threat Model

**Scope**: Inntris Machine Trust Protocol (MTP) — the FastAPI backend (`api/`),
Next.js frontend (`frontend/`), anchor worker (`workers/`), AnchorRegistry
contract (`contracts/`), PostgreSQL schema (`database/`), and MCP server
(`mcp_server/`). Agent-side code (SDKs, key custody) is out of scope except
where it meets a system trust boundary.

**Method**: STRIDE (Spoofing, Tampering, Repudiation, Information disclosure,
Denial of service, Elevation of privilege). Mitigations are cited by
`file:line` where the control lives. Controls introduced in the
enterprise-readiness work are tagged with their phase (0.1–1B.1) for
traceability.

**Status**: Living document. Update alongside every phase that adds, removes,
or meaningfully alters a control. Mitigations listed here are claims about the
current repo; re-verify before acting on them.

---

## 1. System overview

Five trust domains:

| # | Domain | Principal | What it holds |
|---|--------|-----------|---------------|
| A | External agent runtime | Customer-controlled | Ed25519 signing key, signs `/verify` requests |
| B | Public internet client | Unauthenticated | Reads `/public/*`, posts to `/public/agents/register*` |
| C | Admin console user | Org operator | Holds plaintext API key in-memory at login; browser sees only the AES-256-GCM cookie |
| D | Inntris backend plane | Inntris-operated | FastAPI, Next.js BFF, PostgreSQL, Redis, anchor worker, hot wallet |
| E | Base L2 + AnchorRegistry | Public chain | Stores Merkle roots; contract-enforced access control |

### 1.1 Data flow (reference)

```
Agent (A) --signed /verify--> FastAPI (D) --audit_logs--> Postgres (D)
                                   |                          |
                                   +---nonce--> Redis (D)     |
                                                              v
                                                       Anchor worker (D)
                                                              |
                                                       compute Merkle root
                                                              |
                                                              v
                                                       AnchorRegistry (E)
                                                              |
Public (B) <----/public/verify/{id}---- FastAPI (D) <---------+
Admin (C) --login--> Next.js BFF (D) --[encrypted cookie]--> adminFetch --> FastAPI (D)
```

### 1.2 Assets and their integrity guarantees

| Asset | Location | Integrity guarantee | Confidentiality |
|-------|----------|---------------------|------------------|
| Agent private keys | Agent side (A) | Out of scope (customer custody) | Customer-controlled |
| Agent public keys | `agents.public_key` | FK + unique fingerprint index (`database/schemas.sql:91`) | Public |
| Audit logs | `audit_logs` | DB trigger prevents UPDATE/DELETE except one-shot Merkle fields (`database/schemas.sql:315-365`) | Internal; public-safe subset exposed via `/public/verify` |
| Merkle roots on-chain | `AnchorRegistry._batches` | `RootAlreadyAnchored` revert (`contracts/AnchorRegistry.sol:177-179`); immutable mapping | Public |
| Hot-wallet private key | `BLOCKCHAIN_PRIVATE_KEY` env (`workers/anchor_worker.py:49`) | Plain env var — **residual risk**, see §4 | Secret |
| Organization API key | `organizations.api_key_hash` (SHA-256) | Hash-only storage (`api/main.py:183-184`) | Plaintext only in-transit at login |
| Admin session | AES-256-GCM cookie (`frontend/src/lib/admin/session.ts:42-55`) | Authenticated encryption; sliding + absolute TTL | Server-only key material |
| Nonces | Redis `inntris:nonce:{agent}:{nonce}` | 10-min TTL (`api/main.py:920-924`) | Internal |
| `SERVER_SECRET` | Env var | Length ≥32 enforced in prod (`api/main.py:83-87`) | Secret |

---

## 2. Trust boundaries

1. **Internet → Next.js BFF** — unauthenticated surface for `/api/admin/session` login POST, the public verify/register endpoints served via the backend, and the static site. Rate-limited at boundaries §3.D1 and §3.D2.
2. **Next.js BFF → FastAPI** — server-to-server, `X-API-Key` header carries the org's key (read from the encrypted cookie, never from the browser). See `frontend/src/lib/admin/api-client.ts` and proxies under `frontend/src/app/api/admin/*`.
3. **Agent runtime → FastAPI `/verify`** — the only external identity check is the Ed25519 signature over the action hash. §3.S1.
4. **FastAPI → Postgres** — trusted channel. Tenant-scoping policies and an `acquire_as_tenant` role-downgrade path exist (`database/migrations/005_rls_policies.sql`, `api/database.py`). Production enforcement still depends on the applied migrations and runtime DSN, so it must be verified per deployment.
5. **Anchor worker → Base L2 RPC** — funded hot wallet; submission is idempotent via `RootAlreadyAnchored`.
6. **Anchor worker → AnchorRegistry** — contract enforces `SUBMITTER_ROLE` (`contracts/AnchorRegistry.sol:166`).

---

## 3. STRIDE analysis

Each threat below lists: **T#** tag · what · mitigation (file:line) · residual
risk tag (see §4 if relevant).

### S — Spoofing

**S1. Agent impersonation against `/verify`.** An attacker submits an action claiming to be a legitimate agent.
- Action hash is signed with the agent's Ed25519 key and verified against the stored public key (`api/main.py:858-866`, `api/crypto.py:234-291`).
- Signature validated in constant time via libsodium (`api/crypto.py:243-244`).
- Agent lookup is by UUID not public-key substring, so an attacker cannot substitute a public key they control (`api/main.py:835-836`).
- Invalid signatures are logged and raise a `SIGNATURE_VERIFICATION_FAILED` security alert (`database/schemas.sql:391-430`).

**S2. Signature replay across timezones or server versions.** Prior to Phase 0.3, an attacker could capture a signed envelope signed against `datetime.utcnow()` (naive) and replay it after a server tz change.
- Timestamp normalized through `CryptoService.canonicalize_timestamp` before hashing (`api/crypto.py:88-140`, Phase 0.3).
- Wire timestamp and canonical hash timestamp both emit `…Z` UTC (`api/main.py:92-105`).
- Regression: `tests/test_action_hash_timestamp.py`.

**S3. Silent wire-format downgrade.** A malicious client could pick a future/legacy encoding if the server guessed at version.
- `VerifyActionRequest.sig_version` pinned by client, `ge=1 le=3` at the model level, no silent fallback (`api/models.py:132-142`, Phase 0.4).
- Unknown `sig_version` raises `CryptoError`; server refuses rather than trying a different path (`api/crypto.py:217-223`).

**S4. Cross-language signer divergence.** Non-Python SDKs using naive canonicalization produced different hashes on payloads containing `1.0`, `-0.0`, or non-BMP keys.
- `sig_version=3` enforces RFC 8785 JCS on both inner payload hash and outer envelope (`api/jcs.py`, `api/crypto.py:206-216`, Phase 1B.1).
- 12 cross-language vectors pin the contract (`tests/fixtures/canonicalization/jcs_vectors.json`, Node reference runner at `tests/fixtures/canonicalization/verify_jcs_node.js`).

**S5. Admin impersonation via stolen session.** If an attacker captures the admin session cookie, they inherit the org's full admin scope.
- Cookie is AES-256-GCM authenticated (`frontend/src/lib/admin/session.ts:42-55`) — a tampered cookie fails `decipher.setAuthTag` and `decrypt` returns `null` (`session.ts:57-83`).
- `HttpOnly` + `Secure` + `SameSite=strict` (`session.ts:85-93`) blocks JS exfiltration and most CSRF.
- Absolute ceiling `MAX_SESSION_AGE = 7200` seconds caps the blast radius of a leak (`session.ts:12, 123-129`).
- `ADMIN_SESSION_SECRET` must be ≥32 bytes in production (`session.ts:20-28`).

**S6. Merkle-root spoofing on-chain.** An attacker posts a fake root to claim logs that don't exist in our DB.
- Only `SUBMITTER_ROLE` may call `anchorBatch` (`contracts/AnchorRegistry.sol:166`). The role is granted only to our hot-wallet address (constructor, `contracts/AnchorRegistry.sol:129-131`).
- **Residual**: hot-wallet key theft lets an attacker anchor arbitrary roots (see §4.R1).

### T — Tampering

**T1. Audit-log mutation after the fact.** An insider with DB access tries to alter a verdict or delete a record.
- PL/pgSQL trigger `prevent_audit_log_modification` rejects DELETE unconditionally and UPDATE unless the mutation is strictly limited to `merkle_root_id` + `merkle_leaf_index` set-from-NULL (`database/schemas.sql:315-365`).
- Row-level audit entries are immutable at the application layer: INSERT path in `Database.insert_audit_log` never issues UPDATE on existing rows.
- Every audit log row stores `chain_previous_hash`, creating a per-agent local hash chain (`api/main.py:888`).

**T2. Retroactive receipt fingerprint forgery.** An attacker controls a frontend display but wants to render a receipt with a different verdict/policy.
- `receipt_fingerprint` is recomputed from the canonical wire fields (`api/main.py:658-674`). Frontend recomputes the same fingerprint from the wire JSON and compares (`frontend/src/lib/proof-state.ts` and `verify-record-client.tsx`).
- `policy_hash` is stored on the immutable audit row and included in the canonical v2 receipt fingerprint (`api/main.py:889-922`, `frontend/src/lib/proof-state.ts`).
- **Residual**: the current agent Ed25519 signing envelope does not include `policy_hash` (`api/crypto.py:157-232`). A future signing-envelope version must bind the active server-owned policy hash before Inntris can claim the agent signature covered it.

**T3. Merkle-root overwrite on-chain.** Attacker tries to re-anchor a root with different metadata.
- Contract reverts `RootAlreadyAnchored` (`contracts/AnchorRegistry.sol:177-179`).

**T4. Merkle-proof forgery off-chain.** A proof returned to a verifier does not correspond to the claimed leaf.
- `compute_merkle_proof` uses keccak256 matching the on-chain verifier exactly (`workers/anchor_worker.py:166-202`).
- On-chain `verifyProof` recomputes the root from leaf + proof and compares (`contracts/AnchorRegistry.sol:347-380`) — anyone can independently verify without trusting the API.

**T5. Request tampering in transit.** Bearer-token or admin-proxy requests are modified between frontend and FastAPI.
- All upstream calls are HTTPS-only in production (Next.js BFF → FastAPI), with `X-API-Key` carried server-side.
- Browser never holds the API key (`frontend/src/__tests__/no-localstorage-api-key.test.ts`, Phase 0.1). A grep-scan invariant test forbids regression.

### R — Repudiation

**R1. Agent denies signing an action.** Customer claims "my agent didn't do that."
- Ed25519 non-repudiation: only the holder of the private key could have produced the signature (`api/crypto.py:234-291`).
- Full signed envelope — `{agent_id, action_type, payload_hash, nonce, timestamp}` — is hashed and bound in `action_hash` (`api/crypto.py:225-232`).
- Signed envelope plus raw signature bytes are stored in `audit_logs.signature` (`database/schemas.sql:137`).
- Audit log is immutable (§T1) and Merkle-anchored on-chain within the batch cadence (default 60 min, `workers/anchor_worker.py:54`).

**R2. Inntris denies an adverse verdict was issued.** Customer claims "you never blocked this" or "you let this through."
- Both PASS and BLOCK paths write an audit log with signature + verdict + policy_hash (`api/main.py:870-1027`). The signature-invalid path still writes an audit row (`api/main.py:874-904`).
- Batch anchoring commits to the entire day's decisions via Merkle root on Base L2 — the anchored root cryptographically commits to the set of decisions, including blocks.

**R3. Inntris denies a specific policy was in force.** "The rule wasn't there when my agent was denied."
- `policy_hash` is part of the canonical v2 receipt fingerprint and preserved with the immutable audit record.
- **Residual**: the hash is adapter-supplied, is not derived from the current agent controls, and is not included in the agent-signed envelope. Server-owned policy versions and a new signing-envelope version are required for a strong active-policy claim.

### I — Information disclosure

**I1. Plaintext API key exfiltration from the browser.** Pre-0.1, the raw org API key sat in `localStorage` — readable by any XSS payload, browser extension, or shared-machine snooper.
- Key moved to the AES-256-GCM HTTP-only cookie (`frontend/src/lib/admin/session.ts`, Phase 0.1).
- Browser never sees the plaintext key after the login POST body; the key is consumed server-side only (`frontend/src/app/api/admin/session/route.ts:91-108`).
- All admin calls proxy through `/api/admin/*` (e.g. `frontend/src/app/api/admin/agents/[id]/status/route.ts`, `frontend/src/app/api/admin/alerts/*/route.ts`), never calling FastAPI with the browser's key.
- Invariant test prevents regression (`frontend/src/__tests__/no-localstorage-api-key.test.ts`).

**I2. Cross-tenant leakage in admin endpoints.** Org A reads org B's agents or audit logs.
- FastAPI `verify_api_key` resolves the caller's `org_id` and scopes (`api/main.py:157-224`).
- Handlers gate on `agent.org_id == auth["org_id"]` for single-agent reads (`api/main.py:1103-1107` on the test-verify path, same check pattern elsewhere in admin handlers).
- Tenant RLS policies and integration tests exist (`database/migrations/005_rls_policies.sql`, `tests/test_rls_policies.py`).
- **Residual**: production RLS activation and use of the tenant-scoped connection path must be verified. A deployment using the wrong role or unapplied migrations falls back to handler-layer checks.

**I3. Testnet receipt leak through the public verifier.** Pre-launch the public path could surface Sepolia-anchored receipts, giving an attacker a confident-looking but non-canonical receipt URL.
- Public verify endpoint returns 410 for any `chain_id != 8453` (`api/main.py:620-635`).

**I4. Audit-log PII in verdict reasons.** Raw payloads in `audit_logs.payload` may contain PII the customer shipped; verdict reasons may echo portions of it.
- `payload` is JSONB stored alongside the verdict (`database/schemas.sql:134`). Access is gated by the admin auth/org checks (§I2).
- Public verify only exposes a fixed safe field set (`api/main.py:690-713`, `PublicVerificationRecord` in `api/models.py:313-351`), never the raw payload.
- A forensic-integrity-preserving erasure function and operator wrapper exist (`database/migrations/006_gdpr_erasure.sql`, `api/erasure.py`).
- **Residual**: production activation, backup erasure, external logs, and caches remain deployment and operator responsibilities; see §4.R4.

**I5. Server-secret exposure in config.** Leaked `SERVER_SECRET` forges approval tokens.
- Production startup hard-fails if missing or <32 chars (`api/main.py:83-87`).
- Approval tokens are HMAC-SHA-256 keyed by `SERVER_SECRET` and include an absolute `exp` (`api/crypto.py:293-335`); verifier uses `hmac.compare_digest` (`api/crypto.py:363-364`).
- **Residual**: no rotation story. Deferred (not in current approved queue).

### D — Denial of service

**D1. Login brute-force against the admin console.** Attacker tries API keys on `/api/admin/session`.
- Per-IP limit: 5 attempts / 15 min (`frontend/src/app/api/admin/session/route.ts:6-7, 46-59`).
- Fail-closed when Redis is down: returns 503 rather than skipping the check (`frontend/src/app/api/admin/session/route.ts:22-75`, Phase 0.2).
- Dev kill-switch `INNTRIS_DISABLE_LOGIN_RATE_LIMIT=1` is intentionally named to make misuse obvious in prod config review.
- Regression: `frontend/src/app/api/admin/session/__tests__/fail-closed.test.ts`.

**D2. Unbounded public agent registration.** Attacker scripts the public registration endpoint to flood the `organizations`/`agents` tables.
- Per-IP hourly limit on `/public/agents/register*` (`api/main.py:227-254`).
- **Residual**: fail-**open** on Redis outage (`api/main.py:242-243`). Registration is treated as an availability-over-correctness surface. Operators should monitor org/agent churn and page on anomaly.

**D3. Replay flood against `/verify`.** Attacker captures a valid signed request and replays it to exhaust rate limits, trust, or spend.
- Nonce uniqueness enforced in Redis via `SET … NX EX 600` (`api/main.py:920-924`).
- Fail-closed when Redis is unavailable — `/verify` returns 503, not a permissive path (`api/main.py:911-930`).

**D4. Anchor worker stuck in tight retry loop.** A persistent RPC/gas/balance failure previously re-submitted every tick until the row silently fell out of the retry query — operators had no signal.
- Exponential backoff with 1-hour cap (`workers/anchor_worker.py:63-80`, Phase 0.6).
- `next_retry_at` gates the retry query (`workers/anchor_worker.py:483-494`).
- `dead_letter` is a terminal state after `MAX_RETRIES` (`workers/anchor_worker.py:628-661`), with `dead_lettered_at` stamped for alerting.
- Schema + indexes: `database/schemas.sql:196-198, 211-212`; migration `database/migrations/004_merkle_proof_dead_letter.sql`.
- Regression: `tests/test_anchor_worker_retries.py`.

**D5. Anchor worker submitting batches with empty wallet.** Worker would burn a transaction slot on a guaranteed-fail submission.
- Balance floor check before submission (`workers/anchor_worker.py:592-600`).

**D6. FastAPI cold-start DB exhaustion.** Burst traffic exhausts the connection pool.
- `asyncpg` pool sized by `Database.create` with `statement_cache_size=0` for pgbouncer compatibility (`workers/anchor_worker.py:341-346`, analogous in `api/database.py`).
- **Residual**: no circuit breaker; pool exhaustion returns 503 via FastAPI. Load-testing deferred to Phase 5.1.

### E — Elevation of privilege

**E1. Cross-org action via admin API.** Attacker with a low-tier org key tries to operate on another org's agent.
- API key → org binding at `api/main.py:157-224`; org-scope check at every handler that takes an `agent_id` (pattern seen at `api/main.py:1103-1107`).
- Tenant RLS policies provide defense-in-depth when the deployment uses the required role and tenant-scoped connection path.
- **Residual**: same as §I2 — production RLS activation requires live verification.

**E2. Dev-mode bypass reaching production.** The dev path at `api/main.py:171-179` accepts any key starting with `dev_` or `test_` as an enterprise-tier Organization Zero.
- Gated on `ENVIRONMENT != "development"` — production deployments must set `ENVIRONMENT=production` or similar.
- **Residual**: a single misconfigured `ENVIRONMENT=development` in prod gives god-mode to any caller. Deferred: hard-block the dev path behind an additional `INNTRIS_ALLOW_DEV_KEYS` opt-in.

**E3. Playground endpoint fabricating proof-eligible audit rows.** `/admin/test-verify` writes audit rows.
- Rows are tagged `test_request: true` in metadata, signature set to the sentinel `b"TEST_REQUEST"` (`api/main.py:1153-1160`).
- Both unanchored-log query paths exclude `metadata.test_request=true` rows (`api/database.py`, `workers/anchor_worker.py`).
- Regression coverage exists in `tests/test_anchor_worker_hardening.py`.

**E4. Hot-wallet key theft.** Attacker exfiltrates `BLOCKCHAIN_PRIVATE_KEY` from the worker environment.
- Key is loaded from env into `eth_account.LocalAccount` at worker start (`workers/anchor_worker.py:214-227`).
- Exposure is limited to what `SUBMITTER_ROLE` authorises on `AnchorRegistry`: anchoring arbitrary Merkle roots. The contract's `DEFAULT_ADMIN_ROLE` can revoke the compromised submitter (`contracts/AnchorRegistry.sol:238-246`) and `PAUSER_ROLE` can pause the contract (`contracts/AnchorRegistry.sol:252-254`).
- Attacker cannot read or alter existing audit logs via the contract — audit-log integrity is enforced off-chain by §T1.
- **Residual**: key is in plain env — KMS/Vault custody is **explicitly deferred** (see §5).

**E5. Unsafe CORS wildcard.** Non-dev deployment set to `ALLOWED_ORIGINS=*` allows credentialed cross-origin calls from attacker pages.
- `allow_credentials` is forced to `False` when origins is `["*"]` (`api/main.py:132-133`). That defangs the cookie-theft path for the wildcard case.
- **Residual**: `ALLOWED_ORIGINS="*"` is still accepted in non-dev (`api/main.py:127-128`). Lockdown to an explicit allow-list is **Phase 2D.2** in the queue.

**E6. Contract reentrancy or role abuse.**
- `anchorBatch` guarded by `nonReentrant` (`contracts/AnchorRegistry.sol:168`).
- `Pausable` circuit breaker for emergency halts (`contracts/AnchorRegistry.sol:28, 252-262`).
- `DEFAULT_ADMIN_ROLE` is bootstrapped to the deployer-supplied `admin` address (`contracts/AnchorRegistry.sol:125-135`). **Residual**: admin role is a single EOA today — multisig/timelock is **Phase 3.3** in the queue.

---

## 4. Residual risks

These are known gaps where a mitigation exists but is incomplete, or where no
in-repo control exists yet. Each should map to a queued or backlog phase.

| # | Risk | Scope | Planned remediation |
|---|------|-------|---------------------|
| R1 | Hot-wallet key theft (Phase 2 roadmap: KMS/Vault) allows arbitrary Merkle-root submission until the submitter role is revoked. | D → E | **Deferred**: KMS/Vault custody. Paging workflow on anomalous submission batches to compensate meanwhile. |
| R2 | Tenant RLS policies exist, but a production deployment using the wrong runtime role or missing migrations can fall back to handler-layer isolation. | D | Require production role, migration, and cross-tenant readback evidence before claiming RLS enforcement. |
| R3 | Smart-contract admin is a single EOA. A compromised admin can grant `SUBMITTER_ROLE` to attacker, or unpause after an emergency. | E | **Phase 3.3** — migrate admin to a Gnosis Safe + timelock. |
| R4 | Forensic-preserving erasure exists, but production activation, backups, external logs, and caches may retain pre-erasure data. | D → B | Verify the erasure procedure per deployment and document backup/cache handling. |
| R5 | Chain reorg handling: a deep Base reorg could invalidate `block_number`/`tx_hash` already surfaced to users as "verified." | D → E | **Deferred** (roadmap) — worker confirmation-depth wait + receipt `integrity_status=pending_anchor` until depth threshold. |
| R6 | Public-register rate limit is fail-open on Redis outage. | B | Backlog — evaluate severity; current model is availability > correctness here. |
| R7 | Dev-key bypass depends entirely on `ENVIRONMENT != "development"`. | D → E | Backlog — add second gate `INNTRIS_ALLOW_DEV_KEYS=1` required to reach the dev path. |
| R9 | CORS still accepts wildcard in non-dev (with credentials forced off). | D | **Phase 2D.2** — lock to explicit allow-list, reject `*` in prod. |
| R10 | `SERVER_SECRET` / `ADMIN_SESSION_SECRET` have no rotation story. | D | Backlog — dual-key verifier window for rotation. |
| R11 | SAST, SCA, and filesystem scanning exist, but several findings are report-only and do not block release. | D | Review current findings and tighten release gates after the baseline is clean. |
| R12 | No load-test evidence for pool exhaustion or burst behaviour. | D | **Phase 5.1** — k6. |

---

## 5. Explicitly deferred

Per the current roadmap, the following are **out of scope** for the
enterprise-readiness track and do not block the phase queue:

- **KMS / Vault for the hot wallet** (relates to R1). Production anchoring still uses a plain env-var private key; acceptance relies on compensating monitoring and the contract-side revoke/pause controls at `contracts/AnchorRegistry.sol:238-262`.
- **Production RLS activation evidence** (relates to R2). Policies and integration tests exist, but each deployment must prove the required migrations, runtime role, and tenant-scoped connection path are active.
- **Base L2 reorg protection** (relates to R5). No confirmation-depth queue; a receipt is marked `verified` as soon as the anchor tx is mined. Base's reorg depth is empirically ~1 block but this is not a guarantee.
- **Docker-backed integration tests, Helm/Terraform, paid vendor items** — not in this repo, not in scope.

---

## 6. Controls summary by phase

| Phase | Primary threats addressed | Key file(s) |
|-------|---------------------------|-------------|
| 0.1 — API key off browser | S5, I1, T5 | `frontend/src/lib/admin/session.ts`, `frontend/src/app/api/admin/session/route.ts`, `frontend/src/__tests__/no-localstorage-api-key.test.ts` |
| 0.2 — Login rate limit fail-closed | D1 | `frontend/src/app/api/admin/session/route.ts:22-75`, `…/__tests__/fail-closed.test.ts` |
| 0.3 — UTC timestamp canonicalization | S2 | `api/crypto.py:88-140`, `api/main.py:92-105`, `tests/test_action_hash_timestamp.py` |
| 0.4 — `sig_version` envelope field | S3 | `api/models.py:117-142`, `api/crypto.py:151-223` |
| 0.5 — README reconciliation | R-doc | `README.md` |
| 0.6 — Dead-letter anchor retries | D4 | `workers/anchor_worker.py:63-80, 478-494, 628-661`, `database/migrations/004_merkle_proof_dead_letter.sql`, `tests/test_anchor_worker_retries.py` |
| 1B.1 — RFC 8785 JCS | S4 | `api/jcs.py`, `api/crypto.py:206-216`, `tests/test_jcs_canonicalization.py`, `tests/fixtures/canonicalization/` |

---

## 7. How to keep this document honest

- Every future phase that adds a control: add its **T#** row above or expand the nearest existing one; cite the new `file:line`.
- Every phase that closes a residual risk: move the row out of §4 into the mitigated STRIDE table, update §5 if it was explicitly deferred.
- If a cited `file:line` moves, fix the citation. Grep for `file:line` reviews are cheap; stale citations are a sign the model is drifting.
- Before relying on any citation here to justify a new feature, **verify the mitigation still exists** — this document is a snapshot, not a live system check.
