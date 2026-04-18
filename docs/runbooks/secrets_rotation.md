# Secrets management and rotation

Phase 3.5 — canonical inventory of every secret the platform reads
from the environment, how it is stored, and how to rotate it without
an outage.

KMS / Vault integration is deliberately out of scope for the current
milestone (the enterprise-readiness plan explicitly defers it). This
runbook assumes the operator holds secrets in a password manager or
cloud-provider secret store and provides them as environment variables
at boot. When KMS is adopted, the rotation procedures below become the
skeleton for the automated versions.

## Inventory

All env vars read by the API, worker, and MCP server:

| Name | Consumer | Type | Rotation frequency | Source of truth |
|------|----------|------|-------------------|-----------------|
| `SERVER_SECRET` | `api/main.py` | HMAC-style secret, ≥32 chars | Quarterly + on suspicion | Secret store |
| `DATABASE_URL` | `api/main.py`, `workers/` | Postgres DSN, includes password | Quarterly + on suspicion | Secret store |
| `REDIS_URL` | `api/main.py` | Redis URL, may include password | Quarterly + on suspicion | Secret store |
| `BLOCKCHAIN_PRIVATE_KEY` | `workers/anchor_worker.py` | EOA private key (anchor submitter) | **Annually or on suspicion — see §4** | Cold storage + hot copy in secret store |
| `BLOCKCHAIN_PROVIDER_URL` | `workers/anchor_worker.py` | RPC URL (may include API key path) | Per-provider rotation cadence | Secret store |
| `ANCHOR_CONTRACT_ADDRESS` | `workers/anchor_worker.py` | Contract address — NOT a secret | On contract redeploy only | Public |
| `BLOCKCHAIN_CHAIN_ID` | `workers/anchor_worker.py` | `8453` for Base mainnet — NOT a secret | On chain migration | Public |
| `ALLOWED_ORIGINS` | `api/main.py` | Comma-separated origins — NOT a secret | On frontend-host change | Public |
| `INNTRIS_PRIVATE_KEY_B64` | `mcp_server/server.py` | Per-agent Ed25519 signing key | Per issuance + on suspicion | Secret store per tenant |
| `INNTRIS_AGENT_ID` | `mcp_server/server.py` | Agent UUID — NOT a secret | Never | Public |
| `JSON_LOGS` / `ENVIRONMENT` | `api/main.py` | Config toggle — NOT a secret | N/A | Config |

Anything marked "NOT a secret" is safe to write into deploy manifests,
Dockerfiles, or commit history — it is included here to make the
boundary explicit. Everything else must live in the secret store.

## General principles

1. **Never rotate at peak traffic.** All rotations below assume the
   API remains up throughout; rotation windows are chosen so the
   in-flight request count is minimal.
2. **Two-key overlap for HMAC and private keys.** When rotating, the
   new and old keys must both be accepted for at least one rate-limit
   window (60s) before the old one is retired, so in-flight requests
   complete without a signature-verification failure spike.
3. **Record the rotation.** Every rotation produces a short write-up
   under `incidents/rotations/YYYY-MM-DD-<key>.md`: who rotated, why,
   old-key SHA-256 prefix (for IOC / forensics), new-key SHA-256
   prefix, list of systems updated.

## 1. `SERVER_SECRET` rotation

Used for any internal HMAC / token derivation in `api/main.py`.

### Procedure
1. Generate: `openssl rand -hex 32`.
2. Add to secret store as `SERVER_SECRET_NEXT`.
3. Update the API deployment to accept both values (this may require
   a code change if the current module only reads one env var — see
   §Implementation note below).
4. Roll the API pods one by one; confirm 200 rate stays flat and
   `signature_failures_total` does not spike.
5. Retire the old value: rename `SERVER_SECRET_NEXT` to
   `SERVER_SECRET`, remove the old value. Roll pods once more.

### Implementation note
The current code reads a single `SERVER_SECRET`. A two-key overlap
requires adding `SERVER_SECRET_PREV` support before the first real
rotation. File this as Phase 3.5a; for now, a brief single-secret
swap at low traffic is acceptable.

## 2. Postgres credentials (`DATABASE_URL`)

### Procedure
1. `CREATE ROLE inntris_api_next LOGIN PASSWORD '<new>';` and grant
   the same role memberships as `inntris_api` (see Phase 1C.1 RLS
   migration).
2. Update the secret store with the new DSN pointing at
   `inntris_api_next`.
3. Roll the API and worker deployments.
4. After 24h with no errors, `DROP ROLE inntris_api_prev` (whatever
   the old role was named).

Never reuse role names. Dropping the old role is the safety net.

### Rollback
Leave the old role in place for 24h. Roll back by pointing
`DATABASE_URL` at the old role's DSN and redeploying.

## 3. Redis credentials (`REDIS_URL`)

Redis ACLs are simpler than Postgres — a single user can hold
multiple passwords during rotation:

1. `ACL SETUSER inntris on >newpass >oldpass ...` so both
   passwords authenticate.
2. Update the secret store with `newpass` in the DSN.
3. Roll deployments.
4. `ACL SETUSER inntris on >newpass ...` to remove `oldpass`.

## 4. Anchor-submitter private key (`BLOCKCHAIN_PRIVATE_KEY`)

Highest-risk secret in the system — controls who can write Merkle
roots on-chain. A compromise does NOT let an attacker mint fake
receipts (those require the per-tenant Ed25519 key and a valid
signed payload), but it does let them anchor garbage roots that
exhaust our gas budget and pollute the registry.

### Procedure
1. Generate a new EOA offline (hardware wallet or `cast wallet new`
   in an air-gapped environment).
2. Fund it from the treasury with enough ETH for ~30 days of anchor
   gas at current rates.
3. From the Safe, **schedule** a queued op on the timelock:
   * `registry.grantRole(SUBMITTER_ROLE, newAddress)`
4. Wait the 48h delay. During the window:
   * Keep the old key online and anchoring normally.
   * Confirm the new address shows up in
     `getRoleMember(SUBMITTER_ROLE, ...)` once executed.
5. Execute the queued grant.
6. Cut worker config over to `BLOCKCHAIN_PRIVATE_KEY` = new key.
   Restart the worker. Confirm first batch anchors cleanly.
7. Schedule `revokeRole(SUBMITTER_ROLE, oldAddress)` through the
   timelock. Wait the delay. Execute.
8. Sweep any leftover ETH from the old address to treasury, then
   wipe the private key from all systems.

### Emergency rotation (suspected compromise)
* **Pause first.** From the pauser hot wallet, call
  `registry.pause()`. This blocks further anchors regardless of
  who holds `SUBMITTER_ROLE`.
* Follow the regular procedure above, but run it in parallel with
  incident response. Unpause only after the revoke executes.
* Document the outage window — any logs submitted during the pause
  remain in `audit_logs` with `merkle_root_id IS NULL` and will be
  batched in the next anchoring window after unpause.

## 5. Per-tenant Ed25519 signing key (`INNTRIS_PRIVATE_KEY_B64`)

Held by the customer's MCP server / agent runtime; we only hold
the public key in `public_orgs.api_key_hash`.

### Procedure (from the tenant's side)
1. Tenant generates a new Ed25519 keypair.
2. Tenant POSTs the new public key to `/admin/keys/rotate` (when
   implemented — see gap below) alongside a signature from the
   current key proving continuity.
3. API stores the new public key hash, flags the old one as
   `rotating`, and accepts both for a 60-minute grace window.
4. Tenant cuts clients over to the new private key.
5. After grace, API rejects signatures from the old key.

### Current gap
The admin key-rotation endpoint is not yet implemented in the
public API. Today, rotation requires a support ticket: the operator
manually updates `public_orgs.api_key_hash` after verifying the
tenant's identity out-of-band (email signed from their registered
domain, or a signed challenge from the existing key).

Phase 3.5b should add this endpoint so rotation is self-service.

## 6. RPC provider URL (`BLOCKCHAIN_PROVIDER_URL`)

Usually a URL with an embedded API key path segment. Treat the URL
itself as a secret. Rotation follows the provider's cadence; our
only requirement is that the new URL resolves to the same
`BLOCKCHAIN_CHAIN_ID`, which the worker now enforces at startup
(Phase 2B `assert_chain_id`).

### Procedure
1. Update secret store with the new URL.
2. Roll the worker. It will fail-fast on any chain-ID mismatch
   before sending a single transaction.
3. Monitor `inntris_anchor_submissions_total{outcome=...}` for one
   batch interval to confirm the new provider is healthy.

## Rotation smoke checklist (post any rotation)

- [ ] `/metrics` returns 200 with `inntris_verify_requests_total` counters incrementing.
- [ ] A signed test request from a production tenant returns `approved`.
- [ ] The next anchor batch confirms on-chain within one `BATCH_INTERVAL_MINUTES`.
- [ ] No spike on `signature_failures_total` or `anchor_submissions_total{outcome="failed"}`.
- [ ] Incident/rotation record filed in `incidents/rotations/`.

## What is NOT in this runbook yet

* **KMS / HSM integration.** Deferred by the current enterprise-
  readiness plan. When adopted, §1 and §4 should be the first two to
  migrate because they are HMAC / private-key shaped already.
* **Automated rotation via scheduler.** Today everything here is
  operator-driven. That is acceptable for quarterly cadence but
  does not scale to per-customer keys — see the gap in §5.
* **Break-glass procedure for full cluster compromise.** Covered at
  a higher level in the enterprise-readiness doc; the runbook-level
  write-up lands with Phase 4+ work.
