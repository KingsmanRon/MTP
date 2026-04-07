# Inntris Infrastructure Context

## Live Services

```
api.inntris.com — LIVE
  Routes to: Railway web service (inntris-api.up.railway.app)
  Port: 8080
  SSL: Cloudflare proxy (managed by Railway)
  Health check: https://api.inntris.com/health → 200 OK
  Confirmed: 2026-03-18
```

## Blockchain Anchoring

```
Chain: Base Mainnet (chain ID 8453)
RPC: https://base-rpc.publicnode.com (PublicNode — required, Base official RPC blocks Railway IPs)
Contract: AnchorRegistry at 0x0600eA15802c8d2EA429371b2EB0aacCFe321480
Deployer/Admin: 0x2300Fc9eff12ff5ca39621259B121fa3417773bf
Sepolia (historical): chain ID 84532, contract 0x0600ea15802c8d2ea429371b2eb0aaccfe321480
  — Old receipts still verify against sepolia.basescan.org via chain-aware routing
```

## Receipt schema

```
v2 — current
  policy_hash is part of the canonical JSON used to compute the receipt
  fingerprint for any policy-evaluated decision. The presence of a non-null
  policy_hash on the audit row marks the public verification record as v2.
  Receipts without a policy bound are still surfaced as v1 and the verify
  page renders the policy hash check as NOT APPLICABLE.
v1 — legacy
  Pre-cutover receipts. The fingerprint field set is identical to v2;
  the schema bump records the *guarantee* that a v2 receipt binds a policy.
```

## Canonical homepage demo receipts

```
CANONICAL_PASS_ID    = 659c20b1-d1b1-4a4e-9676-4d04e222ae58  (Sepolia-era — TODO: regenerate on mainnet under v2)
CANONICAL_RECEIPT_ID = 62afc74f-9e57-4748-82e3-10f1bfe07b9f  (Sepolia-era — TODO: regenerate on mainnet under v2)
```

The fresh-receipt regeneration step (PR1 §1.3 / §1.5) requires production
database access plus the anchor worker's signing key and Base mainnet RPC
credentials, none of which are present in the development sandbox. This step
must be run from an environment with those secrets before the canonical IDs
in `frontend/src/app/page.tsx` can be swapped.

## Prior PENDING integrity state — root cause

The legacy verify page treated `not_applicable` as `not_included` in the
policy-hash slot and rendered the literal string `Policy hash (SHA-256): Not
included`. The receipt fingerprint already included `policy_hash` in the
canonical JSON server-side, but the frontend display layer never expressed a
non-applicable state distinct from a missing-but-required state. PR1 fixes
this by introducing the explicit `not_applicable` proof check and bumping
the schema version to v2 for receipts whose canonical JSON is asserted to
bind a policy hash.

