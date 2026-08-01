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

Defined in one place: `frontend/src/lib/canonical-receipts.ts`. Every frontend
surface imports from there, so regenerating the pair is a one-line change
rather than a grep across the repo.

```
CANONICAL_RECEIPT_IDS = [
  975151ca-834e-4919-9ef6-d9e80803e5f1,   # BLOCK
  65cc4da3-3774-495d-9748-865a7ff98d40,   # PASS
]
```

The IDs are stored without verdict labels in code on purpose. Which receipt
carries which verdict is a property of the artifact, not of the constant — the
homepage reads the verdict off each fetched record and lays itself out from
that, so a regenerated pair cannot leave the page asserting the wrong thing.
The labels above are for humans reading this file and should be re-checked
against the live records, not trusted from here.

Superseded pair (pre-2026-08-01), retained because the dated audit records and
the canonicalization test vectors still reference them:

```
d8dd0902-4750-42d2-9516-92bf6362e815   # PASS
3030c27c-87c4-4464-b4af-605fbe638e0e   # BLOCK
Demo policy hash = b5e687b5bd9878f561f8050e994fbd8632fec823503fa4bd8c047a3e3b14f686
Anchored         = Base mainnet (chain 8453), block 44,401,999,
                   tx 0x3f86eea4328d00fbd968181f5f188aee95dea65ea690273f229534edd68ecd84
```

Anchor details for the current pair are not recorded here — read them off the
live receipts rather than copying figures that belong to the superseded ones.

## Prior PENDING integrity state — root cause

The legacy verify page treated `not_applicable` as `not_included` in the
policy-hash slot and rendered the literal string `Policy hash (SHA-256): Not
included`. The receipt fingerprint already included `policy_hash` in the
canonical JSON server-side, but the frontend display layer never expressed a
non-applicable state distinct from a missing-but-required state. PR1 fixes
this by introducing the explicit `not_applicable` proof check and bumping
the schema version to v2 for receipts whose canonical JSON is asserted to
bind a policy hash.

