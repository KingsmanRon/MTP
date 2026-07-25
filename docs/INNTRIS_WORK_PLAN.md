# Inntris — Implementation Plan

Working plan derived from the *Inntris Technical Work Specification* handoff, reconciled
against the repository as it actually stands at `7e0bf71`.

This document is planning only. No behaviour has been changed. Every claim below about
current state was checked against the code and, where runnable, executed.

---

## 0. Baseline established by running the repo

Facts, not estimates. Produced in this session on branch
`claude/inntris-implementation-plan-vnt5h1`.

| Measurement | Result |
|---|---|
| Python suite (`pytest -q`, no DB/Redis) | **426 passed, 15 skipped**, 5.6s |
| Skipped cases | Exactly 15 — the set Block G1 names |
| Solidity test functions | **19** (13 in `AnchorRegistry.t.sol`, 6 in `AnchorRegistryTimelock.t.sol`) |
| `/metrics` served through a route | **HTTP 500 — reproduced** (root cause below) |
| `/metrics` handler called directly | 200, valid exposition format |

### Environment bootstrap (do this first, every session)

The container ships Python 3.11 as `python3`; `pyproject.toml` requires `>=3.12`, so a
plain `pip install -e '.[dev]'` fails with a version error. Python 3.12 and `uv` are both
present. Working sequence:

```bash
uv venv --python /usr/bin/python3.12 .venv
uv pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

Not installed and needed for Block A6 / B2.5: **Foundry** (`forge`), plus `lib/forge-std`
and `lib/openzeppelin-contracts`. CI installs these via `foundry-rs/foundry-toolchain`;
locally they need `foundryup` + `forge install`.

Recommendation: commit this as a `SessionStart` hook so the toolchain is never
re-derived. It is the single highest-leverage 20 minutes in this plan — A5, A6, B2.5,
B3.3, and all of Block G are blocked on a working toolchain.

---

## 1. Where the spec and the repository disagree

The handoff was written from a code review. Five of its assumptions no longer match the
tree. Reading these before starting saves a day of chasing things that aren't there.

**A5 — "297 tests" is not in this repository.** `grep -rn "297"` across all markdown,
Python, TypeScript, and JSON returns no test-count claim. `PITCH_DECK.md` carries no test
figure; neither does `README.md` or `frontend/src/`. Either it was already removed, or it
lives only in the published deck and live site — both outside this repo. **Action:** treat
A5 as an off-repo copy task and confirm with the founder where the claim is published. The
in-repo half is instead *adding* a dated figure, for which the number is now known: 426
passed / 15 skipped (Python) + 19 (Solidity), dated at time of run.

**A3 — `demo_recording/` does not exist.** No such directory, and the demo fingerprint
`9d8f82b0…4790` appears nowhere in the tree. **Action:** confirm whether the directory was
already removed or lives in a sibling repo. If it is gone, A3 is closed; say so in the
transcript rather than inventing a rename.

**A7 — the latency claim is real and locatable.** `frontend/src/app/page.tsx:215`:
`{ value: "<100ms", label: "Verification latency" }`. Single occurrence, single-line fix.

**C3 — envelope encryption already exists in this repo.** The spec says to port an
AES-256-GCM pattern "from a sibling project". It is already here, in `api/webhooks.py:424`
–`467`: `_webhook_encryption_key` derives a KEK from the server secret via domain-separated
SHA-256; `encrypt_webhook_signing_secret` writes `prefix ‖ nonce ‖ ciphertext` under
`AESGCM`. Reuse this module directly — no new dependency, no new pattern, and the
constant-time/prefix/version conventions are already reviewed.

**G1 — CI already provides Postgres and Redis.** `.github/workflows/ci.yml` runs
`postgres:16.14` and `redis:7.4.7` services with `INNTRIS_DB_INTEGRATION=1` and
`INNTRIS_REDIS_INTEGRATION=1` exported. So the 15 cases that skip locally very likely
already run in CI. **Action:** G1's real work is *verifying* that (read a CI run's skip
count), not wiring credentials. The residual is `test_production_readback.py`, which needs
a live production database and cannot reach zero skips in ordinary CI without an explicit
decision.

---

## 2. Root causes worth knowing before you start

### A4 — `/metrics` returns 500: found it

`api/observability.py:245` declares:

```python
async def metrics_endpoint() -> Response:
```

`api/main.py:387` mounts it:

```python
app.add_route("/metrics", metrics_endpoint, methods=["GET"])
```

Starlette's `add_route` wraps a plain function with `request_response()`, which invokes it
as `func(request)`. The handler accepts zero positional arguments, so every live scrape
raises `TypeError` and the exception handler turns it into a 500.

`tests/test_observability.py` passes because it `await`s `metrics_endpoint()` **directly**,
bypassing the router. That is the coverage gap that let this ship.

Fix: `async def metrics_endpoint(_request: Request) -> Response`, plus a regression test
that goes through a mounted route (`TestClient(app).get("/metrics")`), not the bare
function. Size: **S**. This is the cheapest item in the entire specification.

### B2.4 — the anchored leaf is the `action_hash`, unmodified

`workers/anchor_worker.py:895`:

```python
leaf_hashes = [row["action_hash"] for row in logs]
```

The leaf *is* the action hash. So adding `registered_policy_hash` to the `compute_action_hash`
preimage (`api/crypto.py:227`) re-commits the anchored leaf as a side effect — B2.3 and
B2.4 are **one change, not two**. The AnchorRegistry needs no modification, confirming the
spec's constraint is satisfiable.

Two consequences the spec does not spell out:

1. The **agent** must know `registered_policy_hash` before signing. The GitHub Action
   already computes and submits `policy_hash` (`api/agent_client.py:63`), but the MCP
   adapter and the reference client do not. They need to fetch it, or the server needs to
   publish it on a pre-flight endpoint.
2. Most action types (`financial_transaction`, `email_send`, …) have **no registered
   policy** — `_check_policy_binding` returns APPROVED early for anything outside
   `CI_GUARD_ACTIONS` (`api/policy.py:401`). The preimage needs a defined encoding for
   "no registered policy" (JSON `null` under JCS, not an empty string, not an omitted key)
   or Python and Solidity will diverge on exactly the common case.

### B2.1 — the rename has a wider blast radius than it looks

`_effective_policy_hash` (`api/main.py:587`) is the derived hash. Renaming it to
`effective_controls_hash` is trivial. What is not trivial is that the same value flows
into the **receipt fingerprint**, whose field set is pinned in three places that must agree
byte-for-byte:

- `api/main.py:1377` — the server's `fingerprint_payload`, carrying the comment
  *"DO NOT MODIFY FIELD SET OR ORDER — MUST MATCH FRONTEND EXACTLY"*
- `evidence_pack/pack_contents/verify_pack.py:316` — `recompute_fingerprint`, the
  seven-field contract
- the frontend's recomputation, which re-derives it from wire JSON

Change the key name and every previously issued fingerprint changes. With zero customers
that is free — which is precisely why it belongs in the Block B release and nowhere else.
`docs/RECEIPT_CANONICALIZATION.md` and `verify_publication.lock` both move with it.

### Invariant 2 is broader than the envelope

B3.2 says "one canonicalisation path remains in the codebase." Deleting envelope v1/v2
does not achieve that. `json.dumps(sort_keys=True, separators=(",", ":"))` also produces
signed or attested objects in at least four other places:

| Site | Object |
|---|---|
| `api/main.py:1386` | receipt fingerprint |
| `api/main.py:599` | effective controls hash |
| `api/policy.py:56` | `canonical_policy_hash` (mirrored in `github-action/index.js`) |
| `api/crypto.py:339` | approval token body (HMAC input) |
| `api/main.py:2227` | `token_consumed` consumption hash |

The approval token is server-to-server HMAC and arguably exempt. The other four are
cross-language contracts and are not. **Decision needed:** does B3.2 mean "one *envelope*
canonicalisation" or "one canonicalisation, full stop"? The second reading is the right
one for Invariant 2, costs roughly 2× B3.2 as scoped, and is far cheaper now than after a
partner signs. Recommend the second, executed inside the same Block B release.

### E2 requires receipt fields that do not exist yet

Strict mode is specified to make nonce uniqueness and token-consumption evidence
mandatory. Neither is currently on a public receipt: `PublicVerificationRecord`
(`api/models.py:521`) exposes no `nonce`, and consumption lives in a separate audit row
(`action_type="token_consumed"`, `api/main.py:2233`) with no export path into a pack.

So E2 depends on schema additions that belong in Block B, not Block E:
- add `nonce` to the public receipt (it is already stored; it is simply not surfaced)
- give the pack builder a way to include consumption receipts alongside the approval they
  consume, so a verifier can pair them

Left as-is, E2 can only be implemented as "fail if absent", which would fail every pack.
**Fold these two schema additions into B1.**

### Cross-repo publication is out of reach this session

B1.7 (publish the manifest v2 schema to `inntris-verify`) and E4 (pin verifier version and
methodology hash in `KEYS.md`) both write to a repository that is **not in this session's
GitHub scope** — only `kingsmanron/mtp` is granted.

There is a usable half-measure already built. `verify_publication.lock` pins the SHA-256 of
`verify_pack.py` and `METHODOLOGY.md`; `frontend/public/.well-known/inntris-keys.txt`
mirrors `KEYS.md`; `scripts/check_verify_publication.py` runs in CI and fails on drift.
**Plan:** prepare the artifacts and update the lock and the `.well-known` mirror in this
repo; hand the `inntris-verify` push to the founder or request scope for that repo.

`inntris-verify` has since been audited from a parallel session. Its findings, and the
resulting changes to B1.3, B1.4, B1.7, E2 and E4, are consolidated in **§12**. Read that
section before designing any manifest v2 key or scope field.

---

## 3. Block A — Truth-up

No dependencies. Do first. Everything here is small; the block is a day, not a week.

| # | Work | Files | Size |
|---|---|---|---|
| **A1** | Build a pack signed with `ipk-2026-01`. The key is already published at `frontend/public/.well-known/inntris-keys.txt:2` (`a2fce5d5…0732`, fingerprint `089c7611…151c`). Needs the private seed, which is a founder-held artifact. Run `scripts/build_evidence_pack.py build` with real receipts. | `scripts/build_evidence_pack.py` | S (blocked on key access) |
| **A2** | `docs/VERIFICATION_TRANSCRIPT.md` — manifest SHA-256, key id, fingerprint, verifier commit, UTC timestamp, verbatim stdout. Reproducible by a stranger from the file alone. | new | S |
| **A3** | **Verify the premise first** — `demo_recording/` is not in the tree. If already removed, record that; do not invent a rename. | — | S |
| **A4** | Add the `request` parameter to `metrics_endpoint`; add a route-level regression test. Root cause in §2. | `api/observability.py:245`, `tests/test_observability.py` | S |
| **A5** | In-repo: add the dated figure (426 passed / 15 skipped Python, 19 Solidity, dated). Off-repo: locate and correct the published "297" claim. | `README.md`, deck, site | S |
| **A6** | `foundryup`; `forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts`; `forge test`. All 19 functions. Feed the result into A5's figure. | — | S |
| **A7** | Delete `{ value: "<100ms", label: "Verification latency" }`. Replace with a claim that has a measurement behind it, or drop the tile to three items until D4 lands. | `frontend/src/app/page.tsx:215` | S |
| **A8** | `payload JSONB NOT NULL, -- Full action details (encrypted sensitive fields)` is false; the request path inserts plaintext. Correct to state field-level encryption covers webhook secrets only. | `database/schemas.sql:149` | S |

**Sequencing note:** A4, A7, A8 are independent one-liners and can go in a single commit.
A1 gates A2; A6 gates the Solidity half of A5. A1 is the only item that can stall — it
needs the production signing seed, which per Block F5 exists as a protected local copy
with an untested restore path. Confirm you can load it before scheduling the rest.

---

## 4. Block B — Breaking changes (one release, no partial ship)

The largest block. Everything here changes a signed or hashed byte sequence, so it ships
atomically. Recommend a single long-lived integration branch merged once, with the format
break recorded in a `CHANGELOG` entry.

### B1 — Manifest v2

`evidence_pack/manifest.py` currently emits `format_version: "1.0"` with `format`,
`pack_name`, `snapshot_time`, `hash_scheme`, `files`, `custody_event_count`, and optional
`inntris_commit` / `anchor` / `notes`.

New fields, all inside the signed manifest and therefore covered by the Ed25519 signature:

| Field | Source | Note |
|---|---|---|
| `schema_version` | literal `2` | verifier branches on it; v1 path retained (B1.1) |
| `tenant_id` | organisation context | **not currently plumbed** — see below |
| `signer_scope` | `KEYS.md` col 5 — **already exists** (`Evidence pack manifests`); see §12 | declares what the key may sign |
| `key_id`, `key_version` | key registry | `ipk-2026-01` is an id; version is new. **Do not parse `-01` as a month** — §12 |
| `registered_policy_version`, `registered_policy_hash` | `agent_policies` (migration 010) | the *registered* document, not derived controls |

**B1.2 has a plumbing gap.** `scripts/build_evidence_pack.py` is CLI-driven from a ledger
plus a receipts directory. Receipts carry `organization_name` but **no `org_id`**
(`api/models.py:537`). So `tenant_id` must come from either a new required `--tenant-id`
argument or a new receipt field. A new receipt field is better — it makes the binding
derivable from evidence rather than asserted by whoever runs the build. Add `org_id` to
`PublicVerificationRecord` in the same release.

**B1.3 / B1.4 — the registry has two incompatible published shapes.** `KEYS.md` and the
`.well-known` mirror carry *different field sets*, neither a superset of the other, and the
verifier reads neither. This is the single most consequential finding from the
`inntris-verify` audit; the full analysis and the resulting design constraint are in
**§12.1**. Design these two fields against that section, not against either file alone.

Interim for `key_version`: emit `1` for `ipk-2026-01` and note in the published schema that
the field's authority relocates to the F1 registry. **Do not derive the version by parsing
`ipk-2026-01` as a date** — the `-01` is a sequence number and its effective date is
2026-07-20.

**B1.8 determinism** is already protected: `evidence_pack/deterministic_zip.py` pins entry
order, timestamps and compression; the manifest sorts files by UTF-8 byte order
(`manifest.py:54`); `sign_manifest` uses Ed25519, which is deterministic. Adding fields
does not threaten this. Keep the existing byte-identity test in `tests/test_evidence_pack.py`
and extend it to v2.

**Additions folded in from Block E** (see §2): add `nonce` to the public receipt, and give
the builder a path for consumption receipts.

**B1.7 is a six-location coordinated change, not a two-location one.** Both repos enforce
exact-set equality on their pinned-file lists, so publishing the manifest v2 schema as a
third pinned artifact touches six places. Enumerated in **§12.2**.

**⚠️ Generate the v1 regression fixture before starting B1.** It does not exist in either
repo and cannot be honestly created after the format break. See **§12.4** — this is the one
item on the whole plan with a hard deadline.

Size: **L**.

### B2 — Policy binding

| # | Work | Note |
|---|---|---|
| B2.1 | Rename derived hash → `effective_controls_hash` | Wide blast radius — see §2. Touches `api/main.py`, `api/models.py`, the DB column, the fingerprint contract in three places, the frontend, and `verify_pack.py`. |
| B2.2 | Expose `effective_controls_hash`, `registered_policy_version`, `registered_policy_hash` on public receipts | `agent_policies.version` already exists (migration 010:24). Needs joining into the receipt query at `api/main.py:1481`. |
| B2.3 + B2.4 | Add `registered_policy_hash` to the `compute_action_hash` preimage | **One change** — the leaf is the action hash. Define the null encoding for unregistered action types. `api/crypto.py:227` |
| B2.5 | Solidity parity + tampered-leaf rejection | The contract does not change; the tests' fixture leaves do. `test/contracts/AnchorRegistry.t.sol` |
| B2.6 | Binding test at both layers | Extend `tests/test_policy_binding.py`. Substituting a policy version must fail the agent signature *and* the anchored leaf. |

Size: **L**. B2.1 alone is a day of careful mechanical work with three canonical-form
contracts to keep in lockstep.

### B3 — Envelope v3

`api/crypto.py:153`–`156` defines `SIG_VERSION_LEGACY=1`, `CURRENT=2`, `JCS=3`, with
`DEFAULT = CURRENT`.

- **B3.1** — flip `SIG_VERSION_DEFAULT` to `SIG_VERSION_JCS`. Trivial line; the work is
  the fan-out.
- **B3.2** — delete v1 and v2. Consumers to update: `api/crypto.py`, `api/agent_client.py`,
  `api/models.py`, `mcp_server/server.py`, `github-action/index.js` **and its committed
  `dist/` bundle** (CI fails on a stale bundle), `scripts/usecase_poc_demo.py`,
  `loadtests/signature_storm.js`, and the tests that pin each version
  (`test_action_hash_timestamp.py`, `test_verify_token.py`, `test_verify_debug.py`,
  `test_jcs_canonicalization.py`). Resolve the Invariant-2 scope question from §2 first.
- **B3.3** — cross-language conformance. **Already substantially built:**
  `tests/fixtures/canonicalization/jcs_vectors.json` is the contract and
  `tests/fixtures/canonicalization/verify_jcs_node.js` is the Node implementation. The
  work is wiring the Node runner into CI as a gating job, not writing it from scratch.

Size: **M**.

---

## 5. Block C — Data layer

Runs parallel to B except where it touches the manifest. C5 does touch pack contents;
schedule it inside the B release or immediately after.

| # | Work | Note | Size |
|---|---|---|---|
| **C1** | EU regions for Supabase, Railway, Vercel | **Infrastructure, not code.** Needs console access this session does not have. `DEPLOYMENT_GUIDE.md:70` currently recommends `us-east-1` — update it as part of the change. With zero data, a fresh EU project beats a migration; recommend fresh, and record which was taken. | M |
| **C2** | Data residency statement | Depends on C1. Publish under `docs/trust/`, alongside `SECURITY_OVERVIEW.md`. | S |
| **C3** | Envelope-encrypt `audit_logs.payload` | Reuse `api/webhooks.py:424`–`467` (§1). New migration; encrypt on the `/verify` insert path; decrypt on the admin read path. **Interaction with C7:** the GDPR erasure function writes a plaintext JSON tombstone and migration 012 validates its exact shape — encrypting the column means the tombstone guard must be reworked or the tombstone must remain plaintext-distinguishable. | L |
| **C4** | Split `request_ip` / `request_user_agent` into their own table | `database/schemas.sql:155`. Note the immutability trigger (`schemas.sql:345`) includes both columns in its comparison tuple — moving them changes the trigger. Erasure already NULLs them (`api/erasure.py`); that path moves too. | M |
| **C5** | Redaction filter on operator-supplied evidence | New. Hooks into `EvidencePackBuilder.add_evidence` (`evidence_pack/builder.py:82`). Must run **before** the custody hash is taken, or ingest and retrieval hashes will disagree and every build will abort. | M |
| **C6** | Per-tenant retention windows | New table + worker. Cryptographic material and payload data get separate policies. | M |
| **C7** | Complete the erasure procedure | Tombstoning exists across migrations 006/012/016 and `api/erasure.py`. Missing: backups, logs, previously exported packs. | M |
| **C8** | Test that erasure preserves verifiability | The design contract already promises `action_hash`, `signature`, `merkle_*` are never touched (`api/erasure.py:11`). The test is: erase, rebuild the pack, run `verify_pack.py`, assert exit 0 and no personal data. | S |

---

## 6. Block D — Enforcement

**D1 is the highest-integrity item in the entire specification.** Everything else closes a
gap between claim and code; this one closes a gap between claim and *behaviour*.

Confirmed current state: `mcp_server/server.py:126` posts to `/verify`, and on 200 the
handler returns (`server.py:395`–`404`):

```
Approval Token: {result.get('approval_token', 'N/A')[:50]}...
...
You may proceed with the action.
```

The adapter never calls `/verify-token`. It hands the model a token — truncated to 50
characters, so not even usable downstream — and tells it to proceed. That path is advisory,
which directly contradicts the pre-execution enforcement claim.

`docs/EXECUTION_BINDING.md` already documents the correct rule in detail (re-present with
`consume: true`, fail closed on any non-`valid:true`). The adapter simply does not
implement its own documentation.

| # | Work | Size |
|---|---|---|
| **D1** | Either the adapter owns the side effect and calls `/verify-token` with `consume: true` itself, or it refuses to return a token at all. Timeout, transport failure, non-2xx, and `valid:false` all block. Recommend **refuse to return a token** — the MCP adapter does not own the downstream effect, so owning it is a fiction. | M |
| **D2** | Same audit for `github-action/index.js` and the reference signing client (`api/agent_client.py`). Neither currently references `verify-token`. | M |
| **D3** | `docs/EXECUTION_BINDING.md` exists and is good, but leads with the rule, not the limitation. Restructure so "Inntris is an API enforcement primitive, not a transparent proxy, and cannot prevent an agent reaching the underlying API by another path" is the **first** thing on the page. | S |
| **D4** | Dated load test. `loadtests/baseline.js` and `loadtests/signature_storm.js` are k6 scripts already in place. Needs a deployed target. Produces p50/p95/p99, volume, error rate, cold start, dependency-failure behaviour. Feeds A7's replacement claim. Depends: A4. | M |

---

## 7. Block E — Verifier

Current honest-but-misleading behaviour, `evidence_pack/pack_contents/verify_pack.py:626`:

```python
print("RESULT: all attempted checks passed")
```

`Reporter` (line 405) counts failures only — `skip()` and `warn()` print and are then
forgotten. Absent `--pubkey`, the signature check degrades to a `warn` (line 483) and the
run still exits 0.

| # | Work | Note |
|---|---|---|
| **E1** | `--strict` flag; any skipped required check becomes a failure | Reporter needs a skip **counter** and a required/optional classification per check. |
| **E2** | Required under strict: pinned pubkey, per-receipt signature material, proof reconstruction for every anchored receipt, `registered_policy_version` + `registered_policy_hash`, nonce uniqueness, consumption evidence | **Blocked on B1 schema additions** — nonce and consumption evidence are not on receipts today (§2). Also a **scope expansion**: a *registry* pin is more than a key pin — see below. |
| **E3** | `PASSED (3 of 9 checks skipped)` in every non-strict success | Falls out of E1's counter. |
| **E4** | Pin verifier version + methodology hash | **There is no verifier version to pin** — it has to be invented first. See §12.3. The methodology half is already free. |

**E2's "registry-pinned public key" is larger than it reads.** `--pubkey` takes 32 raw
bytes and nothing else — `verify_pack.py` never reads `key_id`, never reads `KEYS.md`, and
has no concept of key identity at all, only key *bytes*. Scope, version, status and
effective dates live in a registry the verifier has never seen. So "registry-pinned"
requires giving the verifier a registry input.

Recommended: add `--registry <path to KEYS.md>` as a sibling to `--pubkey` — both supplied
by the operator out-of-band, no network, so **Invariant 6 holds unchanged** — and make it
mandatory under `--strict`. The alternative, baking a registry copy into `verify_pack.py`,
makes every key rotation trigger the full six-location republication cascade (§12.2).

Note the discipline this repo already enforces: any edit to `verify_pack.py` changes its
SHA-256, which fails `check_verify_publication.py` in CI until the lock, the
`inntris-verify` repo, and the `.well-known` mirror are all updated together. Budget for
that update on **every** Block E commit — and see §12.5 for two CI contracts in
`inntris-verify` that a reporting-layer rewrite will break if you are not watching for
them.

Size: **M**.

---

## 8. Block F — Key architecture (blocked)

Do not start. F1–F5 are gated on the founder's tenant signing model decision, and that
decision changes the shape of B1.2, B1.3, and B1.4.

The framing in the spec is correct and worth restating: per-tenant keys held by Inntris
reduce blast radius but do not deliver independence, because Inntris still holds the key.
Only an external co-signer — QTSP seal or customer countersignature — makes the evidence
independent of Inntris.

**Interim measure for Block B**: emit `key_id: "ipk-2026-01"` and `key_version: 1` from the
`.well-known` registry, and note in the published manifest v2 schema that the field's
authority relocates to the F1 registry. This unblocks B1.4 without pre-empting the
decision.

**F5 deserves a flag now, independent of the decision.** The production seed exists as a
protected local copy with an encrypted password-manager backup, and restoration has never
been tested. That is a single point of failure on the only key that can sign an Inntris
evidence pack — and A1 cannot even start without it. Test the restore before it is needed,
regardless of what happens with HSM selection.

---

## 9. Block G — Assurance

**G1 is largely already done** (§1). CI provides both services with the integration flags
set. Real work:

1. Read an actual CI run and record the true skip count.
2. Decide what to do about `test_production_readback.py`, which needs a live production
   database. "Zero skips" is not reachable for it in ordinary CI without either a
   dedicated environment or an explicit carve-out.
3. Add a CI assertion that the skip count is zero (or an agreed number), so a future skip
   cannot creep in silently. The spec's own reasoning applies: a skipped isolation test is
   worse than an absent one, because it looks like coverage.

G2 (backup/restore with RTO/RPO and a dated restoration test) and G3 (key compromise
drill, depends F2) are procedural and unblocked by code.

---

## 10. Recommended execution order

0. **⚠️ Generate and commit the v1 regression fixture pack** (§12.4). Hard deadline: it must
   exist before any Block B code lands, and it cannot be honestly produced afterwards.
   Independent of every open decision — start it today.
1. **Session bootstrap** — venv + Foundry, ideally as a `SessionStart` hook. Blocks A5, A6, B2.5, B3.3, G.
2. **Block A**, minus A1/A2 if the signing seed is not yet accessible. A4/A7/A8 are one commit.
   Add A9: reconcile the two registry schemas (§12.1) — it is a truth-up item.
3. **G1 verification** — read a CI run, confirm the skip count. Needs no decisions.
4. **Founder decision: tenant signing model.** Gates B1.2–B1.4 and all of F.
5. **Block B as one release.** Suggested internal order: B1 schema (including the nonce and consumption additions folded in from E) → B2.1 rename → B2.3/B2.4 preimage → B2.5 Solidity → B3 envelope → B1.7 schema publication.
6. **Block C in parallel**, except C5, which lands with B. C1 needs infrastructure access.
7. **Block D**, then **Block E** (E2 needs both B and D).
8. **Block F** once the partner decision lands.
9. **G2, G3** ongoing.

**Minimum credible package for a first design partner: A + B + E.** On this plan's sizing
that is roughly 3–4 weeks of focused work, with the tenant signing decision on the critical
path from day one — it gates B1.2–B1.4, which sit at the front of the Block B release.

---

## 11. Decisions needed before implementation starts

| # | Question | Blocks | Why it can't be defaulted |
|---|---|---|---|
| 1 | Tenant signing model | B1.2–B1.4, all of F | Spec explicitly gates on it |
| 2 | Invariant 2 scope: one *envelope* canonicalisation, or one canonicalisation full stop? | B3.2 | Roughly 2× the work. Recommend the strict reading — it is free now and expensive later. |
| 3 | Is the "297 tests" claim in the published deck/site rather than the repo? | A5 | It is not in this repository; the fix has no target without this |
| 4 | Was `demo_recording/` already removed, or does it live elsewhere? | A3 | Same — no target in this tree |
| 5 | ~~Scope on `inntris-verify`~~ — **resolved.** Repo confirmed public at `Inntris/inntris-verify`; a parallel session holds push (not admin). Coordinated changes need MTP added *there*, or split by repo. | B1.7, E4 | — |
| 6 | Is the `ipk-2026-01` private seed accessible now? | A1, and therefore A2 | A1 is the first item in the plan and cannot start without it |
| 7 | `test_production_readback.py` under G1's "zero skips" — carve-out or dedicated environment? | G1 | Needs a live production database |
| 8 | Registry reconciliation: extend the mirror to carry `scope`, extend `KEYS.md` to carry `status`, or define an explicit projection between them? | B1.3, E2, A9 | §12.1 — neither file is a superset of the other, so there is no default |
| 9 | Is `https://inntris.com/.well-known/inntris-keys.txt` serving current bytes? | A-block truth-up | **Still open** — network-blocked in *both* sessions (403 at the agent proxy). Needs an unrestricted machine or an allowlist. |

Items 3, 4, and 6 are quick confirmations. Items 1, 2, and 8 are real decisions on the
critical path. Item 9 needs an environment change, not a decision.

---

## 12. The cross-repo publication contract

Audited from a parallel session with read access to `Inntris/inntris-verify`. Everything
below was verified against that repo's files, CI, and git history — not inferred.

**Location confirmed.** `https://github.com/Inntris/inntris-verify`, public, Apache-2.0,
default branch `main`. Owner is a **User account, not an Organization**, which limits
branch protection and team access — relevant if Block B wants enforced review on
republication commits.

**Integrity confirmed clean.** `sha256sum -c SHA256SUMS` passes there, and both digests
match this repo's `verify_publication.lock` exactly
(`332928c8…a366` / `4ca88e16…801`). The key fingerprint recomputes correctly. **No Block A
truth-up item from drift** — the two repos agree today.

But they agree *by coincidence of discipline, not by construction*: this repo's CI validates
local files against the local lock, and that repo's CI validates local files against the
local `SHA256SUMS`. Both stay green while drifting from each other. Closure is cheap and
one-directional — since `inntris-verify` is public, add a job to **this** repo's CI that
fetches raw `SHA256SUMS` and diffs it against the lock. No secrets, no new scope.

⚠️ One ordering caveat: the documented procedure updates this repo's lock (step 2) *before*
copying into `inntris-verify` (step 3), so a hard-failing fetch job would leave an MTP pull
request red between those steps and block the merge. Run it as a **hard fail on `push` to
main, non-blocking on `pull_request`**.

### 12.1 The registry has two incompatible published shapes

`KEYS.md` is the canonical registry. `frontend/public/.well-known/inntris-keys.txt` is
described as its mirror. They carry **different field sets, neither a superset of the
other**:

| Field | `KEYS.md` (canonical) | `.well-known` mirror |
|---|---|---|
| key_id, public key, fingerprint, effective date | ✓ | ✓ |
| **scope** | ✓ column 5 — `Evidence pack manifests` | ✗ absent |
| **status** | ✗ structural (`## Active` / `## Retired` heading) | ✓ field 5 — `active\|retired` |

Both sides pin their own shape by regex and reject anything else
(`scripts/check_verify_publication.py:36` here; `.github/workflows/verify.yml` there).

Three consequences:

**a. `KEYS.md`'s own guarantee is unenforceable by construction.** It states: *"This file is
the single canonical registry. Copies elsewhere (inntris.com) mirror it; on any
discrepancy, treat verification as failed."* The mirror is not a copy — different schema,
not diffable. No automated discrepancy check exists, or can exist, until the shapes are
reconciled. **This is a Block A truth-up item** (tracked as A9): either correct the wording
or make the claim true.

**b. `signer_scope` (B1.3) already has a canonical source, and the mirror drops it.**
`KEYS.md` column 5 *is* the scope. But under Invariant 6 the verifier is offline and cannot
fetch it — so a manifest asserting `signer_scope` has nothing to check against. This drives
the `--registry` recommendation in §7.

**c. Both representations break at first rotation, differently.** The mirror carries
`status` but has no field for a retirement date; `KEYS.md`'s `## Retired` table is literally
`(none)` with no header row, while the rotation policy promises retired rows carry a
retirement date — a sixth column that no regex on either side accepts. Pin both shapes now;
doing it mid-incident during a real rotation is materially worse.

**Also relevant to B1.4:** `verify_pack.py` contains **zero references to `key_id`,
`KEYS.md`, or any version**. It does a raw byte comparison of `--pubkey` against the
embedded `public_key_b64`. `KEYS.md` is a human-and-CI artifact today, with no machine
consumer. Adding `key_id` / `key_version` to the manifest gives the verifier its first
awareness of key *identity* as distinct from key *bytes*.

**Trap:** `ipk-2026-01` has effective date **2026-07-20**. The `-01` is a sequence number,
not a month. Anything parsing it as January 2026 is silently wrong. State this explicitly
in the published manifest v2 schema.

### 12.2 B1.7 touches six locations, not two

Both repos enforce **exact-set equality** on their pinned-file lists — this repo's
`load_pins` raises on any mismatch against `PINNED_PATHS`, and `inntris-verify`'s CI raises
on `set(pins) != expected_files`. Neither is open-ended. Publishing the manifest v2 schema
as a third pinned artifact therefore requires:

1. `PINNED_PATHS` (this repo)
2. `verify_publication.lock` (this repo)
3. `SHA256SUMS` (`inntris-verify`)
4. `.github/workflows/verify.yml` → `expected_files` (`inntris-verify`)
5. `README.md` — the "Integrity of this repository" block inlines both digests verbatim
6. `frontend/public/.well-known/inntris-keys.txt` (this repo)

`.gitattributes` is safe on both sides — the checks are subset checks, so a new LF rule is
additive.

⚠️ **Location 5 is unvalidated today.** Nothing compares README's inlined digests against
`SHA256SUMS`; it is an existing silent-drift surface and B1.7 doubles it. Fold the fix into
Block B: have the integrity job assert every `digest  name` line appears verbatim in
`README.md`. The documented release procedure also omits this step — correct the procedure
at the same time.

### 12.3 E4 begins by inventing versioning

Exhaustively confirmed absent in `inntris-verify`: no `__version__`, no `--version` flag
(argparse has exactly `pack`, `--pubkey`, `--rpc`, `--contract`), zero case-insensitive
matches for `version` in `verify_pack.py`, zero for `version` or `schema` in
`METHODOLOGY.md`, empty `git tag -l`, empty releases API, empty tags API.

The only version string anywhere is the CHANGELOG heading `## v1.0.0 — 2026-07-20`. Step 5
of the documented procedure — *"Tag a release here"* — **has never been executed.** v1.0.0
is prose.

Recommended sequence:

1. **Tag `v1.0.0` at current `main` now.** Free: changes no bytes, triggers no
   republication, and it exactly describes the currently-published `SHA256SUMS`. Closes a
   procedure step that has never run and makes the CHANGELOG's "auditable through tags"
   promise true.
2. Ship `__version__` + `--version` as part of the **first E-block commit that already
   modifies `verify_pack.py`** — adding them changes the file's bytes and triggers the full
   cascade, so it should never get a standalone republication.
3. That commit ships as `v1.1.0`.

The methodology-hash half of E4 is already satisfied: `4ca88e16…801` exists and is stable.

### 12.4 ⚠️ The v1 regression fixture — act before Block B

`git log --all --diff-filter=A --name-only` in `inntris-verify` returns the same 10 paths as
`git ls-files`: **no fixture, sample pack, or test directory has ever existed there**, not
even as a deleted file. This repo has only canonicalization and classification vectors. So
the v1 regression corpus **does not exist in either repo**, and B1.1 ("the v2 verifier still
verifies v1 packs") currently has nothing to test against.

The container is reproducible from METHODOLOGY.md §2–3 and §10. **The signature is not.**
Regenerating a signed v1 pack later would require the live `ipk-2026-01` key, and re-signing
a synthetic pack with the production key manufactures a genuine-looking production
artifact — the exact hazard Block A3 exists to prevent. A late fixture is therefore not just
inconvenient, it is not a genuine v1 pack in the sense B1.1 needs.

Do this now, while the v1 builder is still `HEAD`:

- Generate and commit a small v1 pack.
- Sign it with a **dedicated test key — never `ipk-2026-01`**.
- Keep that test key **out of `KEYS.md`**; publishing it in the canonical registry makes it
  pinnable. The test passes `--pubkey` explicitly instead.
- **Place it in this repo, at `tests/fixtures/packs/v1/`, and keep it out of the publication
  contract.** It is a test artifact, not a published one — no third party pins it, so adding
  it to `SHA256SUMS` or the lock would trigger the §12.2 six-location cascade for no
  external benefit, and vendoring it across repos creates a fourth thing that can drift.
  This repo is where it is generated, where the format break happens, and where the test
  runs. If `inntris-verify` wants an end-to-end test to close the §12.5 gap, it should
  generate its own pack; two independently-generated valid v1 packs are a feature.

**Once E2 lands, this fixture must fail `--strict`** — it has no `registered_policy_version`,
no nonce, no consumption evidence, and a non-registry key. So the regression test asserts
both directions: passes non-strict with an explicit `--pubkey`, fails under `--strict`. That
makes one fixture cover B1.1, E1, and E2.

### 12.5 Two `inntris-verify` CI contracts an E-block rewrite will break

That repo has CI but **no test suite** — no pytest, no `tests/`, no runner.
`.github/workflows/verify.yml` runs two jobs on `pull_request` and `push` to `main`:

- **`integrity`** — parses `SHA256SUMS` with `^([0-9a-f]{64})  (\S+)$` (two spaces, exact),
  rejects malformed / duplicate / unexpected paths, recomputes both digests, checks four
  required `.gitattributes` LF rules, rejects the `PENDING-PUBLICATION-DO-NOT-PIN` marker,
  parses key rows, rejects all-zero public keys, recomputes each fingerprint, validates the
  date via `date.fromisoformat`.
- **`fallbacks`** (matrix 3.10 / 3.11 / 3.12) — monkeypatches `builtins.__import__` to block
  `eth_hash`, `nacl`, and `web3`, then asserts the pure-Python implementation strings.

Constraints this places on E1–E3, none of them obvious from reading `verify_pack.py`:

1. `load_keccak256()` and `load_ed25519_verify()` must keep those exact names, stay
   module-level, and keep returning a `(callable, implementation_string)` 2-tuple.
2. The implementation strings are compared with `!=` against exact literals —
   `"pure-python"` and `"pure-python (RFC 8032)"`. A reporting-layer rewrite must not touch
   them; even `"pure-python (RFC 8032 verify-only)"` fails CI.
3. `import verify_pack` must stay side-effect-safe — the fallbacks job imports at module
   level, so no startup self-test may `sys.exit`, and `main()` must stay behind
   `if __name__ == "__main__"` (it currently does).

Worth stating plainly: **no CI anywhere runs an actual pack verification.** Both jobs are
integrity and import checks. That is the §12.4 gap seen from the other side — the verifier
is published, hash-pinned, and cross-mirrored, but nothing anywhere proves it can verify a
pack.

### 12.6 Still open

`https://inntris.com/.well-known/inntris-keys.txt` could not be fetched from **either**
session — both hit `403` at the agent proxy on `CONNECT` (a policy denial, not a site
failure). Every repo-side input to that mirror is verified correct, so if it is stale it is
a deploy-pipeline defect, not a source-of-truth one.

Note the mirror is a **composite** file: it carries both the key registry and the
`SHA256SUMS` digests. A stale deploy therefore breaks third-party key pinning and hash
cross-checking simultaneously. To close, from an unrestricted machine:

```bash
curl -sS https://inntris.com/.well-known/inntris-keys.txt | sha256sum
sha256sum frontend/public/.well-known/inntris-keys.txt
```
