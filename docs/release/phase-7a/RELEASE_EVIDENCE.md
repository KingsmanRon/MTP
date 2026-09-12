# Phase 7A — release evidence

Inntris Core v0.5 execution authority. This is the record a human merge and
deploy decision is made from.

**Recommendation: DO NOT DEPLOY YET.** Eight of ten gates pass with recorded
evidence. Two do not, for reasons stated below, and one of them is a defect
found by this phase's own measurement rather than a missing artefact.

---

## Identity

| | |
|---|---|
| Repository | `KingsmanRon/MTP` |
| Branch | `claude/new-session-c8k710` |
| Base (reviewed Phase-6 integration head) | `60388bab70b3048473ac76f359fb8050861edfda` |
| Release HEAD | `7194bd63d094620e1004ab7da5a838a28d9f9028` |
| Migration revision | `0025_authority_binding` (single head) |
| Change size | 129 files, +13,619 / −1,366 |

> **Branch note.** The phase brief names
> `release/v05-authority-production`. This session was constrained to
> `claude/new-session-c8k710` and pushed there instead. The content is the
> release candidate; the branch is renamed or merged forward as part of the
> human decision.

### Commits

| Commit | Gate | What |
|---|---|---|
| `d5fa0f2` | 2 | Server-controlled requirement rollout with kill switches |
| `ad80991` | 3 | Production issuer and delegate trust |
| `99c0434` | 4 | v3 evidence signing, publication gate, public verifier |
| `92a5276` | 5 | Least-privilege executor provisioning and action scope |
| `69f27a2` | 6, 7, 8 | Race stress, fault injection, measured performance |
| `4e0c877` | 9 | Secret-scan fix at source |
| `7194bd6` | 8 | Restore rehearsal correctness fix |

---

## Gate results

| Gate | Result | Evidence |
|---|---|---|
| 1 — populated staging migration | **PASS** | `staging_migration.json` |
| 2 — authority requirement rollout | **PASS** | 33 tests, migration 0023 |
| 3 — production issuer/delegate trust | **PASS** | 66 tests, migrations 0024–0025 |
| 4 — evidence signing and public verifier | **PASS with a closed gate** | 53 tests; no `iae-` key published, so production cannot sign v3 |
| 5 — authenticated executor provisioning | **PASS** | 22 tests |
| 6 — policy/consume race safety | **PASS** | 11 scenarios at concurrency 64 × 30 rounds |
| 7 — performance and capacity | **FAIL — release blocker** | `performance.json`, `docs/AUTHORITY_SLO.md` |
| 8 — operational controls | **PASS** | `backup_restore.json`, alerts, runbook |
| 9 — security and release checks | **PASS** | below |
| 10 — production canary | **NOT EXECUTED** | blocked on Phase 7B and on Gate 7 |

---

## Gate 1 — populated staging migration

Rehearsed by `scripts/staging_migration_rehearsal.py` on a database built to
5,000 principals across 1,000 organisations with 100,000 genuinely
hash-chained audit rows (106 MB), upgraded from
`0018_merkle_anchor_visibility` — the last revision before the v0.5
authority work.

| | |
|---|---|
| Revisions applied | 7 (`0019` → `0025`) |
| Total upgrade | **4.696 s** |
| Slowest single revision | 0.734 s (`0024` → `0025`) |
| Tables rewritten | **none** (`pg_class.relfilenode` compared before/after) |
| Data readable afterwards | yes; 0 agents with a broken audit chain |
| Legacy token bridge | 50 unconsumed reservations, 50 still with no grant row, **no backfill occurred** |
| Tenant isolation | 12 tables checked, all with RLS enabled **and forced** |

**Mixed-version window.** A legacy approval token is simply a token with no
grant row, and the rehearsal confirms the upgrade leaves it that way.
Historical tokens are never rewritten. Old application instances keep
issuing and consuming plain approval tokens; new instances additionally
write grants, whose claim key is a token in the same table. An old instance
consuming a grant-backed token still burns it exactly once, because the
uniqueness constraint is the authority.

**Locks — an honest gap.** The rehearsal samples `pg_locks` every 50 ms and
observed no `ACCESS EXCLUSIVE` lock, because every migration completes in
under a second at this volume. That is a limitation of the sampling, not a
claim that no such lock is taken: migration 0019 builds
`agents_id_org_unique`, which does take one for the duration of the index
build. At 5,000 agents it is immaterial. **Production's `agents` row count
is unknown to this rehearsal — re-run at that volume before the maintenance
window decision**, which is exactly what
`docs/EXECUTION_AUTHORITY_PERSISTENCE.md` asked for.

**Recovery mechanism — forward repair, not downgrade.** Every authority
migration raises on `downgrade()`: grants record what was authorised and
whether it was spent, and dropping them would destroy the evidence that
gated real executions.

* *Application rolled back, schema forward:* no repair needed. The new
  tables are inert — nothing in the old code path reads or writes them.
* *Rolling forward again:* one reconciliation. Grants whose
  `approval_token_id` appears in `approval_token_consumptions` while the
  grant still reads `active` — a token consumed by an old instance that
  could not update the grant row. Resolve forward by marking the grant
  consumed against the existing consumption record. Never delete.

```sql
SELECT g.id, c.audit_log_id, c.execution_ref
FROM execution_authority_grants g
JOIN approval_token_consumptions c ON c.token_id = g.approval_token_id
WHERE g.status = 'active';
```

---

## Gate 2 — authority requirement rollout

Migration `0023` moves the answer out of `INNTRIS_AUTHORITY_REQUIRED_ORGS`
and into `authority_requirements` / `authority_controls`.

* **Per organisation / principal / action class**, with a strict
  specificity ladder. A narrower row overrides a broader one **in both
  directions**, so a rollout can be reversed for one principal without
  deleting the organisation-wide row and losing what it said.
* **Safe default unchanged:** an organisation with no row is not required.
  Nothing changes for any existing organisation until somebody deliberately
  configures it.
* **Audit trail:** every write appends to `administrative_audit_events` in
  the same transaction, and that table is append-only by trigger. A write
  without an actor and an approval reference is refused by constraint.
* **Two kill switches.** `requirement_enforcement` suppresses the
  requirement (the rollback for a rollout that went too wide — the one
  control that weakens enforcement, logged loudly on every use);
  `authority_issuance` halts new grants while leaving consumption of
  already-issued authority alone, because halting that would strand an
  executor mid-flight.
* **The environment variable survives as additive break-glass.** It can turn
  the requirement on and can never turn one off.

**Legacy `/verify` cannot bypass an enabled requirement.** `/verify` has no
field in which to present delegated authority, so for an enrolled
organisation the gate always answers "required and absent". It consults the
same resolver `/authority/evaluate` uses, so the two surfaces cannot
disagree. Covered by
`tests/test_authority_requirement_rollout.py::TestLegacyRouteCannotBypass`.

Three outcomes of "no requirement row" are kept distinct: no row (not
required), no table (the pre-0023 schema, so nothing can have been enrolled
— also not required), and a table that exists and could not be read
(indeterminate → `required=True`, blocks). A programming fault is
deliberately outside that set: it propagates rather than being laundered
into a refusal naming the wrong reason.

**33 tests**, all against real PostgreSQL.

---

## Gate 3 — production issuer/delegate trust

**Trust is configured; distrust is data.** Issuer keys come from
`INNTRIS_AUTHORITY_TRUST` / `INNTRIS_AUTHORITY_TRUST_FILE`, reviewable in the
deployment. Revocation lives in `authority_trust_revocations` (migration
`0024`) because a compromised key at 03:00 needs an answer in seconds, not a
review and a deploy. A revocation row overrides configuration and is never
overridden by it.

| Requirement | How |
|---|---|
| Explicit trusted issuer keys | Configuration, strictly validated at load; a malformed file fails the deployment rather than coming up trusting nobody |
| Key fingerprint/thumbprint | SHA-256 of the raw Ed25519 key; a declared fingerprint that disagrees with its own key is refused |
| Rotation | Additive then subtractive, documented in `docs/AUTHORITY_ISSUER_TRUST.md`. `retired` ≠ `revoked`: a retired key may not sign new authority, and what it signed stays verifiable |
| Revocation / disable | `authority_control revoke` for issuer, issuer key, delegate key or a single delegation, scoped per issuer |
| Cache/refresh rules | **None needed — there is no network key discovery.** No cache to poison, no refresh interval, and no network outage that can change a verification answer |
| Outage behaviour | Fail closed. The one live dependency is the revocation read; if it cannot be established, no new delegated authority is accepted |
| Bounded parser | 16 KiB, depth 8, 256 keys, 2048-char strings, 64-element arrays, 2 s monotonic budget. Duplicate JSON keys and floating-point numbers refused |
| No private material in source control | Enforced: a trust config containing `private_key`, `secret`, `seed`, JWK `d`/`k` or any PEM private block at any depth is **refused**, not ignored |

**No Mastercard-operated key discovery is claimed.** This build does not
assert that any card scheme or issuer operates a key-discovery endpoint for
this purpose, and implements none.

**Principal binding is not `agents.metadata`**, and migration `0025` records
why so nobody moves it there later: both registration routes copy
caller-supplied metadata onto an agent. A binding held there would be chosen
by the very party it constrains — register an agent declaring somebody
else's issuer account reference, present that account's *genuine*
delegation, and everything verifies. `authority_principal_bindings` is
written only by the system role through an administrative path with an actor
and an approval reference.

Order of checks is cheapest-first with **revocation before signature
verification**, so a revoked key is never verified. **66 tests.**

---

## Gate 4 — evidence signing and public verifier

**The publication gate is closed, by design and in code.**

No `iae-` authority-evidence key is published, so
`api/receipts/key_registry.py` **refuses to sign v3 evidence in
production**. That is the mechanical form of "do not emit publicly
advertised v3 receipts until the verifier publication gate passes" — a
refusal rather than a process somebody has to remember. A test asserts the
current state so it cannot change silently.

| | |
|---|---|
| Published evidence-pack key | `ipk-2026-01`, fingerprint `089c7611802e5494a4274e6f1af45d514c2ffc8c208db8a50a0df2c4ec99151c`, active |
| Published authority-evidence key | **none** — v3 signing is blocked in production |
| `verify_pack.py` | `aa48f28be5af31c5dc1bec586ccd054fe9e58684e74976853b9a9a2b1b7845c2` |
| `METHODOLOGY.md` | `75c4c26e9eaa3d06d3a27ede23ac87cfb5348d3f5af94d5914ec6306f2c4fc2e` |

Lock, `.well-known` mirror and the contract test were re-pinned together in
one sitting, as the publication contract requires.

**Key separation is enforced, not claimed.** The loader refuses a seed that
is also the agent request-signing key, the anchor wallet, or the offline
evidence-pack seed, comparing raw bytes under every encoding either could be
written in.

**The public verifier now verifies v3.** RFC 8785 canonicalisation inline
(it must run on a stock Python), then: recomputed hash, signature over that
hash, envelope agreement including *missing* outer fields, parent linkage,
and semantic continuity — because a valid parent hash proves only that the
producer chose that parent, not that the events describe the same act.

It also gained `--evidence-pubkey`, parallel to `--pubkey`. Without it, a
wholesale forgery signed with the attacker's own key and naming that key in
the manifest is internally consistent, **and the verifier says so** rather
than pretending otherwise. With the published key pinned, it is caught. Both
cases have a test.

v1 and v2 are untouched: their seven-field fingerprint contract is
re-verified against fixtures through the shipped verifier's own
implementation, and a pack with no v3 evidence verifies exactly as before.

Producer schema at `/schema/receipt/v3.json`; discovery at
`/.well-known/inntris-authority-keys.json`. **53 tests**, most of which run
the published `verify_pack.py` as a subprocess against real packs — testing
the library against itself would only prove Core agrees with Core.

### Remaining action before v3 evidence is public

1. Generate the authority-evidence key in the production key ceremony.
2. Publish it as `iae-YYYY-NN` in `.well-known/inntris-keys.txt`, the
   `inntris-verify` mirror and the publication lock, together.
3. Update `tests/test_verify_publication.py`, which asserts the current
   "none published" state deliberately.

---

## Gate 5 — authenticated executor provisioning

| Requirement | Evidence |
|---|---|
| Identity from credentials, not a request string | `executor_binding_digest` derives from organisation + API key id only. Two keys in one organisation are two executors |
| Organisation membership | Enforced at both `/authority/*` routes; an agent in another organisation returns 404, not 403 — existence is not disclosed |
| Action scope | `execute:<action-class>` scopes. A payments executor cannot be turned on a code release, even inside its own organisation |
| Grant immutable binding | The binding is recorded at issuance and survives the credential being revoked |
| Credential rotation/revocation | `provision_executor create` / `revoke`; rotation is deliberately two commands — an atomic rotate would create a window where neither key works |
| **Copied `execution_ref` cannot impersonate** | An attacker holding a valid credential of their own, replaying a genuine reference seen in a log, is refused. `TestGrantBindingIsImmutable::test_a_copied_execution_ref_does_not_help_the_impostor` |
| Least privilege | Provisioned keys hold `execute:<action>` and nothing else — no agent registration, no audit reads, no webhook secrets |

`INNTRIS_REQUIRE_EXECUTE_SCOPE` makes a dedicated `execute` scope mandatory
and refuses the broad `write`. **It is off in this release**, deliberately:
existing service keys legitimately drive `/verify-token` today and this
phase must not lock them out mid-release. Turn it on once those keys are
migrated. **22 tests.**

---

## Gate 6 — policy/consume race safety

`tests/test_authority_race_stress.py`, **11 scenarios, all passing at
concurrency 64 over 30 rounds** against real PostgreSQL.

| Scenario | Result |
|---|---|
| Concurrent policy update vs consume | No stale-policy consumption succeeded, any round |
| Principal suspension vs consume | Same |
| Delegation narrowing/revocation vs consume | Same; a narrowed-evidence consumer never won |
| Concurrent **different** execution refs | Exactly one authorised, every round |
| Concurrent **same** execution ref | Exactly one authorised; the rest recovered with `may_execute=false` |
| Idempotent issuance storms | One logical grant, capacity committed once |
| Cumulative limit under contention | Never over-committed |
| **Database restart mid-flight** | At most one claim; the durable record agrees |
| Recovery after restart | Service recovers |
| Backend terminated mid-transaction | No half-claim: a claimed token always means a consumed grant |

**The headline invariant holds: no stale-policy first consumption succeeded
after a change that should deny the action.**

A side finding worth carrying into operations: a connection pool whose
server restarted under it can stall trying to close connections the server
already dropped. Production clients need a bounded close.

---

## Gate 7 — performance and capacity — **RELEASE BLOCKER**

Full analysis in `docs/AUTHORITY_SLO.md`; raw data in `performance.json`.

### What passed

| Stage | p50 | p99 | Throughput | Failures |
|---|---|---|---|---|
| Issuance, 32 principals | 59 ms | 132 ms | 497/s | 0 |
| Issuance, 1 principal | 119 ms | 1416 ms | 127/s | 0 |
| 32 consumers racing one grant | 41 ms | 90 ms | 402/s | 0 |
| VI verification | 0.20 ms | 0.37 ms | 4640/s | 0 |
| Receipt v3 signing | 0.14 ms | 0.19 ms | 7054/s | 0 |

VI verification and receipt signing are three orders of magnitude below the
database work. Neither is worth optimising and neither should be blamed when
latency moves.

### What failed

Consuming many **distinct** grants of **one principal** at concurrency 32:
**319 of 320 attempts failed** — 262 lock timeouts and 57 `40P01
deadlock_detected`. Spread across 32 principals it still deadlocks **45 of
320 (14.1%)**.

**Root cause, localised.** `assign_audit_chain_sequence` — a BEFORE INSERT
trigger on `audit_logs` from migration `015_durable_security_state.sql` —
takes a per-agent advisory lock *inside* the insert, and
`idx_audit_logs_agent_chain_sequence` is `UNIQUE (agent_id,
chain_sequence)`. Every observed deadlock has exactly this shape: one
transaction holding the advisory lock and blocked on the index entry,
another holding the index entry and blocked on the lock.

**What it is and is not.** Not a correctness defect — PostgreSQL aborts the
whole transaction and nothing is half-written, which is why every Gate 6
invariant still holds under stress. Not introduced by v0.5 — the trigger
predates the authority work by eight migrations, though the authority path
does more work inside that serialised window. **It is an availability and
capacity defect, and on the consumption path it is severe.**

**Not fixed here, deliberately.** That trigger's lock is what stops two
concurrent appends forking an agent's forensic hash chain. Changing it
changes an integrity mechanism, and a wrong change there is far worse than a
retryable deadlock. Three options are written up in `docs/AUTHORITY_SLO.md`
for a decision outside release engineering.

**Interim constraint:** do not run more than a small number of concurrent
consumptions per principal. The canary is one principal executing serially
and is unaffected; any rollout past it needs this fixed first.

SLOs are published only for the stages that passed. **No
consume-availability SLO is published** — setting one now would mean either
quoting a number the system does not meet or choosing a lenient one to make
the blocker disappear.

---

## Gate 8 — operational controls

**Metrics.** Ten authority metrics, instrumented at the single
evaluate/consume boundary rather than at a dozen return sites, so a decision
that skipped the counter cannot exist.

**Alerts.** Ten rules in `ops/prometheus/inntris-alerts.yml`, every
threshold taken from the Gate 7 measurements with stated headroom. Covers
consume failures, policy-revalidation failures, unresolved executor
outcomes, VI verification failures, key-resolution failures (ours, counted
apart from the caller's), and both kill switches left engaged.

**Kill switches.** `authority_issuance` halts new authority globally or per
organisation; `requirement_enforcement` reverses a requirement rollout. Both
via `scripts/authority_control.py`, both refusing to act without an actor
and an approval reference.

**Disabling a compromised credential.** Issuer, issuer key, delegate key or
a single delegation via `authority_control revoke`; an executor credential
via `provision_executor revoke`.

**Backup restoration rehearsal — executed.** `backup_restore.json`:

| | |
|---|---|
| Dump | 0.617 s, 4.6 MB |
| Restore | 1.099 s |
| Migration revision | matches (`0025_authority_binding`) |
| Row counts | all 12 critical tables match exactly |
| Append-only triggers | both tables **refused** an update (`RaiseError`) |
| RLS | forced on all 12 |
| Spent authority stays spent | a replayed consumption was refused (`UniqueViolationError`) |

**Retention and access.** Authority decisions live in `audit_logs`
(erasable by the authorised GDPR path) *and* in
`authority_decision_evidence`, which reconstruction reads precisely because
the audit payload can be legitimately tombstoned and a quoted receipt must
not stop verifying. Both are append-only by trigger; `inntris_api` holds no
DELETE. Trust revocations and controls are platform state readable only by
the system role.

**Runbooks.** `docs/runbooks/authority_incident.md` (incident and
reconciliation) and `docs/runbooks/authority_canary.md`.

**Unresolved outcomes never auto-release capacity.** A timeout or a thrown
executor is `outcome_unknown`, never `failed_final`: it is not proof that no
money moved. Releasing the reservation would hand the same capacity to a
second transaction while the first may well have settled. Reconciliation
requires the rail's own evidence.

---

## Gate 9 — security and release checks

| Check | Result |
|---|---|
| Full test suite (with PostgreSQL integration) | **1,628 passed, 25 skipped** |
| PostgreSQL integration suite | included above; run as `inntris_worker`, the real runtime role |
| Ruff | clean across `api/ scripts/ tests/ workers/ mcp_server/ evidence_pack/ loadtests/` |
| Black | clean |
| Migration drift / single head | single head `0025_authority_binding` |
| Public verifier fixtures | `check_verify_publication.py` OK; v1/v2 fixtures re-verified through the shipped verifier |
| Dependency audit (`pip-audit`) | **no known vulnerabilities** |
| Secret scan (`gitleaks dir .`) | **0 findings in the working tree** |

The one secret-scan finding this phase introduced was a PEM *detection
pattern* in the trust loader. It was fixed at source — the markers are now
assembled from parts — rather than silenced with an ignore entry, so the
gate stays fully armed. A single scoped `.gitleaksignore` entry covers the
one historical commit that still carries the literals; it contains no key
material.

**CodeQL and Trivy** run in `.github/workflows/security.yml` on push and are
not reproducible in this container. They must be green before merge.

**Phase 4B x402 compatibility rerun: not required.** No legacy contract
changed after the checkpoint. `/verify` gained one call (the requirement
gate, a no-op for every unenrolled organisation, which is all of them);
`/verify-token` reason strings and the approval-token claim set are
unchanged. The `/authority/*` surface is additive.

---

## Gate 10 — production canary — NOT EXECUTED

Procedure, preconditions, bounds, the seven-step sequence and abort
conditions are in `docs/runbooks/authority_canary.md`.

Blocked on two things, both recorded rather than worked around:

1. **Phase 7B has not delivered a guarded executor.** Gate 10 requires one
   by its own terms; without it there is nothing on the far side of an
   ALLOW.
2. **No `iae-` key is published**, so the canary cannot produce verifiable
   v3 evidence (step 6 cannot pass).

The Gate 7 blocker does not affect the canary itself — one principal
executing serially is the one shape that does not contend — but it does
block any rollout past it.

Running a partial canary and reporting it as a pass would be worse than not
running one.

---

## Release claim — what is enforced, and what is external

### Enforced inside Inntris Core, with tests

* Delegated authority is required only where an organisation deliberately
  configured it, at the granularity it chose, with an immutable audit trail
  and two kill switches.
* A delegation is accepted only if a configured trusted issuer signed it
  under an active key, it is in date, nobody has revoked it, and it names
  *this* principal via a binding no caller can write.
* A delegated scope can only narrow. It never widens an organisation limit,
  re-enables a blocked action, or authorises a destination the
  organisation's own policy refuses. An unrecognised constraint fails
  closed rather than being ignored.
* Authority is single-use and bound to the executor credential that
  obtained it. A copied `execution_ref` gains an attacker nothing.
* Consumption re-validates against *current* policy, not the snapshot the
  grant was issued under.
* Every decision — BLOCK as well as ALLOW — is recorded durably in two
  places, both append-only by trigger.
* v3 evidence is signed by a dedicated key that cannot be any other key in
  the system, and cannot be signed at all until that key is published.

### External boundaries — not proved by an MTP receipt

* **Settlement.** Inntris Core owns authority persistence, not settlement.
  There is deliberately no settlement engine here. A verified v3 chain
  proves Core recorded these decisions and consumptions and that nobody has
  altered them since. **It does not prove money moved.** The executor's own
  outcome evidence is a linked boundary.
* **The v3 evidence commitment is not anchored on-chain.** The underlying
  audit decision row participates in the existing Merkle anchoring pipeline
  like any other audit row; the `evidence_payload_hash` itself is committed
  by no anchor path. v3 events are authenticated by their Ed25519 signature
  and their parent links, and that is the whole of their assurance today.
* **The issuer's own decision.** Core verifies that an issuer signed a
  delegation. Whether the issuer should have is theirs.
* **What the executor actually did.** Core authorises once and records what
  it was told. The rail is authoritative for what happened.

---

## Before the merge/deploy decision

**Must fix:**

1. The Gate 7 consumption deadlock. Pick one of the three options in
   `docs/AUTHORITY_SLO.md`, implement, and re-measure.

**Must do before v3 evidence is public:**

2. The authority-evidence key ceremony and publication (Gate 4).

**Must do before the canary:**

3. Phase 7B's guarded executor.

**Should do:**

4. Re-run the staging rehearsal at production `agents` row count, for the
   `agents_id_org_unique` index-build lock duration.
5. Re-run the benchmark on staging hardware.
6. Confirm CodeQL and Trivy are green in CI.
7. Decide whether `INNTRIS_REQUIRE_EXECUTE_SCOPE` goes on, once existing
   service keys are migrated to `execute` scopes.

---

## Handoff

| | |
|---|---|
| Repository | `KingsmanRon/MTP` |
| Release branch/HEAD | `claude/new-session-c8k710` @ `7194bd63d094620e1004ab7da5a838a28d9f9028` |
| Migration revision | `0025_authority_binding` |
| Staging upgrade evidence | `docs/release/phase-7a/staging_migration.json` — 7 revisions, 4.696 s, no rewrites |
| Mixed-version result | Legacy tokens unmodified; no backfill; forward-repair documented |
| Authority requirement config | `authority_requirements` + `authority_controls`, off by default |
| Production issuer trust config | `INNTRIS_AUTHORITY_TRUST*`; none configured in this branch |
| Authority evidence key id/fingerprint | **none published** — v3 signing blocked in production |
| Public verifier publication revision | `verify_pack.py` `aa48f28b…`, `METHODOLOGY.md` `75c4c26e…` |
| Executor identities provisioned | none in production; `scripts/provision_executor.py` ready |
| Concurrency/fault results | 11/11 at concurrency 64 × 30 rounds, including DB restart |
| Performance measurements | `docs/release/phase-7a/performance.json`; **blocker recorded** |
| Monitoring/alerts | 10 metrics, 10 alert rules derived from measurements |
| Backup restore result | `docs/release/phase-7a/backup_restore.json` — usable, all properties held |
| Security checks | 1,628 tests pass; pip-audit clean; 0 working-tree secrets; single migration head |
| Phase 7B executor repo/HEAD | **not delivered** |
| Canary result | **not executed** — blocked on 7B and on the key ceremony |
| Human merge/deploy decision | **pending — recommendation is to hold on the Gate 7 blocker** |
