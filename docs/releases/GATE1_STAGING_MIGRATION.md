# Gate 1 — populated staging migration rehearsal

**Result: FAILED.** The migration chain itself is sound — nine migrations,
no table rewrite, sub-second locks, all compatibility checks green — but the
command production actually runs, `alembic upgrade head`, **cannot reach head
from the deployed revision**. See [Blocker 1](#blocker-1).

| | |
|---|---|
| Branch | `feat/execution-authority-phase7a-corrected` |
| Rehearsed at | `a7dc94d6b22ef8585d43ae51b804cc82df083915` |
| Deployment / default branch | `claude/review-mtp-architecture-p54Q1` @ `53b19ffa0632806f52bc1dd90fc72b0189bf1c45` |
| **Deployed start revision** | **`0018_merkle_anchor_visibility`** |
| Target revision | `0027_authority_config_mgmt` |
| Harness | `scripts/gate1/` |
| Raw evidence | `docs/releases/gate1_evidence/` |

## 1 — Start revision

Taken from the Alembic tree on the **default branch**, which Railway and
Vercel auto-deploy on push. Production itself was not queried and must not
be; if the live `alembic_version` differs from `0018_merkle_anchor_visibility`
this rehearsal does not cover the gap and must be re-run.

Revisions `0001`–`0018` and their SQL are **byte-identical** between the
deployed branch and this one, so upgrading a fresh database to `0018`
reproduces the deployed schema exactly.

**The gap is nine migrations, not five:**

| Revision | SQL | Touches populated tables? | Strongest lock |
|---|---|---|---|
| `0019_authority_persistence` | `023` | **yes — `agents`** | ACCESS EXCLUSIVE (unique index `(id, org_id)`) |
| `0020_authority_evidence` | `024` | no (new table) | — |
| `0021_authority_evidence_int` | `025` | **yes — `audit_logs`** | ACCESS EXCLUSIVE (unique index `(id, agent_id, action_type)`) |
| `0022_authority_evidence_nn` | `026` | no | ACCESS EXCLUSIVE on the new evidence table |
| `0023_authority_requirement` | `027` | no (two new tables, RLS) | — |
| `0024_authority_config_hard` | `028` | no | ACCESS EXCLUSIVE (REVOKE) |
| `0025_authority_config_lin` | `029` | no (functions + triggers) | — |
| `0026_authority_config_glob` | `030` | no (functions) | — |
| `0027_authority_config_mgmt` | `031` | **yes — `administrative_audit_events`** | ACCESS EXCLUSIVE (add column, drop NOT NULL, two CHECKs) |

Role/RLS changes: `0023` and `0027` create policies; `0027` creates the
`inntris_authority_admin` role; `0024` and `0027` change grants.

## 2 — Staging shape

**SYNTHETIC cardinality — not measured production volume.** No production
cardinality was available, so these numbers were chosen to expose index and
constraint cost on the three populated tables the chain touches. Every timing
below scales with them and must not be quoted as a production estimate.

| Table | Rows | Size |
|---|---|---|
| `audit_logs` | 500,000 | 481 MB |
| `approval_token_consumptions` | 41,540 | 27 MB |
| `merkle_proofs` | 20,000 | 10 MB |
| `administrative_audit_events` | 2,000 | 584 kB |
| `agents` | 500 (active, suspended, revoked) | 480 kB |
| `organizations` | 25 | 64 kB |

Database 528 MB. The forensic chain is genuine: 500,000 rows, **0 sequence
gaps and 0 broken hash links**, built the way `assign_audit_chain_sequence()`
builds it.

## 3 — Rehearsal

Nine migrations, **4.0–4.8 s total** across runs. **No table was rewritten**
(`relfilenode` unchanged for every watched table) and **no migration changed
any row count** — including `026`, whose drift guard rolls its probe rows back.

The number an operator needs is the worst latency seen by a **concurrent
reader** running throughout:

| Revision | Duration | ACCESS EXCLUSIVE on populated tables | Worst reader block |
|---|---|---|---|
| `0019` | 0.40–0.55 s | `agents` | 0.028–0.033 s |
| `0020` | 0.38–0.54 s | — | 0.016 s |
| **`0021`** | **0.95–1.51 s** | **`audit_logs`** | **0.572–1.079 s** |
| `0022` | 0.40–0.62 s | (new evidence table) | 0.016 s |
| `0023` | 0.38–0.41 s | — | 0.015 s |
| `0024` | 0.37–0.51 s | (new config tables) | 0.015 s |
| `0025` | 0.37–0.43 s | — | 0.015 s |
| `0026` | 0.37–0.46 s | — | 0.015 s |
| `0027` | 0.39–0.43 s | `administrative_audit_events` + two new tables | 0.015 s |

**All meaningful blocking is `0021`**, building a unique index on
`audit_logs` under ACCESS EXCLUSIVE. At 500k rows readers stall for roughly
0.6–1.1 s. This scales with `audit_logs`; at 5M rows expect ~10× and plan the
window accordingly. `0027` takes ACCESS EXCLUSIVE on
`administrative_audit_events` but the added column uses a fast default and
both CHECKs are added `NOT VALID` then `VALIDATE`d, so the hold is
milliseconds at this size.

## 4 — Compatibility after migration

16/16 (`gate1_evidence/compatibility.json`). All pre-existing data readable;
forensic chain intact; **0 rows gained a `policy_hash`**, so every historical
receipt still classifies **v1** exactly as before; **0 grant rows exist after
migration** — no legacy token was converted or backfilled; an unconsumed
legacy token still claims exactly once through
`approval_token_consumptions` and creates no grant; all 2,000 pre-existing
administrative events defaulted to `scope = 'organisation'` with none
inconsistent; platform-scope events are representable; new issuance,
consumption, same-ref recovery and different-ref refusal
(`execution_ref_conflict`) all work; a Gate-2 requirement is written **and
enforced**; tenant isolation holds; the runtime role is denied INSERT, UPDATE
and DELETE on both configuration tables; the management role has exactly the
accepted privileges and no more.

## 5 — Mixed-version window

**OLD APP / NEW DB → SUPPORTED.** The deployed branch's own suite was run
against a database at `0018` and at `0027`: **identical results both times**
(1 failed, 682 passed, 14 skipped) with the *same* single failure
(`test_release_integrations.py::test_real_postgres_excludes_sandbox_rows_from_anchor_selection`,
which fails on the old schema too — it is the seeded `audit_logs` volume
overflowing an unanchored-row limit, not the migration). The old application
contains **no reference** to any authority table. Its
`administrative_audit_events` INSERT, which names no `scope`, still works and
the row defaults to `organisation`.

**NEW APP / OLD DB → UNSAFE.** Against `0018` the new application finds four
required tables missing. The configuration reader fails **closed**
(`AuthorityConfigurationUnavailable`), but issuance raises a raw
`UndefinedFunctionError: function authority_config_lock_namespace() does not
exist` — an unhandled crash, not a typed refusal.

> **The only permitted deployment sequence is: migrate the database to
> `0027` first, then roll the application forward.** Never the reverse, and
> never both at once with the application arriving first.
>
> Rollback is application-only: leave the database forward.

(The management role appeared present in the old-database probe only because
PostgreSQL roles are cluster-wide and the rehearsal shares one cluster. That
is an artefact of the harness, not of the schema.)

## 6 — Failure and recovery

Failures were injected the way they happen in production — a live query
holding a lock the migration needs, with `lock_timeout` set — not by editing
a migration. **Alembic downgrade is not the recovery mechanism**: `0023`–`0027`
raise `NotImplementedError` on downgrade by design.

| Scenario | State after failure | Operator action |
|---|---|---|
| **A** — failure before the first authority migration | Still `0018`. No constraint, no authority table, no `scope` column. Old app fully functional. | None. Nothing partial was applied. Retry in a quieter window. |
| **B** — failure mid-chain | Sits at `0020` with a consistent schema; `0019`/`0020` applied, `0021` not. Old app fully functional. | None, and **no downgrade**. Each migration commits or rolls back whole. The applied authority tables are inert to the old app. Retry forward. |
| **C** — schema at head, app not yet rolled forward | `0027`; old app writes audit rows (chain assigned) and administrative events (`scope` defaults to `organisation`). | None. This is the normal pre-deploy window. Roll forward when ready. |
| **D** — app rolled back after the database reached head | Database stays at `0027`. Old app fully functional. | Deploy the previous image and **leave the database forward**. Snapshot restore is only for a schema fault no forward repair can fix, and loses everything written since. |

Both retries reached `0027` — **using the stepwise upgrade**, see Blocker 1.

## 7 — Blockers

### Blocker 1 — `alembic upgrade head` cannot upgrade an existing database

`alembic upgrade head` in a **single invocation** fails at `0026` from every
existing start revision tested (`0018`, `0022`, `0024`), leaving the database
at its starting revision:

```
030 drift: a global configuration write holds 2 configuration locks,
           expected exactly the global one
```

**Root cause.** `alembic/env.py` wraps the entire run in **one** transaction
(`transaction_per_migration` is not set). Migration `029`'s drift guard ends
holding one transaction-scoped `authority-config` advisory lock — taken by
the trigger when its probe row was written. Migration `030`'s drift guard then
asserts that a *global* configuration write holds **exactly one** such lock,
counts the two, and refuses. The two guards cannot share a transaction.

**Why this was never seen.** From an **empty** database the same command
succeeds — because `database/migrations/006_gdpr_erasure.sql` (revision
`0002`) contains a bare `COMMIT;`, which ends Alembic's enclosing transaction
early and leaves every later migration effectively in its own. An upgrade
starting at `0018` never executes `006`, so the single transaction survives to
`029`/`030`. **Every green full-stack build in this project so far has been
green by accident.**

Starting at `0025` or `0026` also succeeds — `029` is already applied, so the
guards no longer share a transaction. That is the discriminator, not the data.

**The stepwise upgrade works.** One revision per invocation — each its own
transaction — takes `0018` to `0027` cleanly, and is what the rehearsal and
both recovery retries used.

This is a **release blocker**. It needs a deliberate remediation decision
(a forward migration relaxing `030`'s guard, `transaction_per_migration` in
`env.py`, or an explicitly stepwise deploy command). No fix is included here:
Gate 1's job was to find it.

### Blocker 2 — deployment applies migrations automatically

On **both** the deployed branch and this one, `railway.json` **and**
`railway.worker.json` declare:

```json
"preDeployCommand": "alembic upgrade head"
```

**Merging this branch into `claude/review-mtp-architecture-p54Q1` would
automatically attempt to apply all nine migrations `0019`–`0027` on the next
deploy**, with no human step — and, per Blocker 1, that command would **fail**,
leaving the database at `0018` while the new application rolls out against it.
That is precisely the NEW APP / OLD DB combination proved unsafe in §5.

Two further discrepancies with `DEPLOY_RUNBOOK.md`:

- the runbook says the worker "should use `railway.worker.json` so it does
  **not** also run migrations" — but that file **does** run
  `alembic upgrade head`, so both services race for the same migration;
- the runbook does not describe the stepwise requirement, because it was not
  known until this rehearsal.

Nothing in deployment configuration was changed here, as instructed. This
remains a release blocker until migration execution is deliberately
controlled and the runbook matches reality.

### Blocker 3 — `AUTHORITY_MANAGEMENT_DATABASE_URL` is not wired

`0027` creates `inntris_authority_admin` without a password and
`scripts/configure_authority_management_role.py` provisions it, but no
deployment configuration sets `AUTHORITY_MANAGEMENT_DATABASE_URL` or
`AUTHORITY_MANAGEMENT_DATABASE_PASSWORD`. In a real environment the role
would exist unprovisioned and no authority configuration change could be
made.

## 8 — Reproducing

```bash
export ALEMBIC_DATABASE_URL=postgresql://<privileged>@host/inntris_stage
export DATABASE_URL=postgresql://inntris_worker:<pw>@host/inntris_stage
export AUTHORITY_MANAGEMENT_DATABASE_URL=postgresql://inntris_authority_admin:<pw>@host/inntris_stage
export RUNTIME_DATABASE_PASSWORD=<pw>
export AUTHORITY_MANAGEMENT_DATABASE_PASSWORD=<pw>

bash scripts/gate1/build_staging.sh                     # 0018 + synthetic data
python scripts/gate1/rehearse.py       out/rehearsal.json
python scripts/configure_authority_management_role.py
python scripts/gate1/verify_staging.py out/compatibility.json
python scripts/gate1/inject_failures.py out/recovery.json  # needs lock_timeout set
python scripts/gate1/new_app_old_db.py                  # against a 0018 database
```

Never point any of this at production.
