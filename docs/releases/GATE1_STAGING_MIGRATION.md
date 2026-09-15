# Gate 1 — populated staging migration rehearsal

**Result: PASSED.** `alembic upgrade head` — the command Railway actually
runs — upgrades a populated database from the deployed revision to head in
**one invocation**, and two concurrent invocations are safe.

The first rehearsal (`d7f8206`) **FAILED**: the same command could not
upgrade an existing database at all. The cause and the remediation are in
[§7](#7--the-gate-1-failure-and-its-remediation); that history is kept
because it is why the migration transaction model is the way it is.

| | |
|---|---|
| Branch | `feat/execution-authority-phase7a-corrected` |
| Deployment / default branch | `claude/review-mtp-architecture-p54Q1` @ `53b19ffa0632806f52bc1dd90fc72b0189bf1c45` |
| **Deployed start revision** | **`0018_merkle_anchor_visibility`** |
| Target revision | `0027_authority_config_mgmt` |
| Command rehearsed | `alembic upgrade head` — one invocation, no stepwise workaround |
| Harness | `scripts/gate1/` |
| Raw evidence | `docs/releases/gate1_evidence/` |
| Migration-model tests | `tests/test_alembic_migration_model.py` (M1–M8) |

## 1 — Start revision

Taken from the Alembic tree on the **default branch**, which Railway and
Vercel auto-deploy on push. Production itself was not queried and must not
be; if the live `alembic_version` differs from `0018_merkle_anchor_visibility`
this rehearsal does not cover the gap and must be re-run.

Revisions `0001`–`0018` and their SQL are **byte-identical** between the
deployed branch and this one, so upgrading a fresh database to `0018`
reproduces the deployed schema exactly.

**The gap is nine migrations:**

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
| `approval_token_consumptions` | ~41,700 | 27 MB |
| `merkle_proofs` | 20,000 | 10 MB |
| `administrative_audit_events` | 2,000 | 584 kB |
| `agents` | 500 (active, suspended, revoked) | 480 kB |
| `organizations` | 25 | 64 kB |

Database 528 MB. The forensic chain is genuine: 500,000 rows, **0 sequence
gaps and 0 broken hash links**, built the way `assign_audit_chain_sequence()`
builds it.

## 3 — Rehearsal: one `alembic upgrade head`

`0018_merkle_anchor_visibility` → `0027_authority_config_mgmt` in **1.76 s**,
one invocation. **No table was rewritten** (`relfilenode` unchanged for every
watched table) and **no migration changed any row count** — including `026`,
whose drift guard rolls its probe rows back.

Per-revision timings come from watching the version row move, which is only
possible because each revision now commits on its own. A sample taken while
revision N runs is attributed to N, not to the revision still showing in the
version row.

| Revision | Duration | ACCESS EXCLUSIVE on populated tables | Worst reader block |
|---|---|---|---|
| `0019` | 0.662 s | `agents` | 0.016 s |
| `0020` | 0.005 s | — | — |
| **`0021`** | **1.116 s** | **`audit_logs`** | **1.128 s** |
| `0022` | 0.008 s | (new evidence table) | — |
| `0023` | 0.014 s | — | 0.001 s |
| `0024` | 0.011 s | (new config tables) | 0.011 s |
| `0025` | 0.008 s | — | — |
| `0026` | 0.008 s | — | 0.011 s |
| `0027` | 0.011 s | `administrative_audit_events` + two new tables | 0.001 s |

**All meaningful blocking is `0021`**, building a unique index on
`audit_logs` under ACCESS EXCLUSIVE. At 500k rows readers stall for roughly
1.1 s. This scales with `audit_logs`; at 5M rows expect ~10× and plan the
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
> `0027` first, then roll the application forward.** That is exactly what a
> pre-deploy command gives you. Rollback is application-only: leave the
> database forward.

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
| **A** — failure before the first authority migration | Still `0018`. No constraint, no authority table, no `scope` column. Old app fully functional. | None. Nothing partial was applied. Retry `alembic upgrade head`. |
| **B** — failure mid-chain | Sits at `0020` with a consistent schema; `0019`/`0020` applied, `0021` not. Old app fully functional. | None, and **no downgrade**. One revision is one transaction. Retry forward. |
| **C** — schema at head, app not yet rolled forward | `0027`; old app writes audit rows (chain assigned) and administrative events (`scope` defaults to `organisation`). | None. This is the normal pre-deploy window. Roll forward when ready. |
| **D** — app rolled back after the database reached head | Database stays at `0027`. Old app fully functional. | Deploy the previous image and **leave the database forward**. Snapshot restore is only for a schema fault no forward repair can fix, and loses everything written since. |

Both retries reached `0027` with **`alembic upgrade head`**, one invocation.

A migrator killed mid-series also releases the invocation lock automatically:
it is a session lock, so it dies with the session (M7).

## 7 — The Gate-1 failure and its remediation

### What failed at `d7f8206`

`alembic upgrade head` in a **single invocation** failed at `0026` from every
existing start revision tested (`0018`, `0022`, `0024`), leaving the database
at its starting revision:

```
030 drift: a global configuration write holds 2 configuration locks,
           expected exactly the global one
```

`alembic/env.py` wrapped the entire run in **one** transaction. Migration
`029`'s drift guard ended holding a transaction-scoped `authority-config`
advisory lock — taken by the trigger when its probe row was written.
Migration `030`'s drift guard then asserts that a *global* configuration
write holds **exactly one** such lock, counted the two, and refused. The two
guards could not share a transaction.

From an **empty** database the same command succeeded — because
`database/migrations/006_gdpr_erasure.sql` (revision `0002`) contains a bare
`COMMIT;`, which ended Alembic's enclosing transaction early and left every
later migration effectively in its own. An upgrade starting at `0018` never
executes `006`. **Every green full-stack build before this rehearsal was
green by accident.**

### The remediation

The transaction boundary was wrong, so the transaction boundary was fixed.
No migration was rewritten and no drift guard was weakened.

```
session migration lock        pg_advisory_lock, dedicated AUTOCOMMIT connection
    revision 0019   → COMMIT
    revision 0020   → COMMIT
    ...
    revision 0027   → COMMIT
release session lock          pg_advisory_unlock, in a finally
```

- `transaction_per_migration=True`: one revision, one transaction, so a
  transaction-scoped lock taken by one migration is released before the next;
- the invocation lock moved from `pg_advisory_xact_lock` on the migration
  connection to **`pg_advisory_lock` on a connection of its own**. It has to
  outlive each per-revision transaction, which a transaction-scoped lock
  cannot, and acquiring it must not open a transaction Alembic then inherits —
  hence AUTOCOMMIT. That connection issues no DDL and holds no transaction
  open, so it does not hold back vacuum during a long migration;
- a session lock dies with its session, so a migrator that is killed releases
  it without operator intervention.

`tests/test_alembic_migration_model.py` holds this to its contract with real
subprocesses against real databases. **7 of its 10 cases fail against
`d7f8206`**, M1 among them.

| | Contract | Result |
|---|---|---|
| M1 | `upgrade head` from `0018` reaches head in one invocation | PASS (fails at `d7f8206`) |
| M2 | …from `0022` | PASS |
| M3 | …from `0024` | PASS |
| M4 | …from empty, with `0002`'s own BEGIN/COMMIT intact | PASS |
| M5 | each revision commits independently — an outside reader observes intermediate revisions, and `029`→`030` applies cleanly | PASS |
| M6 | two concurrent `upgrade head`: exactly one migrates, both exit 0, one version row, no deadlock | PASS |
| M7 | a migrator that fails mid-series releases the lock; database at the last committed revision; the next invocation continues to head | PASS |
| M8 | nothing migrates while another runner holds the session lock; it waits on *that* lock and resumes | PASS |

## 8 — Deployment: both services migrate, and that is safe

`railway.json` (API) and `railway.worker.json` (worker) both declare
`preDeployCommand: alembic upgrade head`. That is now deliberate and
documented, not an oversight.

```
API pre-deploy ──┐
                 ├── one SESSION advisory lock serialises them
worker pre-deploy┘
        ↓  one invocation migrates 0018 → head, one revision per transaction
        ↓  the waiter acquires the lock, reads alembic_version, finds head,
           applies nothing, exits 0
        ↓  both service deployments continue
```

Proved against the populated staging database at `0018`
(`gate1_evidence/dual_predeploy.json`): the worker applied **9 revisions in
1.79 s**; the API **waited 1.82 s** and exited as a clean no-op; one
`alembic_version` row; no deadlock.

`DEPLOY_RUNBOOK.md` previously claimed the worker does not migrate. It always
did. The runbook now matches the configuration.

## 9 — The management credential

`AUTHORITY_MANAGEMENT_DATABASE_URL` is **not** wired into the API or worker
environment, deliberately. Nothing in `api/`, `workers/` or `mcp_server/`
imports the management primitive — only tests and this harness do — so no
runtime service needs it, and giving it to them would hand every container
the privilege migration 028 removed.

Operational model: migration `031` creates `inntris_authority_admin` with no
password; `scripts/configure_authority_management_role.py` provisions one as
a SCRAM verifier; the credential is held as an operator/management secret and
supplied only to an authorised management job for the duration of a
configuration change. See `docs/runbooks/authority_requirement_rollout.md`.

## 10 — Remaining risks

- **`0021` is the window.** ~1.1 s of blocked reads at 500k `audit_logs`
  rows, scaling with the table. It is the one migration worth timing against
  real production cardinality before the deploy.
- **Production's actual revision is assumed.** Everything here starts from
  `0018_merkle_anchor_visibility`, read from the default branch's migration
  tree. Confirm the live `alembic_version` before deploying.
- **NEW APP / OLD DB crashes rather than refusing.** The sequence protects
  against it, but an out-of-order deploy would produce raw
  `UndefinedFunctionError`s rather than typed refusals.
- **Synthetic sizing.** Every timing here is from invented cardinality.

## 11 — Reproducing

```bash
export ALEMBIC_DATABASE_URL=postgresql://<privileged>@host/inntris_stage
export DATABASE_URL=postgresql://inntris_worker:<pw>@host/inntris_stage
export AUTHORITY_MANAGEMENT_DATABASE_URL=postgresql://inntris_authority_admin:<pw>@host/inntris_stage
export RUNTIME_DATABASE_PASSWORD=<pw>
export AUTHORITY_MANAGEMENT_DATABASE_PASSWORD=<pw>

bash scripts/gate1/build_staging.sh                        # 0018 + synthetic data
python scripts/gate1/rehearse.py        out/rehearsal.json # alembic upgrade head
python scripts/configure_authority_management_role.py
python scripts/gate1/verify_staging.py  out/compatibility.json
python scripts/gate1/inject_failures.py out/recovery.json  # needs lock_timeout set
python scripts/gate1/dual_predeploy.py  out/dual.json      # API + worker together
python scripts/gate1/new_app_old_db.py                     # against a 0018 database

pytest tests/test_alembic_migration_model.py               # M1-M8
```

Never point any of this at production.
