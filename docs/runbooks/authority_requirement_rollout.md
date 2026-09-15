# Delegated-authority requirement rollout — deployment and enrolment

The delegated-authority requirement decides whether real money may move
without a delegation. Its configuration now lives in the database and
nowhere else.

## Sources

| source | status |
|---|---|
| `authority_requirements` / `authority_controls` | **the only source** |
| `INNTRIS_AUTHORITY_REQUIRED_ORGS` | **decommissioned**; startup tripwire only |
| injected `requirement_resolver` | test and proof seam only; production passes none |

The environment variable is never unioned with, intersected with, or used
as a fallback for the database answer. It cannot enrol anything.

## What the runtime resolves

One statement, one snapshot, per operation — `resolve_authority_configuration`
in `api/persistence/authority_configuration.py`. It answers three questions
together, because asking them separately against a mutable table can produce
a decision assembled from two different configurations:

1. **Is new issuance halted?** `authority_issuance`, global or per
   organisation. A global row cannot be cancelled by an organisation row set
   to `engaged = FALSE`: only engaged rows are considered, so there is
   nothing for a tenant to override. Consumption of already-issued authority
   is deliberately unaffected — halting it would strand an executor
   mid-flight and turn one uncertain payment into an unanswerable one.
2. **Which requirement row wins?** Most specific first:
   `(agent, class)` → `(agent, *)` → `(*, class)` → `(*, *)` → no row means
   **not required**.
3. **Is enforcement suspended?** `requirement_enforcement`, organisation
   scoped only — migration 028 makes a global row impossible, because one
   switch must not suspend every organisation at once. It suppresses only a
   requirement that was configured; with nothing configured it changes
   nothing, and it never lifts an issuance halt.

The resolved snapshot is carried through the rest of evaluation.
`PaymentDomainPolicy` receives the result, not the resolver, so it cannot
re-query.

**A configuration that cannot be read is not a value.** It does not become
"required", because the halt state would still be unknown. It raises, and
the caller returns `AUTHORITY_CONFIGURATION_UNAVAILABLE`. No new execution
authority is issued under it, and there is no fallback to the environment,
to legacy behaviour, or to "not required".

## Deployment preflight

Before activating the configuration reader:

1. **Confirm `INNTRIS_AUTHORITY_REQUIRED_ORGS` is empty** in every
   environment. The repository cannot prove what a hosting dashboard sets,
   so the application refuses to start in production while it is non-empty.
   If it is set, migrate each listed organisation to a requirement row
   first, then unset it.
2. Confirm the schema is at `0024_authority_config_hard` or later.
3. Confirm the runtime role holds only `SELECT` on both tables.

## Enrolment order — do not shortcut this

```
1. schema (0023 + 0024) deployed, both tables EMPTY
2. reader code deployed
3. ALL old application instances gone
4. every live instance verified to be running the reader
5. ONLY THEN create the first authority_requirements row
```

Old instances are blind to requirement rows: they read the decommissioned
environment variable, which now enrols nothing. A row created while any old
instance is still serving is enforced by some instances and ignored by
others — a partial fail-open that is invisible from the table, because the
row looks correct.

This cannot be fixed in code. Old code cannot be taught to read a table it
does not know about. The ordering is the mitigation.

## Blocker before any production enrolment

**Consume-time re-check is not implemented yet.** A grant issued while the
requirement was `FALSE` can currently still be consumed after the
requirement becomes `TRUE`.

The intended invariant, to be implemented and tested before enrolling a
production organisation:

- a **fresh** consume re-checks the current requirement; if delegation is
  now required and the grant carries no qualifying delegated authority, the
  fresh consume refuses;
- **same-`execution_ref` recovery** of an already-consumed grant remains
  recovery of a historical fact and is not re-authorised;
- `authority_issuance` stays issuance-only and never invalidates already
  valid consumed or recovery state.

Do not enrol a production organisation until this exists, or an alternative
semantic is explicitly approved.

## Linearisation — the lock discipline

There are **two** configuration locks, in one advisory namespace, and they
are **ranked**:

```
CONFIG_GLOBAL   authority-config:global      ← platform-wide rows (org_id IS NULL)
    ↓
CONFIG_ORG      authority-config:<org_id>    ← one organisation's rows
```

Who takes what:

| Path | Takes | Why |
|---|---|---|
| **Issuance** | `CONFIG_GLOBAL` shared → `CONFIG_ORG` shared | gated by the global `authority_issuance` halt *and* the organisation's rows, so it must lock both scopes it reads |
| **Fresh consumption** | `CONFIG_ORG` shared only | does not consult the global control; halting new issuance must not invalidate authority already issued |
| **Every configuration write** | `CONFIG_GLOBAL` exclusive → `CONFIG_ORG` exclusive (org-scoped rows only) | migrations 029/030 take these from a `BEFORE INSERT OR UPDATE OR DELETE` row trigger, so a writer cannot forget and a direct SQL writer cannot bypass them |

Each path takes its locks on the connection whose transaction will commit
the decision, reads the configuration on that same connection, and holds
them to commit.

**The global lock is taken first on every configuration write, whatever the
row's scope.** That is what makes the ranking total: `CONFIG_ORG →
CONFIG_GLOBAL` becomes unconstructible, so no two writers — in any statement
order, across any number of rows — can form a cycle. It also means an
issuance past the global lock can never queue behind a configuration writer,
because a writer can only hold `CONFIG_ORG` exclusively if it also holds
`CONFIG_GLOBAL`.

Why the global lock had to exist: `authority-config:<A>` and
`authority-config:global` do not conflict, yet the effective configuration
for organisation A *consults* the global row. Issuance holding only the
organisation key let a platform-wide halt commit underneath an issuance
already in flight, and that issuance still wrote its grant. **The scope that
is read has to be the scope that is locked.**

Every part of both keys is derived by PostgreSQL —
`authority_config_lock_namespace()` and `authority_config_lock_key()`, the
same functions the trigger calls. Nothing about a key is computed in Python,
including the literal `global`. A hash collision merely serialises two
scopes that did not need it; it can never produce a missed lock.

What this buys:

> If a configuration change commits before a fresh consumption or issuance
> commits, that operation either observed the new configuration, or it had
> already linearised before the change by holding a lock that prevented the
> change from committing.

`org_id` is immutable on both tables. Moving a row between organisations
would mean two different locks governing one statement, so the trigger
refuses it outright rather than picking one.

### Lock order — read this before adding a management path

```
issuance     ISSUE  → CONFIG_GLOBAL → CONFIG_ORG → PRINCIPAL → GRANT → RESERVATION
consumption  GRANT  → TOKEN → CONFIG_ORG → FORENSIC CHAIN → PRINCIPAL → GRANT ROW → claim/audit
writer       CONFIG_GLOBAL → CONFIG_ORG → administrative audit → commit
```

A management path must take the **configuration locks first**, and then do
its administrative audit work:

```
CONFIG_GLOBAL exclusive → CONFIG_ORG exclusive → configuration mutation
                        → administrative audit → commit
```

It must **never** take `FORENSIC CHAIN → CONFIG`. Consumption holds CONFIG
before CHAIN, so the reverse order closes the ABBA cycle Gate 7 was opened
to remove. Concretely: write the configuration row **before** the audit row,
because the trigger takes the configuration locks at the moment the
configuration row is written — a path that wrote its audit row first would
still invert.

Do **not** add `CONFIG_GLOBAL` to consumption. It changes no decision
consumption makes, and it would put every spend on the platform behind a
single lock that operators take exclusively.

## Management writes

A configuration change and its administrative audit record commit in **one
transaction**, or neither commits. There is no supported path that produces a
policy change nobody can attribute, or an audit record for a change that
rolled back.

### The primitive

`api/persistence/authority_configuration_management.py`:

- `apply_authority_configuration_change(management_db, …)` — one change in a
  transaction of its own;
- `apply_authority_configuration_change_on(conn, …)` — the same on a
  caller-supplied connection, for a surface that must do something else in
  the same atomic act.

**The caller of `*_on` must already have opened a transaction, and the
primitive refuses to run otherwise.** Outside one, asyncpg commits every
statement by itself: each configuration lock is released as its statement
ends and serialises nothing, the configuration row commits alone, and a
failing audit insert leaves the change with no record of it — invariant 7
violated, silently. The check is the first thing `*_on` does, before the
locks, the pre-image read and both writes, and it fails closed: a connection
that cannot report its transaction state is refused too.

It does **not** open a transaction of its own. `*_on` exists so several
actions can be composed inside one caller-owned transaction; a transaction
opened here would commit the first of them independently and break exactly
the composition it is for. Use the wrapper for a single change:

```python
async with management_db.acquire() as conn, conn.transaction():
    await apply_authority_configuration_change_on(conn, …)   # one
    await apply_authority_configuration_change_on(conn, …)   # or several
```

`setting` is `"requirement"`, `"authority_issuance"` or
`"requirement_enforcement"`. There is deliberately **no generic
INSERT/UPDATE/DELETE contract**: a caller states which setting it is changing
and to what, and supplies `actor`, `reason` and `approval_reference`. Absent,
blank or whitespace-only values are refused before anything is written — the
`CHECK` constraints behind them are the backstop, not the contract.

The audit record carries who, what row, from what, to what, why, under which
approval, when, and for which organisation / principal / action-class scope.
Its own id is the correlation reference and is returned to the caller.

### Transaction boundary and lock order

```
BEGIN
  CONFIG_GLOBAL exclusive
  CONFIG_ORG    exclusive        (organisation-scoped changes only)
  read the row being replaced    -- the audit pre-image
  write the configuration row    -- the 029/030 trigger re-takes the same
                                    two keys, in the same order, free
  append administrative_audit_events
COMMIT
```

The two locks are taken **before** the pre-image read on purpose. The trigger
would take them anyway, but only when the write statement runs, and a read
before that could report a version another writer had already replaced —
making the recorded transition one that never happened. This is the same
order the trigger uses, not a different one.

The configuration row is written **before** the audit row. The trigger takes
the configuration locks at the moment the configuration row is written, so a
path that wrote its audit row first would invert the accepted order even
though both rows still committed together.

`administrative_audit_events` carries no forensic-chain trigger, so this path
never takes the per-agent chain lock. `CONFIG → FORENSIC CHAIN` cannot invert
with consumption's `CONFIG_ORG → FORENSIC CHAIN` because this side of it does
not exist. That is asserted from `pg_locks`, not assumed.

### Why there is no audit trigger on the configuration tables

An `AFTER` trigger would make the audit automatic and harder to forget. It is
not used:

- the record must name the actor, the reason and the approval reference. A
  trigger sees only the row, so those would travel in session GUCs — unset by
  an emergency operator, and the audit then records nobody;
- it would make every direct SQL write acquire whatever the audit path
  acquires, inside transactions whose lock graph nobody has proved. The
  Gate-7 deadlock was exactly that shape.

### The direct-SQL boundary — read this before an incident

The 029/030 trigger guarantees **lock ordering** for any writer, including
raw SQL. It cannot guarantee **audit semantics**: nothing in the database
forces a direct `UPDATE authority_controls …` to also write an audit row.

- the **runtime role** (`inntris_worker`) is `SELECT`-only on
  `authority_requirements`, `authority_controls` and — for writes —
  `administrative_audit_events`. It cannot change configuration at all, and
  must never be given the privilege to. Migration 028 exists for this;
- the **tenant role** (`inntris_api`) is `SELECT`-only on configuration,
  scoped by RLS to its own organisation, and cannot see the administrative
  audit trail at all;
- the **supported** production configuration change is the primitive above,
  running as `inntris_authority_admin` (migration 031, password provisioned
  by `scripts/configure_authority_management_role.py`, never by migration
  history). That role may change the two configuration tables and append to
  `administrative_audit_events`, and nothing else — no `DELETE` anywhere;
- **migrator / operator emergency SQL** bypasses the primitive and therefore
  bypasses the audit record. It is exceptional. If it is used, the operator
  must record the change out of band — who, what, from what, to what, why,
  under which approval — and reconcile it against
  `administrative_audit_events` afterwards, because the table will not show
  it. Treat an emergency configuration change with no corresponding audit row
  as an unexplained change until that reconciliation exists.
