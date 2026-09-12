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

One advisory namespace per organisation, `authority-config:<org_id>`:

- **Fresh consumption and fresh issuance** take it **SHARED** and hold it to
  commit, then read the configuration on that same connection.
- **Every mutation** of `authority_requirements` / `authority_controls` takes
  it **EXCLUSIVE** and holds it to commit. Migration 029 takes it from a
  `BEFORE INSERT OR UPDATE OR DELETE` row trigger, so a writer cannot forget
  and a direct SQL writer cannot bypass it.

Both halves of the key are derived by PostgreSQL —
`hashtext(authority_config_lock_namespace())` and `hashtext(<org text>)` —
and the application calls the same `authority_config_lock_namespace()`
function the trigger calls. Nothing about the key is computed in Python. A
hash collision merely serialises two organisations that did not need it; it
can never produce a missed lock.

What this buys:

> If a configuration change commits before a fresh consumption or issuance
> commits, that operation either observed the new configuration, or it had
> already linearised before the change by holding the shared lock that
> prevented the change from committing.

`org_id` is immutable on both tables. Moving a row between organisations
would mean two different locks governing one statement, so the trigger
refuses it outright rather than picking one.

### Lock order — read this before adding a management path

```
GRANT/ISSUE → TOKEN → CONFIG → FORENSIC CHAIN → PRINCIPAL ROW → GRANT ROW → claim/audit
```

A management path must take **CONFIG (exclusive) first**, then do its
administrative audit work:

```
CONFIG exclusive → configuration mutation → administrative audit → commit
```

It must **never** take `FORENSIC CHAIN → CONFIG`. Consumption holds CONFIG
before CHAIN, so the reverse order closes the ABBA cycle Gate 7 was opened
to remove. Concretely: write the configuration row **before** the audit row,
because the trigger takes CONFIG at the moment the configuration row is
written — a path that wrote its audit row first would still invert.

## Management writes

There is no authority-management write surface, and the runtime role cannot
create one by accident: it holds `SELECT` only. When that surface is built:

- every requirement/control change must write an immutable
  `administrative_audit_events` row in the **same transaction**, enforced by
  the database rather than by convention;
- the guard must not fabricate actor, reason or approval provenance — those
  are supplied by the caller and recorded, not invented by a trigger;
- prefer a narrow management role or function; the generic runtime role must
  not regain configuration DML.
