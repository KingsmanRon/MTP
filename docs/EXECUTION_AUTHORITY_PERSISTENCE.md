# Execution authority persistence

How bounded, single-use execution authority is stored, claimed and
reconciled. Companion to `EXECUTION_BINDING.md`, which describes the
executor-facing `/verify-token` contract that this layer preserves.

## One authoritative consumption state

There is exactly one answer to "has this authority been spent", and it is
the `approval_token_consumptions` row. That table was already the
single-use authority for approval tokens: primary key on `token_id`,
unique `token_digest`, unique `(agent_id, execution_ref)` partial index
for retries, and triggers that block UPDATE and DELETE.

A grant carries an `approval_token_id`. Claiming the grant **is**
inserting that row, through the same code path the legacy executor gate
uses. There is no second table that could disagree.

```
execution_authority_grants ──approval_token_id──► approval_token_consumptions
            │                                              ▲
            └──spend_reservation_id──► spend_reservations ─┘
                                        (flipped to 'consumed' by the claim)
```

## Deployment gate: `agents_id_org_unique`

> **This migration must not reach the deployment branch without a
> deliberate release decision.** `railway.json`, `railway.worker.json` and
> the Dockerfile all run `alembic upgrade head`, so a merge migrates
> production automatically.

Migration 023 adds `ALTER TABLE agents ADD CONSTRAINT agents_id_org_unique
UNIQUE (id, org_id)`. `agents` is a hot table on the `/verify` path, and
building a unique index takes an `ACCESS EXCLUSIVE` lock for the duration
— every read and write on `agents` blocks while it runs.

**No claim is made here about how long that takes in production, and no
measurement has been done.** Before release this needs, at minimum:

1. row count and index build time measured on a production-sized copy;
2. a decision between accepting the lock in a maintenance window and
   building it concurrently (`CREATE UNIQUE INDEX CONCURRENTLY` outside a
   transaction, then `ADD CONSTRAINT ... USING INDEX`), which Alembic's
   transactional DDL does not do by default;
3. confirmation that no long-running transaction is holding `agents`,
   since the `ACCESS EXCLUSIVE` request queues behind it and blocks every
   later reader in the meantime.

The composite ownership design is kept because it is the right integrity
model. The *deployment* of it is a separate, unmade decision.

## Reservation accounting

Spend is held in `spend_reservations`, reserved by the same
advisory-locked increment-and-test `/verify` uses. Its state across the
authority lifecycle:

| Event | Reservation | Why |
|---|---|---|
| Issuance succeeds | `reserved` | Capacity is committed the moment authority exists, not when it is spent. Otherwise two grants could each be issued against the same headroom. |
| Issuance fails (limit) | none | The whole transaction rolls back. A refused request leaves no counter incremented. |
| Issuance fails (any error) | none | Same transaction, same rollback. |
| Grant expires unspent | `expired` | Swept by the existing expiry pass at approval-token expiry; capacity returns automatically. |
| Grant revoked unspent | `released` | An explicit withdrawal is proof nothing will be executed. |
| First consumption | `consumed` | Charged. Done by the existing claim path, not by new code. |
| Outcome: succeeded | `consumed` | Money moved. |
| Outcome: proven final failure | `consumed` | **Not released here.** Returning capacity belongs to a reconciliation path holding the rail's own evidence, not to the executor's report. |
| Outcome: unknown | `consumed` | **Never released.** See below. |

### An unknown outcome is not a refund

A timeout, a dropped connection, or a thrown executor is
`outcome_unknown`, never `failed_final`. **It is not proof that no money
moved.**

Releasing the reservation on an unknown outcome would hand the same
capacity to a second transaction while the first may well have settled —
turning one uncertain payment into two certain ones. So reserved and
consumed spend is never released because an executor timed out. The
reservation stays charged until authoritative evidence resolves the
outcome to `succeeded` or `failed_final`, and the database only permits
that one direction: nothing returns to `pending`.

This mirrors the failure model used by the x402 policy adapter
(`docs/RECONCILIATION.md` in that repository), which classifies a thrown
settlement as unknown by default for the same reason. **Core owns
authority persistence, not rail settlement**; there is deliberately no
settlement engine here.

Releasing consumed capacity is therefore never automatic, in any outcome
including a proven final failure. It requires a separate reconciliation
path holding authoritative downstream evidence, which is not part of this
phase.

## Lock order

Every path takes locks in the same order, so two of them cannot form a
cycle:

1. the entry advisory lock — `authority-issuance:<agent>:<ref>` for
   issuance, `authority-grant:<grant>` for consumption;
2. the `agents` row, `FOR SHARE`. This is the mutable principal and policy
   state that authorisation derives from. Taking it *before* deriving
   current policy, and holding it until commit, is what closes the window
   in which a concurrent `UPDATE agents` could commit between the read and
   the claim. `FOR SHARE` rather than `FOR UPDATE` so concurrent
   consumptions of different grants for one agent still proceed, while any
   writer to that row waits;
3. the `execution_authority_grants` row, `FOR UPDATE`;
4. the spend advisory lock `spend-reservation:<agent>` (issuance only,
   inside the reused reservation primitive);
5. inserts into `audit_logs` / `approval_token_consumptions`, then the
   grant and reservation updates.

Nothing acquires a lock earlier in this list while holding one later in it.

## Delegated authority evidence

When a grant was issued under delegated authority it records that
authority's digest. Consumption then **requires** current trusted evidence
about it — absent evidence is not evidence of validity, and a grant whose
basis may have been revoked minutes ago must not be spendable just because
nobody looked.

That evidence is one input binding four things together so they cannot be
supplied separately or partially: which authority it concerns
(`scope_digest`), whether it still verifies, whether it has been revoked,
and its own expiry.

**The store validates evidence supplied to it; it does not re-resolve an
external issuer.** Phase 3 is provider-neutral and performs no network
call. A later phase resolves the provider *before* entering the atomic
consume section and hands the result in.

## Grant lifetime

`expires_at` is clamped at issuance to the earliest of:

1. the configured execution-authority TTL ceiling
   (`MAX_EXECUTION_AUTHORITY_TTL`);
2. whatever the caller requested;
3. the delegated authority's own expiry, when delegation exists;
4. any tighter trusted bound supplied.

A grant may never outlive the authority it rests on. The clamp is
application code; the schema enforces the same rule independently
(`execution_authority_within_delegated_validity`), so a row that violates
it cannot exist even if written by something other than the store. An
already-expired delegation raises rather than issuing a grant that is
dead on arrival.

## Same-reference retry versus different-reference replay

Two different questions, deliberately answered differently.

**Same `execution_ref`** — "I lost your response; what happened?" The
caller generated the reference before its first attempt and is retrying
the *same* attempt. A committed consumption with that exact reference is
returned as `RECOVERED`, including after the grant expired: the authority
was spent while it was valid, and this hands back the record of it.
`RECOVERED` carries `may_execute = False`. It authorises nothing, starts
no execution, and does not move the grant.

**Different `execution_ref`** — "here is a *new* attempt." Against a
grant that has already been claimed this is a second execution of
single-use authority, and it is refused with `execution_ref_conflict`.

Recovery is checked before every lifecycle rejection, which is what lets
an expired grant still answer a retry. It is never reachable for an
unconsumed grant: with nothing committed there is nothing to recover, and
the request falls through to the normal lifecycle checks, where an
expired grant is refused. A caller that omits `execution_ref` entirely
gets strict single-use with no recovery — the pre-existing behaviour,
carried over deliberately.

## Rolling deployment and mixed versions

**No conversion, no backfill.** A legacy approval token is simply a token
with no grant row. Both paths claim through
`approval_token_consumptions`, so during a rolling deploy:

* old application instances keep issuing and consuming plain approval
  tokens, unchanged;
* new instances additionally write grants, whose claim key is a token in
  the same table;
* an old instance consuming a grant-backed token still burns it exactly
  once, because the uniqueness constraint is the authority — it just does
  not update the grant row's status. The grant remains unspendable
  afterwards: the store's claim would find the token already consumed.

Historical tokens are never rewritten.

### Forward repair after an application rollback

If the migration applies but the application rollout has to be rolled
back, the new table is inert: nothing in the old code path reads or
writes `execution_authority_grants`, and the reservation and consumption
tables it references are unchanged. No repair is required to run the old
version.

Rolling forward again needs one reconciliation only: grants whose
`approval_token_id` appears in `approval_token_consumptions` while the
grant row still reads `active` — a token consumed by an old instance that
could not update the grant. These are resolved forward by marking the
grant consumed against the existing consumption record. They are found
with:

```sql
SELECT g.id, c.audit_log_id, c.execution_ref
FROM execution_authority_grants g
JOIN approval_token_consumptions c ON c.token_id = g.approval_token_id
WHERE g.status = 'active';
```

The migration is forward-only. `downgrade()` raises: grants record what
was authorised and whether it was spent, and dropping them would destroy
the evidence that gated real executions.

## Typed outcomes

Issuance: `issued`, `idempotent`, `conflict`, `refused`.

Consumption: `authorised`, `recovered`, `rejected` — with a stable
rejection code drawn from the existing decision vocabulary:
`grant_not_found`, `grant_malformed`, `grant_action_mismatch`,
`grant_executor_mismatch`, `execution_ref_conflict`, `grant_revoked`,
`grant_expired`, `grant_already_consumed`, `agent_not_active`,
`policy_hash_mismatch`, `authority_expired`, `authority_revoked`,
`authority_verification_failed`, `authority_scope_exceeded`.

These are internal. The legacy `/verify-token` reason strings are
unchanged; internal outcomes are mapped at the compatibility boundary
rather than altering the deployed contract.
