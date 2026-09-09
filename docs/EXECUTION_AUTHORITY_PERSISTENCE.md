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
