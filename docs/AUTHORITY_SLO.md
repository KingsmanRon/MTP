# Authority path — measured performance, SLOs, and one release blocker

Phase 7A, Gate 7. Every number here was measured by
`loadtests/authority_benchmark.py`; none was chosen. Raw output:
`docs/release/phase-7a/performance.json`.

> **Host caveat, stated once.** Measured on the release-engineering host
> against its own PostgreSQL 16, single node, no network hop. Absolute
> latencies are host-specific. What transfers is the *shape*: which stage
> dominates, where contention appears, and which failures are structural
> rather than incidental. Re-run on staging hardware before quoting these
> as production SLOs.

---

## RELEASE BLOCKER — consumption deadlocks under concurrent load

**This gate does not pass.** It is recorded here rather than smoothed over,
because it is the kind of finding a release gate exists to produce.

### What was measured

Consuming many *distinct* grants belonging to **one principal**, at
concurrency 32:

| | |
|---|---|
| Attempts | 320 |
| Succeeded | 1 |
| Failed | 319 |
| — lock timeouts | 262 |
| — `40P01 deadlock_detected` | 57 |

Spreading the identical work across **32 principals** improves it greatly
but does not fix it:

| | |
|---|---|
| Attempts | 320 |
| Succeeded | 275 |
| Failed | 45 (14.1%), all `40P01 deadlock_detected` |
| p50 | 4.9 ms |
| p99 | 6993 ms |

A 14% deadlock rate on the path that spends authority to move money is not
acceptable for production, and the single-principal case is worse than that.

### Root cause

Two per-agent serialisation points that can be acquired in either order.

`assign_audit_chain_sequence`, a BEFORE INSERT trigger on `audit_logs`
(migration `015_durable_security_state.sql`), does this **inside the
insert**:

```sql
PERFORM pg_advisory_xact_lock(hashtext(NEW.agent_id::TEXT)::BIGINT);
SELECT action_hash, chain_sequence INTO ...
  FROM audit_logs WHERE agent_id = NEW.agent_id
  ORDER BY chain_sequence DESC LIMIT 1;
NEW.chain_sequence := COALESCE(v_previous_sequence, 0) + 1;
```

and `idx_audit_logs_agent_chain_sequence` is `UNIQUE (agent_id,
chain_sequence)`.

So an audit append holds a per-agent advisory lock until its transaction
commits, *and* claims a per-agent unique index entry. Every observed
deadlock has exactly this shape:

```
Process A: INSERT INTO audit_logs   -> waits for ShareLock on transaction B
                                       (B already claimed that chain_sequence)
Process B:                          -> waits for ExclusiveLock on advisory lock
                                       (held by A)
```

A transaction that appends audit rows while holding a per-agent advisory
lock it took earlier — or that appends under more than one agent — can
form a cycle with another doing the same in the opposite order.

### What this is, and is not

* **Not a correctness defect.** PostgreSQL detects the cycle and aborts one
  transaction whole. Nothing is half-written: no grant, no consumption
  record, no reservation change. The system fails closed, which is why
  every Gate 6 invariant still holds under stress (see
  `tests/test_authority_race_stress.py`, 11 passed at concurrency 64 ×
  30 rounds).
* **Not introduced by v0.5.** The trigger and its unique index come from
  migration 015, which predates the authority work in 023+. The authority
  path does more work inside that serialised window, so it is more exposed
  — but the serialisation point is older than this release.
* **It is an availability and capacity defect**, and on the consumption
  path specifically it is severe.

### Reproduce it

```bash
DATABASE_URL=... python -m loadtests.authority_benchmark \
    --concurrency 32 --iterations 320 --agents 32
```

The `consume` and `multi_agent_consume` stages report the failures and
their SQLSTATEs.

### What a fix looks like — not attempted here

Deliberately not fixed in this phase. The trigger's lock is *documented as
intentional*: it is what stops two concurrent appends forking one agent's
forensic hash chain. Changing it changes an integrity mechanism, and a
wrong change there is far worse than a retryable deadlock. The options, for
a decision outside release engineering:

1. **Retry on 40P01.** A deadlock abort rolls the transaction back
   entirely, and issuance is already idempotent on `issuance_ref`, so a
   bounded retry is safe and would mask the symptom. Cheapest; does not
   address the ceiling.
2. **Take the agent lock first, always.** Give every path one documented
   entry lock per agent, acquired before any other per-agent resource, so
   no two paths can invert. Removes the cycle; keeps the serialisation.
3. **Stop serialising the chain per agent.** Chain by insertion order with
   a monotonic sequence, or shard the chain. Removes the ceiling; changes
   what the hash chain asserts, so it needs its own review.

Until one of these lands, the deployment constraint below applies.

### Interim deployment constraint

Do not run more than a small number of concurrent consumptions per
principal. The canary (Gate 10) is bounded to one principal executing
serially and is unaffected. Any rollout beyond that needs this fixed first.

---

## Measurements that did pass

Concurrency 32, 320 iterations, 32 principals for the multi-agent stages.

| Stage | p50 | p95 | p99 | Throughput | Failures |
|---|---|---|---|---|---|
| `authority_evaluation` (1 principal) | 119 ms | — | 1416 ms | 127/s | 0 |
| `multi_agent_issuance` (32 principals) | 59 ms | — | 132 ms | 497/s | 0 |
| `lock_contention` (many → 1 grant) | 41 ms | — | 90 ms | 402/s | 0 |
| `vi_verification` | 0.20 ms | — | 0.37 ms | 4640/s | 0 |
| `receipt_signing` | 0.14 ms | — | 0.19 ms | 7054/s | 0 |

Three things worth stating plainly:

**Issuance scales across principals and degrades within one.** 497/s spread
over 32 principals against 127/s on a single one, with p99 rising from
132 ms to 1416 ms. The same per-agent serialisation as above, surviving
rather than failing.

**Contention on a single grant is well behaved.** 32 consumers racing one
grant: zero failures, p99 90 ms, exactly one authorised. The lock ordering
*within* a single grant is correct; the problem is across grants of one
agent.

**Verification and signing are free.** VI verification (parse, Ed25519
verify, binding checks) at 0.2 ms and v3 evidence signing at 0.14 ms are
three orders of magnitude below the database work. Neither is worth
optimising, and neither should be blamed when latency moves.

---

## SLOs derived from the measurements

Set from the stages that passed, at the multi-principal shape, which is
what production looks like. Each threshold is the measured p99 with
headroom, so it fires on a real regression rather than on normal variance.

| Objective | Threshold | Derived from |
|---|---|---|
| Authority evaluation p99 | < 500 ms | measured 132 ms multi-principal; ~3.8× headroom |
| Authority evaluation availability | ≥ 99.5% non-error | measured 0 failures in 320 |
| Consume p99 | < 250 ms | measured 4.9 ms p50 multi-principal; p99 excluded pending the blocker |
| VI verification p99 | < 10 ms | measured 0.37 ms; ~27× headroom for a network-resolving future |
| Receipt signing p99 | < 5 ms | measured 0.19 ms |
| Deadlock rate | **0 per hour** | measured 45/320; any occurrence is the blocker above |

**No consume-availability SLO is published.** Setting one now would mean
either quoting a number the system does not meet or choosing a lenient one
to make the blocker disappear. It is published once the blocker is fixed
and re-measured.

The alert rules in `ops/prometheus/inntris-alerts.yml` use these thresholds
and nothing else.

---

## Re-measuring

```bash
DATABASE_URL=... python -m loadtests.authority_benchmark \
    --concurrency 32 --iterations 320 --agents 32 \
    --json docs/release/phase-7a/performance.json
```

Re-run on staging before the merge/deploy decision, and again after the
deadlock fix. A comparison against `performance.json` is the evidence that
a change helped.
