# Runbook — execution authority incidents

Phase 7A, Gate 8. What to do when something about delegated authority goes
wrong, written for somebody who has been woken up and has not read the rest
of this repository.

Everything below needs `DATABASE_URL` and is run with
`python -m scripts.authority_control` or
`python -m scripts.provision_executor`. Every mutating command requires
`--by`, `--approval` and `--reason`, and writes immutable evidence.

---

## The one thing to know first

**Halting issuance is safe. Halting consumption is not.**

New authority can always be refused — nothing is mid-flight. But a grant
that has been consumed may already have moved money downstream, and
refusing the executor's retry does not undo that; it only destroys the
record it was trying to reconcile. So the kill switch stops *issuance* and
deliberately leaves consumption alone.

If you believe executions must stop, the lever is the executor's own
credential (below), not the consumption path.

---

## Stop new authority now

```bash
python -m scripts.authority_control kill \
    --control authority_issuance --global \
    --by you@example.com --approval INC-XXXX --reason "one line"
```

Scope it to one tenant with `--org <uuid>` instead of `--global`. A global
engagement wins over any per-organisation row; one tenant cannot opt out.

Effect: every `/authority/evaluate` in scope returns BLOCK with
`authority_issuance_halted`. Grants already issued keep their own lifecycle
and can still be consumed. Release with `restore`.

---

## Symptom → action

### "A customer's delegation was compromised"

Revoke the specific delegation. Nothing else is affected.

```bash
python -m scripts.authority_control revoke \
    --subject authority_reference --issuer <issuer-id> --id <their reference> \
    --by you@example.com --approval INC-XXXX --reason "customer reported compromise"
```

### "An issuer says one of their signing keys is compromised"

Revoke the key by fingerprint. Everything that key signed stops resolving;
the issuer's other keys are unaffected, so a rotated issuer keeps working.

```bash
python -m scripts.authority_control revoke \
    --subject issuer_key --issuer <issuer-id> --id <fingerprint> \
    --by you@example.com --approval INC-XXXX --reason "issuer disclosed compromise"
```

Then remove or mark the key `revoked` in the trust configuration and deploy,
so the revocation survives a database restore. The row is the fast path; the
configuration is the durable one.

### "An entire issuer is compromised"

```bash
python -m scripts.authority_control revoke \
    --subject issuer --id <issuer-id> \
    --by you@example.com --approval INC-XXXX --reason "issuer breach"
```

Consider halting issuance globally as well while you assess: revocation
stops that issuer, a halt stops everything, and during an unclear incident
the second is the safer default.

### "An executor credential has leaked"

Revoke the credential. It stops authenticating immediately, so it can issue
nothing and consume nothing.

```bash
python -m scripts.provision_executor revoke --key-id <uuid> \
    --by you@example.com --approval INC-XXXX --reason "credential leaked"
```

Grants already issued to that executor become unspendable — nothing else
holds its binding — and expire on their own schedule. **Their reserved
spend is not released**, deliberately: see *Unresolved outcomes* below.

Issue the replacement with `provision_executor create` and give it to the
service. It is a *different* executor and cannot spend the old one's
grants; that is the cost of binding authority to a credential and it is the
right cost.

### "We rolled the delegated-authority requirement out too widely"

```bash
python -m scripts.authority_control kill \
    --control requirement_enforcement --org <uuid> \
    --by you@example.com --approval INC-XXXX --reason "rollback"
```

This is the **only** control here that weakens enforcement. Every
suppressed requirement is logged at WARNING and counted in
`inntris_authority_requirement_suppressed_total`. It should never be left
on quietly — fix the configuration with `authority_control require
--exempt` for the specific scope and then `restore` the switch.

### "Consume failures are spiking"

Read the rejection reason on `inntris_authority_consumptions_total`. It
tells you which of these you have:

| Reason | What it means | Action |
|---|---|---|
| `policy_hash_mismatch` | A policy changed after grants were issued | Expected in a burst after a deliberate change. Sustained means something is issuing against policy it cannot spend under — look at what changed |
| `agent_not_active` | A principal was suspended mid-flight | Expected if somebody just suspended it |
| `grant_already_consumed` / `execution_ref_conflict` | An executor is retrying with a NEW reference | The executor is generating a fresh reference per attempt. That is a client bug: retries must reuse the original reference, or they read as second executions |
| `grant_executor_mismatch` | Something is presenting another executor's grant | Investigate as a possible credential problem |
| `authority_revoked` / `authority_expired` | The delegation died between issuance and consumption | Expected after a revocation |
| `grant_sandbox_execution_denied` | A sandbox principal reached a production path | A provisioning error, not an attack |

### "Authority verification failures are spiking"

`inntris_authority_verification_failures_total` (by code) is *callers*
presenting delegations that do not verify.
`inntris_authority_key_resolution_failures_total` is **us** being unable to
check at all. They are counted separately on purpose.

If key-resolution failures are rising, the cause is almost always that the
revocation read is failing — which fails closed, so nothing unsafe is
happening, but nothing is being authorised either. Check the database
before anything else.

---

## Unresolved outcomes, and why capacity is never auto-released

`inntris_authority_unresolved_outcomes` counts grants that were consumed
and whose downstream result is still unknown. Each one holds spend capacity
that is **never released automatically**, in any outcome, including a
proven failure.

This looks wrong and is not. A timeout, a dropped connection or a thrown
executor is `outcome_unknown`, never `failed_final`: it is not proof that
no money moved. Releasing the reservation would hand the same capacity to a
second transaction while the first may well have settled, turning one
uncertain payment into two certain ones.

So releasing consumed capacity requires authoritative downstream evidence
and a reviewed reconciliation, never a timer.

**When this gauge climbs:**

1. Find the grants:

   ```sql
   SELECT id, agent_id, outcome_state, outcome_reference, outcome_recorded_at
   FROM execution_authority_grants
   WHERE status = 'consumed' AND outcome_state = 'pending'
   ORDER BY issued_at;
   ```

2. For each, ask the downstream rail what actually happened, using
   `outcome_reference`. The rail is authoritative; our record is not.
3. Record the resolved outcome. The database permits one direction only —
   nothing returns to `pending`.
4. Only then, and only with the rail's own evidence in hand, decide whether
   capacity should be returned.

If the executor cannot tell you, the answer is not "assume it failed".

---

## After a rolling deploy or rollback

Grants whose token was consumed by an old application instance show as
`active` while the token is spent. They are unspendable (the claim would
find the token gone) but the row disagrees with reality. Find them:

```sql
SELECT g.id, c.audit_log_id, c.execution_ref
FROM execution_authority_grants g
JOIN approval_token_consumptions c ON c.token_id = g.approval_token_id
WHERE g.status = 'active';
```

Resolve forward by marking each grant consumed against the existing
consumption record. Never delete them.

---

## Checking what is currently configured

```bash
python -m scripts.authority_control show --org <uuid>   # requirements + switches
python -m scripts.authority_control trust               # issuers + revocations
python -m scripts.authority_control bindings --agent <uuid>
python -m scripts.provision_executor list --org <uuid>
```

`show` states the effective default explicitly so you do not have to infer
it from an empty list: **where no row applies, delegated authority is not
required.**

---

## What is NOT in this runbook

Rail settlement. Inntris Core owns authority persistence, not settlement;
there is deliberately no settlement engine here. If money needs to be
moved, refunded or reversed, that is the rail's runbook and the executor's,
and the MTP receipt is a linked boundary rather than proof of it.
