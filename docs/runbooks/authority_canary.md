# Production canary — bounded first execution

Phase 7A, Gate 10. The procedure for the first real delegated execution in
production, and the evidence each step must produce.

> **Status: NOT EXECUTED.**
>
> Two things block it, both recorded rather than worked around:
>
> 1. **Phase 7B has not delivered a guarded executor.** Gate 10 requires one
>    by its own terms. Without it there is nothing on the far side of an
>    ALLOW, and steps 4–7 below cannot happen at all.
> 2. **The Gate 7 deadlock blocker** (`docs/AUTHORITY_SLO.md`). The canary
>    itself is unaffected — it is one principal executing serially, which is
>    the one shape that does not contend — but no rollout past the canary
>    should happen until it is fixed.
>
> Running a partial canary and reporting it as a pass would be worse than
> not running one: it would put a green tick against a boundary nobody has
> actually crossed.

---

## Preconditions

Every one of these is checked before the first probe, not assumed.

| # | Precondition | How to check |
|---|---|---|
| 1 | Migration at head | `alembic current` matches `0025_authority_binding` |
| 2 | A trusted issuer is configured | `authority_control trust` lists it active with the expected fingerprint |
| 3 | The canary principal is bound to its issuer identity | `authority_control bindings --agent <uuid>` |
| 4 | An executor credential exists, scoped to one action class | `provision_executor list --org <uuid>` shows `execute:<action>` and nothing else |
| 5 | The requirement is enabled for the canary scope ONLY | `authority_control show --org <uuid>` |
| 6 | No kill switch is engaged | same command |
| 7 | An authority-evidence key is published | `scripts/check_verify_publication.py` reports an active `iae-` key |
| 8 | Alerts are live | the `inntris_authority` group is loaded in Prometheus |

**Precondition 7 is currently false** and is enforced in code: production
refuses to sign v3 evidence with an unpublished key
(`api/receipts/key_registry.py`). The canary cannot produce verifiable
evidence until the key ceremony happens.

## Bounds

The canary is deliberately small enough that the worst case is affordable.

* **One organisation**, created for this purpose, with no other traffic.
* **One principal**, production-approved, with `daily_limit_usd` and
  `per_action_limit_usd` set to the canary amount — so even a total failure
  of every other control caps the loss at one transaction.
* **One action class.**
* **A low-value or test-safe action.** If the rail has a test mode, use it;
  if not, use the smallest amount the rail will accept.
* **One executor credential**, scoped to that action class, revoked as soon
  as the canary completes.
* **Serial execution.** One probe at a time. This is also why the Gate 7
  blocker does not affect the canary.

## The sequence

Each step has an expected result AND an artefact. A step without its
artefact has not passed, however it looked at the time.

### 1. Negative authority probe → BLOCK, no executor call

Present a delegation that must not verify: one signed by a key that is not
configured, or one for a different principal.

* **Expect:** `POST /authority/evaluate` returns `decision: "block"` with an
  `authority_*` reason. No `grant_id`, no `authority_token`.
* **Must not happen:** any executor call. Check the executor's own logs, not
  ours — the whole point is that the boundary held.
* **Artefact:** the decision's `audit_id`, and the executor's log for the
  window showing nothing arrived.

### 2. Valid delegation, Inntris policy BLOCK → no executor call

Present a genuine, verifying delegation for an act the organisation's own
policy refuses — an amount above `per_action_limit_usd` is simplest.

* **Expect:** `block`, with a *policy* reason rather than an authority one.
  This is the step that proves a delegation narrows and never widens: the
  issuer said yes and Inntris still said no.
* **Artefact:** the decision `audit_id` and its recorded reason.

### 3. Valid ALLOW → authenticated, exact-action consume

Present the delegation for an act policy permits.

* **Expect:** `allow`, with `grant_id`, `authority_token` and `expires_at`.
* Then `POST /authority/consume` with the token, the **same** action and
  payload, and a stable `execution_ref` the executor generated *before* its
  first attempt.
* **Expect:** `outcome: "authorised"`, `may_execute: true`.
* **Artefact:** `grant_id`, `consumption_audit_id`, `execution_ref`.

Also verify, before step 4, that the consume was bound to the credential:
the grant's `executor_binding_digest` must equal the one
`provision_executor list` printed for that key.

### 4. The executor executes, once

* **Expect:** exactly one downstream effect.
* **Artefact:** the rail's own transaction reference. Ours is not evidence
  of settlement; theirs is.

### 5. Outcome and reconciliation evidence recorded

* **Expect:** the grant's `outcome_state` moves off `pending` with the
  rail's reference recorded.
* **Artefact:** the grant row, and the rail's record showing the same
  reference.

If the executor cannot say what happened, the outcome is `unknown` — never
`failed`. Reserved capacity stays charged. See the reconciliation section of
`authority_incident.md`.

### 6. Receipt and evidence verification passes

* Fetch the v3 evidence chain and verify it with the **published**
  `verify_pack.py`, pinning the published key:

  ```bash
  python verify_pack.py <pack> --evidence-pubkey <published iae- key>
  ```

* **Expect:** exit 0, with the chain verifying and the key matching the
  pinned one.
* **Artefact:** the verifier's output, including the key fingerprint it
  matched.

Verifying without `--evidence-pubkey` is not sufficient for a canary: it
proves internal consistency only.

### 7. Retry the same `execution_ref` → no second effect

Send `POST /authority/consume` again, byte-identical, same `execution_ref`.

* **Expect:** `outcome: "recovered"`, `may_execute: false`. It hands back
  the record of the earlier spend and authorises nothing.
* **Must not happen:** a second downstream effect. Check the rail.
* **Artefact:** the recovered response, and the rail showing one
  transaction.

Then, separately, retry with a **different** `execution_ref`:

* **Expect:** rejected with `execution_ref_conflict`. A new reference is a
  new attempt against single-use authority, and that is refused.

## Immediately after

1. Revoke the canary executor credential (`provision_executor revoke`).
2. Leave the requirement enabled for the canary scope — it is the one scope
   where it has been proven to work.
3. Record every artefact in the release evidence document.

## Abort conditions

Stop and pull the issuance kill switch if any of these occur:

* an executor call after a BLOCK (steps 1–2) — the boundary is not holding;
* two downstream effects for one `execution_ref` — single-use authority is
  not single-use;
* a v3 chain that does not verify against the published key;
* any `40P01` deadlock during the canary — the Gate 7 blocker reaching a
  shape it was not expected to reach;
* an outcome that cannot be reconciled against the rail within the agreed
  window.

```bash
python -m scripts.authority_control kill \
    --control authority_issuance --global \
    --by you@example.com --approval INC-XXXX --reason "canary abort"
```

## What a passed canary does and does not establish

It establishes that the authority boundary held end to end, once, for one
bounded act: a delegation was verified against configured trust, tied to a
principal by server-side binding, narrowed by organisation policy, spent
exactly once by an authenticated executor, and the whole thing produced
evidence a third party can verify without trusting Inntris.

It does **not** establish that the system is ready for volume. The Gate 7
blocker is precisely about what happens when more than one execution
happens at once, and a serial canary cannot speak to it.
