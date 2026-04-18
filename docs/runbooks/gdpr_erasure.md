# GDPR / CCPA erasure

Phase 4B — operator procedure for honoring a right-to-erasure request
without invalidating the forensic Merkle proofs that back our audit
logs.

## What erasure does and does not change

| Field | Touched? | Why |
|-------|----------|-----|
| `audit_logs.action_hash` | **No** | Merkle leaf value; on-chain proofs depend on it. |
| `audit_logs.signature` | **No** | Ed25519 signature; preserves non-repudiation for parties who still hold the original payload. |
| `audit_logs.signature_valid` | **No** | Historical fact. |
| `audit_logs.merkle_root_id` | **No** | Links to the on-chain anchor. |
| `audit_logs.merkle_leaf_index` | **No** | Position in the Merkle tree. |
| `audit_logs.chain_previous_hash` | **No** | Local hash-chain ordering. |
| `audit_logs.policy_hash` | **No** | Historical fact; does not identify a person. |
| `audit_logs.action_type`, `verdict`, `timestamp`, `trust_score_at_time` | **No** | Categorical / aggregate; no PII. |
| `audit_logs.payload` | **Replaced** with `{erased: true, erased_at, erasure_request_id}` |
| `audit_logs.metadata` | **Replaced** with `{erased: true}` (retains `test_request=true` if set) |
| `audit_logs.request_ip` | **NULLed** |
| `audit_logs.request_user_agent` | **NULLed** |

After erasure, a row is proof-of-existence only. Anyone holding the
original payload out-of-band (e.g. the data subject themselves) can
re-compute SHA-256 and match it against `action_hash`; that is the
legal carve-out we rely on under GDPR Art. 17(3)(e).

## Procedure

1. **Receive and classify the request.** Confirm it is a GDPR Art. 17
   or CCPA 1798.105 request (or operator-initiated cleanup). Out-of-
   scope requests go to legal; we do not redact forensic data on a
   whim.

2. **Identify the scope.** One organization, and optionally one agent
   within it. We do not support per-row erasure — a data subject
   request maps to the agent(s) that logged on their behalf.

3. **Run the erasure.** From an admin shell connected to Postgres
   under a role that has been granted `EXECUTE` on
   `app.erase_personal_data(...)`:

   ```sql
   SELECT app.erase_personal_data(
       p_org_id        := '00000000-0000-0000-0000-000000000000',
       p_agent_id      := NULL,                -- or a specific agent UUID
       p_requested_by  := 'dpo@inntris.com',
       p_legal_basis   := 'gdpr_art17',        -- or ccpa_1798_105, operator_request
       p_reason        := 'DSR ticket #4821'
   );
   ```

   The return value is the `erasure_requests.id` — record it in the
   ticket. The accompanying row counts `rows_affected`.

4. **Confirm**. Query `erasure_requests` and a representative sample
   of the affected `audit_logs` rows to verify payload tombstoning
   and NULLed IP/UA.

5. **Respond to the data subject.** Include the `erasure_requests.id`
   and the count of redacted entries. Explain that cryptographic
   proofs of existence remain because the law requires retaining
   records necessary for "establishment, exercise or defence of
   legal claims" (Art. 17(3)(e)).

## From Python

For endpoints exposed to operators, use the wrapper in
`api/erasure.py` rather than hand-building the SQL:

```python
from api.erasure import erase_personal_data

async with db.acquire_as_tenant(org_id) as conn:
    result = await erase_personal_data(
        conn,
        organization_id=org_id,
        requested_by="dpo@inntris.com",
        legal_basis="gdpr_art17",
        reason="DSR #4821",
    )
# result.request_id, result.rows_affected
```

The wrapper whitelists `legal_basis`, trims `requested_by`, and emits a
structured log line (`gdpr.erasure.completed`) for operator audit.

## Idempotency

Re-running erasure for the same scope is a no-op on already-tombstoned
rows. The `erasure_requests` row is still created (with
`rows_affected = 0`), which is the correct record: the operator
attempted an erasure, and zero additional rows needed redaction.

## Granting execute rights

By default the function is not executable by any role (the migration
REVOKEs from PUBLIC). Grant to a named admin role only when an
erasure process is approved:

```sql
GRANT EXECUTE ON FUNCTION app.erase_personal_data(UUID, UUID, TEXT, TEXT, TEXT)
    TO inntris_erasure_admin;
```

Revoke immediately after the window closes. The grant itself should
be logged — Postgres will record it in the server log if
`log_statement = ddl` is set.

## What this procedure does NOT cover

* **Backups.** Point-in-time backups of Postgres may still contain
  the pre-erasure payload. Erasure of backups requires either
  restoring + re-erasing + re-backing-up, or waiting out the backup
  retention window. Document the choice per compliance obligation.
* **External caches / logs.** Application logs, error traces, and
  Redis snapshots may contain payload data. Cache rotation is
  separate.
* **On-chain data.** We deliberately never write PII to the chain —
  only Merkle roots, which are SHA-256 hashes and not reversible.
  Erasure does not require any on-chain action.
