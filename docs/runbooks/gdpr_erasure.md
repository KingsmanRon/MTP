# GDPR and CCPA erasure

This procedure honours an approved right to erasure request without changing
the cryptographic evidence needed to verify an existing receipt.

Migration `012_gdpr_erasure_guard.sql`, applied by Alembic revision
`0008_gdpr_erasure_guard`, is the active contract. It is a forward repair for
the earlier migration. Do not edit or replay an already applied migration by
hand.

## Security contract

The only supported entry point is
`app.erase_personal_data(UUID, UUID, TEXT, TEXT, TEXT)`.

The function creates a pending row in `erasure_requests`, issues an internal
transaction scoped capability for that ledger row, writes exact tombstones,
clears the capability, and completes the ledger row. The audit trigger rejects
an erasure when the ledger reference is missing, complete, for another tenant,
or for another agent.

Application roles `inntris_api` and `inntris_worker` cannot insert ledger rows
or execute the erasure function. Never grant them that access. Never set
`app.erasure_request_id` manually or update `audit_logs` directly.

The function may change only these fields:

| Field | Result |
| --- | --- |
| `audit_logs.payload` | Exact `{erased, erased_at, erasure_request_id}` tombstone |
| `audit_logs.metadata` | Exact `{erased: true}` tombstone, with `test_request: true` retained when present |
| `audit_logs.request_ip` | Set to `NULL` |
| `audit_logs.request_user_agent` | Set to `NULL` |

Every other audit field remains byte for byte unchanged, including the action
hash, signature, verdict, timestamps, policy hash, chain hash, and Merkle
fields. Merkle fields retain their separate one time anchoring transition from
`NULL` to a value.

## Before the change window

1. Confirm legal or privacy approval and record the DSR ticket.

2. Identify one organisation and, when appropriate, one agent in that
   organisation. The function does not erase arbitrary individual rows.

3. Confirm the agent belongs to the organisation. The database rejects a
   mismatched organisation and agent pair.

4. Confirm the deployment is at Alembic head:

   ```shell
   alembic current
   alembic upgrade head
   ```

5. Take the required operational backup and record its retention policy. A
   backup may still contain data that existed before the erasure.

## Grant a controlled execution window

Use a dedicated NOLOGIN role that operators assume through your normal
privileged access process. The migration leaves execution denied by default.

```sql
GRANT USAGE ON SCHEMA app TO inntris_erasure_admin;
GRANT EXECUTE ON FUNCTION app.erase_personal_data(UUID, UUID, TEXT, TEXT, TEXT)
    TO inntris_erasure_admin;
```

Record the grant in the change ticket. Configure PostgreSQL DDL logging so the
grant and revoke are retained in server audit logs.

## Execute

Run from a connection whose active role is `inntris_erasure_admin`:

```sql
SELECT app.erase_personal_data(
    p_org_id       := '00000000-0000-0000-0000-000000000000',
    p_agent_id     := NULL,
    p_requested_by := 'dpo@inntris.com',
    p_legal_basis  := 'gdpr_art17',
    p_reason       := 'DSR ticket 4821'
);
```

`p_agent_id := NULL` covers every agent in the organisation. Otherwise provide
one agent UUID. Accepted legal bases are `gdpr_art17`, `ccpa_1798_105`, and
`operator_request`.

Record the returned erasure request UUID immediately.

## Verify

Check the immutable ledger entry:

```sql
SELECT id, organization_id, subject_agent_id, requested_by, legal_basis,
       reason, rows_affected, created_at, completed_at
FROM erasure_requests
WHERE id = '00000000-0000-0000-0000-000000000000';
```

`completed_at` must be populated. `rows_affected` is the number of newly
tombstoned audit rows. A repeated approved request may legitimately report
zero because already tombstoned rows are not changed again.

Inspect a representative sample and confirm the tombstone has only the allowed
keys:

```sql
SELECT id, payload, metadata, request_ip, request_user_agent,
       action_hash, signature, merkle_root_id, merkle_leaf_index
FROM audit_logs
WHERE payload->>'erasure_request_id' =
      '00000000-0000-0000-0000-000000000000';
```

Compare retained proof fields with the pre change evidence recorded in the DSR
ticket. Close the request only when the ledger and representative rows match
the contract.

## Revoke access

End the execution window even when no rows were changed:

```sql
REVOKE EXECUTE ON FUNCTION app.erase_personal_data(UUID, UUID, TEXT, TEXT, TEXT)
    FROM inntris_erasure_admin;
```

## Python operator tooling

`api.erasure.erase_personal_data` validates inputs and returns both the ledger
UUID and affected row count. Pass it a connection authenticated as the
dedicated erasure role. Do not use a normal tenant or worker connection.

```python
from api.erasure import erase_personal_data

result = await erase_personal_data(
    erasure_admin_connection,
    organization_id=org_id,
    agent_id=agent_id,
    requested_by="dpo@inntris.com",
    legal_basis="gdpr_art17",
    reason="DSR ticket 4821",
)
```

## Deployment proof

The integration test creates a clean temporary PostgreSQL database, replays
the complete Alembic chain, tests rejected bypasses, performs a legitimate
erasure, and verifies that all forensic fields remain unchanged.

```shell
INNTRIS_DB_INTEGRATION=1 \
ALEMBIC_DATABASE_URL=postgresql://migration_admin:secret@localhost/postgres \
python -m pytest tests/test_gdpr_erasure.py -q
```

The configured migration role must be allowed to create and drop a temporary
database. Use a disposable CI PostgreSQL service, not a production cluster.

## Outside this procedure

This database function does not erase point in time backups, application logs,
error traces, Redis snapshots, third party exports, or support attachments.
Track each relevant system in the DSR ticket. Inntris writes only Merkle roots
on chain, not payload data, so no blockchain mutation is part of this
procedure.
