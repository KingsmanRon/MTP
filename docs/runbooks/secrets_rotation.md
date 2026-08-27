# Secrets management and rotation

This runbook describes the rotation mechanisms that exist in the current
codebase. Store secret values in the deployment provider's secret store. Never
commit them, print them in CI, or attach them to an incident record.

## Inventory

| Name or secret | Consumer and storage | Rotation owner |
| --- | --- | --- |
| `SERVER_SECRET` | API approval-token HMAC and encryption key derivation for organisation webhook secrets | Platform security |
| `SERVER_SECRET_PREVIOUS` | Temporary API overlap value during `SERVER_SECRET` rotation | Platform security |
| `MASTER_ADMIN_KEY` | Operator organisation-provisioning endpoint | Platform security |
| `ADMIN_SESSION_SECRET` | Frontend admin-session encryption | Platform security |
| `DATABASE_URL` | API and worker PostgreSQL credential | Database owner |
| `REDIS_URL` | API Redis credential | Platform owner |
| `BLOCKCHAIN_PRIVATE_KEY` | Anchor worker submitter EOA | Treasury and platform security |
| `BLOCKCHAIN_PROVIDER_URL` | Worker RPC URL; treat it as secret when it embeds provider credentials | Platform owner |
| `BLOCKCHAIN_READ_PROVIDER_URLS` | Read-only failover RPC URLs; same handling as the primary. Rotating these never affects broadcast, so they can be replaced without a submission window | Platform owner |
| Organisation API keys | Plaintext shown once; SHA-256 hashes stored in `api_keys.key_hash` | Tenant administrator |
| Agent Ed25519 private key | Customer agent or MCP runtime only; public key stored in `agents.public_key` | Tenant administrator |
| Organisation webhook signing secret | Plaintext shown once; AES-GCM ciphertext stored in `organizations.webhook_secret_ciphertext` | Tenant administrator |

`ANCHOR_CONTRACT_ADDRESS`, `BLOCKCHAIN_CHAIN_ID`, `ALLOWED_ORIGINS`,
`INNTRIS_AGENT_ID`, `ENVIRONMENT`, and logging or interval settings are
configuration, not secrets.

## Rotation record

For every rotation, record the owner, reason, start and completion timestamps,
affected environments, old and new SHA-256 fingerprint prefixes, deployment
identifiers, readback evidence, and rollback decision. A fingerprint is not a
substitute for deleting the old value from every secret store and runtime.

## 1. `SERVER_SECRET`

The current API accepts approval tokens and decrypts webhook-secret envelopes
with the ordered pair `SERVER_SECRET`, then `SERVER_SECRET_PREVIOUS`. New
approval tokens and new webhook envelopes always use `SERVER_SECRET`.

### Safe overlap procedure

1. Generate a new value with at least 32 random bytes, for example
   `openssl rand -hex 32`.
2. First deploy all API instances with the old value as `SERVER_SECRET` and the
   new value as `SERVER_SECRET_PREVIOUS`. No new material uses the new value
   yet, but every instance can accept either value during the later rolling
   change.
3. Confirm `/health`, approval-token verification, and a controlled webhook
   delivery on every instance.
4. Roll all API instances to the new value as `SERVER_SECRET` and the old value
   as `SERVER_SECRET_PREVIOUS`. Mixed old and new instances accept both values.
5. Wait at least the five-minute approval-token lifetime and confirm no old
   deployment instance remains.
6. Complete the webhook-envelope work below before removing
   `SERVER_SECRET_PREVIOUS`.
7. Remove `SERVER_SECRET_PREVIOUS`, roll every API instance, and repeat the
   readbacks only after all webhook rows use envelopes encrypted by the new
   key.

### Webhook-envelope limitation

There is currently no bulk rewrap operation that decrypts each existing
`organizations.webhook_secret_ciphertext` with the old server secret and
reencrypts the same tenant signing secret with the new server secret. Removing
`SERVER_SECRET_PREVIOUS` while any old envelope remains makes those webhook
deliveries fail decryption and eventually dead letter.

The available tenant endpoint,
`POST /admin/organization/webhook-secret/rotate`, generates a different
webhook signing secret and encrypts it with the current `SERVER_SECRET`. It is
not a transparent rewrap. Before retiring the old server secret, either:

1. Coordinate that endpoint for every organisation with a webhook, update each
   receiver from the one-time plaintext response, send a controlled delivery,
   and confirm the new secret version; or
2. Implement, review, and run a one-off rewrap tool that preserves tenant
   signing-secret plaintext while replacing only its envelope.

Until one of those paths is complete for every row, retain
`SERVER_SECRET_PREVIOUS` and record the extended exposure as an open rotation
item. A low-traffic single-secret swap is not safe.

Use this readback without selecting ciphertext:

```sql
SELECT id, webhook_url, webhook_secret_version, webhook_secret_rotated_at
FROM organizations
WHERE webhook_url IS NOT NULL
ORDER BY id;
```

## 2. `MASTER_ADMIN_KEY` and `ADMIN_SESSION_SECRET`

These controls do not currently have a two-key overlap.

1. Schedule a controlled maintenance window and stop organisation provisioning
   for `MASTER_ADMIN_KEY`, or admin sign-in for `ADMIN_SESSION_SECRET`.
2. Generate a new value of at least 32 random bytes and update the secret store.
3. Roll all consuming instances.
4. Confirm the old master key returns 401 and the new key can perform an
   approved sandbox provisioning smoke test. For the session secret, confirm
   old cookies fail closed and a new login creates a valid secure cookie.
5. Remove the old value from the secret store and close the maintenance item.

## 3. PostgreSQL credential

Use a parallel login rather than changing the active password in place.

1. Create a new login with a unique name, strong password, required object-role
   membership, and the same explicit attributes as the current runtime login.
   If the deployment relies on `BYPASSRLS`, read that attribute back on the new
   login; role membership does not substitute for an explicit security review.
2. Test the new DSN against `/health`, tenant isolation, audit immutability, and
   worker Merkle-field updates.
3. Roll API and worker instances to the new `DATABASE_URL`.
4. Confirm no sessions use the old login, then revoke login and remove its
   credential. Drop the old role only after ownership and grants are verified.

Keep the old login disabled rather than deleted during the agreed rollback
window.

## 4. Redis credential

Use Redis ACL password overlap when the provider supports it:

1. Add the new password while retaining the old password.
2. Test a dedicated connection and the `/verify` pre-authentication limits,
   nonce replay control, and bounded invalid-signature telemetry.
3. Roll the API to the new `REDIS_URL`.
4. Confirm all instances use it, then remove the old password.

A Redis restart or flush can remove replay state. Treat any loss of nonce keys
as a security incident, not a routine rotation side effect.

## 5. Organisation API key

`POST /admin/api-keys/rotate` revokes every existing key for the organisation
and returns one new key. It does not provide overlap.

1. Schedule tenant cutover and stop writes using the old key.
2. Call the rotation endpoint through a protected operator session.
3. Store the one-time new key, update every client, and verify an authenticated
   read with the new key.
4. Verify the same authenticated endpoint returns 401 with the old key.
5. Record the new key prefix from `api_keys`, never the hash or plaintext.

If zero-downtime overlap is required, create a separately named API key first,
cut clients over, and then revoke the old key by prefix. Do not use the
all-keys rotation endpoint for that workflow.

## 6. Agent Ed25519 signing key

The tenant generates the private key. Inntris stores the public key and its
fingerprint on the `agents` row.

1. Suspend the agent if compromise is suspected.
2. Generate the replacement keypair in the tenant-controlled runtime.
3. Call `POST /admin/agents/{agent_id}/rotate-key` with the base64-encoded
   32-byte public key and a reason. The old key stops verifying immediately;
   there is no overlap window.
4. Update the tenant runtime with the new private key.
5. Submit a side-effect-free `/verify/debug` request, then a sandbox or approved
   production request appropriate to that agent.
6. Read back `agents.key_version`, `public_key_fingerprint`, and
   `key_rotated_at`. Review prior `audit_logs.metadata.key_fingerprint` values
   to scope activity signed by the retired key.

## 7. Organisation webhook signing secret

1. Prepare the receiver to accept a replacement secret.
2. Call `POST /admin/organization/webhook-secret/rotate` with a tenant admin
   key and the approved change or incident reference. Capture the one-time
   plaintext response directly into the receiver's secret store.
3. Deploy the receiver, send a controlled verification event, and confirm the
   corresponding `webhook_deliveries` row reaches `delivered` with the expected
   secret version header.
4. Remove the old receiver secret only after successful delivery.
5. Review retrying and dead-letter rows for failures during the cutover.
6. Confirm the immutable `administrative_audit_events` row records the actor,
   organisation, approval reference, secret version, and rotation time.

The API supports one active organisation webhook signing secret. Receiver-side
overlap must provide the safe transition.

Creating, replacing, or clearing a webhook URL is also a privileged security
change. Supply a non-empty approval reference, then confirm the corresponding
administrative event before treating the configuration as active. Do not use a
generic organisation update without that evidence.

## 8. Anchor submitter private key

This key can submit Merkle roots and spend gas. It cannot create a valid agent
signature, but compromise can pollute the registry and exhaust funds.

1. Generate a replacement EOA offline and fund only the approved operating
   amount.
2. Through the Safe and timelock, grant `SUBMITTER_ROLE` to the new address.
3. After the delay and independent role readback, update
   `BLOCKCHAIN_PRIVATE_KEY` and restart the worker.
4. Confirm chain ID, contract address, first transaction, root, and matching
   `merkle_proofs` row.
5. Through the Safe and timelock, revoke the old submitter role.
6. Sweep remaining funds and destroy all copies of the retired key.

For suspected compromise, pause the registry and stop the worker first. Do not
unpause until the hostile key is revoked and pending operations are reviewed.

## 9. RPC provider credential

1. Create or rotate the provider credential and update
   `BLOCKCHAIN_PROVIDER_URL` in the secret store.
2. Roll the worker. It must fail before submission if
   `BLOCKCHAIN_CHAIN_ID` does not match.
3. Confirm the worker scrape, heartbeat, successful cycle, and one expected
   anchor transaction.
4. Revoke the old provider credential.

## Post-rotation evidence

* `/health` and the relevant authenticated readback pass.
* Old credentials fail on an endpoint that actually requires them.
* New credentials work on the intended consumer.
* Worker or webhook metrics show no unexplained failure increase.
* Persistent database state matches the expected key version, delivery state,
  or proof state.
* The rotation record identifies owner, timestamps, evidence, and any remaining
  dependency on an old value.

KMS or HSM custody and automated fleet-wide rewrap remain future hardening.
Do not describe manual environment-secret storage as equivalent to either.
