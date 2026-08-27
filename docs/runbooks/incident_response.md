# Incident response runbook

Use this runbook for the incident classes emitted by the current API, webhook
outbox, and anchor worker. All times are UTC. Preserve request IDs, row IDs,
metric snapshots, deployment identifiers, and relevant log windows in the
incident record. Never copy credentials, signing secrets, raw webhook payloads,
or private keys into that record.

## Operator handles

| Handle | Current source |
| --- | --- |
| API metrics | API `/metrics`, with `inntris_verify_*`, signature, replay, rate-limit, and webhook series |
| Worker metrics | Anchor worker `:9100/metrics`, scraped as job `inntris-anchor-worker` |
| Logs | Structured stdout when `INNTRIS_JSON_LOGS=1`; correlate with `request_id` |
| Audit evidence | PostgreSQL `audit_logs`; authenticated policy decisions only |
| Proof state | PostgreSQL `merkle_proofs` |
| Webhook state | PostgreSQL `webhook_deliveries` |
| Erasure ledger | PostgreSQL `erasure_requests` |

Severity 1 means user-visible or evidence-pipeline failure requiring immediate
response. Severity 2 means degraded security or delivery requiring prompt
investigation. Severity 3 means an informational event that still needs an
owner and disposition.

## 1. Invalid signature spike

**Severity: 2. Promote to 1 if valid customer traffic is broadly failing.**

An invalid signature is an unauthenticated attack signal. It is not evidence
that the named agent acted. The API does not create an `audit_logs` row, consume
the nonce, change trust, advance usage counters, send a webhook, or create an
anchor-eligible receipt for this path.

### Detect

* `rate(inntris_signature_failures_total[5m])` rises above the agreed baseline.
* `rate(inntris_verify_requests_total{verdict="invalid_signature"}[5m])` rises.
* API logs contain `SECURITY ALERT: invalid signature` with a hashed
  `source_id`, claimed `agent_id`, and request ID.
* Redis contains bounded hourly counters under
  `inntris:security:signature_invalid:source:*` and
  `inntris:security:signature_invalid:agent:*`. These expire after one hour.

Do not query `audit_logs` for `signature_invalid`. A row there would contradict
the security contract and should be treated as a separate integrity incident.

### Contain

1. If one source dominates, block or challenge it at the edge using the direct
   peer evidence and a short expiry. Do not create an application allowlist.
2. If many sources claim one agent, contact the tenant. Suspend that agent only
   when key compromise or a legitimate client regression is supported by
   evidence:

   ```bash
   curl -X PATCH "$API_URL/admin/agents/$AGENT_ID/status?new_status=suspended" \
     -H "X-API-Key: $INNTRIS_API_KEY"
   ```

3. If many agents fail after a deployment, stop the rollout and investigate
   signing canonicalisation before disabling tenants.

### Investigate

* Group structured logs by `source_id`, claimed `agent_id`, deployment ID, and
  client version. Raw source IPs are intentionally absent from bounded Redis
  telemetry.
* Compare the client hash with `expected_action_hash` from the 401 response and
  use side-effect-free `POST /verify/debug`.
* Check timestamp and `sig_version` handling against `docs/REQUEST_SIGNING.md`.
* Confirm no unexpected forensic row was inserted:

  ```sql
  SELECT id, agent_id, timestamp, verdict, signature_valid
  FROM audit_logs
  WHERE agent_id = 'CLAIMED_AGENT_UUID'
    AND timestamp >= now() - interval '15 minutes'
  ORDER BY timestamp DESC;
  ```

  Compare this result with known authenticated requests. Do not interpret the
  absence of an invalid row as missing telemetry; it is the intended boundary.

### Recover

* For a client regression, deploy the corrected signing implementation and
  verify with `/verify/debug` before resuming `/verify` traffic.
* For confirmed key compromise, generate the replacement key client-side and
  call `POST /admin/agents/{agent_id}/rotate-key`. The old key stops verifying
  immediately. Review all audits pinned to the retired key fingerprint.
* Remove temporary edge controls only after the metric and log rate returns to
  baseline.

## 2. Nonce replay attempts

**Severity: 2.**

### Detect

* `rate(inntris_nonce_replays_total[5m]) > 0`.
* `/verify` returns 401 with `Nonce already used`.
* The live Redis key is `inntris:nonce:{agent_id}:{nonce}` and normally has at
  most a 600 second lifetime.

The audit schema has no nonce column. Do not search `audit_logs` for a nonce or
claim that it identifies the original request.

### Contain and investigate

1. Capture the request ID, agent ID, source logs, and the key's remaining TTL:

   ```bash
   redis-cli TTL "inntris:nonce:${AGENT_ID}:${NONCE}"
   ```

2. If a client retried an identical request, stop its automatic retries and
   issue a fresh nonce for the new request.
3. If sources or payloads differ, suspend and rotate the agent key as described
   in section 1.
4. Check Redis availability and restart history. A Redis flush removes replay
   memory and is a security incident even though it cannot produce a false
   replay response.

### Recover

Resume only after the client generates a unique nonce per signed request and
Redis remains healthy. Record whether the replay window or Redis persistence
settings need adjustment.

## 3. Anchor worker stale, failed, or dead lettered

**Severity: 1 if the receipt anchoring service level is breached; otherwise 2.**

### Detect

* `up{job="inntris-anchor-worker"} == 0`.
* `time() - inntris_anchor_worker_heartbeat_timestamp_seconds > 900`.
* `inntris_anchor_proof_backlog{status=~"failed|dead_letter"} > 0`.
* `increase(inntris_anchor_submissions_total{outcome=~"failed|dead_letter"}[10m]) > 0`.
* A proof whose transaction was broadcast but whose reads keep failing appears
  in neither of the two above. It shows as
  `inntris_anchor_proof_backlog{status="awaiting_reconciliation"} > 0` and is
  covered by section 3a, not this one.
* PostgreSQL confirms the persistent state:

  ```sql
  SELECT id, status, retry_count, next_retry_at, dead_lettered_at,
         error_message, created_at
  FROM merkle_proofs
  WHERE status IN ('failed', 'dead_letter')
  ORDER BY created_at;

  SELECT count(*) AS eligible_unanchored
  FROM audit_logs
  WHERE merkle_root_id IS NULL
    AND NOT COALESCE((metadata->>'test_request')::boolean, false);
  ```

### Contain

1. Stop the worker if it is submitting to the wrong chain, repeatedly failing,
   or producing unexpected roots. Stopping the worker does not delete audits.
2. Do not delete or rewrite `merkle_proofs` or `audit_logs` rows.
3. If only the RPC is unavailable, leave the API online and communicate the
   receipt delay.

### Investigate and recover

* For chain mismatch, correct `BLOCKCHAIN_PROVIDER_URL` and verify
  `BLOCKCHAIN_CHAIN_ID` before restarting.
* For gas refusal, compare live gas with `ANCHOR_MAX_GAS_PRICE_GWEI`. Any
  temporary increase needs an approved change reference and rollback time.
* For a `dead_letter` row, record the error, transaction state, and operator
  decision before any manual retry.
* Restart the worker after the cause is corrected. Confirm a fresh heartbeat,
  a successful cycle, backlog reduction, database status, and the on-chain
  transaction before resolving the incident.

## 3a. Anchor stuck at `submitted` because the RPC refuses reads

**Severity: 2. The anchor is on chain; only the platform's view of it is stale.**

A transaction that broadcast successfully is anchored on Base whether or not
we can read its receipt. An RPC answering `403 Forbidden` — an IP block, a
referrer rule, a plan limit — tells us nothing about that transaction. The
worker treats every such answer as an availability failure: it never
rebroadcasts on one, never counts one against the retry budget, and never
dead-letters an already-broadcast proof because of one.

### Detect

* `increase(inntris_anchor_submissions_total{outcome="read_unavailable"}[10m]) > 0`.
* `increase(inntris_anchor_rpc_read_failover_total{endpoint="primary"}[10m]) > 0`
  means reads are being served by failover endpoints. A rate with no
  `endpoint="read-1"` counterpart means failover is working; a rate on every
  endpoint means no endpoint can answer.
* Worker logs carry `anchor_read_unavailable` and
  `anchor_rpc_read_unavailable`, each naming the endpoint and operation.
* Persistent state — proofs holding a transaction hash but no block:

  ```sql
  SELECT id, status, transaction_hash, submission_nonce, retry_count,
         submitted_at, last_reconciliation_at, error_message
  FROM merkle_proofs
  WHERE status IN ('prepared', 'submitted')
  ORDER BY submitted_at;
  ```

  An `error_message` beginning `rpc_read_unavailable` confirms this class.

### Contain

1. **Do not** rotate `BLOCKCHAIN_PROVIDER_URL` as the fix, and do not clear or
   rewrite `transaction_hash`. The hash is the identity of a transaction that
   may already be mined; replacing it risks a second anchor for one batch.
2. Confirm the transaction independently — `https://basescan.org/tx/<hash>`,
   or any RPC you can reach:

   ```bash
   curl -s -X POST https://mainnet.base.org \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt",
          "params":["<transaction_hash>"]}'
   ```

   A receipt with `"status":"0x1"` means the anchor exists and only the
   database row is behind.

### Recover

1. Add a read endpoint that is independent of the primary, then restart the
   worker:

   ```bash
   BLOCKCHAIN_READ_PROVIDER_URLS=https://mainnet.base.org
   ```

   The primary is unchanged and remains the only endpoint that broadcasts.
   Every read endpoint is chain-id verified before its answers are trusted, so
   a wrong-chain endpoint is disabled rather than believed.

2. Reconcile the stranded proofs. Neither command broadcasts anything:

   ```bash
   # The transaction you just confirmed on the explorer
   python -m workers.anchor_worker --reconcile-transaction <transaction_hash>

   # One known proof
   python -m workers.anchor_worker --reconcile-proof <proof_id>

   # Every prepared, submitted, failed, and dead-lettered proof
   python -m workers.anchor_worker --reconcile-unresolved
   ```

   Exit status `0` means the proof reached `confirmed`; `2` means chain
   evidence was not found or could not be read, and the proof was left
   untouched and still retryable.

   Reconciliation asks about the already-persisted transaction hash first,
   then validates the `BatchAnchored` event and the AnchorRegistry entry —
   log count, timestamp window, batch ID, block number, and submitter must all
   agree — before it writes anything.

3. Read back the repaired row. `block_number`, `gas_used`, `confirmed_at`, and
   `reconciliation_source` must all be populated:

   ```sql
   SELECT id, status, transaction_hash, block_number, gas_used,
          gas_price_gwei, confirmed_at, reconciled_at, reconciliation_source
   FROM merkle_proofs
   WHERE transaction_hash = '<transaction_hash>';
   ```

   Expect `status = 'confirmed'`, `reconciliation_source` of
   `transaction_receipt` (or `contract_state` when the registry supplied the
   evidence), and a `block_number` matching the explorer.

4. Confirm no duplicate anchor was created for the batch — one row per
   `root_hash`, one transaction hash on it:

   ```sql
   SELECT root_hash, count(*) AS rows, count(DISTINCT transaction_hash) AS hashes
   FROM merkle_proofs
   GROUP BY root_hash
   HAVING count(*) > 1 OR count(DISTINCT transaction_hash) > 1;
   ```

5. Resolve the incident once the primary is serving reads again, or once the
   read endpoint is accepted as the standing configuration. Leaving
   `BLOCKCHAIN_READ_PROVIDER_URLS` set is the recommended steady state.

## 4. Webhook retry or dead letter growth

**Severity: 2. Promote to 1 for a contractual delivery outage.**

### Detect

* `increase(inntris_webhook_delivery_attempts_total{outcome=~"retry|dead_letter|security_rejected"}[10m]) > 0`.
* Tenant readback:
  `GET /admin/organization/webhook-deliveries?status=dead_letter`.
* Persistent readback:

  ```sql
  SELECT id, org_id, event, status, attempt_count, response_status,
         last_error, next_attempt_at, last_attempt_at, dead_lettered_at
  FROM webhook_deliveries
  WHERE status IN ('retrying', 'dead_letter')
  ORDER BY updated_at DESC;
  ```

### Contain and recover

1. A `security_rejected` outcome means the destination failed the HTTPS, DNS,
   public address, redirect, peer, or response-size boundary. Do not weaken
   destination validation. Disable or replace the tenant webhook URL.
2. For receiver errors, confirm the tenant can accept the signed request within
   the timeout and response-size limits. Do not log or replay the raw payload
   outside the durable outbox.
3. For a suspected signing-secret leak, rotate with
   `POST /admin/organization/webhook-secret/rotate`, supply the approved change
   or incident reference, update the receiver from the one-time response, and
   run a controlled delivery. Confirm the matching immutable
   `administrative_audit_events` row before closing the incident.
4. Assign every dead-letter row an owner and disposition. Preserve the row as
   delivery evidence.

## 5. Contract pause or submitter compromise

**Severity: 1.**

1. Read `AnchorRegistry.paused()` and inspect recent `Paused`, `RoleGranted`,
   and `RoleRevoked` events against the recorded addresses.
2. For a hostile or uncertain submitter event, pause through the authorised
   pauser, stop the worker, and inspect pending timelock operations.
3. Use the Safe and timelock procedure to grant a replacement submitter and
   revoke the old one. Do not bypass the configured delay.
4. Keep the worker stopped until chain ID, contract address, role holders, Safe
   threshold, and expected operation IDs have been read back independently.
5. On recovery, confirm the first root against the exact `merkle_proofs` row
   before unpausing normal operations.

## 6. Rate-limit storm or denial of service

**Severity: 2. Promote to 1 if legitimate verification is broadly unavailable.**

### Detect

* `rate(inntris_rate_limit_trips_total[1m])` rises by window label.
* 429 responses dominate `/verify` or public registration traffic.
* Structured logs identify `verify_preauth_source`, `verify_preauth_agent`,
  `tenant_minute`, or another specific window.

### Respond

1. Keep fail-closed limits in place.
2. Block a proven abusive network at the edge with an expiry.
3. Do not raise global limits to accommodate one tenant. Change a tenant or
   agent limit only with measured capacity evidence and approval.
4. Confirm Redis latency and API saturation before attributing the event to an
   attacker.
5. After recovery, verify the pre-authentication source and agent limits still
   run before signature processing.

## Generic evidence capture

1. Stop the unsafe activity first while preserving `audit_logs`,
   `merkle_proofs`, `webhook_deliveries`, `approval_token_consumptions`,
   `administrative_audit_events`, and `erasure_requests`.
2. Capture the relevant PostgreSQL rows, Redis TTL or counter summaries,
   Prometheus query results, Alertmanager notification evidence, deployment
   identifiers, and structured logs. Hash exported files.
3. Record every temporary control with an owner and expiry.
4. Write the postmortem with timeline, blast radius, root cause, detection gap,
   recovery gap, and prevention action.
