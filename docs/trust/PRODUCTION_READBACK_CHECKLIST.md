# Production Trust Readback Checklist

**Purpose:** Capture current evidence before a buyer security review, pilot
kickoff, production rollout, or public security claim.

Repository configuration is not proof that a control is live. Complete this
checklist from the environment being discussed and attach the evidence to the
review packet. Never paste secrets into the packet.

The database-backed checks (promotion evidence, paused webhooks, dead
letters, anchor backlog) can be executed in one read-only command against the
production runtime DSN:

    DATABASE_URL=postgresql://inntris_worker:...@host/db \
    python scripts/production_readback.py

## Review Header

| Field | Value |
| --- | --- |
| Environment | `[production / staging / customer]` |
| Date and time UTC | `[timestamp]` |
| Reviewer | `[name]` |
| Application commit | `[sha]` |
| Frontend deployment | `[deployment id / url]` |
| API deployment | `[deployment id / url]` |
| Database migration version | `0012_erasure_idempotency / [evidence]` |
| Contract address and chain | `[address / chain id]` |

## 1. Public Service And Receipt Evidence

- [ ] `GET /health` returns the expected environment state.
- [ ] `TRUST_PROXY_HEADERS` and `TRUSTED_PROXY_HOPS` match the deployment's
      real proxy chain: two requests from different networks produce different
      `source_id` values in the API logs, and a new audit row records the
      caller's address in `request_ip`, not the platform edge's.
- [ ] Canonical PASS receipt loads and all expected checks resolve.
- [ ] Canonical BLOCK receipt loads and all expected checks resolve.
- [ ] Receipt chain ID and block-explorer destination are correct.
- [ ] Public receipt does not expose the raw action payload.
- [ ] A newly generated receipt reaches `pending_anchor` and later `verified`.
- [ ] The deployment smoke receipt returns `sandbox: true` and its proof returns
      `status: sandbox`; it never receives a Merkle root.

Evidence:

```text
[URLs, timestamps, receipt IDs, screenshots, or exported JSON hashes]
```

## 2. Mandatory Execution Boundary

- [ ] The selected workflow calls Inntris before the protected action.
- [ ] The downstream system rejects calls without a valid approval result or
      equivalent enforced gateway decision.
- [ ] Token consumption requires the complete action parameters and creates one
      durable `approval_token_consumptions` row linked to its consumption audit
      row; replaying the same token fails closed.
- [ ] Direct credentials or bypass routes are removed, scoped, or documented.
- [ ] Suspended-agent behavior was tested against the real protected path.

Evidence:

```text
[architecture path, configuration reference, test result]
```

Read back a controlled consumed token without storing the token itself:

```sql
SELECT token_id, encode(token_digest, 'hex') AS token_digest,
       agent_id, action_hash, audit_log_id, consumed_at
FROM approval_token_consumptions
WHERE token_id = 'CONTROLLED_TOKEN_ID';

SELECT id, agent_id, action_type, action_hash, verdict, metadata, timestamp
FROM audit_logs
WHERE id = 'CONSUMPTION_AUDIT_UUID';
```

The first query must return exactly one row, the audit IDs must match, and the
audit action type must be `token_consumed`. Keep only the digest in evidence.

## 3. Policy And Admin Controls

- [ ] Agent status control works.
- [ ] Every production agent has explicit promotion evidence: `sandbox=false`,
      a non-empty approval reference, approver, and approval timestamp.
- [ ] The matching immutable `administrative_audit_events` promotion row records
      the organisation, actor, approval reference, agent, and resulting state.
- [ ] A write-scoped key without `admin` scope cannot promote an agent.
- [ ] Explicit blocklist takes precedence over allowlist.
- [ ] Non-allowlisted actions are blocked.
- [ ] Per-action spend limit was tested.
- [ ] Daily spend limit was tested.
- [ ] Rate limit was tested.
- [ ] Policy update validation rejects contradictory controls.
- [ ] Policy change owner and approval process are recorded.

Evidence:

```text
[agent id, policy hash, scenario receipts, owner]
```

Read back production promotion evidence without exposing keys:

```sql
SELECT id, org_id, status,
       metadata->>'sandbox' AS sandbox,
       metadata->>'production_approval_reference' AS approval_reference,
       metadata->>'production_approved_by' AS approved_by,
       metadata->>'production_approved_at' AS approved_at
FROM agents
WHERE id = 'PRODUCTION_AGENT_UUID';

SELECT count(*) AS production_agents_missing_evidence
FROM agents
WHERE metadata @> '{"sandbox": false}'::jsonb
  AND (
      NULLIF(btrim(metadata->>'production_approval_reference'), '') IS NULL
      OR NULLIF(btrim(metadata->>'production_approved_by'), '') IS NULL
      OR NULLIF(btrim(metadata->>'production_approved_at'), '') IS NULL
  );

SELECT id, org_id, event_type, actor, approval_reference, details, created_at
FROM administrative_audit_events
WHERE org_id = 'ORGANISATION_UUID'
  AND event_type = 'agent.production_promoted'
  AND approval_reference = 'APPROVAL_REFERENCE'
  AND details->>'agent_id' = 'PRODUCTION_AGENT_UUID'
ORDER BY created_at DESC;
```

The second query must return zero.

## 4. Database And Tenant Isolation

- [ ] Required migrations are applied.
- [ ] Runtime database role is recorded without exposing credentials.
- [ ] Tenant RLS role and policies are active if RLS is claimed.
- [ ] Cross-tenant read and write tests fail as expected.
- [ ] Audit-log UPDATE and DELETE restrictions are active.
- [ ] Anchor worker can update only required Merkle reference fields.
- [ ] A clean database replay reaches `0012_erasure_idempotency`.
- [ ] The selected sandbox smoke audit row has both `sandbox=true` and
      `test_request=true`, remains unanchored after a worker cycle, and returns
      sandbox proof status publicly.
- [ ] The latest authorised erasure has a completed `erasure_requests` ledger
      row and an exact tombstone; cryptographic and decision fields remain
      unchanged from the pre-erasure evidence.
- [ ] Runtime roles cannot insert erasure ledger rows or execute
      `app.erase_personal_data`.

Evidence:

```text
[migration output, role flags, test output, query hashes]
```

Required database readbacks:

```sql
SELECT version_num FROM alembic_version;

SELECT al.id, al.merkle_root_id,
       al.metadata->>'sandbox' AS sandbox,
       al.metadata->>'test_request' AS test_request
FROM audit_logs AS al
WHERE al.id = 'SANDBOX_AUDIT_UUID';

SELECT id, organization_id, subject_agent_id, requested_by, legal_basis,
       rows_affected, completed_at
FROM erasure_requests
ORDER BY requested_at DESC
LIMIT 20;

SELECT al.id, al.payload, al.metadata, al.request_ip, al.request_user_agent,
       al.action_hash, al.verdict, al.signature_valid, al.merkle_root_id
FROM audit_logs AS al
WHERE al.payload @> '{"erased": true}'::jsonb
ORDER BY al.timestamp DESC
LIMIT 20;

SELECT has_function_privilege(
           'inntris_api',
           'app.erase_personal_data(uuid,uuid,text,text,text)',
           'EXECUTE'
       ) AS api_can_erase,
       has_function_privilege(
           'inntris_worker',
           'app.erase_personal_data(uuid,uuid,text,text,text)',
           'EXECUTE'
       ) AS worker_can_erase;
```

The migration result must be `0012_erasure_idempotency`; the two
privilege values must be false. Save pre-erasure hashes or an approved export
so the preserved forensic fields can be compared rather than inferred.

## 5. Key And Secret Controls

- [ ] Agent private keys remain in customer-controlled custody.
- [ ] Organization API keys are stored as hashes.
- [ ] Admin session secret and server secret meet production length rules.
- [ ] Anchor submitter key storage method is documented.
- [ ] Current rotation owner and last rotation date are recorded.
- [ ] No plaintext secrets appear in the attached evidence.

Evidence:

```text
[secret-store reference names, fingerprints, dates; never raw values]
```

## 6. Blockchain And Anchor Operations

- [ ] Worker verifies the expected chain ID.
- [ ] Contract address matches the intended environment.
- [ ] Current admin, submitter, and pauser holders are read back.
- [ ] Safe and timelock topology is verified before it is claimed.
- [ ] Anchor backlog is within the agreed target.
- [ ] Failed and dead-letter anchor batches are reviewed.
- [ ] Gas cap and RPC circuit breaker settings are recorded.
- [ ] Sandbox rows are absent from every confirmed `merkle_proofs` batch.
- [ ] Exactly one `anchor-worker` instance is running. Do not scale this worker
      horizontally until a fenced lease prevents an old database session from
      submitting after lock ownership is lost.
- [ ] An independent Base event monitor alerts when the anchor contract records
      a root or submitter transaction that is absent from `merkle_proofs`.

Evidence:

```text
[block explorer links, role readback, worker metrics]
```

## 7. Monitoring, Backup, And Incident Readiness

- [ ] Verification, signature-failure, replay, rate-limit, and anchor metrics
      are visible.
- [ ] Alerts have owners and tested destinations.
- [ ] Prometheus has an active `inntris-anchor-worker` target and the worker
      `/metrics` scrape contains heartbeat, last-success, cycle, backlog, and
      submission series.
- [ ] Prometheus has an active `inntris-api` target and a controlled Redis
      stop trips `InntrisVerifyFailClosedUnavailable` (verification refusals
      must page the operator, not be discovered by customers).
- [ ] `ops/prometheus/inntris-alerts.yml` is loaded and all four worker rules
      are visible through the Prometheus rules API.
- [ ] A controlled warning and critical test alert reached the intended
      Alertmanager receivers and resolved successfully.
- [ ] Webhook delivery metrics are visible.
- [ ] Each configured organisation webhook is public HTTPS, has an encrypted
      tenant signing secret and version, and was verified by a real delivery.
- [ ] Privileged webhook configuration changes and secret rotations require a
      non-empty approval reference and have a matching immutable
      `administrative_audit_events` row.
- [ ] Retrying and dead-letter webhook rows are visible to the tenant and have
      an owner or documented disposition.
- [ ] Backup and retention configuration is read back from the provider.
- [ ] Restore or recovery procedure has a recorded test date.
- [ ] Incident-response owner and customer contact path are agreed.
- [ ] Security-reporting contact works.

Evidence:

```text
[dashboard links, alert tests, provider readback, owner names]
```

Required worker and alerting readbacks:

```bash
curl -fsS http://INNTRIS_WORKER_HOST:9100/metrics | grep '^inntris_anchor_'
curl -fsS 'http://PROMETHEUS_HOST:9090/api/v1/targets?state=active'
curl -fsS http://PROMETHEUS_HOST:9090/api/v1/rules
curl -fsS http://PROMETHEUS_HOST:9090/api/v1/alerts
curl -fsS http://ALERTMANAGER_HOST:9093/api/v2/status
promtool check config ops/prometheus/prometheus.yml
promtool check rules ops/prometheus/inntris-alerts.yml
amtool check-config ops/prometheus/alertmanager.yml
```

The active target labels must include `job="inntris-anchor-worker"`. Also
capture the actual notification from a controlled routed test; configuration
syntax alone does not prove paging.

Also capture the deployment platform replica readback for `anchor-worker` and a
successful test notification from the independent Base event monitor.

Required webhook readbacks:

```sql
SELECT id, webhook_url, webhook_secret_version, webhook_secret_rotated_at
FROM organizations
WHERE webhook_url IS NOT NULL
ORDER BY id;

SELECT status, count(*)
FROM webhook_deliveries
GROUP BY status
ORDER BY status;

SELECT id, org_id, event, attempt_count, response_status, last_error,
       last_attempt_at, dead_lettered_at
FROM webhook_deliveries
WHERE status IN ('retrying', 'dead_letter')
ORDER BY updated_at DESC
LIMIT 100;

SELECT id, org_id, event_type, actor, approval_reference, details, created_at
FROM administrative_audit_events
WHERE org_id = 'ORGANISATION_UUID'
  AND event_type IN (
      'organization.webhook_url_changed',
      'organization.webhook_secret_rotated'
  )
ORDER BY created_at DESC
LIMIT 100;
```

For each tenant, also call
`GET /admin/organization/webhook-deliveries?status=dead_letter` with
that tenant's read-scoped key. Attach row IDs and dispositions, never payloads
or signing secrets.

## 8. Security Scanning And Release State

- [ ] CI ran against the exact intended release commit.
- [ ] Frontend tests, type-check, and build passed.
- [ ] Backend tests passed.
- [ ] Contract tests passed if contract code changed.
- [ ] Current dependency findings were reviewed.
- [ ] SAST, SCA, and secret-scan findings were reviewed.
- [ ] Any accepted finding has an owner and expiry or follow-up date.

Evidence:

```text
[run URLs, command output summary, accepted-risk register]
```

## Final Decision

| Decision | Value |
| --- | --- |
| Ready for buyer review | `[yes / no]` |
| Ready for pilot | `[yes / no]` |
| Ready for production | `[yes / no]` |
| Blocking findings | `[list]` |
| Accepted residual risks | `[list]` |
| Approver | `[name]` |
| Approval timestamp UTC | `[timestamp]` |

Approval of this checklist authorizes only the named environment and scope. It
does not authorize unrelated policy changes, releases, or customer workflows.
