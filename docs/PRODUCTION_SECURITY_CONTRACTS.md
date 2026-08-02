# Production security contracts

This document defines the invariants that production code, migrations, tests,
and operations must preserve. A change that weakens one of these contracts is a
security change and requires explicit review.

## 1. Unauthenticated verification traffic

An invalid Ed25519 signature is an attack signal. It is not evidence that the
registered agent acted.

1. `POST /verify` reserves both a source budget and an agent identifier budget
   before agent lookup, action hashing, or signature verification.
2. The default budgets are 300 source attempts and 120 agent attempts per
   minute. `VERIFY_SOURCE_ATTEMPTS_PER_MINUTE` and
   `VERIFY_AGENT_ATTEMPTS_PER_MINUTE` may lower or raise them deliberately.
3. Redis is part of this security boundary. If the limiter is unavailable or
   fails, verification returns HTTP 503 and performs no signature work.
4. An invalid signature increments Prometheus counters and bounded Redis
   security counters with a one hour lifetime. Logs use a derived source
   identifier and the claimed agent identifier.
5. An invalid signature must not insert an audit row, reserve a nonce, evaluate
   policy, change trust, change activity counters, dispatch a webhook, issue an
   approval token, or create an anchor eligible receipt.
6. Source identity must reflect the true caller. A proxied deployment enables
   `TRUST_PROXY_HEADERS` with an accurate `TRUSTED_PROXY_HOPS` so the source
   budget and forensic `request_ip` key on the caller rather than the platform
   edge. Only the entries a trusted proxy appended to `X-Forwarded-For` are
   used; an unparseable header falls back to the socket peer. Never enable
   this on a listener that is reachable without passing through that chain.
7. Every fail closed refusal increments
   `inntris_verify_unavailable_total{component=...}` and the corresponding
   alert rule pages the operator. A nonce replay is a caller error (HTTP 401)
   and is never reported as unavailability.

The forensic execution chain begins only after successful authentication.

## 2. Agent registration and production approval

Every new agent is sandboxed. This is enforced in the API, in
`Database.create_agent`, and by the database default and constraint introduced
in migration `014_agent_production_approval.sql`.

1. Public registration always creates a sandbox agent. A caller supplied
   `sandbox: false` value and lifecycle metadata are ignored.
2. Authenticated `POST /admin/agents` also creates a sandbox agent. Registration
   and production approval are deliberately separate actions.
3. Only `POST /admin/agents/{agent_id}/promote` can clear the sandbox flag. It
   requires the tenant scoped `admin` permission, same organisation ownership,
   and a nonblank approval reference.
4. Promotion atomically records `production_approved_at`,
   `production_approved_by`, and `production_approval_reference` and activates
   the agent.
5. Generic agent updates cannot clear sandbox or fabricate approval metadata.
6. Sandbox audit rows carry both `sandbox: true` and `test_request: true`.
   Anchor selection excludes them.
7. The authenticated `/v1/events` synthetic identity follows the same rule.
   Its first records are sandbox records until an organisation admin promotes
   the returned agent identifier.

Migration `014_agent_production_approval.sql` converts legacy agents without
complete approval evidence to sandbox. Operators must review and promote each
intended production agent after the migration.

## 3. Webhook outbound boundary

Webhook delivery accepts only a canonical HTTPS URL on port 443. Credentials,
fragments, backslashes, control characters, nonpublic host suffixes, and unsafe
IP literals are rejected.

Before each delivery, Inntris resolves every DNS answer and rejects loopback,
private, link local, multicast, unspecified, and reserved addresses. The
transport resolves again when connecting, requires an intersection with the
approved address set, pins the connection to that public address, validates TLS
for the original hostname, and checks the connected peer address.

Redirects are disabled. Proxy environment variables are ignored. Connect,
read, write, and pool timeouts are bounded. Responses are limited to 64 KiB.

Each organisation has a random signing secret encrypted with AES GCM under a
key derived from `SERVER_SECRET` and bound to the organisation identifier. The
secret is revealed only when first installed or rotated. Deliveries contain an
HMAC SHA256 signature, secret version, event, and delivery identifier.

Delivery state is durable. Retryable failures receive at most three cumulative
attempts with bounded delays. Nonretryable failures and exhausted deliveries
enter `dead_letter`. Startup recovery resumes persisted pending and retrying
deliveries. See `docs/runbooks/webhooks.md`.

## 4. Authorised erasure

Migration `012_gdpr_erasure_guard.sql`, applied by Alembic revision
`0008_gdpr_erasure_guard`, is the active erasure contract. It is a forward
repair and does not rewrite an applied migration.

The erasure function uses `agents.org_id`, creates an `erasure_requests` ledger
entry, and issues a transaction local capability tied to that ledger entry.
The audit trigger permits only the exact payload tombstone, exact permitted
metadata, and clearing of request IP and user agent fields. It rejects an
incorrect tenant, agent, ledger state, capability, or any change to forensic
proof fields. Normal API and worker roles cannot execute the erasure function.

Every release replays the complete Alembic chain into a clean PostgreSQL
database and runs the end to end erasure contract. See
`docs/runbooks/gdpr_erasure.md`.

## 5. Execution proof

`POST /verify-token` may perform a stateless authenticity check with
`consume: false`. An execution gate must use `consume: true` and supply the
complete `action_type`, `payload`, `nonce`, and `timestamp`. The action hash
must match and the token can be consumed only once.

Executors should also send a stable `execution_ref`. The first successful call
returns `consumption_status: "consumed"`. An exact retry with the same token,
action, and reference returns `consumption_status: "idempotent"` and the same
`consumption_audit_id`. A different reference conflicts. Omitting the reference
keeps the legacy single-use contract, so a lost response remains ambiguous.

The approval token signs the sandbox state. A stateless `consume: false` check
may authenticate a sandbox token and reports `sandbox: true`, but an execution
gate using `consume: true` returns `valid: false` when either the signed token or
the current agent lifecycle state is sandboxed. Promoting an agent after token
issue therefore cannot authorise or anchor earlier test activity.

Only a production eligible token can return `consumption_audit_id`. The executor
must retain this identifier as evidence that approval was checked before
execution.

## 6. Release and operations gates

The release workflow starts PostgreSQL and Redis and runs migration replay,
GDPR, row level security, abuse limit, and anchor selection integration tests.
Python dependency audit, frontend production dependency audit, Gitleaks,
Semgrep findings, and Trivy configuration and secret findings block the security
workflow.

The anchor worker exposes Prometheus metrics on its dedicated metrics port.
The supplied rules in `ops/prometheus/inntris-alerts.yml` alert when the worker
is not scraped, its heartbeat becomes stale, proof failures or dead letters
exist, or submissions fail.

Green local checks establish deployable code. They do not prove that hosted
migrations, secrets, metrics scraping, alerts, DNS, TLS, or the worker process
are correctly configured. Production release requires the readback checks in
`docs/trust/PRODUCTION_READBACK_CHECKLIST.md`.
