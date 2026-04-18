# Incident response runbook

Phase 3.4 — triage playbook for the five incident classes the platform
actually reports on. Each section is organized the same way:
**Symptom → Detect → Contain → Investigate → Recover → Postmortem
checklist**.

Common operator handles referenced below:

| Handle | What it is |
|--------|-----------|
| `metrics` | The Prometheus `/metrics` endpoint (Phase 2C) — `inntris_*` series. |
| `logs` | Stdout JSON logs when `INNTRIS_JSON_LOGS=1` (Phase 2C). Grep on `request_id`. |
| `pauser` | Hot wallet holding `PAUSER_ROLE` on `AnchorRegistry` (Phase 3.3). |
| `safe` | Gnosis Safe holding `PROPOSER_ROLE` on the `TimelockController`. |
| `worker` | `workers/anchor_worker.py` process (can be stopped without data loss). |

All times are UTC. "Sev" tags follow the usual Sev1 (user-visible
breakage, hour-scale response) / Sev2 (degraded, business-hours) /
Sev3 (informational) convention.

---

## 1. Signature-failure spike

**Sev: 2 (can promote to 1 if sustained).**

Signatures in `/verify` are failing unexpectedly. Either a key has
rotated without the client being updated, or an attacker is probing.

### Detect
* `rate(inntris_signature_failures_total[5m])` crosses its alert
  threshold.
* Logs show `signature_invalid` records clustered on a single
  `agent_id` or source IP.

### Contain
1. If one agent dominates: disable its API key in the public_orgs
   table; RLS will stop accepting new calls within one rate-limit
   window.
2. If the spike is cross-agent: suspect a clock-skew or a canonical
   payload regression — jump straight to Investigate.

### Investigate
* `SELECT agent_id, count(*) FROM audit_logs WHERE verdict='invalid_signature' AND created_at > now()-interval '15 min' GROUP BY 1 ORDER BY 2 DESC`
  tells you whether the failures concentrate on a small agent set.
* Compare `fingerprint` in the failing payloads against the canonical
  rules in `docs/RECEIPT_CANONICALIZATION.md`. A mismatch almost
  always means the client skipped the `policy_hash` field or the
  timestamp canonicalization changed.
* Check recent deploys — a backend canonicalization change is the
  most common cause of a legitimate-client mass failure.

### Recover
* Key compromise suspected → see `secrets_rotation.md` §API keys.
* Canonicalization regression → roll back the offending deploy; the
  anchor worker has no state that cares.

### Postmortem checklist
* Were the failures blocked by rate limits or just logged? (Should
  have been rate-limited at the per-agent window.)
* Did the signature-failures counter move at least 5 minutes before
  a human noticed?

---

## 2. Nonce replay attempts

**Sev: 2. Usually an attacker / misconfigured client replaying.**

### Detect
* `rate(inntris_nonce_replays_total[5m])` > 0 for more than one
  window. Legitimate clients should never hit this.

### Contain
* Identify the source agent from the JSON log for the replayed
  request (each replay log carries `agent_id` and `request_id`).
* Same as §1 Contain step 1 — disable the API key of the replaying
  agent.

### Investigate
* Confirm the original request that established the nonce: search
  audit_logs by `nonce` value. If no prior request exists, Redis has
  been wiped (e.g. a cache flush) and this is a false alarm; see
  Recover.
* If a prior request exists with a different client IP, the key is
  likely leaked — proceed to rotation.

### Recover
* Key leak: rotate via `secrets_rotation.md` §API keys and revoke the
  old one.
* Redis wipe: accept the replay window loss; nonces pre-wipe are now
  also reusable. Mitigation: the Ed25519 signature *plus* the
  rolling-window rate limit still rejects most replay-based abuse.

### Postmortem checklist
* Did the nonce TTL match the expected signature validity window?
  Misaligned TTLs are a common false-positive source.

---

## 3. Anchor worker stuck or mempool issues

**Sev: 1 if unanchored log backlog exceeds SLA; Sev 2 otherwise.**

### Detect
* `inntris_anchor_submissions_total{outcome="failed"}` climbing or
  `outcome="dead_letter"` non-zero (Phase 2B+2C).
* `get_unanchored_logs` returning a growing count — surface via a
  scrape on the worker's metrics.
* Worker log line `assert_chain_id mismatch` or `gas cap exceeded —
  refusing to submit`.

### Contain
1. **Stop the worker.** `SIGINT` is safe — the anchor worker state
   machine (Phase 0.6) ensures in-flight batches either confirm or
   move to `failed` on retry.
2. Do **not** delete the `pending_anchor` batches. They carry the
   audit-log integrity story.

### Investigate
* `gas cap exceeded`: network is congested. Either raise
  `MAX_GAS_PRICE_GWEI` for a single scheduled run, or wait for gas
  to subside. Never raise the cap silently in production config —
  set it on a one-shot invocation with an explicit env override.
* `chain id mismatch`: the RPC endpoint has been pointed at the
  wrong network. Check `BASE_RPC_URL`. Do NOT restart the worker
  until resolved.
* `outcome=dead_letter`: inspect the batch row. These require a
  human decision to either retry or close out with a documented
  reason.

### Recover
* Restart the worker once the blocker is cleared. The retry loop
  picks up `failed` rows automatically.
* If the on-chain contract is paused (see §5), do not restart until
  unpause is queued through the timelock.

### Postmortem checklist
* How long was the unanchored log window?
* Did monitoring page in under 10 minutes?

---

## 4. Paused contract / admin incident

**Sev: 1.**

### Detect
* `AnchorRegistry.paused()` returns `true` unexpectedly; worker
  cannot anchor and starts logging `outcome=failed`.
* Unexpected `RoleGranted` / `RoleRevoked` events on the registry.

### Contain — IMMEDIATE
1. **Verify the pause is ours.** Check the `Paused` event sender
   against the known pauser hot-wallet address.
   * If it matches: intentional — likely a sibling incident;
     coordinate with whoever initiated.
   * If it does NOT match: the `DEFAULT_ADMIN_ROLE` (timelock) has
     been used to grant `PAUSER_ROLE` to a new address, which means
     a 48h timelock op successfully executed against us.
2. If the pause is hostile, check `TimelockController` for pending
   ops and cancel any that are not ours from the Safe.

### Investigate
* `etherscan` / `basescan` for recent calls to the registry and the
  timelock. Compare against our Safe's proposal history.
* Confirm the Safe signer set has not been altered (Safe mgmt UI).

### Recover
* Hostile pauser: from the Safe, schedule
  `revokeRole(PAUSER_ROLE, attackerAddr)` through the timelock.
  Wait the delay. Execute. During the delay, keep the contract
  paused — the worker is read-safe, just cannot write.
* Once remediated, schedule `unpause` from the Safe and execute
  after the delay.

### Postmortem checklist
* Did the Safe threshold require more signatures than expected
  given the incident?
* Did on-chain monitoring alert on the scheduled op while the delay
  was still running? The 48h delay is only useful if we actually
  watch the queue.

---

## 5. Rate-limit storm / denial-of-service

**Sev: 2 (public), Sev: 1 (admin-login lockout).**

### Detect
* `rate(inntris_rate_limit_trips_total[1m])` surges, especially the
  `window="public_verify"` label.
* 429 responses dominate the `/verify` latency histogram.

### Contain
* The rate limiter is fail-closed (Phase 0.5). That is the correct
  state under load.
* If legitimate traffic is being blocked, identify the offending
  agent set and consider raising that agent's per-minute window in
  code — NOT the global limit.

### Investigate
* Is the surge from a single `/32` or `/24`? Add a WAF rule at the
  edge; do not add IP allowlists to app code.
* Check whether the surge correlates with a recent documentation
  release — it is common for new clients to over-fetch on first
  integration.

### Recover
* Edge WAF rule for the offending network range, 1-hour TTL.
* Comm to affected legitimate clients: their requests are being
  queued client-side by retries; our API is deliberately rejecting.

### Postmortem checklist
* Did fail-closed behavior cause any secondary outage (e.g.
  cascading timeouts in downstream systems)?
* Did alerting for `admin_login` rate-limit trips page separately?
  (Admin login trips are ~always incident-worthy.)

---

## Generic triage template

When an incident does not match a pre-written class:

1. **Stop the bleeding first.** Prefer pausing writes over losing
   data — our forensic guarantee depends on `audit_logs` being a
   complete record of what the API decided.
2. **Capture state before changing it.** `pg_dump` of `audit_logs`
   and the relevant `agent` rows, Redis `DEBUG INFO`, current
   metrics scrape, last 1k log lines. These live forever on shared
   storage under `incidents/YYYY-MM-DD-short-slug/`.
3. **Narrow the blast radius with the timelock.** `schedule` the
   remediation from the Safe; if the situation escalates during
   the delay, `cancel` is always available.
4. **Write the postmortem the same day.** Template:
   `what happened / detection gap / recovery gap / prevention`.
