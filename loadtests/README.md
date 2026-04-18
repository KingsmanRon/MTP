# Load tests

Phase 5.1 — k6 scripts for stress-testing the API. These are meant for
a staging environment with production-like resources, not against the
public API.

## Prerequisites

* [k6](https://k6.io/docs/get-started/installation/) installed on the
  machine that will generate load. On Linux:
  `sudo apt-get install k6`. On macOS: `brew install k6`.
* Network access to the target API.
* For `signature_storm.js`, an `AGENT_ID` that exists in the target
  environment — otherwise every request is rejected with 404 before
  reaching the signature-check hot path, which makes the test
  measure the wrong thing.

## Scripts

| Script | Purpose | Mode |
|--------|---------|------|
| [baseline.js](baseline.js) | Happy-path public read throughput: `/health`, `/metrics`, `/public/agent/{id}` | Ramping VUs 0 → 100 over ~4 min |
| [signature_storm.js](signature_storm.js) | Hostile traffic: malformed `/verify` at high arrival rate. Verifies the rate limiter stays fail-closed and the signature-check path does not induce 5xx | Constant arrival rate (default 200 rps, 2 min) |

## Running

```bash
# Baseline — a fresh environment check
BASE_URL=https://staging-api.example.com \
AGENT_ID=00000000-0000-0000-0000-000000000000 \
k6 run loadtests/baseline.js

# Signature storm
BASE_URL=https://staging-api.example.com \
AGENT_ID=00000000-0000-0000-0000-000000000000 \
RATE=200 \
DURATION=2m \
k6 run loadtests/signature_storm.js
```

## What to watch during a run

On the API side:

* `inntris_verify_requests_total{verdict=…}` — should show only
  `invalid_signature` and `rate_limited` under the storm script.
* `inntris_rate_limit_trips_total{window="public_verify"}` — should
  climb within the first 15 seconds of the storm run.
* `inntris_verify_latency_seconds` — the p99 should stay bounded
  even when the rate limiter is rejecting most requests (the
  approved path never runs, so this histogram barely moves).
* 5xx ratio — **must stay near zero**. A 5xx spike under load is the
  regression signal.

On the worker side (if running):

* `inntris_anchor_submissions_total` — the worker should not be
  affected by load-test traffic; if it starts failing, the shared
  DB pool is saturated.

## Thresholds

Both scripts have thresholds declared inline. A failed threshold
produces a non-zero exit code, so these can be wired into a CI job
for nightly performance regression alerts. **Tighten** the initial
baseline thresholds after the first real run on staging — the
defaults are generous so the scripts do not fail on a cold cache.

## Explicitly NOT tested here

* **Happy path `/verify` with valid signatures.** Generating valid
  Ed25519 signatures inside k6 requires either a pre-generated pool
  of signed requests or a [k6 crypto
  extension](https://github.com/szkiba/xk6-crypto). When this is
  needed, add a `loadtests/build_signed_pool.py` helper that emits
  a `requests.ndjson` file the VU reads from.
* **Sustained multi-hour runs.** The scripts are sized for a short
  CI/staging validation, not for burn-in. For endurance testing,
  raise `DURATION` and `RATE` explicitly and schedule during a
  low-traffic window.
* **Worker stress.** The anchor worker runs on its own schedule; it
  is not exercised directly by these scripts. To stress it, seed
  the `audit_logs` table with a known number of unanchored rows
  and observe the time to drain.
