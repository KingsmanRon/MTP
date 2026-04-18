// -----------------------------------------------------------------------------
// loadtests/signature_storm.js — stress test the signature-failure path
// -----------------------------------------------------------------------------
// Sends malformed /verify requests at high concurrency to verify that the
// rate limiter stays fail-closed under load and that the signature-check
// hot path does not become a throughput bottleneck.
//
// Why not send valid signatures? A real load test of the approved path
// requires per-VU Ed25519 signing, which needs either a pre-generated pool
// of signed requests or a k6 crypto extension. The *hostile traffic* path
// below exercises the same code up through the Ed25519 verify call — which
// is the CPU-bound step we care about — and has the advantage of not
// requiring any production key material or seeded test agents.
//
// Expected steady-state under this script:
//   * 401 (signature invalid) or 429 (rate limited) for every request.
//   * inntris_signature_failures_total counter climbs.
//   * inntris_rate_limit_trips_total{window="public_verify"} climbs.
//   * No 5xx. A 5xx spike means the rate limiter is not fail-closed or
//     the DB / Redis pool is exhausting under backpressure.
//
// Run:
//   BASE_URL=https://api.example.com \
//   AGENT_ID=00000000-0000-0000-0000-000000000000 \
//   k6 run loadtests/signature_storm.js

import http from 'k6/http';
import { check } from 'k6';
import { Counter, Rate } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const AGENT_ID = __ENV.AGENT_ID || '00000000-0000-0000-0000-000000000000';

export const options = {
    scenarios: {
        storm: {
            executor: 'constant-arrival-rate',
            rate: Number(__ENV.RATE || 200),      // requests per second
            timeUnit: '1s',
            duration: __ENV.DURATION || '2m',
            preAllocatedVUs: 50,
            maxVUs: 500,
        },
    },
    thresholds: {
        // Property we care about: NO 5xx even under sustained hostile load.
        // Every response must be either a deliberate client-error (401/404/
        // 429) or a 200 — but 200 is impossible here because the signatures
        // are intentionally wrong.
        'http_req_failed':         ['rate<0.001'],
        'server_errors':           ['rate<0.001'],
        // The whole point of rate limiting is backpressure without work —
        // so p99 should be small even under load.
        'http_req_duration':       ['p(99)<2000'],
        // Every request should be classified (not a timeout).
        'classified_responses':    ['count>0'],
    },
};

const serverErrors = new Rate('server_errors');
const classified = new Counter('classified_responses');
const clientRejects = new Counter('client_rejects');

// A deliberately invalid Ed25519 signature. 64 bytes base64url of zeros is
// never a valid signature for any real message. We vary the nonce per
// request so nonce-replay is not the primary rejection reason — the
// signature check should reject first.
const FAKE_SIG = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function isoTimestamp() {
    return new Date().toISOString();
}

function randomNonce() {
    // 32 hex chars — sufficient uniqueness for a 2-minute storm, cheap to
    // generate in k6's runtime.
    let s = '';
    for (let i = 0; i < 32; i++) {
        s += Math.floor(Math.random() * 16).toString(16);
    }
    return s;
}

export default function () {
    const body = JSON.stringify({
        agent_id: AGENT_ID,
        action_type: 'loadtest_storm',
        payload: { resource: 'loadtest', operation: 'read' },
        signature: FAKE_SIG,
        nonce: randomNonce(),
        timestamp: isoTimestamp(),
        sig_version: 2,
    });

    const res = http.post(`${BASE_URL}/verify`, body, {
        headers: { 'Content-Type': 'application/json' },
        tags: { endpoint: 'verify_storm' },
    });

    serverErrors.add(res.status >= 500);

    // Classify. Anything other than these is unexpected.
    const ok = res.status === 401  // signature invalid
            || res.status === 403  // policy violation / blocked
            || res.status === 404  // unknown agent (if AGENT_ID not seeded)
            || res.status === 422  // validation error
            || res.status === 429; // rate limited

    if (ok) {
        classified.add(1);
        clientRejects.add(1);
    }

    check(res, {
        'no 5xx under storm':     (r) => r.status < 500,
        'classified rejection':   () => ok,
    });
}
