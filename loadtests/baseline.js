// -----------------------------------------------------------------------------
// loadtests/baseline.js — Phase 5.1 baseline throughput for public endpoints
// -----------------------------------------------------------------------------
// Hits the unauthenticated read paths under load so we have a steady-state
// reference number: RPS sustainable, p95/p99 latency, and error ratio before
// any hostile traffic is mixed in. Run this first on any new environment;
// deviations here invalidate everything else.
//
// Endpoints hit:
//   * GET /health                    — startup/liveness check, near-free
//   * GET /metrics                   — Prometheus generate_latest() path
//   * GET /public/agent/{agent_id}   — DB read path with RLS enforcement
//
// Run:
//   BASE_URL=https://api.example.com \
//   AGENT_ID=00000000-0000-0000-0000-000000000000 \
//   k6 run loadtests/baseline.js
//
// Thresholds fail the run if the SLA regresses, so this can be wired
// into CI once the target numbers are established.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const AGENT_ID = __ENV.AGENT_ID || '00000000-0000-0000-0000-000000000000';

export const options = {
    scenarios: {
        ramp: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '30s', target: 20 },   // warm up
                { duration: '2m',  target: 50 },   // steady load
                { duration: '1m',  target: 100 },  // peak
                { duration: '30s', target: 0 },    // cool down
            ],
            gracefulRampDown: '15s',
        },
    },
    // Baseline SLA: these are intentionally generous for a first run. Tighten
    // once we have real numbers from a representative environment.
    thresholds: {
        http_req_failed:   ['rate<0.01'],        // <1% errors
        http_req_duration: ['p(95)<500', 'p(99)<1500'],
        // per-endpoint breakdowns
        'http_req_duration{endpoint:health}':  ['p(95)<100'],
        'http_req_duration{endpoint:metrics}': ['p(95)<300'],
        'http_req_duration{endpoint:agent}':   ['p(95)<500'],
    },
};

// Per-endpoint trend so a regression on one path doesn't hide behind
// another's latency.
const agentReadTrend = new Trend('agent_read_ms', true);
const errorRate = new Rate('errors');

export default function () {
    const r1 = http.get(`${BASE_URL}/health`, {
        tags: { endpoint: 'health' },
    });
    errorRate.add(r1.status !== 200);
    check(r1, { 'health 200': (r) => r.status === 200 });

    const r2 = http.get(`${BASE_URL}/metrics`, {
        tags: { endpoint: 'metrics' },
    });
    errorRate.add(!(r2.status === 200 || r2.status === 501));
    check(r2, {
        'metrics 200 or 501': (r) => r.status === 200 || r.status === 501,
    });

    const r3 = http.get(`${BASE_URL}/public/agent/${AGENT_ID}`, {
        tags: { endpoint: 'agent' },
    });
    agentReadTrend.add(r3.timings.duration);
    // 404 is a legitimate response for a non-seeded environment — we only
    // count 5xx as baseline errors.
    errorRate.add(r3.status >= 500);
    check(r3, { 'agent not 5xx': (r) => r.status < 500 });

    sleep(0.5);
}

export function handleSummary(data) {
    return {
        'stdout': defaultSummary(data),
        'loadtests/out/baseline-summary.json': JSON.stringify(data, null, 2),
    };
}

// Minimal CLI summary renderer so the script works without @k6/summary
// extensions. k6 v0.49+ provides textSummary; we fall back to JSON.stringify
// if the import is unavailable.
function defaultSummary(data) {
    try {
        // eslint-disable-next-line import/no-unresolved
        const { textSummary } = require('https://jslib.k6.io/k6-summary/0.0.2/index.js');
        return textSummary(data, { indent: ' ', enableColors: true });
    } catch (_e) {
        return JSON.stringify(data, null, 2);
    }
}
