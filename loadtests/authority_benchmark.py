"""Phase 7A, Gate 7 — measure the authority path, then set SLOs from it.

The rule this exists to serve: **do not invent targets without evidence.**
An alert threshold picked from intuition either fires constantly or never
fires, and both are worse than no alert. So this measures, and the SLO
document quotes what it measured.

What it measures
----------------
Each stage separately, because they have different costs and different
failure modes, and an aggregate number hides which one moved:

``authority_evaluation``  policy evaluation plus issuance (a grant row, a
                          spend reservation, an audit row, evidence)
``consume``               claiming a grant once, under its lock
``vi_verification``       resolving a delegated-authority artefact: parse,
                          signature, revocation read, principal binding
``receipt_signing``       signing one v3 evidence event
``lock_contention``       many consumers against ONE grant, which is the
                          shape that actually serialises

Reported: p50, p95, p99, max, throughput, and the failure rate. A run that
hides failures behind a latency figure is measuring the wrong thing, so
errors are counted and reported alongside.

Running it
----------
    DATABASE_URL=postgresql://... \\
      python -m loadtests.authority_benchmark --concurrency 32 --iterations 500

``--json path`` writes the measurements for the release record. Nothing
here writes an SLO: that is a judgement made from the numbers, in
docs/AUTHORITY_SLO.md, not by this script.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import secrets
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import UUID, uuid4

from nacl.signing import SigningKey

from api import jcs
from api.core.authority.authority import (
    DelegatedAuthorityClaim,
    ExecutionContext,
    trusted_authority_construction,
)
from api.database import Database
from api.persistence.authority_store import AuthorityStore
from api.receipts.v3 import (
    EvidenceEventType,
    EvidenceSigningKey,
    sign_evidence_event,
)
from api.services.authority_provider import (
    ARTEFACT_EVIDENCE_KEY,
    TrustedIssuerAuthorityProvider,
)
from api.trust.artefact import ARTEFACT_FORMAT
from api.trust.issuer_registry import TrustedIssuerRegistry, public_key_fingerprint
from api.trust.revocations import RevocationSnapshot

POLICY_HASH = "b" * 64
BINDING = "c" * 64
FORMAT = "inntris-payment-authority-policy-v1"
ISSUER_ID = "benchmark-issuer"

#: Benchmark-only key material. Signs nothing outside this process.
ISSUER_KEY = SigningKey(hashlib.sha256(b"gate-7-issuer").digest())
EVIDENCE_KEY = SigningKey(hashlib.sha256(b"gate-7-evidence").digest())


@dataclass
class Measurement:
    """Latencies for one stage, and how often it failed -- and why.

    A failure rate with no reason attached is not a measurement: it cannot
    tell an operator whether the system is saturated, deadlocking, or
    simply refusing what it should refuse. So every failure is counted
    under its SQLSTATE where PostgreSQL gave one, and under its exception
    type otherwise.
    """

    stage: str
    samples: list[float] = field(default_factory=list)
    failures: int = 0
    failure_reasons: dict[str, int] = field(default_factory=dict)
    wall_seconds: float = 0.0

    def record(self, seconds: float) -> None:
        self.samples.append(seconds * 1000.0)

    def record_failure(self, exc: BaseException) -> None:
        self.failures += 1
        sqlstate = getattr(exc, "sqlstate", None)
        key = f"sqlstate:{sqlstate}" if sqlstate else type(exc).__name__
        if sqlstate == "40P01":
            key = "sqlstate:40P01 (deadlock_detected)"
        elif sqlstate == "40001":
            key = "sqlstate:40001 (serialization_failure)"
        self.failure_reasons[key] = self.failure_reasons.get(key, 0) + 1

    def summary(self) -> dict[str, object]:
        if not self.samples:
            return {
                "stage": self.stage,
                "samples": 0,
                "failures": self.failures,
                "failure_reasons": dict(sorted(self.failure_reasons.items())),
                "note": "no successful samples",
            }
        ordered = sorted(self.samples)
        total = len(ordered) + self.failures
        return {
            "stage": self.stage,
            "samples": len(ordered),
            "failures": self.failures,
            "failure_reasons": dict(sorted(self.failure_reasons.items())),
            "failure_rate": round(self.failures / total, 6) if total else 0.0,
            "p50_ms": round(_percentile(ordered, 50), 3),
            "p95_ms": round(_percentile(ordered, 95), 3),
            "p99_ms": round(_percentile(ordered, 99), 3),
            "max_ms": round(ordered[-1], 3),
            "mean_ms": round(statistics.fmean(ordered), 3),
            "wall_seconds": round(self.wall_seconds, 3),
            "throughput_per_second": (
                round(len(ordered) / self.wall_seconds, 2) if self.wall_seconds else None
            ),
        }


def _percentile(ordered: list[float], percentile: float) -> float:
    """Nearest-rank, so a p99 is a sample that actually happened."""
    if not ordered:
        return 0.0
    rank = max(1, min(len(ordered), round(percentile / 100.0 * len(ordered) + 0.5)))
    return ordered[rank - 1]


def _static_policy():
    def resolver(_agent, _action_type, _domain):
        return POLICY_HASH, "revision-1"

    return resolver


def action_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


async def setup_agent(db: Database) -> tuple[UUID, UUID]:
    org_id, agent_id = uuid4(), uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
            VALUES ($1, $2, 'enterprise', $3, $4)
            """,
            org_id,
            f"benchmark-{org_id}",
            f"benchmark-{org_id}@invalid.test",
            hashlib.sha256(str(org_id).encode()).digest(),
        )
        await conn.execute(
            """
            INSERT INTO agents (
                id, org_id, name, public_key, public_key_fingerprint, trust_score,
                status, daily_limit_usd, per_action_limit_usd, allowed_actions,
                blocked_actions, rate_limit_per_minute, metadata
            ) VALUES (
                $1, $2, $3, $4, $5, 95, 'active', 100000000, 100000000,
                ARRAY['financial_transaction']::TEXT[], ARRAY[]::TEXT[], 10000000, $6::JSONB
            )
            """,
            agent_id,
            org_id,
            f"benchmark-agent-{agent_id}",
            secrets.token_bytes(32),
            hashlib.sha256(str(agent_id).encode()).hexdigest(),
            json.dumps(
                {
                    "sandbox": False,
                    "production_approval_reference": "gate-7-benchmark",
                    "production_approved_at": "2026-01-01T00:00:00Z",
                    "production_approved_by": "gate-7-benchmark",
                }
            ),
        )
    return org_id, agent_id


async def _issue(store: AuthorityStore, org_id: UUID, agent_id: UUID, ref: str):
    now = datetime.now(UTC)
    return await store.issue(
        agent_id=agent_id,
        organisation_id=org_id,
        issuance_ref=ref,
        execution_action_hash=action_hash(ref),
        policy_hash=POLICY_HASH,
        policy_snapshot_format=FORMAT,
        policy_revision="revision-1",
        executor_binding_digest=BINDING,
        domain="payment",
        action_type="financial_transaction",
        minute_start=now.replace(second=0, microsecond=0),
        day_start=now.replace(hour=0, minute=0, second=0, microsecond=0),
        rate_limit_per_minute=10_000_000,
        daily_limit_usd=Decimal("100000000"),
        amount_usd=Decimal("1"),
    )


async def _run_concurrent(measurement: Measurement, tasks: list, concurrency: int) -> None:
    """Run ``tasks`` with at most ``concurrency`` in flight, timing each."""
    semaphore = asyncio.Semaphore(concurrency)

    async def timed(factory) -> None:
        async with semaphore:
            started = time.perf_counter()
            try:
                await factory()
            except Exception as exc:  # noqa: BLE001 — a failure is a measurement
                measurement.record_failure(exc)
                return
            measurement.record(time.perf_counter() - started)

    wall_started = time.perf_counter()
    await asyncio.gather(*(timed(factory) for factory in tasks))
    measurement.wall_seconds = time.perf_counter() - wall_started


async def measure_issuance(
    db: Database, org_id: UUID, agent_id: UUID, *, iterations: int, concurrency: int
) -> Measurement:
    store = AuthorityStore(db, current_policy_resolver=_static_policy())
    measurement = Measurement("authority_evaluation")
    run = uuid4().hex[:8]
    tasks = [
        (lambda index=index: _issue(store, org_id, agent_id, f"bench-{run}-{index}"))
        for index in range(iterations)
    ]
    await _run_concurrent(measurement, tasks, concurrency)
    return measurement


async def measure_consume(
    db: Database, org_id: UUID, agent_id: UUID, *, iterations: int, concurrency: int
) -> Measurement:
    """One consumer per grant: the uncontended cost of claiming authority."""
    store = AuthorityStore(db, current_policy_resolver=_static_policy())
    run = uuid4().hex[:8]
    # Bounded, and errors kept rather than raised: the setup for this stage
    # must not silently become the measurement.
    setup = Measurement("consume_setup")
    grants: list = []

    async def _setup_one(index: int) -> None:
        ref = f"consume-{run}-{index}"
        # Keep the reference WITH its grant: IssueResult does not carry the
        # action hash, and reconstructing it from a list position would make
        # a reordered setup measure action-hash mismatches instead of
        # consumption.
        grants.append((ref, await _issue(store, org_id, agent_id, ref)))

    await _run_concurrent(
        setup, [(lambda i=i: _setup_one(i)) for i in range(iterations)], concurrency
    )
    if setup.failures:
        print(
            f"NOTE: {setup.failures} of {iterations} setup issuances failed "
            f"({setup.failure_reasons}); the consume stage measures the "
            f"{len(grants)} that succeeded",
            file=sys.stderr,
        )
    measurement = Measurement("consume")
    # Each grant is consumed with the reference its own issuance used, so a
    # reordered setup cannot make this measure action-hash mismatches.
    tasks = [
        (
            lambda ref=ref, grant=grant: store.consume(
                grant_id=grant.grant_id,
                execution_action_hash=action_hash(ref),
                executor_binding_digest=BINDING,
                execution_ref=f"exec-{uuid4().hex}",
            )
        )
        for ref, grant in grants
        if grant.grant_id is not None
    ]
    await _run_concurrent(measurement, tasks, concurrency)
    return measurement


async def measure_lock_contention(
    db: Database, org_id: UUID, agent_id: UUID, *, concurrency: int, rounds: int
) -> Measurement:
    """Many consumers, ONE grant. This is the shape that serialises.

    Only one consumer per round can win; the rest are refused. Both are
    measured, because an operator's dashboard sees both and the refusals
    are the ones that queue behind the lock.
    """
    store = AuthorityStore(db, current_policy_resolver=_static_policy())
    measurement = Measurement("lock_contention")
    run = uuid4().hex[:8]
    wall_started = time.perf_counter()

    for round_index in range(rounds):
        ref = f"contend-{run}-{round_index}"
        grant = await _issue(store, org_id, agent_id, ref)

        async def one(index: int, grant_id, round_ref: str = "") -> None:
            started = time.perf_counter()
            try:
                await store.consume(
                    grant_id=grant_id,
                    execution_action_hash=action_hash(round_ref),
                    executor_binding_digest=BINDING,
                    execution_ref=f"exec-{round_ref}-{index}",
                )
            except Exception as exc:  # noqa: BLE001
                measurement.record_failure(exc)
                return
            measurement.record(time.perf_counter() - started)

        await asyncio.gather(*(one(index, grant.grant_id) for index in range(concurrency)))

    measurement.wall_seconds = time.perf_counter() - wall_started
    return measurement


def _benchmark_artefact() -> dict:
    payload = {
        "format": ARTEFACT_FORMAT,
        "issuer": ISSUER_ID,
        "authority_id": "bench-auth-1",
        "principal": {"account_reference": "acct-benchmark"},
        "scope": {"max_amount": "500.00", "currency": "USD"},
    }
    signature = ISSUER_KEY.sign(jcs.canonicalize(payload)).signature
    return {
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "key_id": "bench-key-1",
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def measure_vi_verification(*, iterations: int) -> Measurement:
    """Artefact parse, signature verification, binding checks.

    Synchronous and CPU-bound. The revocation read it depends on is a
    separate database round trip, measured as part of issuance rather than
    double-counted here.
    """
    registry = TrustedIssuerRegistry.from_document(
        {
            "version": 1,
            "issuers": [
                {
                    "issuer_id": ISSUER_ID,
                    "status": "active",
                    "keys": [
                        {
                            "key_id": "bench-key-1",
                            "public_key": bytes(ISSUER_KEY.verify_key).hex(),
                            "fingerprint": public_key_fingerprint(bytes(ISSUER_KEY.verify_key)),
                            "status": "active",
                        }
                    ],
                    "principal_claim_bindings": {"account_reference": "issuer_account_reference"},
                }
            ],
        }
    )
    provider = TrustedIssuerAuthorityProvider(registry, RevocationSnapshot())
    artefact = _benchmark_artefact()
    claim = DelegatedAuthorityClaim(
        issuer=ISSUER_ID,
        external_reference_id="bench-auth-1",
        evidence={ARTEFACT_EVIDENCE_KEY: artefact},
    )
    context = ExecutionContext(
        trusted_authority_construction(),
        organisation_id=str(uuid4()),
        principal_id=str(uuid4()),
        principal_binding={"issuer_account_reference": "acct-benchmark"},
    )

    measurement = Measurement("vi_verification")
    wall_started = time.perf_counter()
    for _ in range(iterations):
        started = time.perf_counter()
        resolved = provider.resolve(claim, context)
        if not resolved.is_verified:
            measurement.failures += 1
            continue
        measurement.record(time.perf_counter() - started)
    measurement.wall_seconds = time.perf_counter() - wall_started
    return measurement


def measure_receipt_signing(*, iterations: int) -> Measurement:
    key = EvidenceSigningKey(signing_key=EVIDENCE_KEY, key_id="iae-benchmark")
    body = {
        "decision": "allow",
        "grant_id": str(uuid4()),
        "execution_action_hash": "ab" * 32,
        "executor_binding_digest": BINDING,
        "agent_id": str(uuid4()),
        "organisation_id": str(uuid4()),
    }
    measurement = Measurement("receipt_signing")
    wall_started = time.perf_counter()
    for _ in range(iterations):
        started = time.perf_counter()
        sign_evidence_event(
            event_id=str(uuid4()),
            event_type=EvidenceEventType.DECISION,
            body=body,
            key=key,
            recorded_at=datetime.now(UTC),
        )
        measurement.record(time.perf_counter() - started)
    measurement.wall_seconds = time.perf_counter() - wall_started
    return measurement


async def measure_multi_agent_issuance(
    db: Database, *, agents: int, per_agent: int, concurrency: int
) -> Measurement:
    """The same work spread across MANY principals.

    This is the stage that decides whether the per-principal serialisation
    measured above is a global ceiling or a per-principal one. The audit
    hash chain is per agent and the spend advisory lock is per agent, so the
    prediction is that spreading the same load over many principals removes
    the contention entirely. If it does not, the ceiling is global and the
    release has a much bigger problem.
    """
    store = AuthorityStore(db, current_policy_resolver=_static_policy())
    pairs = [await setup_agent(db) for _ in range(agents)]
    measurement = Measurement("multi_agent_issuance")
    run = uuid4().hex[:8]
    tasks = [
        (
            lambda org=org, agent=agent, index=index: _issue(
                store, org, agent, f"multi-{run}-{index}"
            )
        )
        for org, agent in pairs
        for index in range(per_agent)
    ]
    await _run_concurrent(measurement, tasks, concurrency)
    return measurement


async def measure_multi_agent_consume(
    db: Database, *, agents: int, per_agent: int, concurrency: int
) -> Measurement:
    """Consumption spread across many principals, for the same reason."""
    store = AuthorityStore(db, current_policy_resolver=_static_policy())
    pairs = [await setup_agent(db) for _ in range(agents)]
    run = uuid4().hex[:8]

    setup = Measurement("multi_agent_consume_setup")
    grants: list = []

    async def _setup_one(org: UUID, agent: UUID, index: int) -> None:
        ref = f"multi-consume-{run}-{index}"
        grants.append((ref, await _issue(store, org, agent, ref)))

    await _run_concurrent(
        setup,
        [
            (lambda org=org, agent=agent, i=i: _setup_one(org, agent, i))
            for org, agent in pairs
            for i in range(per_agent)
        ],
        concurrency,
    )

    measurement = Measurement("multi_agent_consume")
    await _run_concurrent(
        measurement,
        [
            (
                lambda ref=ref, grant=grant: store.consume(
                    grant_id=grant.grant_id,
                    execution_action_hash=action_hash(ref),
                    executor_binding_digest=BINDING,
                    execution_ref=f"exec-{uuid4().hex}",
                )
            )
            for ref, grant in grants
            if grant.grant_id is not None
        ],
        concurrency,
    )
    return measurement


async def database_lock_statistics(db: Database) -> dict[str, object]:
    """What the database itself says about contention during the run."""
    async with db.acquire() as conn:
        waiting = await conn.fetchval("""
            SELECT COUNT(*) FROM pg_stat_activity
            WHERE datname = current_database() AND wait_event_type = 'Lock'
            """)
        deadlocks = await conn.fetchval(
            "SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()"
        )
        rolled_back = await conn.fetchval(
            "SELECT xact_rollback FROM pg_stat_database WHERE datname = current_database()"
        )
        committed = await conn.fetchval(
            "SELECT xact_commit FROM pg_stat_database WHERE datname = current_database()"
        )
    return {
        "sessions_waiting_on_locks_now": waiting,
        "deadlocks_total": deadlocks,
        "transactions_committed": committed,
        "transactions_rolled_back": rolled_back,
    }


async def run(args: argparse.Namespace) -> dict[str, object]:
    dsn = os.getenv("DATABASE_URL", "").strip()
    if not dsn:
        raise SystemExit("DATABASE_URL is required")

    db = await Database.create(dsn, min_size=4, max_size=max(args.concurrency + 4, 16))
    try:
        org_id, agent_id = await setup_agent(db)

        # Warm the pool and the prepared-statement cache so the first
        # sample is not measuring connection setup.
        await _issue(
            AuthorityStore(db, current_policy_resolver=_static_policy()),
            org_id,
            agent_id,
            f"warmup-{uuid4().hex[:8]}",
        )

        measurements = [
            await measure_issuance(
                db,
                org_id,
                agent_id,
                iterations=args.iterations,
                concurrency=args.concurrency,
            ),
            await measure_consume(
                db,
                org_id,
                agent_id,
                iterations=args.iterations,
                concurrency=args.concurrency,
            ),
            await measure_lock_contention(
                db,
                org_id,
                agent_id,
                concurrency=args.concurrency,
                rounds=args.contention_rounds,
            ),
            await measure_multi_agent_issuance(
                db,
                agents=args.agents,
                per_agent=max(1, args.iterations // args.agents),
                concurrency=args.concurrency,
            ),
            await measure_multi_agent_consume(
                db,
                agents=args.agents,
                per_agent=max(1, args.iterations // args.agents),
                concurrency=args.concurrency,
            ),
            measure_vi_verification(iterations=args.iterations),
            measure_receipt_signing(iterations=args.iterations),
        ]
        locks = await database_lock_statistics(db)
    finally:
        await db.close()

    return {
        "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "configuration": {
            "concurrency": args.concurrency,
            "iterations": args.iterations,
            "contention_rounds": args.contention_rounds,
            "python": sys.version.split()[0],
        },
        "stages": [measurement.summary() for measurement in measurements],
        "database": locks,
        "caveat": (
            "Measured on the benchmark host against its own PostgreSQL. "
            "Absolute latencies are host-specific; the shape (which stage "
            "dominates, how contention behaves) is what transfers. Re-run on "
            "staging hardware before quoting these as production SLOs."
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="authority_benchmark", description=__doc__)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument(
        "--agents",
        type=int,
        default=16,
        help="Principals to spread the multi-agent stages across",
    )
    parser.add_argument(
        "--contention-rounds",
        type=int,
        default=20,
        help="Rounds of many-consumers-one-grant",
    )
    parser.add_argument("--json", type=Path, default=None, help="Write results here")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    results = asyncio.run(run(args))
    rendered = json.dumps(results, indent=2)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {args.json}")
    print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
