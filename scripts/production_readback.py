"""Read-only production readback for the fail-closed migration debts.

Migrations 013 and 014 deliberately broke things closed: every pre-existing
agent was returned to sandbox, and webhook delivery stays paused for any
organisation without a signing secret. Nothing pages when those debts are
left unpaid — anchoring quietly excludes sandbox rows and webhook rows queue
into dead letter. This script turns the relevant checklist queries from
``docs/trust/PRODUCTION_READBACK_CHECKLIST.md`` into one command an operator
can run (and re-run) after every deploy:

    DATABASE_URL=postgresql://inntris_worker:...@host/db \\
    python scripts/production_readback.py

Every query is a SELECT and the session is forced read-only. Exit status is
non-zero when any check FAILs, so the command can gate a release pipeline.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

import psycopg2
import psycopg2.extras

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

SANDBOX_ACTIVITY_WINDOW_DAYS = 7
WEBHOOK_STUCK_MINUTES = 10
ANCHOR_BACKLOG_FAIL_MINUTES = 60


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    message: str


# ---------------------------------------------------------------------------
# Pure evaluators — one row of aggregates in, one CheckResult out.
# ---------------------------------------------------------------------------


def evaluate_production_approval_integrity(row: Mapping[str, object]) -> CheckResult:
    violations = int(row["violations"] or 0)
    if violations:
        return CheckResult(
            "production_approval_integrity",
            FAIL,
            f"{violations} non-sandbox agent(s) lack complete promotion evidence; "
            "the agent_production_approval_required constraint should make this "
            "impossible — investigate before trusting any receipt.",
        )
    return CheckResult(
        "production_approval_integrity",
        PASS,
        "Every non-sandbox agent carries complete promotion evidence.",
    )


def evaluate_active_sandbox_agents(row: Mapping[str, object]) -> CheckResult:
    active = int(row["active_sandbox"] or 0)
    if active:
        return CheckResult(
            "active_sandbox_agents",
            WARN,
            f"{active} sandbox agent(s) acted in the last "
            f"{SANDBOX_ACTIVITY_WINDOW_DAYS} days. Their decisions are NOT "
            "anchored. Promote each intended production agent via "
            "POST /admin/agents/{id}/promote or confirm it is test traffic.",
        )
    return CheckResult(
        "active_sandbox_agents",
        PASS,
        "No sandbox agent produced recent activity.",
    )


def evaluate_paused_webhooks(row: Mapping[str, object]) -> CheckResult:
    paused = int(row["paused"] or 0)
    if paused:
        return CheckResult(
            "paused_webhooks",
            FAIL,
            f"{paused} organisation(s) have a webhook_url but no signing "
            "secret; their deliveries are silently paused since migration 013. "
            "Rotate a secret via POST /admin/organization/webhook-secret/rotate.",
        )
    return CheckResult(
        "paused_webhooks",
        PASS,
        "Every configured webhook has an installed signing secret.",
    )


def evaluate_webhook_dead_letters(row: Mapping[str, object]) -> CheckResult:
    dead = int(row["dead_letters"] or 0)
    if dead:
        return CheckResult(
            "webhook_dead_letters",
            WARN,
            f"{dead} webhook delivery(ies) are dead lettered. Review "
            "GET /admin/organization/webhook-deliveries per tenant and "
            "docs/runbooks/webhooks.md.",
        )
    return CheckResult("webhook_dead_letters", PASS, "No dead lettered deliveries.")


def evaluate_stuck_webhook_deliveries(row: Mapping[str, object]) -> CheckResult:
    stuck = int(row["stuck"] or 0)
    if stuck:
        return CheckResult(
            "stuck_webhook_deliveries",
            WARN,
            f"{stuck} delivery(ies) have been due for more than "
            f"{WEBHOOK_STUCK_MINUTES} minutes; the recovery loop may not be "
            "running.",
        )
    return CheckResult(
        "stuck_webhook_deliveries",
        PASS,
        "No overdue pending or retrying deliveries.",
    )


def evaluate_anchor_backlog(row: Mapping[str, object]) -> CheckResult:
    oldest_minutes = row["oldest_minutes"]
    if oldest_minutes is None:
        return CheckResult(
            "anchor_backlog",
            PASS,
            "No production audit rows are waiting for a Merkle anchor.",
        )
    oldest = float(oldest_minutes)
    if oldest > ANCHOR_BACKLOG_FAIL_MINUTES:
        return CheckResult(
            "anchor_backlog",
            FAIL,
            f"Oldest unanchored production audit row is {oldest:.0f} minutes "
            "old (cadence is 10 minutes). Check the anchor worker heartbeat "
            "and merkle_proofs failures.",
        )
    return CheckResult(
        "anchor_backlog",
        PASS,
        f"Oldest unanchored production audit row is {oldest:.0f} minutes old.",
    )


CHECKS: Sequence[tuple[str, Callable[[Mapping[str, object]], CheckResult]]] = (
    (
        """
        SELECT count(*) AS violations
        FROM agents
        WHERE NOT (
            metadata @> '{"sandbox": true}'::jsonb
            OR (
                metadata @> '{"sandbox": false}'::jsonb
                AND btrim(COALESCE(metadata->>'production_approval_reference', '')) <> ''
                AND btrim(COALESCE(metadata->>'production_approved_at', '')) <> ''
                AND btrim(COALESCE(metadata->>'production_approved_by', '')) <> ''
            )
        )
        """,
        evaluate_production_approval_integrity,
    ),
    (
        f"""
        SELECT count(*) AS active_sandbox
        FROM agents
        WHERE metadata @> '{{"sandbox": true}}'::jsonb
          AND last_action_at > NOW() - INTERVAL '{SANDBOX_ACTIVITY_WINDOW_DAYS} days'
        """,
        evaluate_active_sandbox_agents,
    ),
    (
        """
        SELECT count(*) AS paused
        FROM organizations
        WHERE webhook_url IS NOT NULL
          AND webhook_secret_ciphertext IS NULL
        """,
        evaluate_paused_webhooks,
    ),
    (
        """
        SELECT count(*) AS dead_letters
        FROM webhook_deliveries
        WHERE status = 'dead_letter'
        """,
        evaluate_webhook_dead_letters,
    ),
    (
        f"""
        SELECT count(*) AS stuck
        FROM webhook_deliveries
        WHERE status IN ('pending', 'retrying')
          AND next_attempt_at < NOW() - INTERVAL '{WEBHOOK_STUCK_MINUTES} minutes'
        """,
        evaluate_stuck_webhook_deliveries,
    ),
    (
        """
        SELECT EXTRACT(EPOCH FROM (NOW() - MIN(timestamp))) / 60 AS oldest_minutes
        FROM audit_logs
        WHERE merkle_root_id IS NULL
          AND NOT COALESCE((metadata->>'test_request')::boolean, false)
          AND NOT COALESCE((metadata->>'sandbox')::boolean, false)
        """,
        evaluate_anchor_backlog,
    ),
)


def run_readback(connection) -> list[CheckResult]:
    """Execute every check on an open connection and return the results."""
    results: list[CheckResult] = []
    with connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
        cursor.execute("SET default_transaction_read_only = on")
        for query, evaluator in CHECKS:
            cursor.execute(query)
            results.append(evaluator(cursor.fetchone()))
    return results


def main() -> int:
    dsn = os.environ.get("READBACK_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not dsn:
        print("Set DATABASE_URL (or READBACK_DATABASE_URL) to run the readback.")
        return 2

    connection = psycopg2.connect(dsn)
    try:
        results = run_readback(connection)
    finally:
        connection.close()

    width = max(len(result.name) for result in results)
    for result in results:
        print(f"[{result.status:<4}] {result.name.ljust(width)}  {result.message}")

    failures = sum(1 for result in results if result.status == FAIL)
    warnings = sum(1 for result in results if result.status == WARN)
    print(f"\n{len(results)} checks: {failures} FAIL, {warnings} WARN")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
