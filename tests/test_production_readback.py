"""Readback checks for the fail-closed migration debts (scripts/production_readback.py).

The evaluators are pure so their thresholds are pinned here without a
database; one integration test proves every query executes against the real
migrated schema.
"""

from __future__ import annotations

import os

import pytest

from scripts.production_readback import (
    FAIL,
    PASS,
    WARN,
    evaluate_active_sandbox_agents,
    evaluate_anchor_backlog,
    evaluate_paused_webhooks,
    evaluate_production_approval_integrity,
    evaluate_stuck_webhook_deliveries,
    evaluate_webhook_dead_letters,
    run_readback,
)


def test_approval_integrity_violations_fail():
    assert evaluate_production_approval_integrity({"violations": 1}).status == FAIL
    assert evaluate_production_approval_integrity({"violations": 0}).status == PASS


def test_recent_sandbox_activity_warns():
    result = evaluate_active_sandbox_agents({"active_sandbox": 3})
    assert result.status == WARN
    assert "3 sandbox agent(s)" in result.message
    assert evaluate_active_sandbox_agents({"active_sandbox": 0}).status == PASS


def test_webhook_url_without_secret_fails():
    result = evaluate_paused_webhooks({"paused": 2})
    assert result.status == FAIL
    assert "paused" in result.message
    assert evaluate_paused_webhooks({"paused": 0}).status == PASS


def test_dead_letters_and_stuck_deliveries_warn():
    assert evaluate_webhook_dead_letters({"dead_letters": 1}).status == WARN
    assert evaluate_webhook_dead_letters({"dead_letters": 0}).status == PASS
    assert evaluate_stuck_webhook_deliveries({"stuck": 5}).status == WARN
    assert evaluate_stuck_webhook_deliveries({"stuck": 0}).status == PASS


def test_anchor_backlog_thresholds():
    assert evaluate_anchor_backlog({"oldest_minutes": None}).status == PASS
    assert evaluate_anchor_backlog({"oldest_minutes": 12.0}).status == PASS
    assert evaluate_anchor_backlog({"oldest_minutes": 61.0}).status == FAIL


def test_null_counts_are_treated_as_zero():
    # A cursor can hand back NULL for count(*) aggregates on some code paths;
    # the evaluators must not crash or fabricate a failure.
    assert evaluate_production_approval_integrity({"violations": None}).status == PASS
    assert evaluate_paused_webhooks({"paused": None}).status == PASS


INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")


@pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="readback integration requires INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)
def test_every_query_runs_against_the_migrated_schema():
    psycopg2 = pytest.importorskip("psycopg2")

    connection = psycopg2.connect(DATABASE_URL)
    try:
        results = run_readback(connection)
    finally:
        connection.close()

    assert [result.name for result in results] == [
        "production_approval_integrity",
        "active_sandbox_agents",
        "paused_webhooks",
        "webhook_dead_letters",
        "stuck_webhook_deliveries",
        "anchor_backlog",
    ]
    assert all(result.status in {PASS, WARN, FAIL} for result in results)
    # The schema constraint makes approval-evidence violations impossible.
    assert results[0].status == PASS
