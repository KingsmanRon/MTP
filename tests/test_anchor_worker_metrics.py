"""Anchor worker heartbeat, backlog, and scrape endpoint contracts."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api import observability
from workers.anchor_worker import AnchorWorker, DatabaseService, resolve_worker_metrics_port


class _AdvisoryLockState:
    owner: object | None = None


class _FakeConnection:
    def __init__(self, state: _AdvisoryLockState) -> None:
        self.state = state
        self.identity = object()
        self.terminated = False

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction(self)

    async def execute(self, query: str) -> None:
        assert query == "SET LOCAL idle_in_transaction_session_timeout = 0"

    async def fetchval(self, query: str, _lock_id: int) -> bool:
        if "pg_try_advisory_xact_lock" in query:
            if self.state.owner is None:
                self.state.owner = self.identity
                return True
            return False
        raise AssertionError(f"Unexpected SQL: {query}")

    def terminate(self) -> None:
        self.terminated = True
        if self.state.owner is self.identity:
            self.state.owner = None


class _FakeTransaction:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection

    async def start(self) -> None:
        return None

    async def commit(self) -> None:
        if self.connection.state.owner is self.connection.identity:
            self.connection.state.owner = None

    async def rollback(self) -> None:
        if self.connection.state.owner is self.connection.identity:
            self.connection.state.owner = None


class _FakePool:
    def __init__(self, state: _AdvisoryLockState) -> None:
        self.connection = _FakeConnection(state)
        self.release_count = 0

    async def acquire(self) -> _FakeConnection:
        return self.connection

    async def release(self, connection: _FakeConnection) -> None:
        assert connection is self.connection
        self.release_count += 1


def test_worker_cycle_metrics_are_updated() -> None:
    with (
        patch.object(
            observability,
            "anchor_worker_heartbeat_timestamp_seconds",
        ) as heartbeat,
        patch.object(
            observability,
            "anchor_worker_last_success_timestamp_seconds",
        ) as last_success,
        patch.object(observability, "anchor_worker_cycles_total") as cycles,
    ):
        AnchorWorker._record_liveness_heartbeat(100.0)
        AnchorWorker._record_cycle_success(101.0)
        AnchorWorker._record_cycle_error()

    heartbeat.set.assert_called_once_with(100.0)
    last_success.set.assert_called_once_with(101.0)
    cycles.labels.assert_any_call(outcome="success")
    cycles.labels.assert_any_call(outcome="error")


def test_worker_metrics_port_does_not_inherit_api_port() -> None:
    assert resolve_worker_metrics_port({"PORT": "8000"}) == 9100
    assert resolve_worker_metrics_port(
        {"PORT": "8000", "ANCHOR_METRICS_PORT": "9200"}
    ) == 9200


@pytest.mark.asyncio
async def test_liveness_heartbeat_does_not_claim_processing_success() -> None:
    worker = AnchorWorker(db_service=MagicMock(), blockchain_service=MagicMock())
    worker._running = True
    worker._shutdown_event.set()

    with (
        patch.object(worker, "_record_liveness_heartbeat") as heartbeat,
        patch.object(
            observability,
            "anchor_worker_last_success_timestamp_seconds",
        ) as last_success,
    ):
        await worker._heartbeat_loop()

    heartbeat.assert_called_once()
    last_success.set.assert_not_called()


@pytest.mark.asyncio
async def test_postgres_advisory_lock_blocks_a_concurrent_worker() -> None:
    state = _AdvisoryLockState()
    first = DatabaseService(_FakePool(state))  # type: ignore[arg-type]
    second = DatabaseService(_FakePool(state))  # type: ignore[arg-type]

    async with first.anchor_cycle_lock() as first_acquired:
        assert first_acquired is True
        async with second.anchor_cycle_lock() as second_acquired:
            assert second_acquired is False

    async with second.anchor_cycle_lock() as acquired_after_release:
        assert acquired_after_release is True


@pytest.mark.asyncio
async def test_processing_cycle_skips_work_and_success_on_lock_contention() -> None:
    db = MagicMock()

    @asynccontextmanager
    async def contended_lock():  # type: ignore[no-untyped-def]
        yield False

    db.anchor_cycle_lock = contended_lock
    worker = AnchorWorker(db_service=db, blockchain_service=MagicMock())
    worker._process_batch = AsyncMock()  # type: ignore[method-assign]

    with (
        patch.object(observability, "anchor_worker_cycles_total") as cycles,
        patch.object(
            observability,
            "anchor_worker_last_success_timestamp_seconds",
        ) as last_success,
    ):
        completed = await worker._run_processing_cycle()

    assert completed is False
    worker._process_batch.assert_not_awaited()  # type: ignore[attr-defined]
    cycles.labels.assert_called_once_with(outcome="lock_contended")
    last_success.set.assert_not_called()


@pytest.mark.asyncio
async def test_processing_cycle_releases_lock_after_exception() -> None:
    state = _AdvisoryLockState()
    first = DatabaseService(_FakePool(state))  # type: ignore[arg-type]
    second = DatabaseService(_FakePool(state))  # type: ignore[arg-type]

    with pytest.raises(RuntimeError, match="boom"):
        async with first.anchor_cycle_lock() as acquired:
            assert acquired is True
            raise RuntimeError("boom")

    async with second.anchor_cycle_lock() as acquired_after_error:
        assert acquired_after_error is True


@pytest.mark.skipif(
    os.getenv("INNTRIS_DB_INTEGRATION") != "1" or not os.getenv("DATABASE_URL"),
    reason="Postgres worker lock integration requires INNTRIS_DB_INTEGRATION=1",
)
@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_postgres_anchor_lock_serialises_worker_processes() -> None:
    database_url = os.environ["DATABASE_URL"]
    first = await DatabaseService.create(database_url)
    second = await DatabaseService.create(database_url)
    try:
        async with first.anchor_cycle_lock() as first_acquired:
            assert first_acquired is True
            async with second.anchor_cycle_lock() as second_acquired:
                assert second_acquired is False

        async with second.anchor_cycle_lock() as acquired_after_release:
            assert acquired_after_release is True
    finally:
        await first.close()
        await second.close()


@pytest.mark.asyncio
async def test_worker_publishes_persistent_failure_backlog() -> None:
    db = MagicMock()

    async def get_counts() -> dict[str, int]:
        return {"failed": 2, "dead_letter": 1}

    db.get_proof_failure_counts = get_counts
    worker = AnchorWorker(db_service=db, blockchain_service=MagicMock())

    with patch.object(observability, "anchor_proof_backlog") as backlog:
        await worker._publish_failure_backlog()

    backlog.labels.assert_any_call(status="failed")
    backlog.labels.assert_any_call(status="dead_letter")
    backlog.labels.return_value.set.assert_any_call(2)
    backlog.labels.return_value.set.assert_any_call(1)


def test_worker_metrics_endpoint_uses_configured_bind_address() -> None:
    with patch.object(observability, "start_http_server") as start:
        observability.start_worker_metrics_endpoint(9100, "127.0.0.1")

    start.assert_called_once_with(port=9100, addr="127.0.0.1")


def test_prometheus_alerts_cover_stale_worker_and_failed_proofs() -> None:
    rules = (
        __import__("pathlib").Path(__file__).parents[1]
        / "ops"
        / "prometheus"
        / "inntris-alerts.yml"
    ).read_text(encoding="utf-8")
    assert "InntrisAnchorWorkerHeartbeatStale" in rules
    assert "inntris_anchor_worker_heartbeat_timestamp_seconds" in rules
    assert "InntrisAnchorWorkerLastSuccessStale" in rules
    assert "inntris_anchor_worker_last_success_timestamp_seconds" in rules
    assert "InntrisAnchorWorkerProcessingErrors" in rules
    assert 'inntris_anchor_worker_cycles_total{outcome="error"}' in rules
    assert 'absent(up{job="inntris-anchor-worker"})' in rules
    assert "InntrisAnchorProofBacklog" in rules
    assert "inntris_anchor_proof_backlog" in rules
