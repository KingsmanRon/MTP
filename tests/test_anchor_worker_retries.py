"""Phase 0.6 — bounded retries + dead-letter state for the anchor worker.

Before this fix, `_retry_pending_proofs` re-submitted every ``failed``
proof on every tick with no spacing, and when ``retry_count`` finally
hit ``MAX_RETRIES`` the row silently dropped out of the query — there
was no terminal state, no next_retry_at, and no signal to operators
that a batch was stuck. These tests pin the new contract:

  * ``compute_retry_backoff`` grows exponentially and is capped.
  * The worker schedules ``next_retry_at`` on transient failure.
  * When ``retry_count + 1 >= MAX_RETRIES`` the proof flips to the
    terminal ``dead_letter`` status and is not retried again.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from workers import anchor_worker
from workers.anchor_worker import (
    AnchorWorker,
    compute_retry_backoff,
)


class TestComputeRetryBackoff:
    def test_first_retry_uses_base_delay(self) -> None:
        assert compute_retry_backoff(0, base_seconds=60) == timedelta(seconds=60)

    def test_backoff_is_exponential(self) -> None:
        # retry_count=1 -> 2x, 2 -> 4x, 3 -> 8x
        assert compute_retry_backoff(1, base_seconds=60) == timedelta(seconds=120)
        assert compute_retry_backoff(2, base_seconds=60) == timedelta(seconds=240)
        assert compute_retry_backoff(3, base_seconds=60) == timedelta(seconds=480)

    def test_backoff_is_capped(self) -> None:
        # Without the cap, retry 20 would be ~730 years.
        capped = compute_retry_backoff(
            20, base_seconds=60, max_seconds=3600
        )
        assert capped == timedelta(seconds=3600)

    def test_huge_retry_count_does_not_overflow(self) -> None:
        # Proof that the clamp prevents pathological left-shifts.
        capped = compute_retry_backoff(
            10_000, base_seconds=60, max_seconds=3600
        )
        assert capped == timedelta(seconds=3600)

    def test_negative_retry_count_raises(self) -> None:
        with pytest.raises(ValueError):
            compute_retry_backoff(-1)


class TestRecordFailure:
    def _make_worker(self) -> tuple[AnchorWorker, MagicMock]:
        db = MagicMock()
        db.update_merkle_proof_status = AsyncMock()
        blockchain = MagicMock()
        worker = AnchorWorker(db_service=db, blockchain_service=blockchain)
        return worker, db

    @pytest.mark.asyncio
    async def test_transient_failure_schedules_backoff(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(anchor_worker, "MAX_RETRIES", 5)
        worker, db = self._make_worker()
        proof_id = uuid4()

        await worker._record_failure(proof_id, current_retry_count=0, error_message="rpc timeout")

        db.update_merkle_proof_status.assert_awaited_once()
        kwargs = db.update_merkle_proof_status.await_args.kwargs
        args = db.update_merkle_proof_status.await_args.args
        assert args == (proof_id,)
        assert kwargs["status"] == "failed"
        assert kwargs["error_message"] == "rpc timeout"
        assert isinstance(kwargs["next_retry_at"], datetime)
        # next_retry_at is in the future and tz-aware.
        assert kwargs["next_retry_at"].tzinfo is not None
        assert kwargs["next_retry_at"] > datetime.now(timezone.utc)

    @pytest.mark.asyncio
    async def test_exhausted_retries_transition_to_dead_letter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(anchor_worker, "MAX_RETRIES", 3)
        worker, db = self._make_worker()
        proof_id = uuid4()

        # current_retry_count=2 means this is the 3rd attempt — the next
        # bump would hit MAX_RETRIES=3, so the proof must dead-letter.
        await worker._record_failure(
            proof_id, current_retry_count=2, error_message="insufficient gas, permanent"
        )

        kwargs = db.update_merkle_proof_status.await_args.kwargs
        assert kwargs["status"] == "dead_letter"
        assert kwargs["error_message"] == "insufficient gas, permanent"
        # dead_letter must not schedule a next retry.
        assert "next_retry_at" not in kwargs or kwargs["next_retry_at"] is None

    @pytest.mark.asyncio
    async def test_one_retry_before_dead_letter_when_max_is_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # MAX_RETRIES=1 means the very first failure already exhausts the
        # budget — this pins off-by-one behavior.
        monkeypatch.setattr(anchor_worker, "MAX_RETRIES", 1)
        worker, db = self._make_worker()
        proof_id = uuid4()

        await worker._record_failure(proof_id, current_retry_count=0, error_message="boom")

        kwargs = db.update_merkle_proof_status.await_args.kwargs
        assert kwargs["status"] == "dead_letter"
