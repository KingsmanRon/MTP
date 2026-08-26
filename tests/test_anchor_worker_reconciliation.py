"""Regression coverage for the production anchor reconciliation incident."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from workers.anchor_worker import (
    AnchorConfirmation,
    AnchorWorker,
    DatabaseService,
    DeterministicContractRevert,
    PreparedAnchorTransaction,
    ReconciliationResult,
    RootAlreadyAnchoredError,
)

CONTRACT = "0x0600eA15802c8d2EA429371b2EB0aacCFe321480"
TX_HASH = "0x" + "ab" * 32
ROOT = "cd" * 32


def _proof(
    *,
    status: str = "pending",
    transaction_hash: str | None = None,
    submission_nonce: int | None = None,
    submitted_at: datetime | None = None,
    retry_count: int = 0,
) -> dict:
    now = datetime.now(UTC)
    return {
        "id": uuid4(),
        "root_hash": ROOT,
        "leaf_hashes": ["ef" * 32],
        "log_count": 1,
        "start_timestamp": now,
        "end_timestamp": now,
        "status": status,
        "transaction_hash": transaction_hash,
        "submission_nonce": submission_nonce,
        "prepared_at": submitted_at,
        "submitted_at": submitted_at,
        "retry_count": retry_count,
        "contract_address": CONTRACT,
        "chain_id": 8453,
    }


def _confirmation(
    *,
    source: str = "transaction_receipt",
) -> AnchorConfirmation:
    return AnchorConfirmation(
        transaction_hash=TX_HASH,
        block_number=50_454_274,
        gas_used=225_716,
        gas_price_gwei=Decimal("0.006"),
        anchored_at=datetime.now(UTC),
        batch_id=23,
        submitter="0x2300Fc9eff12ff5ca39621259B121fa3417773bf",
        source=source,
    )


def _worker() -> tuple[AnchorWorker, MagicMock, MagicMock]:
    db = MagicMock()
    for method in (
        "record_reconciliation_attempt",
        "record_submission_prepared",
        "mark_submission_broadcast",
        "schedule_retry",
        "mark_proof_dead_letter",
        "mark_proof_confirmed",
    ):
        setattr(db, method, AsyncMock())
    blockchain = MagicMock()
    blockchain.expected_chain_id = 8453
    blockchain.contract_address = CONTRACT
    blockchain.get_balance.return_value = Decimal("1")
    blockchain.wait_for_confirmation = AsyncMock()
    return AnchorWorker(db, blockchain), db, blockchain


@pytest.mark.asyncio
async def test_broadcast_hash_survives_receipt_provider_failure() -> None:
    worker, db, blockchain = _worker()
    proof = _proof()
    prepared = PreparedAnchorTransaction(
        transaction_hash=TX_HASH,
        nonce=17,
        gas_price_gwei=Decimal("0.006"),
        raw_transaction=b"signed",
    )
    blockchain.reconcile_anchor.return_value = ReconciliationResult(None, "none")
    blockchain.prepare_anchor_transaction.return_value = prepared
    blockchain.broadcast.return_value = TX_HASH
    blockchain.wait_for_confirmation.side_effect = RuntimeError("HTTP 403 during receipt polling")

    assert await worker._process_proof(proof) is False

    db.record_submission_prepared.assert_awaited_once_with(proof["id"], prepared)
    blockchain.broadcast.assert_called_once_with(prepared)
    db.mark_submission_broadcast.assert_awaited_once_with(proof["id"], TX_HASH)
    retry = db.schedule_retry.await_args
    assert retry.kwargs["status"] == "submitted"
    assert "already-broadcast" in retry.kwargs["error_message"]


@pytest.mark.asyncio
async def test_recent_submitted_hash_is_reconciled_before_any_replacement() -> None:
    worker, db, blockchain = _worker()
    proof = _proof(
        status="submitted",
        transaction_hash=TX_HASH,
        submission_nonce=17,
        submitted_at=datetime.now(UTC),
        retry_count=1,
    )
    blockchain.reconcile_anchor.return_value = ReconciliationResult(
        None,
        "not_found",
    )

    assert await worker._process_proof(proof) is False

    blockchain.reconcile_anchor.assert_called_once()
    blockchain.prepare_anchor_transaction.assert_not_called()
    blockchain.broadcast.assert_not_called()
    assert db.schedule_retry.await_args.kwargs["status"] == "submitted"


@pytest.mark.asyncio
async def test_recent_prepared_hash_remains_prepared_until_replacement_window() -> None:
    worker, db, blockchain = _worker()
    proof = _proof(
        status="prepared",
        transaction_hash=TX_HASH,
        submission_nonce=17,
        submitted_at=datetime.now(UTC),
        retry_count=1,
    )
    proof["submitted_at"] = None
    blockchain.reconcile_anchor.return_value = ReconciliationResult(
        None,
        "not_found",
    )

    assert await worker._process_proof(proof) is False

    blockchain.prepare_anchor_transaction.assert_not_called()
    blockchain.broadcast.assert_not_called()
    assert db.schedule_retry.await_args.kwargs["status"] == "prepared"


@pytest.mark.asyncio
async def test_submitted_receipt_is_recovered_without_rebroadcast() -> None:
    worker, db, blockchain = _worker()
    proof = _proof(
        status="submitted",
        transaction_hash=TX_HASH,
        submission_nonce=17,
        retry_count=2,
    )
    confirmation = _confirmation()
    blockchain.reconcile_anchor.return_value = ReconciliationResult(
        confirmation,
        "none",
    )

    assert await worker._process_proof(proof) is True

    db.mark_proof_confirmed.assert_awaited_once_with(
        proof["id"],
        confirmation,
        reconciled=True,
    )
    blockchain.prepare_anchor_transaction.assert_not_called()
    blockchain.broadcast.assert_not_called()


@pytest.mark.asyncio
async def test_root_already_anchored_reconciles_instead_of_sending() -> None:
    worker, db, blockchain = _worker()
    proof = _proof()
    confirmation = _confirmation(source="contract_state")
    blockchain.reconcile_anchor.side_effect = [
        ReconciliationResult(None, "none"),
        ReconciliationResult(confirmation, "none"),
    ]
    blockchain.prepare_anchor_transaction.side_effect = RootAlreadyAnchoredError(
        "RootAlreadyAnchored"
    )

    assert await worker._process_proof(proof) is True

    assert blockchain.reconcile_anchor.call_count == 2
    blockchain.broadcast.assert_not_called()
    db.mark_proof_confirmed.assert_awaited_once_with(
        proof["id"],
        confirmation,
        reconciled=True,
    )


@pytest.mark.asyncio
async def test_deterministic_revert_is_terminal_and_never_broadcast() -> None:
    worker, db, blockchain = _worker()
    proof = _proof()
    blockchain.reconcile_anchor.return_value = ReconciliationResult(None, "none")
    blockchain.prepare_anchor_transaction.side_effect = DeterministicContractRevert(
        "InvalidLogCount"
    )

    assert await worker._process_proof(proof) is False

    db.mark_proof_dead_letter.assert_awaited_once_with(
        proof["id"],
        error_message="InvalidLogCount",
    )
    blockchain.broadcast.assert_not_called()


@pytest.mark.asyncio
async def test_assigned_batch_is_resumed_without_creating_duplicate_proof() -> None:
    worker, db, _blockchain = _worker()
    proof = _proof(status="failed", retry_count=1)
    db.get_retryable_proofs = AsyncMock(return_value=[proof])
    db.get_unanchored_logs = AsyncMock(return_value=[])
    db.create_merkle_proof_record = AsyncMock()
    worker._publish_failure_backlog = AsyncMock()
    worker._process_proof = AsyncMock(return_value=False)

    await worker._process_batch()

    worker._process_proof.assert_awaited_once_with(proof)
    db.create_merkle_proof_record.assert_not_awaited()


class _Lock:
    @asynccontextmanager
    async def acquired(self):
        yield True


@pytest.mark.asyncio
async def test_dead_letter_explicit_reconciliation_is_no_broadcast() -> None:
    worker, db, blockchain = _worker()
    proof = _proof(
        status="dead_letter",
        transaction_hash=TX_HASH,
        submission_nonce=17,
        retry_count=5,
    )
    confirmation = _confirmation(source="contract_state")
    lock = _Lock()
    db.anchor_cycle_lock = lock.acquired
    db.get_proof_by_id = AsyncMock(return_value=proof)
    blockchain.reconcile_anchor.return_value = ReconciliationResult(
        confirmation,
        "none",
    )

    assert await worker.reconcile_proof(UUID(str(proof["id"]))) is True

    db.mark_proof_confirmed.assert_awaited_once_with(
        proof["id"],
        confirmation,
        reconciled=True,
    )
    blockchain.prepare_anchor_transaction.assert_not_called()
    blockchain.broadcast.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_submitted_outcome_is_not_lost_at_retry_cap() -> None:
    worker, db, blockchain = _worker()
    proof = _proof(
        status="submitted",
        transaction_hash=TX_HASH,
        submission_nonce=17,
        retry_count=12,
    )
    blockchain.reconcile_anchor.side_effect = TimeoutError("provider unavailable")

    assert await worker._process_proof(proof) is False

    db.mark_proof_dead_letter.assert_not_awaited()
    assert db.schedule_retry.await_args.kwargs["status"] == "submitted"
    blockchain.prepare_anchor_transaction.assert_not_called()
    blockchain.broadcast.assert_not_called()


@pytest.mark.asyncio
async def test_retry_query_never_drops_known_transaction_states() -> None:
    pool = MagicMock()
    connection = MagicMock()
    connection.fetch = AsyncMock(return_value=[])

    class _Acquire:
        async def __aenter__(self):
            return connection

        async def __aexit__(self, *_args):
            return False

    pool.acquire.return_value = _Acquire()
    await DatabaseService(pool).get_retryable_proofs()

    sql = connection.fetch.await_args.args[0]
    assert "status IN ('prepared', 'submitted')" in sql
    assert "OR retry_count < $1" in sql
