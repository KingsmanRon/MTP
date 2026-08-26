"""Anchor submission must never confuse "broadcast" with "confirmed".

These tests pin the contract established after the 2026-08-25 production
incident, in which a Merkle root that Base had in fact anchored was recorded
as ``dead_letter``:

  * a transaction that reached the network keeps its identity even when the
    receipt cannot be read;
  * an already-anchored root is reconciled, never resubmitted;
  * a deterministic contract revert is not a gas-estimation hiccup;
  * logs bound to a batch are not re-batched by a resumed worker.

The lettered names map to the recovery handoff's required test list.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from workers.anchor_worker import (
    CONTRACT_ERROR_SELECTORS,
    ROOT_ALREADY_ANCHORED,
    AnchorRejectedError,
    AnchorWorker,
    PreparedAnchor,
    ReconciliationResult,
    SubmissionErrorKind,
    classify_submission_error,
)

ROOT = "d5" * 32
TX_HASH = "0x" + "c5" * 32


def _worker() -> tuple[AnchorWorker, MagicMock, MagicMock]:
    """A worker whose DB and chain are both mocks, with async DB methods."""
    db = MagicMock()
    db.update_merkle_proof_status = AsyncMock()
    db.record_submission_prepared = AsyncMock()
    db.mark_proof_confirmed = AsyncMock()
    db.assign_logs_to_proof = AsyncMock()

    chain = MagicMock()
    chain.get_balance = MagicMock(return_value=Decimal("1"))
    chain.is_root_anchored = MagicMock(return_value=False)
    chain.contract_address = "0x0600eA15802c8d2EA429371b2EB0aacCFe321480"

    worker = AnchorWorker.__new__(AnchorWorker)
    worker.db = db
    worker.blockchain = chain
    return worker, db, chain


def _prepared(nonce: int = 33) -> PreparedAnchor:
    return PreparedAnchor(
        transaction_hash=TX_HASH,
        nonce=nonce,
        raw_transaction=b"signed",
        gas_price_gwei=Decimal("0.005"),
    )


async def _submit(worker: AnchorWorker, **overrides):
    now = datetime.now(UTC)
    kwargs = {
        "proof_id": uuid4(),
        "merkle_root": ROOT,
        "log_count": 1,
        "start_timestamp": now,
        "end_timestamp": now,
        "current_retry_count": 0,
    }
    kwargs.update(overrides)
    await worker._submit_to_blockchain(**kwargs)
    return kwargs["proof_id"]


# ---------------------------------------------------------------------------
# Test A — broadcast succeeds, receipt polling fails
# ---------------------------------------------------------------------------

class TestBroadcastSurvivesReceiptFailure:
    @pytest.mark.asyncio
    async def test_transaction_identity_is_persisted_before_the_receipt(self) -> None:
        """The whole incident in one test.

        send_raw_transaction succeeds; the receipt poll 403s. The transaction
        hash must already be in the database, the proof must be ``submitted``
        rather than ``failed``, and no failure may be recorded — the network
        has the transaction.
        """
        worker, db, chain = _worker()
        prepared = _prepared()
        chain.prepare_anchor_transaction = MagicMock(return_value=prepared)
        chain.broadcast = MagicMock(return_value=TX_HASH)
        chain.wait_for_confirmation = AsyncMock(
            side_effect=Exception("403 Client Error: Forbidden for url: ...")
        )
        worker._record_failure = AsyncMock()

        proof_id = await _submit(worker)

        db.record_submission_prepared.assert_awaited_once()
        kwargs = db.record_submission_prepared.await_args.kwargs
        assert kwargs["transaction_hash"] == TX_HASH
        assert kwargs["nonce"] == 33

        # Deferred, not failed. The distinction is the point.
        worker._record_failure.assert_not_awaited()
        db.update_merkle_proof_status.assert_awaited_once()
        assert db.update_merkle_proof_status.await_args.kwargs["status"] == "submitted"
        assert db.update_merkle_proof_status.await_args.args[0] == proof_id

    @pytest.mark.asyncio
    async def test_next_cycle_does_not_rebroadcast(self) -> None:
        """A proof carrying a hash must not enter anchorBatch() again."""
        worker, _db, chain = _worker()
        chain.reconcile_anchor = MagicMock(
            return_value=ReconciliationResult(
                confirmed=False, source="unresolved", detail="still pending"
            )
        )
        chain.prepare_anchor_transaction = MagicMock()
        chain.broadcast = MagicMock()

        await _submit(worker, transaction_hash=TX_HASH, submission_nonce=33)

        chain.prepare_anchor_transaction.assert_not_called()
        chain.broadcast.assert_not_called()


# ---------------------------------------------------------------------------
# Test B — receipt recovered on a later cycle
# ---------------------------------------------------------------------------

class TestReceiptRecoveredLater:
    @pytest.mark.asyncio
    async def test_confirms_without_sending_anything(self) -> None:
        worker, db, chain = _worker()
        chain.reconcile_anchor = MagicMock(
            return_value=ReconciliationResult(
                confirmed=True,
                source="receipt",
                detail="receipt confirms",
                transaction_hash=TX_HASH,
                block_number=47762091,
                gas_used=35220,
            )
        )
        chain.prepare_anchor_transaction = MagicMock()
        chain.broadcast = MagicMock()

        proof_id = await _submit(worker, transaction_hash=TX_HASH)

        db.mark_proof_confirmed.assert_awaited_once()
        args, kwargs = db.mark_proof_confirmed.await_args
        assert args[0] == proof_id
        assert kwargs["block_number"] == 47762091
        assert kwargs["transaction_hash"] == TX_HASH
        # Confirmed by watching our own submission, not by discovery.
        assert kwargs["reconciled"] is False
        chain.broadcast.assert_not_called()


# ---------------------------------------------------------------------------
# Test C — RootAlreadyAnchored during estimation
# ---------------------------------------------------------------------------

class TestRootAlreadyAnchored:
    def test_selector_matches_the_deployed_contract(self) -> None:
        """0xdb34c203 is the selector observed throughout the incident."""
        assert CONTRACT_ERROR_SELECTORS["0xdb34c203"] == ROOT_ALREADY_ANCHORED

    def test_classified_as_already_anchored_not_transient(self) -> None:
        kind, name = classify_submission_error(
            Exception("execution reverted: custom error 0xdb34c203")
        )
        assert kind is SubmissionErrorKind.ROOT_ALREADY_ANCHORED
        assert name == ROOT_ALREADY_ANCHORED

    @pytest.mark.asyncio
    async def test_reconciles_and_never_broadcasts(self) -> None:
        worker, db, chain = _worker()
        chain.prepare_anchor_transaction = MagicMock(
            side_effect=AnchorRejectedError(
                SubmissionErrorKind.ROOT_ALREADY_ANCHORED,
                ROOT_ALREADY_ANCHORED,
                "execution reverted: 0xdb34c203",
            )
        )
        chain.broadcast = MagicMock()
        chain.reconcile_anchor = MagicMock(
            return_value=ReconciliationResult(
                confirmed=True,
                source="contract_state",
                detail="AnchorRegistry holds batch 12",
            )
        )
        worker._record_failure = AsyncMock()

        await _submit(worker)

        assert chain.broadcast.call_count == 0
        db.mark_proof_confirmed.assert_awaited_once()
        # Discovered by reading the chain, so flagged as reconciled.
        assert db.mark_proof_confirmed.await_args.kwargs["reconciled"] is True
        worker._record_failure.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_pre_submission_check_short_circuits(self) -> None:
        """isAnchored() true means we never even prepare a transaction."""
        worker, db, chain = _worker()
        chain.is_root_anchored = MagicMock(return_value=True)
        chain.reconcile_anchor = MagicMock(
            return_value=ReconciliationResult(
                confirmed=True, source="contract_state", detail="already there"
            )
        )
        chain.prepare_anchor_transaction = MagicMock()
        chain.broadcast = MagicMock()

        await _submit(worker)

        chain.prepare_anchor_transaction.assert_not_called()
        chain.broadcast.assert_not_called()
        db.mark_proof_confirmed.assert_awaited_once()


# ---------------------------------------------------------------------------
# Test D — deterministic, non-idempotency revert
# ---------------------------------------------------------------------------

class TestDeterministicRevert:
    @pytest.mark.parametrize(
        "message,expected_name",
        [
            ("custom error 0xf2dd03dc", "InvalidLogCount"),
            ("custom error 0x9dd854d3", "InvalidMerkleRoot"),
            ("execution reverted: AccessControl: account is missing role", None),
        ],
    )
    def test_classified_as_deterministic(self, message, expected_name) -> None:
        kind, name = classify_submission_error(Exception(message))
        assert kind is SubmissionErrorKind.DETERMINISTIC
        assert name == expected_name

    @pytest.mark.asyncio
    async def test_records_failure_without_broadcasting(self) -> None:
        worker, _db, chain = _worker()
        chain.prepare_anchor_transaction = MagicMock(
            side_effect=AnchorRejectedError(
                SubmissionErrorKind.DETERMINISTIC,
                "InvalidLogCount",
                "execution reverted",
            )
        )
        chain.broadcast = MagicMock()
        worker._record_failure = AsyncMock()

        await _submit(worker)

        chain.broadcast.assert_not_called()
        worker._record_failure.assert_awaited_once()
        assert "InvalidLogCount" in worker._record_failure.await_args.args[2]


# ---------------------------------------------------------------------------
# Test E — transient estimation failure keeps the fallback
# ---------------------------------------------------------------------------

class TestTransientEstimationFailure:
    @pytest.mark.parametrize(
        "message",
        ["Read timed out", "429 Too Many Requests", "Connection reset by peer",
         "502 Bad Gateway"],
    )
    def test_classified_as_transient(self, message) -> None:
        kind, name = classify_submission_error(Exception(message))
        assert kind is SubmissionErrorKind.TRANSIENT
        assert name is None

    def test_a_403_on_a_read_is_transient_not_a_revert(self) -> None:
        """The incident's own error string must not read as a contract decision."""
        kind, _ = classify_submission_error(
            Exception("403 Client Error: Forbidden for url: https://base-rpc.publicnode.com")
        )
        assert kind is SubmissionErrorKind.TRANSIENT


# ---------------------------------------------------------------------------
# Test F — crash after batch assignment
# ---------------------------------------------------------------------------

class TestResumeAfterCrash:
    @pytest.mark.asyncio
    async def test_assigned_logs_are_not_rebatched(self) -> None:
        """Logs already bound to a proof are invisible to the batch query.

        The binding happens before submission precisely so a crash resumes the
        existing proof rather than minting a second root over the same logs.
        """
        worker, db, chain = _worker()
        db.get_unanchored_logs = AsyncMock(return_value=[])
        db.get_pending_proofs = AsyncMock(return_value=[])
        db.create_merkle_proof_record = AsyncMock()
        db.get_proof_failure_counts = AsyncMock(return_value={})
        worker.batch_size = 100

        await worker._process_batch()

        # Nothing unanchored -> no new proof, no submission.
        db.create_merkle_proof_record.assert_not_awaited()
        db.assign_logs_to_proof.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_resumed_proof_is_reconciled_not_resubmitted(self) -> None:
        worker, db, chain = _worker()
        proof_id = uuid4()
        now = datetime.now(UTC)
        db.get_pending_proofs = AsyncMock(return_value=[{
            "id": proof_id,
            "root_hash": ROOT,
            "leaf_hashes": ["ab" * 32],
            "retry_count": 2,
            "status": "submitted",
            "transaction_hash": TX_HASH,
            "submission_nonce": 33,
            "start_timestamp": now,
            "end_timestamp": now,
        }])
        chain.reconcile_anchor = MagicMock(
            return_value=ReconciliationResult(
                confirmed=True, source="receipt", detail="ok",
                transaction_hash=TX_HASH, block_number=1, gas_used=2,
            )
        )
        chain.prepare_anchor_transaction = MagicMock()
        chain.broadcast = MagicMock()

        await worker._retry_pending_proofs()

        chain.broadcast.assert_not_called()
        db.mark_proof_confirmed.assert_awaited_once()


# ---------------------------------------------------------------------------
# Test G — dead-letter recovery
# ---------------------------------------------------------------------------

class TestDeadLetterRecovery:
    @pytest.mark.asyncio
    async def test_confirms_from_chain_without_broadcasting(self) -> None:
        """A dead-lettered proof whose root IS on Base recovers by reading it.

        This is the Gate 1 case. Recovery must not involve a transaction.
        """
        worker, db, chain = _worker()
        chain.reconcile_anchor = MagicMock(
            return_value=ReconciliationResult(
                confirmed=True,
                source="contract_state",
                detail="AnchorRegistry holds this root",
                transaction_hash=TX_HASH,
            )
        )
        chain.broadcast = MagicMock()
        proof_id = uuid4()

        confirmed = await worker._reconcile_proof(proof_id, ROOT, TX_HASH)

        assert confirmed is True
        chain.broadcast.assert_not_called()
        db.mark_proof_confirmed.assert_awaited_once()
        assert db.mark_proof_confirmed.await_args.kwargs["reconciled"] is True

    @pytest.mark.asyncio
    async def test_unresolved_chain_state_writes_nothing(self) -> None:
        """Never mark confirmed on anything short of chain evidence."""
        worker, db, chain = _worker()
        chain.reconcile_anchor = MagicMock(
            return_value=ReconciliationResult(
                confirmed=False, source="unresolved", detail="root not present"
            )
        )

        confirmed = await worker._reconcile_proof(uuid4(), ROOT, None)

        assert confirmed is False
        db.mark_proof_confirmed.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_receipt_to_a_foreign_contract_is_rejected(self) -> None:
        """A confirmed receipt for some other contract proves nothing here."""
        worker, _db, chain = _worker()
        from workers.anchor_worker import BlockchainService

        svc = BlockchainService.__new__(BlockchainService)
        svc.contract_address = "0x0600eA15802c8d2EA429371b2EB0aacCFe321480"
        svc.get_receipt_if_available = MagicMock(return_value={
            "transaction_hash": TX_HASH,
            "block_number": 1,
            "gas_used": 2,
            "status": "confirmed",
            "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        })
        svc.is_root_anchored = MagicMock(return_value=False)

        result = svc.reconcile_anchor(ROOT, TX_HASH)

        assert result.confirmed is False
        assert "not the expected AnchorRegistry" in result.detail


# ---------------------------------------------------------------------------
# Test I — test_request rows stay out of production batches
# ---------------------------------------------------------------------------

class TestTestRequestExclusion:
    def test_unanchored_query_still_filters_test_requests(self) -> None:
        """Guard against regressing the /admin/test-verify exclusion."""
        import inspect

        from workers.anchor_worker import DatabaseService

        source = inspect.getsource(DatabaseService.get_unanchored_logs)
        assert "test_request" in source
        assert "merkle_root_id IS NULL" in source
