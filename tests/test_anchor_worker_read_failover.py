"""Regression coverage for the Base RPC 403 anchor reconciliation incident.

A batch was broadcast successfully to Base and mined in block 50520278. The
primary RPC then began answering ``403 Forbidden`` to receipt and
contract-state reads, so the worker could never see its own confirmation and
the proof sat at ``submitted``.

The invariants pinned here:

1. ``403`` during a read is an RPC *availability* failure. It is never
   evidence that the transaction failed, reverted, or was never sent.
2. A read that the primary refuses fails over to a configured read endpoint,
   with the primary unchanged as the only endpoint that ever broadcasts.
3. Reconciliation asks about the already-persisted transaction hash first,
   then validates the ``BatchAnchored`` event and AnchorRegistry state exactly
   as it always has.
4. A receipt lookup returning ``403`` never causes a second broadcast.
5. The proof reaches ``confirmed`` from chain evidence with block number, gas,
   confirmation time, and reconciliation source populated.
6. An already-broadcast proof is never dead-lettered because reads failed, and
   never loses its place in the retry queue.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests

web3 = pytest.importorskip("web3")  # whole module depends on the eth stack

from workers import anchor_worker  # noqa: E402
from workers.anchor_worker import (  # noqa: E402
    AnchorConfirmation,
    AnchorWorker,
    BlockchainService,
    PreparedAnchorTransaction,
    ReconciliationResult,
    RpcAvailabilityError,
    is_rpc_availability_error,
)

# The incident's real shape.
CONTRACT = "0x0600ea15802c8d2ea429371b2eb0aaccfe321480"
SUBMITTER = "0x2300fc9eff12ff5ca39621259b121fa3417773bf"
TX_HASH = "0x" + "ab" * 32
ROOT = "cd" * 32
BLOCK_NUMBER = 50_520_278
GAS_USED = 225_716
EFFECTIVE_GAS_PRICE_WEI = 6_000_000  # 0.006 gwei
BATCH_ID = 24
LOG_COUNT = 3
ANCHORED_AT = datetime(2026, 8, 26, 11, 42, 17, tzinfo=UTC)
START_TS = datetime(2026, 8, 26, 11, 30, 0, tzinfo=UTC)
END_TS = datetime(2026, 8, 26, 11, 40, 0, tzinfo=UTC)


def _forbidden() -> requests.exceptions.HTTPError:
    """The exception web3's HTTPProvider raises for a 403 from the endpoint."""
    response = requests.Response()
    response.status_code = 403
    response.reason = "Forbidden"
    return requests.exceptions.HTTPError("403 Client Error: Forbidden", response=response)


def _topic(value: int) -> str:
    return "0x" + f"{value:064x}"


def _receipt() -> dict:
    return {
        "status": 1,
        "to": CONTRACT,
        "transactionHash": TX_HASH,
        "blockNumber": BLOCK_NUMBER,
        "gasUsed": GAS_USED,
        "effectiveGasPrice": EFFECTIVE_GAS_PRICE_WEI,
        "logs": [
            {
                "address": CONTRACT,
                "topics": [
                    "0x" + anchor_worker._BATCH_ANCHORED_TOPIC,
                    _topic(BATCH_ID),
                    "0x" + ROOT,
                    _topic(int(SUBMITTER, 16)),
                ],
                "data": hex(LOG_COUNT),
            }
        ],
    }


def _registry_batch() -> list:
    """``getBatchFull`` tuple, consistent with the receipt above."""
    return [
        BATCH_ID,
        LOG_COUNT,
        int(ANCHORED_AT.timestamp()),
        BLOCK_NUMBER,
        int(START_TS.timestamp()),
        int(END_TS.timestamp()),
        SUBMITTER,
    ]


# -----------------------------------------------------------------------------
# 1. Classification: a 403 is about the provider, never about the transaction
# -----------------------------------------------------------------------------


def test_http_403_is_an_availability_failure() -> None:
    assert is_rpc_availability_error(_forbidden()) is True


@pytest.mark.parametrize("status", [401, 402, 403, 429, 500, 502, 503])
def test_endpoint_level_statuses_are_availability_failures(status: int) -> None:
    response = requests.Response()
    response.status_code = status
    exc = requests.exceptions.HTTPError(f"{status} error", response=response)

    assert is_rpc_availability_error(exc) is True


def test_transaction_not_found_is_evidence_not_unavailability() -> None:
    """A node that looked and has no receipt gave a real answer."""
    exc = web3.exceptions.TransactionNotFound(f"Transaction {TX_HASH} not found")

    assert is_rpc_availability_error(exc) is False


def test_evidence_mismatch_is_never_treated_as_unavailability() -> None:
    exc = anchor_worker.AnchorEvidenceError("Receipt target mismatch")

    assert is_rpc_availability_error(exc) is False


# -----------------------------------------------------------------------------
# 2. Read failover at the BlockchainService boundary
# -----------------------------------------------------------------------------


def _fake_web3(chain_id: int) -> MagicMock:
    w3 = MagicMock()
    w3.eth.chain_id = chain_id
    w3.from_wei = lambda wei, unit: (
        Decimal(wei) / Decimal(10**9) if unit == "gwei" else Decimal(wei) / Decimal(10**18)
    )
    w3.eth.contract = MagicMock(return_value=MagicMock())
    return w3


def _build_service_with_failover(
    primary: MagicMock,
    fallback: MagicMock,
) -> BlockchainService:
    """Construct a service whose primary is followed by one read endpoint."""
    account = MagicMock()
    account.address = SUBMITTER

    with (
        patch.object(anchor_worker, "Web3") as MockWeb3,
        patch.object(anchor_worker, "Account") as MockAccount,
    ):
        MockWeb3.side_effect = [primary, fallback]
        MockWeb3.HTTPProvider = MagicMock()
        MockWeb3.to_checksum_address = lambda address: address
        MockAccount.from_key.return_value = account

        service = BlockchainService(
            rpc_url="https://primary.example",
            contract_address=CONTRACT,
            private_key="0x" + "11" * 32,
            read_rpc_urls=("https://fallback.example",),
        )
    return service


def _configure_registry(w3: MagicMock, *, anchored: bool = True) -> MagicMock:
    contract = w3.eth.contract.return_value
    contract.functions.isAnchored.return_value.call.return_value = anchored
    contract.functions.getBatchFull.return_value.call.return_value = _registry_batch()
    return contract


def test_receipt_403_on_primary_is_served_by_the_read_endpoint() -> None:
    """The incident, at the read boundary: primary 403s, fallback answers."""
    primary = _fake_web3(anchor_worker.BASE_CHAIN_ID)
    fallback = _fake_web3(anchor_worker.BASE_CHAIN_ID)
    primary.eth.get_transaction_receipt.side_effect = _forbidden()
    fallback.eth.get_transaction_receipt.return_value = _receipt()

    service = _build_service_with_failover(primary, fallback)
    _configure_registry(primary, anchored=False)  # primary would say "not anchored"
    primary.eth.contract.return_value.functions.isAnchored.return_value.call.side_effect = (
        _forbidden()
    )
    _configure_registry(fallback)

    result = service.reconcile_anchor(
        merkle_root=ROOT,
        log_count=LOG_COUNT,
        start_timestamp=START_TS,
        end_timestamp=END_TS,
        transaction_hash=TX_HASH,
    )

    confirmation = result.confirmation
    assert confirmation is not None
    # Same transaction hash the worker already persisted before broadcast.
    assert confirmation.transaction_hash == TX_HASH
    assert confirmation.block_number == BLOCK_NUMBER
    assert confirmation.gas_used == GAS_USED
    assert confirmation.gas_price_gwei == Decimal("0.006")
    assert confirmation.anchored_at == ANCHORED_AT
    assert confirmation.batch_id == BATCH_ID
    assert confirmation.source == "transaction_receipt"
    # The persisted hash was asked about first, on the primary, and the 403
    # moved the same question to the read endpoint.
    primary.eth.get_transaction_receipt.assert_called_once_with(TX_HASH)
    fallback.eth.get_transaction_receipt.assert_called_once_with(TX_HASH)
    # Reads never broadcast.
    primary.eth.send_raw_transaction.assert_not_called()
    fallback.eth.send_raw_transaction.assert_not_called()


def test_read_endpoint_on_the_wrong_chain_cannot_confirm_anything() -> None:
    """A misconfigured fallback must not be able to manufacture evidence."""
    primary = _fake_web3(anchor_worker.BASE_CHAIN_ID)
    fallback = _fake_web3(1)  # Ethereum mainnet where we expect Base
    primary.eth.get_transaction_receipt.side_effect = _forbidden()
    fallback.eth.get_transaction_receipt.return_value = _receipt()

    service = _build_service_with_failover(primary, fallback)
    primary.eth.contract.return_value.functions.isAnchored.return_value.call.side_effect = (
        _forbidden()
    )
    _configure_registry(fallback)

    with pytest.raises(RpcAvailabilityError):
        service.reconcile_anchor(
            merkle_root=ROOT,
            log_count=LOG_COUNT,
            start_timestamp=START_TS,
            end_timestamp=END_TS,
            transaction_hash=TX_HASH,
        )

    # The wrong-chain endpoint is never consulted, for the receipt or for the
    # registry, so it cannot contribute a single byte of confirmation evidence.
    fallback.eth.get_transaction_receipt.assert_not_called()
    fallback.eth.contract.return_value.functions.isAnchored.assert_not_called()


def test_every_endpoint_403_raises_availability_not_a_missing_transaction() -> None:
    primary = _fake_web3(anchor_worker.BASE_CHAIN_ID)
    fallback = _fake_web3(anchor_worker.BASE_CHAIN_ID)
    primary.eth.get_transaction_receipt.side_effect = _forbidden()
    fallback.eth.get_transaction_receipt.side_effect = _forbidden()

    service = _build_service_with_failover(primary, fallback)
    for w3 in (primary, fallback):
        w3.eth.contract.return_value.functions.isAnchored.return_value.call.side_effect = (
            _forbidden()
        )

    with pytest.raises(RpcAvailabilityError) as excinfo:
        service.reconcile_anchor(
            merkle_root=ROOT,
            log_count=LOG_COUNT,
            start_timestamp=START_TS,
            end_timestamp=END_TS,
            transaction_hash=TX_HASH,
        )

    # The error names the provider problem, and is not a ReconciliationResult
    # that a caller could mistake for "this transaction does not exist".
    assert "rpc_read_unavailable" in str(excinfo.value)
    assert excinfo.value.operation == "isAnchored"


def test_transaction_not_found_still_reports_not_found() -> None:
    """Failover must not blur a real not-found answer into unavailability."""
    primary = _fake_web3(anchor_worker.BASE_CHAIN_ID)
    fallback = _fake_web3(anchor_worker.BASE_CHAIN_ID)
    primary.eth.get_transaction_receipt.side_effect = web3.exceptions.TransactionNotFound(
        f"Transaction {TX_HASH} not found"
    )

    service = _build_service_with_failover(primary, fallback)
    _configure_registry(primary, anchored=False)

    result = service.reconcile_anchor(
        merkle_root=ROOT,
        log_count=LOG_COUNT,
        start_timestamp=START_TS,
        end_timestamp=END_TS,
        transaction_hash=TX_HASH,
    )

    assert result.transaction_state == "not_found"
    assert result.confirmation is None
    # A node answered, so the question was not re-asked elsewhere.
    fallback.eth.get_transaction_receipt.assert_not_called()


# -----------------------------------------------------------------------------
# 3. Worker lifecycle: broadcast, 403, later read, confirmed, one broadcast
# -----------------------------------------------------------------------------


def _proof(**overrides: object) -> dict:
    proof = {
        "id": "3f1b8f0e-8a1e-4f0e-9c1a-0d1f2e3a4b5c",
        "root_hash": ROOT,
        "leaf_hashes": ["ef" * 32] * LOG_COUNT,
        "log_count": LOG_COUNT,
        "start_timestamp": START_TS,
        "end_timestamp": END_TS,
        "status": "pending",
        "transaction_hash": None,
        "submission_nonce": None,
        "prepared_at": None,
        "submitted_at": None,
        "retry_count": 0,
        "contract_address": CONTRACT,
        "chain_id": anchor_worker.BASE_CHAIN_ID,
    }
    proof.update(overrides)
    return proof


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
    blockchain.expected_chain_id = anchor_worker.BASE_CHAIN_ID
    blockchain.contract_address = CONTRACT
    blockchain.get_balance.return_value = Decimal("1")
    blockchain.wait_for_confirmation = AsyncMock()
    return AnchorWorker(db, blockchain), db, blockchain


@pytest.mark.asyncio
async def test_403_receipt_then_later_read_confirms_with_a_single_broadcast() -> None:
    """The full incident: one broadcast, a 403, then reconciliation to confirmed."""
    worker, db, blockchain = _worker()
    prepared = PreparedAnchorTransaction(
        transaction_hash=TX_HASH,
        nonce=17,
        gas_price_gwei=Decimal("0.006"),
        raw_transaction=b"signed",
    )
    confirmation = AnchorConfirmation(
        transaction_hash=TX_HASH,
        block_number=BLOCK_NUMBER,
        gas_used=GAS_USED,
        gas_price_gwei=Decimal("0.006"),
        anchored_at=ANCHORED_AT,
        batch_id=BATCH_ID,
        submitter=SUBMITTER,
        source="transaction_receipt",
    )

    # --- Cycle 1: nothing anchored yet, broadcast succeeds, receipt read 403s.
    first_proof = _proof()
    blockchain.reconcile_anchor.return_value = ReconciliationResult(None, "none")
    blockchain.prepare_anchor_transaction.return_value = prepared
    blockchain.broadcast.return_value = TX_HASH
    blockchain.wait_for_confirmation.side_effect = RpcAvailabilityError(
        "get_transaction_receipt",
        ("primary: HTTPError: 403 Client Error: Forbidden",),
    )

    assert await worker._process_proof(first_proof) is False

    blockchain.broadcast.assert_called_once_with(prepared)
    db.mark_submission_broadcast.assert_awaited_once_with(first_proof["id"], TX_HASH)
    retry = db.schedule_retry.await_args
    assert retry.kwargs["status"] == "submitted"
    assert retry.kwargs["increment_retry"] is False
    db.mark_proof_dead_letter.assert_not_awaited()
    db.mark_proof_confirmed.assert_not_awaited()

    # --- Cycle 2: the proof is retried; a working read finds the same hash.
    second_proof = _proof(
        status="submitted",
        transaction_hash=TX_HASH,
        submission_nonce=17,
        prepared_at=datetime.now(UTC),
        submitted_at=datetime.now(UTC),
        retry_count=0,
    )
    blockchain.reconcile_anchor.return_value = ReconciliationResult(confirmation, "none")

    assert await worker._process_proof(second_proof) is True

    # Confirmed from chain evidence, with the incident's block populated.
    db.mark_proof_confirmed.assert_awaited_once_with(
        second_proof["id"],
        confirmation,
        reconciled=True,
    )
    persisted = db.mark_proof_confirmed.await_args.args[1]
    assert persisted.transaction_hash == TX_HASH
    assert persisted.block_number == BLOCK_NUMBER
    assert persisted.gas_used == GAS_USED
    assert persisted.gas_price_gwei == Decimal("0.006")
    assert persisted.anchored_at == ANCHORED_AT
    assert persisted.source == "transaction_receipt"

    # The whole point: exactly one broadcast across both cycles.
    assert blockchain.broadcast.call_count == 1
    assert blockchain.prepare_anchor_transaction.call_count == 1
    db.mark_proof_dead_letter.assert_not_awaited()


@pytest.mark.asyncio
async def test_receipt_403_never_replaces_the_broadcast_transaction() -> None:
    """Even past the replacement window, an unreadable receipt sends nothing."""
    worker, db, blockchain = _worker()
    long_ago = datetime.fromtimestamp(0, tz=UTC)
    proof = _proof(
        status="submitted",
        transaction_hash=TX_HASH,
        submission_nonce=17,
        prepared_at=long_ago,
        submitted_at=long_ago,
        retry_count=3,
    )
    blockchain.reconcile_anchor.side_effect = RpcAvailabilityError(
        "get_transaction_receipt",
        ("primary: HTTPError: 403 Client Error: Forbidden",),
    )

    assert await worker._process_proof(proof) is False

    blockchain.prepare_anchor_transaction.assert_not_called()
    blockchain.broadcast.assert_not_called()
    db.mark_proof_dead_letter.assert_not_awaited()
    assert db.schedule_retry.await_args.kwargs["status"] == "submitted"
    assert db.schedule_retry.await_args.kwargs["increment_retry"] is False


@pytest.mark.asyncio
async def test_unreadable_receipt_state_is_not_a_missing_transaction() -> None:
    """``unknown`` must gate the replacement path just like an outright error."""
    worker, db, blockchain = _worker()
    long_ago = datetime.fromtimestamp(0, tz=UTC)
    proof = _proof(
        status="submitted",
        transaction_hash=TX_HASH,
        submission_nonce=17,
        prepared_at=long_ago,
        submitted_at=long_ago,
        retry_count=3,
    )
    # Receipt unreadable, registry readable and reporting the root absent.
    blockchain.reconcile_anchor.return_value = ReconciliationResult(None, "unknown")

    assert await worker._process_proof(proof) is False

    blockchain.prepare_anchor_transaction.assert_not_called()
    blockchain.broadcast.assert_not_called()
    db.mark_proof_dead_letter.assert_not_awaited()


@pytest.mark.asyncio
async def test_broadcast_proof_is_never_dead_lettered_by_read_failures() -> None:
    """Requirement: reads failing forever must not bury a live transaction."""
    worker, db, blockchain = _worker()
    proof = _proof(
        status="submitted",
        transaction_hash=TX_HASH,
        submission_nonce=17,
        submitted_at=datetime.now(UTC),
        retry_count=anchor_worker.MAX_RETRIES * 4,
    )
    blockchain.reconcile_anchor.side_effect = RpcAvailabilityError(
        "get_transaction_receipt",
        ("primary: HTTPError: 403 Client Error: Forbidden",),
    )

    for _ in range(10):
        assert await worker._process_proof(proof) is False

    db.mark_proof_dead_letter.assert_not_awaited()
    assert db.schedule_retry.await_count == 10
    for call in db.schedule_retry.await_args_list:
        assert call.kwargs["status"] == "submitted"
        # Never spends the retry budget, so the proof stays selectable by
        # get_retryable_proofs() no matter how long the outage runs.
        assert call.kwargs["increment_retry"] is False


@pytest.mark.asyncio
async def test_unreadable_receipt_after_broadcast_is_not_recorded_as_a_revert() -> None:
    """Post-broadcast: no receipt evidence must not become "reverted, failed"."""
    worker, db, blockchain = _worker()
    prepared = PreparedAnchorTransaction(
        transaction_hash=TX_HASH,
        nonce=17,
        gas_price_gwei=Decimal("0.006"),
        raw_transaction=b"signed",
    )
    blockchain.reconcile_anchor.return_value = ReconciliationResult(None, "none")
    blockchain.prepare_anchor_transaction.return_value = prepared
    blockchain.broadcast.return_value = TX_HASH
    # Receipt unreadable, registry readable and reporting the root absent.
    blockchain.wait_for_confirmation.return_value = ReconciliationResult(None, "unknown")

    assert await worker._process_proof(_proof()) is False

    retry = db.schedule_retry.await_args
    assert retry.kwargs["status"] == "submitted"
    assert retry.kwargs["increment_retry"] is False
    db.mark_proof_dead_letter.assert_not_awaited()
    assert blockchain.broadcast.call_count == 1


@pytest.mark.asyncio
async def test_observed_revert_after_broadcast_is_still_a_real_failure() -> None:
    """The counterpart: a receipt that was read and says reverted still fails."""
    worker, db, blockchain = _worker()
    prepared = PreparedAnchorTransaction(
        transaction_hash=TX_HASH,
        nonce=17,
        gas_price_gwei=Decimal("0.006"),
        raw_transaction=b"signed",
    )
    blockchain.reconcile_anchor.return_value = ReconciliationResult(None, "none")
    blockchain.prepare_anchor_transaction.return_value = prepared
    blockchain.broadcast.return_value = TX_HASH
    blockchain.wait_for_confirmation.return_value = ReconciliationResult(None, "reverted")

    assert await worker._process_proof(_proof()) is False

    retry = db.schedule_retry.await_args
    assert retry.kwargs["status"] == "failed"
    # A real fault does spend the retry budget (the default), unlike a read
    # that never landed.
    assert retry.kwargs.get("increment_retry", True) is True


@pytest.mark.asyncio
async def test_root_already_anchored_with_unreadable_receipt_is_not_terminal() -> None:
    """estimateGas says anchored, reads cannot prove it — that is not a verdict."""
    worker, db, blockchain = _worker()
    proof = _proof(status="failed", retry_count=1)
    blockchain.reconcile_anchor.side_effect = [
        ReconciliationResult(None, "none"),
        ReconciliationResult(None, "unknown"),
    ]
    blockchain.prepare_anchor_transaction.side_effect = anchor_worker.RootAlreadyAnchoredError(
        "RootAlreadyAnchored"
    )

    assert await worker._process_proof(proof) is False

    db.mark_proof_dead_letter.assert_not_awaited()
    blockchain.broadcast.assert_not_called()
    assert db.schedule_retry.await_args.kwargs["increment_retry"] is False


@pytest.mark.asyncio
async def test_explicit_reconciliation_recovers_a_stranded_submitted_proof() -> None:
    """``--reconcile-proof`` closes out the incident without broadcasting."""
    worker, db, blockchain = _worker()
    proof = _proof(
        status="submitted",
        transaction_hash=TX_HASH,
        submission_nonce=17,
        submitted_at=datetime.now(UTC),
        retry_count=2,
    )
    confirmation = AnchorConfirmation(
        transaction_hash=TX_HASH,
        block_number=BLOCK_NUMBER,
        gas_used=GAS_USED,
        gas_price_gwei=Decimal("0.006"),
        anchored_at=ANCHORED_AT,
        batch_id=BATCH_ID,
        submitter=SUBMITTER,
        source="transaction_receipt",
    )
    blockchain.reconcile_anchor.return_value = ReconciliationResult(confirmation, "none")

    assert await worker._process_proof(proof, reconciliation_only=True) is True

    db.mark_proof_confirmed.assert_awaited_once_with(
        proof["id"],
        confirmation,
        reconciled=True,
    )
    blockchain.broadcast.assert_not_called()


# -----------------------------------------------------------------------------
# 4. Persistence contract for the confirmed row
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confirmed_row_records_block_gas_time_and_source() -> None:
    pool = MagicMock()
    connection = MagicMock()
    connection.execute = AsyncMock()

    class _Acquire:
        async def __aenter__(self):
            return connection

        async def __aexit__(self, *_args):
            return False

    pool.acquire.return_value = _Acquire()

    confirmation = AnchorConfirmation(
        transaction_hash=TX_HASH,
        block_number=BLOCK_NUMBER,
        gas_used=GAS_USED,
        gas_price_gwei=Decimal("0.006"),
        anchored_at=ANCHORED_AT,
        batch_id=BATCH_ID,
        submitter=SUBMITTER,
        source="transaction_receipt",
    )
    proof_id = "3f1b8f0e-8a1e-4f0e-9c1a-0d1f2e3a4b5c"

    await anchor_worker.DatabaseService(pool).mark_proof_confirmed(
        proof_id,
        confirmation,
        reconciled=True,
    )

    sql, *args = connection.execute.await_args.args
    assert "status = 'confirmed'" in sql
    assert "reconciliation_source = $8" in sql
    assert args[1] == TX_HASH
    assert args[2] == BLOCK_NUMBER
    assert args[3] == GAS_USED
    assert args[5] == ANCHORED_AT
    assert args[6] is True
    assert args[7] == "transaction_receipt"


@pytest.mark.asyncio
async def test_availability_retry_does_not_increment_the_retry_count() -> None:
    pool = MagicMock()
    connection = MagicMock()
    connection.execute = AsyncMock()

    class _Acquire:
        async def __aenter__(self):
            return connection

        async def __aexit__(self, *_args):
            return False

    pool.acquire.return_value = _Acquire()

    await anchor_worker.DatabaseService(pool).schedule_retry(
        "3f1b8f0e-8a1e-4f0e-9c1a-0d1f2e3a4b5c",
        status="submitted",
        error_message="rpc_read_unavailable",
        next_retry_at=datetime.now(UTC),
        increment_retry=False,
    )

    sql, *args = connection.execute.await_args.args
    assert "retry_count = retry_count + CASE WHEN $5::boolean THEN 1 ELSE 0 END" in sql
    assert args[4] is False


@pytest.mark.asyncio
async def test_reconcilable_sweep_includes_every_unresolved_state() -> None:
    pool = MagicMock()
    connection = MagicMock()
    connection.fetch = AsyncMock(return_value=[])

    class _Acquire:
        async def __aenter__(self):
            return connection

        async def __aexit__(self, *_args):
            return False

    pool.acquire.return_value = _Acquire()

    await anchor_worker.DatabaseService(pool).get_reconcilable_proofs()

    sql = connection.fetch.await_args.args[0]
    for state in ("prepared", "submitted", "failed", "dead_letter"):
        assert f"'{state}'" in sql


# -----------------------------------------------------------------------------
# 5. Configuration
# -----------------------------------------------------------------------------


def test_read_provider_urls_parse_in_order_without_the_primary() -> None:
    parsed = anchor_worker.parse_read_provider_urls(
        "https://one.example, https://two.example https://primary.example",
        primary_url="https://primary.example",
    )

    assert parsed == ("https://one.example", "https://two.example")


def test_read_provider_urls_reject_plaintext_and_embedded_credentials() -> None:
    with pytest.raises(ValueError):
        anchor_worker.parse_read_provider_urls(
            "http://public.example",
            primary_url="https://primary.example",
        )
    with pytest.raises(ValueError):
        anchor_worker.parse_read_provider_urls(
            "https://user:secret@rpc.example",
            primary_url="https://primary.example",
        )


def test_redacted_rpc_url_hides_provider_api_keys() -> None:
    redacted = anchor_worker.redacted_rpc_url("https://base-mainnet.example/v2/SUPER_SECRET")

    assert "SUPER_SECRET" not in redacted
    assert redacted.startswith("https://base-mainnet.example")


# -----------------------------------------------------------------------------
# 6. End to end: real BlockchainService + real AnchorWorker, mocked RPC only
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_end_to_end_403_receipt_reconciles_through_the_read_endpoint() -> None:
    """No worker or service internals stubbed — only the two RPC endpoints.

    Broadcast succeeds on the primary, the primary then 403s every receipt and
    contract-state read, and the read endpoint supplies the evidence that moves
    the proof to ``confirmed``. Exactly one transaction ever leaves the process.
    """
    primary = _fake_web3(anchor_worker.BASE_CHAIN_ID)
    fallback = _fake_web3(anchor_worker.BASE_CHAIN_ID)

    # Primary: healthy for signing and broadcast.
    raw_transaction = b"signed-anchor-batch"
    broadcast_hash = anchor_worker.normalize_transaction_hash(web3.Web3.keccak(raw_transaction))
    primary.eth.get_transaction_count.return_value = 17
    primary.eth.gas_price = EFFECTIVE_GAS_PRICE_WEI
    primary.eth.get_balance.return_value = 10**18
    signed = MagicMock()
    signed.raw_transaction = raw_transaction
    primary.eth.account.sign_transaction.return_value = signed

    # The chain only holds the batch once the broadcast lands, so the
    # pre-broadcast reconciliation correctly finds nothing anchored.
    chain = {"anchored": False}

    def _send(raw: bytes) -> str:
        assert raw == raw_transaction
        chain["anchored"] = True
        return broadcast_hash

    primary.eth.send_raw_transaction.side_effect = _send

    # Primary: 403 on every read the confirmation path needs.
    primary.eth.wait_for_transaction_receipt.side_effect = _forbidden()
    primary.eth.get_transaction_receipt.side_effect = _forbidden()

    service = _build_service_with_failover(primary, fallback)

    primary_contract = primary.eth.contract.return_value
    primary_contract.functions.anchorBatch.return_value.estimate_gas.return_value = 200_000
    primary_contract.functions.anchorBatch.return_value.build_transaction.return_value = {
        "nonce": 17
    }
    primary_contract.functions.isAnchored.return_value.call.side_effect = _forbidden()
    primary_contract.functions.getBatchFull.return_value.call.side_effect = _forbidden()

    # Read endpoint: has the receipt, the event, and the registry entry.
    receipt = _receipt()
    receipt["transactionHash"] = broadcast_hash

    def _fallback_receipt(transaction_hash: str) -> dict:
        if not chain["anchored"] or transaction_hash != broadcast_hash:
            raise web3.exceptions.TransactionNotFound(f"Transaction {transaction_hash} not found")
        return receipt

    fallback.eth.get_transaction_receipt.side_effect = _fallback_receipt
    fallback_contract = fallback.eth.contract.return_value
    fallback_contract.functions.isAnchored.return_value.call.side_effect = lambda: chain["anchored"]
    fallback_contract.functions.getBatchFull.return_value.call.return_value = _registry_batch()

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
    worker = AnchorWorker(db, service)

    assert await worker._process_proof(_proof()) is True

    # One broadcast, on the primary, and none on the read endpoint.
    assert primary.eth.send_raw_transaction.call_count == 1
    fallback.eth.send_raw_transaction.assert_not_called()

    # The proof was confirmed from the read endpoint's evidence, keyed on the
    # very hash that was persisted before the broadcast.
    db.mark_proof_confirmed.assert_awaited_once()
    confirmation = db.mark_proof_confirmed.await_args.args[1]
    assert confirmation.transaction_hash == broadcast_hash
    assert confirmation.block_number == BLOCK_NUMBER
    assert confirmation.gas_used == GAS_USED
    assert confirmation.gas_price_gwei == Decimal("0.006")
    assert confirmation.anchored_at == ANCHORED_AT
    assert confirmation.source == "transaction_receipt"
    db.mark_proof_dead_letter.assert_not_awaited()


# -----------------------------------------------------------------------------
# 7. The incident must not be silent
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_backlog_counts_proofs_waiting_on_reconciliation() -> None:
    """A proof stuck at ``submitted`` never shows up as failed or dead-lettered."""
    pool = MagicMock()
    connection = MagicMock()
    connection.fetchrow = AsyncMock(
        return_value={"failed": 0, "dead_letter": 0, "awaiting_reconciliation": 1}
    )

    class _Acquire:
        async def __aenter__(self):
            return connection

        async def __aexit__(self, *_args):
            return False

    pool.acquire.return_value = _Acquire()

    counts = await anchor_worker.DatabaseService(pool).get_proof_failure_counts()

    assert counts["awaiting_reconciliation"] == 1
    sql = connection.fetchrow.await_args.args[0]
    assert "transaction_hash IS NOT NULL" in sql


@pytest.mark.asyncio
async def test_worker_publishes_the_awaiting_reconciliation_gauge() -> None:
    from api import observability

    db = MagicMock()
    db.get_proof_failure_counts = AsyncMock(
        return_value={"failed": 0, "dead_letter": 0, "awaiting_reconciliation": 2}
    )
    worker = AnchorWorker(db_service=db, blockchain_service=MagicMock())

    with patch.object(observability, "anchor_proof_backlog") as backlog:
        await worker._publish_failure_backlog()

    backlog.labels.assert_any_call(status="awaiting_reconciliation")
    backlog.labels.return_value.set.assert_any_call(2)


def test_alert_rules_cover_unreadable_rpc_and_unconfirmed_broadcasts() -> None:
    from pathlib import Path

    rules = (Path(__file__).parents[1] / "ops" / "prometheus" / "inntris-alerts.yml").read_text(
        encoding="utf-8"
    )

    assert "InntrisAnchorRpcReadUnavailable" in rules
    assert "InntrisAnchorProofAwaitingReconciliation" in rules
    assert 'outcome="read_unavailable"' in rules
    assert 'status="awaiting_reconciliation"' in rules
    assert "inntris_anchor_rpc_read_failover_total" in rules


@pytest.mark.asyncio
async def test_reconcile_by_transaction_hash_confirms_without_broadcasting() -> None:
    """The operator path from a block explorer hash back to a confirmed row."""
    from contextlib import asynccontextmanager

    worker, db, blockchain = _worker()
    proof = _proof(
        status="submitted",
        transaction_hash=TX_HASH,
        submission_nonce=17,
        submitted_at=datetime.now(UTC),
        retry_count=4,
    )
    confirmation = AnchorConfirmation(
        transaction_hash=TX_HASH,
        block_number=BLOCK_NUMBER,
        gas_used=GAS_USED,
        gas_price_gwei=Decimal("0.006"),
        anchored_at=ANCHORED_AT,
        batch_id=BATCH_ID,
        submitter=SUBMITTER,
        source="transaction_receipt",
    )

    @asynccontextmanager
    async def _lock():
        yield True

    db.anchor_cycle_lock = _lock
    db.get_proof_by_transaction_hash = AsyncMock(return_value=proof)
    blockchain.reconcile_anchor.return_value = ReconciliationResult(confirmation, "none")

    assert await worker.reconcile_transaction(TX_HASH.upper().replace("0X", "0x")) is True

    db.get_proof_by_transaction_hash.assert_awaited_once()
    db.mark_proof_confirmed.assert_awaited_once_with(
        proof["id"],
        confirmation,
        reconciled=True,
    )
    assert db.mark_proof_confirmed.await_args.args[1].block_number == BLOCK_NUMBER
    blockchain.broadcast.assert_not_called()


@pytest.mark.asyncio
async def test_transaction_hash_lookup_is_case_insensitive_in_sql() -> None:
    pool = MagicMock()
    connection = MagicMock()
    connection.fetchrow = AsyncMock(return_value=None)

    class _Acquire:
        async def __aenter__(self):
            return connection

        async def __aexit__(self, *_args):
            return False

    pool.acquire.return_value = _Acquire()

    result = await anchor_worker.DatabaseService(pool).get_proof_by_transaction_hash(TX_HASH)

    assert result is None
    assert "lower(transaction_hash) = lower($1)" in connection.fetchrow.await_args.args[0]
