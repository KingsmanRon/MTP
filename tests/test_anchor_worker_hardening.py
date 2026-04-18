"""Phase 2B — anchor-worker hardening.

Three load-bearing invariants this file pins:

1. ``DatabaseService.get_unanchored_logs`` excludes rows whose
   ``metadata.test_request`` is true. /admin/test-verify has always
   documented this exclusion; before Phase 2B the exclusion was prose
   only, and test sentinels silently ended up in real Merkle batches.

2. ``BlockchainService.assert_chain_id`` refuses to submit if the RPC
   is serving a different chain than ``BASE_CHAIN_ID``. A misconfigured
   or DNS-hijacked provider could otherwise spend our private key on
   the wrong chain.

3. The gas-price cap (``MAX_GAS_PRICE_GWEI``) short-circuits before
   the transaction is built, so a runaway gas oracle does not burn
   funds even if the chain-id check has been fooled.

We exercise these against mocked ``web3.Web3`` and ``asyncpg.Pool``
surfaces so the tests run without an RPC endpoint or database.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

web3 = pytest.importorskip("web3")  # whole module depends on eth stack

from workers import anchor_worker  # noqa: E402
from workers.anchor_worker import BlockchainService, DatabaseService  # noqa: E402


# -----------------------------------------------------------------------------
# 1. test_request filter
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_unanchored_logs_filters_test_request_rows() -> None:
    """The SQL must carry the NOT COALESCE(... test_request ...) predicate."""
    pool = MagicMock()
    conn = MagicMock()
    conn.fetch = AsyncMock(return_value=[])

    # asyncpg Pool.acquire() returns an async context manager that yields conn.
    class _CM:
        async def __aenter__(self): return conn
        async def __aexit__(self, *a): return False

    pool.acquire = MagicMock(return_value=_CM())

    svc = DatabaseService(pool)
    await svc.get_unanchored_logs(limit=500)

    # Exactly one query issued, and it must reference both the merkle_root_id
    # NULL filter AND the metadata.test_request exclusion. If someone
    # "simplifies" the query back to the pre-2B form, this test fails.
    conn.fetch.assert_awaited_once()
    sql = conn.fetch.await_args.args[0]
    assert "merkle_root_id IS NULL" in sql
    assert "test_request" in sql
    assert "metadata->>'test_request'" in sql
    # COALESCE guard is important — without it, NULL metadata rows get
    # filtered instead of kept.
    assert "COALESCE" in sql


# -----------------------------------------------------------------------------
# 2. Chain-id verification
# -----------------------------------------------------------------------------

def _build_service(chain_id: int, gas_price_wei: int = 1_000_000_000) -> BlockchainService:
    """Construct a BlockchainService with Web3 mocked out.

    We patch the Web3 class the constructor uses, bypass the real RPC
    handshake, and inject a private key / contract address so downstream
    methods do not crash on attribute access.
    """
    fake_web3 = MagicMock()
    fake_web3.eth.chain_id = chain_id
    fake_web3.eth.gas_price = gas_price_wei
    fake_web3.from_wei = lambda wei, unit: Decimal(wei) / Decimal(10**9) \
        if unit == "gwei" else Decimal(wei) / Decimal(10**18)
    fake_web3.to_checksum_address = lambda a: a
    fake_web3.eth.contract = MagicMock(return_value=MagicMock())

    # eth_account is pure-Python, but patch it to sidestep keccak on a bogus key.
    fake_account = MagicMock()
    fake_account.address = "0x0000000000000000000000000000000000000001"

    with patch.object(anchor_worker, "Web3") as MockWeb3, \
         patch.object(anchor_worker, "Account") as MockAccount:
        MockWeb3.return_value = fake_web3
        MockWeb3.HTTPProvider = MagicMock()
        MockWeb3.to_checksum_address = lambda a: a
        MockAccount.from_key.return_value = fake_account

        svc = BlockchainService(
            rpc_url="http://example.invalid",
            contract_address="0x0000000000000000000000000000000000000002",
            private_key="0x" + "11" * 32,
        )
    # Re-attach the mocked web3 that the constructor stored on self.
    svc.w3 = fake_web3
    return svc


def test_assert_chain_id_passes_on_match() -> None:
    svc = _build_service(chain_id=anchor_worker.BASE_CHAIN_ID)
    svc.assert_chain_id()  # must not raise


def test_assert_chain_id_raises_on_mismatch() -> None:
    svc = _build_service(chain_id=1)  # mainnet ETH where we expect Base
    with pytest.raises(RuntimeError, match="chain-id mismatch"):
        svc.assert_chain_id()


# -----------------------------------------------------------------------------
# 3. Gas-price cap
# -----------------------------------------------------------------------------

def test_gas_price_cap_default_is_conservative() -> None:
    # If someone bumps the default to, say, 500 gwei "to avoid alerts,"
    # the cap stops protecting against a runaway oracle. Pin the default.
    assert anchor_worker.MAX_GAS_PRICE_GWEI == Decimal("50")


def test_anchor_batch_refuses_excessive_gas_price(monkeypatch: pytest.MonkeyPatch) -> None:
    """A gas price above the cap must raise before any tx is submitted."""
    # 100 gwei = 100 * 10^9 wei, exceeds default cap of 50 gwei.
    svc = _build_service(
        chain_id=anchor_worker.BASE_CHAIN_ID,
        gas_price_wei=100 * 10**9,
    )

    # Set up the contract mock deep enough that we reach the gas-price line.
    contract_fn = MagicMock()
    contract_fn.estimate_gas = MagicMock(return_value=200_000)
    contract_fn.build_transaction = MagicMock()
    svc.contract.functions.anchorBatch = MagicMock(return_value=contract_fn)
    svc.w3.eth.get_transaction_count = MagicMock(return_value=0)

    # Drive anchor_batch synchronously via asyncio to exercise the raise path.
    import asyncio
    from datetime import datetime, timezone

    async def _run() -> None:
        await svc.anchor_batch(
            merkle_root="00" * 32,
            log_count=1,
            start_timestamp=datetime.now(timezone.utc),
            end_timestamp=datetime.now(timezone.utc),
        )

    with pytest.raises(RuntimeError, match="exceeds cap"):
        asyncio.run(_run())

    # Critical: we must have bailed BEFORE calling build_transaction. Any
    # signed-tx construction past the cap would defeat the point of the cap.
    contract_fn.build_transaction.assert_not_called()
