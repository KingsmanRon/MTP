"""
Inntris Core - Blockchain Anchor Worker

The "Forensic Recorder" that anchors audit logs to Base L2.

This worker:
1. Pulls unanchored audit logs from the database
2. Computes a Merkle tree of log hashes
3. Submits the Merkle root to the AnchorRegistry smart contract
4. Updates the database with transaction details

Philosophy: "Immutable Truth" - Once anchored, audit logs cannot be disputed.
"""

import asyncio
import logging
import os
import signal
import socket
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import asyncpg
from web3 import Web3
from eth_account import Account
from eth_account.signers.local import LocalAccount

from workers.circuit_breaker import RpcCircuitBreaker, RpcCircuitOpenError

# =============================================================================
# CONFIGURATION
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Database
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/inntris"
).strip()

# Blockchain
BLOCKCHAIN_PROVIDER_URL = os.getenv("BLOCKCHAIN_PROVIDER_URL", "https://base-rpc.publicnode.com")
ANCHOR_CONTRACT_ADDRESS = os.getenv("ANCHOR_CONTRACT_ADDRESS")
BLOCKCHAIN_PRIVATE_KEY = os.getenv("BLOCKCHAIN_PRIVATE_KEY")  # With or without 0x prefix

# Worker settings
BATCH_SIZE = int(os.getenv("ANCHOR_BATCH_SIZE", "1000"))
# Support both ANCHOR_INTERVAL_MINUTES (new) and ANCHOR_BATCH_INTERVAL (old, seconds)
BATCH_INTERVAL_MINUTES = int(os.getenv("ANCHOR_INTERVAL_MINUTES", "60"))  # Default: 1 hour
BATCH_INTERVAL_SECONDS = int(os.getenv("ANCHOR_BATCH_INTERVAL", str(BATCH_INTERVAL_MINUTES * 60)))
MAX_RETRIES = int(os.getenv("ANCHOR_MAX_RETRIES", "5"))
# Exponential backoff between failed retries. retry N waits
# RETRY_BACKOFF_BASE_SECONDS * 2^(N-1), capped at RETRY_BACKOFF_MAX_SECONDS.
RETRY_BACKOFF_BASE_SECONDS = int(os.getenv("ANCHOR_RETRY_BACKOFF_BASE", "60"))
RETRY_BACKOFF_MAX_SECONDS = int(os.getenv("ANCHOR_RETRY_BACKOFF_MAX", str(60 * 60)))


def compute_retry_backoff(
    retry_count: int,
    base_seconds: int = RETRY_BACKOFF_BASE_SECONDS,
    max_seconds: int = RETRY_BACKOFF_MAX_SECONDS,
) -> timedelta:
    """Return the delay before retry #(retry_count+1) after `retry_count` failures.

    retry_count=0 is the delay before the *first* retry (i.e. after the
    initial attempt failed). Caps at ``max_seconds`` so a long-lived
    failure doesn't push next_retry_at out past the heat death of the
    universe via int overflow (2**63 retries is still wild, but bounded).
    """
    if retry_count < 0:
        raise ValueError("retry_count must be non-negative")
    # Clamp the exponent to avoid huge left-shifts before the min().
    exponent = min(retry_count, 30)
    delay = base_seconds * (2 ** exponent)
    return timedelta(seconds=min(delay, max_seconds))

# Base L2 Chain ID
BASE_CHAIN_ID = int(os.getenv("BLOCKCHAIN_CHAIN_ID", "8453"))

# Phase 2B hardening — gas-price sanity cap (gwei).
# Base mainnet typically runs well under 1 gwei. A cap catches a runaway
# gas-price oracle (e.g. a malicious or broken RPC returning eth-mainnet
# prices for what we believe is an L2 tx). Set conservatively high enough
# that legitimate congestion does not trip it; operators can raise via env.
# If the cap trips, the proof is recorded as ``failed`` with a descriptive
# error, retried with exponential backoff, and dead-lettered if persistent.
MAX_GAS_PRICE_GWEI = Decimal(os.getenv("ANCHOR_MAX_GAS_PRICE_GWEI", "50"))

# Phase resilience — RPC circuit breaker config. See
# docs/superpowers/specs/2026-04-21-blockchain-rpc-circuit-breaker-design.md
RPC_BREAKER_ENABLED = os.getenv("ANCHOR_RPC_BREAKER_ENABLED", "true").lower() not in ("0", "false", "no")
RPC_BREAKER_THRESHOLD = int(os.getenv("ANCHOR_RPC_BREAKER_THRESHOLD", "5"))
RPC_BREAKER_OPEN_SECONDS = float(os.getenv("ANCHOR_RPC_BREAKER_OPEN_SECONDS", "60"))


def _redacted_dsn(dsn: str) -> str:
    """Return DSN with password hidden for safe logs."""
    parts = urlsplit(dsn)
    if not parts.netloc:
        return dsn

    netloc = parts.netloc
    if "@" in netloc:
        userinfo, hostpart = netloc.rsplit("@", 1)
        if ":" in userinfo:
            user = userinfo.split(":", 1)[0]
            userinfo = f"{user}:***"
        netloc = f"{userinfo}@{hostpart}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _database_host_from_dsn(dsn: str) -> str:
    """Extract hostname from a DSN, empty string when parsing fails."""
    try:
        return urlsplit(dsn).hostname or ""
    except Exception:
        return ""

# AnchorRegistry ABI (minimal for anchoring)
ANCHOR_REGISTRY_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"},
            {"internalType": "uint256", "name": "logCount", "type": "uint256"},
            {"internalType": "uint256", "name": "startTimestamp", "type": "uint256"},
            {"internalType": "uint256", "name": "endTimestamp", "type": "uint256"},
        ],
        "name": "anchorBatch",
        "outputs": [{"internalType": "uint256", "name": "batchId", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"}],
        "name": "getBatch",
        "outputs": [
            {"internalType": "uint256", "name": "batchId", "type": "uint256"},
            {"internalType": "uint256", "name": "logCount", "type": "uint256"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "address", "name": "submitter", "type": "address"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "batchId", "type": "uint256"},
            {"indexed": True, "internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"},
            {"indexed": False, "internalType": "uint256", "name": "logCount", "type": "uint256"},
            {"indexed": False, "internalType": "address", "name": "submitter", "type": "address"},
        ],
        "name": "BatchAnchored",
        "type": "event",
    },
]


# =============================================================================
# MERKLE TREE UTILITIES
# =============================================================================

def keccak256(data: bytes) -> bytes:
    """
    Compute keccak256 hash (Ethereum standard).
    CRITICAL: Must match the Solidity contract's keccak256 function.
    """
    return Web3.keccak(data)


def compute_merkle_root(leaf_hashes: list[str]) -> str:
    """
    Compute Merkle root from a list of leaf hashes.
    Uses Keccak-256 for internal nodes to match Solidity.
    """
    if not leaf_hashes:
        raise ValueError("Cannot compute Merkle root of empty list")

    # Convert hex strings to bytes
    nodes = [bytes.fromhex(h) for h in leaf_hashes]

    while len(nodes) > 1:
        # If odd number of nodes, duplicate the last one
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])

        # Combine pairs
        next_level = []
        for i in range(0, len(nodes), 2):
            combined = nodes[i] + nodes[i + 1]
            # FIX 1: Use keccak256 instead of sha256
            next_level.append(keccak256(combined))

        nodes = next_level

    # FIX 2: Strip '0x' prefix to fit VARCHAR(64) database column
    return nodes[0].hex().replace("0x", "")


def compute_merkle_proof(leaf_hashes: list[str], leaf_index: int) -> list[dict[str, Any]]:
    """
    Compute Merkle proof for a specific leaf.
    """
    if not leaf_hashes:
        raise ValueError("Cannot compute proof for empty list")

    if leaf_index < 0 or leaf_index >= len(leaf_hashes):
        raise ValueError(f"Invalid leaf index: {leaf_index}")

    nodes = [bytes.fromhex(h) for h in leaf_hashes]
    proof = []
    index = leaf_index

    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])

        # Add sibling to proof
        sibling_index = index + 1 if index % 2 == 0 else index - 1
        proof.append({
            # FIX 2: Strip '0x' prefix
            "hash": nodes[sibling_index].hex().replace("0x", ""),
            "position": 1 if index % 2 == 0 else 0,
        })

        # Move up the tree
        next_level = []
        for i in range(0, len(nodes), 2):
            combined = nodes[i] + nodes[i + 1]
            # FIX 1: Use keccak256
            next_level.append(keccak256(combined))

        nodes = next_level
        index = index // 2

    return proof


# =============================================================================
# BLOCKCHAIN SERVICE
# =============================================================================

class BlockchainService:
    """
    Service for interacting with the Base L2 blockchain.
    """

    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        private_key: str,
        expected_chain_id: int = BASE_CHAIN_ID,
    ):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=ANCHOR_REGISTRY_ABI,
        )
        self.account: LocalAccount = Account.from_key(private_key)
        self._breaker = RpcCircuitBreaker(
            threshold=RPC_BREAKER_THRESHOLD,
            open_duration_seconds=RPC_BREAKER_OPEN_SECONDS,
            enabled=RPC_BREAKER_ENABLED,
        )
        self.expected_chain_id = expected_chain_id
        logger.info(f"Blockchain service initialized. Address: {self.account.address}")
        logger.info(
            "RPC circuit breaker: enabled=%s threshold=%d open_seconds=%.1f",
            RPC_BREAKER_ENABLED,
            RPC_BREAKER_THRESHOLD,
            RPC_BREAKER_OPEN_SECONDS,
        )

    def _rpc(self, fn):
        """Route an RPC call through the circuit breaker."""
        return self._breaker.call(fn)

    def assert_chain_id(self) -> None:
        """Phase 2B hardening — verify the RPC is serving the expected chain.

        A misconfigured ``BLOCKCHAIN_PROVIDER_URL`` (or a compromised/upstream-
        DNS-hijacked endpoint) could route our anchor transactions to a chain
        we did not intend — mainnet ETH fees on what we thought was Base, or
        worse, a chain where our private key controls a different account.
        We call this before submitting each batch; failure raises so the
        caller records the proof as ``failed`` and retries.
        """
        actual = self._rpc(lambda: self.w3.eth.chain_id)
        if actual != self.expected_chain_id:
            raise RuntimeError(
                f"RPC chain-id mismatch: expected {self.expected_chain_id} "
                f"(BASE_CHAIN_ID), got {actual}. Refusing to submit."
            )

    def is_connected(self) -> bool:
        try:
            return self._rpc(lambda: self.w3.is_connected())
        except Exception:
            return False

    def get_balance(self) -> Decimal:
        balance_wei = self._rpc(lambda: self.w3.eth.get_balance(self.account.address))
        return Decimal(str(self.w3.from_wei(balance_wei, "ether")))

    async def anchor_batch(
        self,
        merkle_root: str,
        log_count: int,
        start_timestamp: datetime,
        end_timestamp: datetime,
    ) -> dict[str, Any]:
        # Phase 2B — verify the RPC still serves the chain we expect before
        # spending gas. Cheap check (one eth_chainId call), huge blast-radius
        # if it's ever wrong.
        self.assert_chain_id()

        # Ensure 0x prefix for Web3, but input might be raw hex
        if not merkle_root.startswith("0x"):
            merkle_root_hex = "0x" + merkle_root
        else:
            merkle_root_hex = merkle_root
            
        root_bytes = bytes.fromhex(merkle_root_hex[2:]) # Strip 0x for bytes conversion

        start_unix = int(start_timestamp.timestamp())
        end_unix = int(end_timestamp.timestamp())

        nonce = self._rpc(lambda: self.w3.eth.get_transaction_count(self.account.address))

        try:
            gas_estimate = self._rpc(lambda: self.contract.functions.anchorBatch(
                root_bytes,
                log_count,
                start_unix,
                end_unix,
            ).estimate_gas({"from": self.account.address}))
        except Exception as e:
            if isinstance(e, RpcCircuitOpenError):
                raise
            logger.warning(f"Gas estimation failed, using default: {e}")
            gas_estimate = 150000

        gas_price = self._rpc(lambda: self.w3.eth.gas_price)
        gas_price_gwei = Decimal(str(self.w3.from_wei(gas_price, "gwei")))

        # Phase 2B hardening — reject suspiciously high gas prices.
        # Trips on a broken gas oracle or an RPC silently serving mainnet.
        # A tripped cap costs nothing except a retry; a burst of legitimate
        # Base congestion above the cap also retries, so operators should
        # raise ANCHOR_MAX_GAS_PRICE_GWEI rather than remove this check.
        if gas_price_gwei > MAX_GAS_PRICE_GWEI:
            raise RuntimeError(
                f"Gas price {gas_price_gwei} gwei exceeds cap "
                f"{MAX_GAS_PRICE_GWEI} gwei. Refusing to submit."
            )

        tx = self.contract.functions.anchorBatch(
            root_bytes,
            log_count,
            start_unix,
            end_unix,
        ).build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": int(gas_estimate * 1.2),
            "gasPrice": gas_price,
            "chainId": BASE_CHAIN_ID,
        })

        signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)
        # Compatibility: web3.py v6+ uses raw_transaction, older uses rawTransaction
        raw_tx = getattr(signed_tx, 'raw_transaction', None) or signed_tx.rawTransaction
        tx_hash = self._rpc(lambda: self.w3.eth.send_raw_transaction(raw_tx))
        logger.info(f"Transaction submitted: {tx_hash.hex()}")

        receipt = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._rpc(
                lambda: self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            ),
        )

        return {
            "transaction_hash": receipt["transactionHash"].hex(),
            "block_number": receipt["blockNumber"],
            "gas_used": receipt["gasUsed"],
            "gas_price_gwei": gas_price_gwei,
            "status": "confirmed" if receipt["status"] == 1 else "failed",
        }

    def verify_batch_anchored(self, merkle_root: str) -> Optional[dict[str, Any]]:
        # Ensure clean hex for bytes conversion
        if merkle_root.startswith("0x"):
            merkle_root = merkle_root[2:]
            
        root_bytes = bytes.fromhex(merkle_root)

        try:
            result = self.contract.functions.getBatch(root_bytes).call()
            batch_id, log_count, timestamp, submitter = result

            if batch_id == 0:
                return None

            return {
                "batch_id": batch_id,
                "log_count": log_count,
                "timestamp": datetime.fromtimestamp(timestamp, tz=timezone.utc),
                "submitter": submitter,
            }
        except Exception as e:
            logger.error(f"Error verifying batch: {e}")
            return None


# =============================================================================
# DATABASE SERVICE
# =============================================================================

class DatabaseService:
    def __init__(self, pool: asyncpg.Pool):
        self._pool = pool

    @classmethod
    async def create(cls, dsn: str) -> "DatabaseService":
        # statement_cache_size=0 required for pgbouncer compatibility
        pool = await asyncpg.create_pool(
            dsn,
            min_size=2,
            max_size=10,
            statement_cache_size=0,
        )
        if pool is None:
            raise RuntimeError("Failed to create database pool")
        return cls(pool)

    async def close(self):
        await self._pool.close()

    async def get_unanchored_logs(self, limit: int = 1000) -> list[dict[str, Any]]:
        # Phase 2B: exclude test_request rows from real Merkle batches.
        # /admin/test-verify writes audit rows with metadata.test_request=true
        # and signature=b"TEST_REQUEST" as a sentinel. Those entries must
        # never end up in a publicly-verifiable proof: they carry no real
        # cryptographic attestation, and the api/main.py docstring has
        # promised callers they will be excluded since the endpoint shipped.
        # Before this query, the promise was documentation-only — the worker
        # happily hashed the sentinel alongside real signed actions.
        #
        # Filter pattern: metadata ? 'test_request' is cheap (JSONB key test)
        # and short-circuits before the cast; the COALESCE guards the empty-
        # metadata case where ->>'test_request' returns NULL.
        query = """
            SELECT id, action_hash, timestamp
            FROM audit_logs
            WHERE merkle_root_id IS NULL
              AND NOT COALESCE(
                  (metadata->>'test_request')::boolean,
                  false
              )
            ORDER BY timestamp ASC
            LIMIT $1
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, limit)
        return [dict(row) for row in rows]

    async def create_merkle_proof_record(
        self,
        root_hash: str,
        leaf_hashes: list[str],
        start_timestamp: datetime,
        end_timestamp: datetime,
        contract_address: str,
        chain_id: int = BASE_CHAIN_ID,
    ) -> UUID:
        # ON CONFLICT: if root already exists, return existing ID
        query = """
            INSERT INTO merkle_proofs (
                root_hash, leaf_hashes, start_timestamp, end_timestamp,
                contract_address, chain_id, log_count, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
            ON CONFLICT (root_hash) DO UPDATE SET root_hash = EXCLUDED.root_hash
            RETURNING id
        """
        async with self._pool.acquire() as conn:
            proof_id = await conn.fetchval(
                query,
                root_hash,
                leaf_hashes,
                start_timestamp,
                end_timestamp,
                contract_address,
                chain_id,
                len(leaf_hashes),
            )
        return proof_id

    async def update_merkle_proof_status(
        self,
        proof_id: UUID,
        status: str,
        transaction_hash: Optional[str] = None,
        block_number: Optional[int] = None,
        gas_used: Optional[int] = None,
        gas_price_gwei: Optional[Decimal] = None,
        error_message: Optional[str] = None,
        next_retry_at: Optional[datetime] = None,
    ):
        # $2::varchar avoids asyncpg "could not determine data type" errors.
        # When status='failed', the worker has already computed next_retry_at
        # for the caller based on the *current* retry_count, so bump
        # retry_count in the same statement without re-reading the row.
        # When status='dead_letter', stamp dead_lettered_at and clear
        # next_retry_at so the retry query cannot pick this row up again.
        query = """
            UPDATE merkle_proofs
            SET
                status = $2::varchar,
                transaction_hash = COALESCE($3, transaction_hash),
                block_number = COALESCE($4, block_number),
                gas_used = COALESCE($5, gas_used),
                gas_price_gwei = COALESCE($6, gas_price_gwei),
                error_message = COALESCE($7, error_message),
                next_retry_at = CASE
                    WHEN $2::varchar = 'failed' THEN $8
                    WHEN $2::varchar = 'dead_letter' THEN NULL
                    WHEN $2::varchar = 'confirmed' THEN NULL
                    ELSE next_retry_at
                END,
                dead_lettered_at = CASE
                    WHEN $2::varchar = 'dead_letter' AND dead_lettered_at IS NULL
                        THEN NOW()
                    ELSE dead_lettered_at
                END,
                confirmed_at = CASE WHEN $2::varchar = 'confirmed' THEN NOW() ELSE confirmed_at END,
                retry_count = CASE
                    WHEN $2::varchar IN ('failed', 'dead_letter') THEN retry_count + 1
                    ELSE retry_count
                END
            WHERE id = $1
        """
        async with self._pool.acquire() as conn:
            await conn.execute(
                query,
                proof_id,
                status,
                transaction_hash,
                block_number,
                gas_used,
                gas_price_gwei,
                error_message,
                next_retry_at,
            )

    async def mark_logs_as_anchored(
        self,
        log_ids: list[UUID],
        merkle_root_id: UUID,
    ):
        query = """
            UPDATE audit_logs
            SET
                merkle_root_id = $1,
                merkle_leaf_index = sub.idx
            FROM (
                SELECT
                    unnest($2::uuid[]) as log_id,
                    generate_series(0, array_length($2::uuid[], 1) - 1) as idx
            ) sub
            WHERE audit_logs.id = sub.log_id
              AND audit_logs.merkle_root_id IS NULL
        """
        async with self._pool.acquire() as conn:
            await conn.execute(query, merkle_root_id, log_ids)

        logger.info(f"Marked {len(log_ids)} logs as anchored")

    async def get_pending_proofs(self) -> list[dict[str, Any]]:
        # Only rows whose backoff window has elapsed. 'dead_letter' is a
        # terminal state and is never returned here — operators must
        # requeue manually once the underlying problem (RPC, gas, key) is
        # fixed.
        query = """
            SELECT id, root_hash, leaf_hashes, retry_count,
                   start_timestamp, end_timestamp
            FROM merkle_proofs
            WHERE status IN ('pending', 'failed')
              AND retry_count < $1
              AND (next_retry_at IS NULL OR next_retry_at <= NOW())
            ORDER BY created_at ASC
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, MAX_RETRIES)
        return [dict(row) for row in rows]


# =============================================================================
# ANCHOR WORKER
# =============================================================================

class AnchorWorker:
    def __init__(
        self,
        db_service: DatabaseService,
        blockchain_service: BlockchainService,
        batch_size: int = BATCH_SIZE,
        interval_seconds: int = BATCH_INTERVAL_SECONDS,
    ):
        self.db = db_service
        self.blockchain = blockchain_service
        self.batch_size = batch_size
        self.interval_seconds = interval_seconds
        self._running = False
        self._shutdown_event = asyncio.Event()

    async def start(self):
        self._running = True
        logger.info(
            f"Anchor worker started. Batch size: {self.batch_size}, "
            f"Interval: {self.interval_seconds}s"
        )

        while self._running:
            try:
                await self._process_batch()
            except Exception as e:
                logger.exception(f"Error in batch processing: {e}")

            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.interval_seconds,
                )
                break
            except asyncio.TimeoutError:
                pass

        logger.info("Anchor worker stopped")

    async def stop(self):
        logger.info("Stopping anchor worker...")
        self._running = False
        self._shutdown_event.set()

    async def _process_batch(self):
        await self._retry_pending_proofs()

        logs = await self.db.get_unanchored_logs(self.batch_size)
        if not logs:
            logger.debug("No unanchored logs to process")
            return

        logger.info(f"Processing batch of {len(logs)} logs")

        log_ids = [row["id"] for row in logs]
        leaf_hashes = [row["action_hash"] for row in logs]
        start_timestamp = logs[0]["timestamp"]
        end_timestamp = logs[-1]["timestamp"]

        merkle_root = compute_merkle_root(leaf_hashes)
        logger.info(f"Computed Merkle root: {merkle_root}")

        proof_id = await self.db.create_merkle_proof_record(
            root_hash=merkle_root,
            leaf_hashes=leaf_hashes,
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
            contract_address=self.blockchain.contract_address,
        )

        await self.db.mark_logs_as_anchored(log_ids, proof_id)

        await self._submit_to_blockchain(
            proof_id=proof_id,
            merkle_root=merkle_root,
            log_count=len(logs),
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
        )

    async def _submit_to_blockchain(
        self,
        proof_id: UUID,
        merkle_root: str,
        log_count: int,
        start_timestamp: datetime,
        end_timestamp: datetime,
        current_retry_count: int = 0,
    ):
        try:
            # FIX 4: Lowered threshold to 0.0001 ETH
            balance = self.blockchain.get_balance()
            if balance < Decimal("0.0001"):
                logger.error(f"Insufficient balance: {balance} ETH")
                await self._record_failure(
                    proof_id,
                    current_retry_count,
                    f"Insufficient balance: {balance} ETH",
                )
                return

            result = await self.blockchain.anchor_batch(
                merkle_root=merkle_root,
                log_count=log_count,
                start_timestamp=start_timestamp,
                end_timestamp=end_timestamp,
            )

            await self.db.update_merkle_proof_status(
                proof_id,
                status=result["status"],
                transaction_hash=result["transaction_hash"],
                block_number=result["block_number"],
                gas_used=result["gas_used"],
                gas_price_gwei=result["gas_price_gwei"],
            )

            # Phase 2C — count by actual receipt outcome, not by "we called
            # the RPC". ``result["status"]`` comes from the on-chain receipt
            # so a reverted tx counts as failed, not confirmed.
            try:
                from api.observability import anchor_submissions_total
                anchor_submissions_total.labels(outcome=result["status"]).inc()
            except ImportError:
                pass  # worker can run without the API package in some deploys

            logger.info(
                f"Batch anchored successfully! "
                f"TX: {result['transaction_hash']}, "
                f"Block: {result['block_number']}"
            )

        except Exception as e:
            logger.error(f"Blockchain submission failed: {e}")
            await self._record_failure(proof_id, current_retry_count, str(e))

    async def _record_failure(
        self,
        proof_id: UUID,
        current_retry_count: int,
        error_message: str,
    ):
        # After this attempt, retry_count becomes current_retry_count + 1
        # (the SQL does the increment). Transition to dead_letter once we
        # hit the cap so the retry query stops picking this row up.
        next_retry_count = current_retry_count + 1
        if next_retry_count >= MAX_RETRIES:
            logger.error(
                f"Proof {proof_id} exhausted {MAX_RETRIES} retries — "
                f"transitioning to dead_letter. Last error: {error_message}"
            )
            await self.db.update_merkle_proof_status(
                proof_id,
                status="dead_letter",
                error_message=error_message,
            )
            # Phase 2C — dead-letter is the terminal failure. Alert on any
            # non-zero rate of this: it means operator attention is needed
            # (RPC broken, gas cap too tight, private key out of funds).
            try:
                from api.observability import anchor_submissions_total
                anchor_submissions_total.labels(outcome="dead_letter").inc()
            except ImportError:
                pass
            return

        backoff = compute_retry_backoff(next_retry_count)
        next_retry_at = datetime.now(timezone.utc) + backoff
        logger.warning(
            f"Proof {proof_id} failed (attempt {next_retry_count}/{MAX_RETRIES}). "
            f"Next retry at {next_retry_at.isoformat()} ({backoff})."
        )
        await self.db.update_merkle_proof_status(
            proof_id,
            status="failed",
            error_message=error_message,
            next_retry_at=next_retry_at,
        )

    async def _retry_pending_proofs(self):
        pending = await self.db.get_pending_proofs()

        for proof in pending:
            logger.info(f"Retrying proof {proof['id']} (attempt {proof['retry_count'] + 1})")

            await self._submit_to_blockchain(
                proof_id=proof["id"],
                merkle_root=proof["root_hash"],
                log_count=len(proof["leaf_hashes"]),
                start_timestamp=proof["start_timestamp"],
                end_timestamp=proof["end_timestamp"],
                current_retry_count=proof["retry_count"],
            )


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

async def main():
    """Main entry point for the anchor worker."""
    # Validate configuration
    if not ANCHOR_CONTRACT_ADDRESS:
        logger.error("ANCHOR_CONTRACT_ADDRESS environment variable is required")
        sys.exit(1)

    if not BLOCKCHAIN_PRIVATE_KEY:
        logger.error("BLOCKCHAIN_PRIVATE_KEY environment variable is required")
        sys.exit(1)

    # Initialize services
    logger.info("Initializing anchor worker...")
    db_host = _database_host_from_dsn(DATABASE_URL)
    if not db_host:
        logger.critical(
            "DATABASE_URL is invalid or missing hostname. Got: %s",
            _redacted_dsn(DATABASE_URL),
        )
        sys.exit(1)
    if any(token in db_host for token in ("<", ">", "xxx", "your_", "example")):
        logger.critical(
            "DATABASE_URL hostname looks like a template placeholder (%s). "
            "Use the exact Supabase host from Project Settings > Database > Connection string.",
            db_host,
        )
        sys.exit(1)

    try:
        db_service = await DatabaseService.create(DATABASE_URL)
        logger.info("Database connection established")
    except socket.gaierror as e:
        logger.critical(
            "Failed to resolve database hostname %r from DATABASE_URL (%s): %s",
            db_host,
            _redacted_dsn(DATABASE_URL),
            e,
        )
        logger.critical(
            "This is a DNS/host configuration issue, not a database password issue."
        )
        if ".pooler.supabase.com" in db_host:
            logger.critical(
                "For Supabase pooled connections, copy the host exactly from Supabase "
                "(Project Settings -> Database -> Connection string). Do not guess aws-0/aws-1."
            )
        sys.exit(1)
    except asyncpg.InvalidPasswordError as e:
        logger.critical("Database authentication failed for host '%s': %s", db_host, e)
        logger.critical(
            "For Supabase role-based setup, set a password on inntris_worker and use that in DATABASE_URL."
        )
        sys.exit(1)
    except asyncpg.InvalidAuthorizationSpecificationError as e:
        logger.critical("Database role/auth configuration error for host '%s': %s", db_host, e)
        logger.critical(
            "If using inntris_api in DATABASE_URL, switch to inntris_worker (inntris_api is NOLOGIN)."
        )
        sys.exit(1)

    blockchain_service = BlockchainService(
        rpc_url=BLOCKCHAIN_PROVIDER_URL,
        contract_address=ANCHOR_CONTRACT_ADDRESS,
        private_key=BLOCKCHAIN_PRIVATE_KEY,
    )

    if not blockchain_service.is_connected():
        logger.error("Failed to connect to blockchain")
        sys.exit(1)

    balance = blockchain_service.get_balance()
    logger.info(f"Blockchain connected. Balance: {balance} ETH")

    # Create worker
    worker = AnchorWorker(db_service, blockchain_service)

    # Handle shutdown signals
    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, initiating shutdown...")
        asyncio.create_task(worker.stop())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        await worker.start()
    finally:
        await db_service.close()
        logger.info("Anchor worker shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
