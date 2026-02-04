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
import hashlib
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Optional
from uuid import UUID

import asyncpg
from web3 import Web3
from eth_account import Account
from eth_account.signers.local import LocalAccount

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
)

# Blockchain
BLOCKCHAIN_PROVIDER_URL = os.getenv("BLOCKCHAIN_PROVIDER_URL", "https://mainnet.base.org")
ANCHOR_CONTRACT_ADDRESS = os.getenv("ANCHOR_CONTRACT_ADDRESS")
BLOCKCHAIN_PRIVATE_KEY = os.getenv("BLOCKCHAIN_PRIVATE_KEY")  # With or without 0x prefix

# Worker settings
BATCH_SIZE = int(os.getenv("ANCHOR_BATCH_SIZE", "1000"))
# Support both ANCHOR_INTERVAL_MINUTES (new) and ANCHOR_BATCH_INTERVAL (old, seconds)
BATCH_INTERVAL_MINUTES = int(os.getenv("ANCHOR_INTERVAL_MINUTES", "60"))  # Default: 1 hour
BATCH_INTERVAL_SECONDS = int(os.getenv("ANCHOR_BATCH_INTERVAL", str(BATCH_INTERVAL_MINUTES * 60)))
MAX_RETRIES = int(os.getenv("ANCHOR_MAX_RETRIES", "5"))

# Base L2 Chain ID
BASE_CHAIN_ID = int(os.getenv("BLOCKCHAIN_CHAIN_ID", "8453"))

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

def compute_merkle_root(leaf_hashes: list[str]) -> str:
    """
    Compute Merkle root from a list of leaf hashes.

    Uses SHA-256 for internal nodes. If the number of leaves is odd,
    the last leaf is duplicated.

    Args:
        leaf_hashes: List of hex-encoded SHA-256 hashes.

    Returns:
        Hex-encoded Merkle root hash.
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
            next_level.append(hashlib.sha256(combined).digest())

        nodes = next_level

    return nodes[0].hex()


def compute_merkle_proof(leaf_hashes: list[str], leaf_index: int) -> list[dict[str, Any]]:
    """
    Compute Merkle proof for a specific leaf.

    Args:
        leaf_hashes: List of all leaf hashes.
        leaf_index: Index of the leaf to prove.

    Returns:
        List of proof elements with hash and position.
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
            "hash": nodes[sibling_index].hex(),
            "position": "right" if index % 2 == 0 else "left",
        })

        # Move up the tree
        next_level = []
        for i in range(0, len(nodes), 2):
            combined = nodes[i] + nodes[i + 1]
            next_level.append(hashlib.sha256(combined).digest())

        nodes = next_level
        index = index // 2

    return proof


# =============================================================================
# BLOCKCHAIN SERVICE
# =============================================================================

class BlockchainService:
    """
    Service for interacting with the Base L2 blockchain.

    Handles transaction submission with retry logic and gas estimation.
    """

    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        private_key: str,
    ):
        """
        Initialize blockchain service.

        Args:
            rpc_url: Base L2 RPC endpoint URL.
            contract_address: AnchorRegistry contract address.
            private_key: Hex-encoded private key (without 0x prefix).
        """
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))

        # Note: ExtraDataToPOAMiddleware was removed in web3.py v7+
        # Base L2 (and modern EVM chains) don't require POA middleware
        # The chain handles extraData correctly by default

        self.contract_address = Web3.to_checksum_address(contract_address)
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=ANCHOR_REGISTRY_ABI,
        )

        # Load account
        self.account: LocalAccount = Account.from_key(private_key)
        logger.info(f"Blockchain service initialized. Address: {self.account.address}")

    def is_connected(self) -> bool:
        """Check if connected to the blockchain."""
        try:
            return self.w3.is_connected()
        except Exception:
            return False

    def get_balance(self) -> Decimal:
        """Get ETH balance of the signing account."""
        balance_wei = self.w3.eth.get_balance(self.account.address)
        return Decimal(str(self.w3.from_wei(balance_wei, "ether")))

    async def anchor_batch(
        self,
        merkle_root: str,
        log_count: int,
        start_timestamp: datetime,
        end_timestamp: datetime,
    ) -> dict[str, Any]:
        """
        Submit a Merkle root to the AnchorRegistry contract.

        Args:
            merkle_root: Hex-encoded Merkle root (64 chars).
            log_count: Number of logs in the batch.
            start_timestamp: Timestamp of the first log.
            end_timestamp: Timestamp of the last log.

        Returns:
            Transaction receipt details.
        """
        # Convert merkle root to bytes32
        root_bytes = bytes.fromhex(merkle_root)

        # Convert timestamps to Unix
        start_unix = int(start_timestamp.timestamp())
        end_unix = int(end_timestamp.timestamp())

        # Build transaction
        nonce = self.w3.eth.get_transaction_count(self.account.address)

        # Estimate gas
        try:
            gas_estimate = self.contract.functions.anchorBatch(
                root_bytes,
                log_count,
                start_unix,
                end_unix,
            ).estimate_gas({"from": self.account.address})
        except Exception as e:
            logger.warning(f"Gas estimation failed, using default: {e}")
            gas_estimate = 150000

        # Get gas price
        gas_price = self.w3.eth.gas_price

        # Build transaction
        tx = self.contract.functions.anchorBatch(
            root_bytes,
            log_count,
            start_unix,
            end_unix,
        ).build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": int(gas_estimate * 1.2),  # 20% buffer
            "gasPrice": gas_price,
            "chainId": BASE_CHAIN_ID,
        })

        # Sign transaction
        signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)

        # Send transaction
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        logger.info(f"Transaction submitted: {tx_hash.hex()}")

        # Wait for receipt (with timeout)
        receipt = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120),
        )

        return {
            "transaction_hash": receipt["transactionHash"].hex(),
            "block_number": receipt["blockNumber"],
            "gas_used": receipt["gasUsed"],
            "gas_price_gwei": Decimal(str(self.w3.from_wei(gas_price, "gwei"))),
            "status": "confirmed" if receipt["status"] == 1 else "failed",
        }

    def verify_batch_anchored(self, merkle_root: str) -> Optional[dict[str, Any]]:
        """
        Verify that a batch has been anchored on-chain.

        Args:
            merkle_root: Hex-encoded Merkle root to verify.

        Returns:
            Batch details if anchored, None otherwise.
        """
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
    """Database operations for the anchor worker."""

    def __init__(self, pool: asyncpg.Pool):
        self._pool = pool

    @classmethod
    async def create(cls, dsn: str) -> "DatabaseService":
        """Create database service with connection pool."""
        pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10)
        if pool is None:
            raise RuntimeError("Failed to create database pool")
        return cls(pool)

    async def close(self):
        """Close connection pool."""
        await self._pool.close()

    async def get_unanchored_logs(self, limit: int = 1000) -> list[dict[str, Any]]:
        """Get audit logs that haven't been anchored yet."""
        query = """
            SELECT id, action_hash, timestamp
            FROM audit_logs
            WHERE merkle_root_id IS NULL
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
        """Create a merkle proof record."""
        query = """
            INSERT INTO merkle_proofs (
                root_hash, leaf_hashes, start_timestamp, end_timestamp,
                contract_address, chain_id, log_count, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
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
    ):
        """Update merkle proof record after blockchain submission."""
        query = """
            UPDATE merkle_proofs
            SET
                status = $2,
                transaction_hash = COALESCE($3, transaction_hash),
                block_number = COALESCE($4, block_number),
                gas_used = COALESCE($5, gas_used),
                gas_price_gwei = COALESCE($6, gas_price_gwei),
                error_message = COALESCE($7, error_message),
                confirmed_at = CASE WHEN $2 = 'confirmed' THEN NOW() ELSE confirmed_at END,
                retry_count = CASE WHEN $2 = 'failed' THEN retry_count + 1 ELSE retry_count END
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
            )

    async def mark_logs_as_anchored(
        self,
        log_ids: list[UUID],
        merkle_root_id: UUID,
    ):
        """Mark audit logs as anchored to a merkle root."""
        # Note: We need to work around the UPDATE trigger on audit_logs
        # In production, this should update only the merkle fields
        # which should be allowed by a modified trigger

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
        """Get merkle proofs pending submission."""
        query = """
            SELECT id, root_hash, leaf_hashes, retry_count,
                   start_timestamp, end_timestamp
            FROM merkle_proofs
            WHERE status IN ('pending', 'failed')
              AND retry_count < $1
            ORDER BY created_at ASC
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, MAX_RETRIES)
        return [dict(row) for row in rows]


# =============================================================================
# ANCHOR WORKER
# =============================================================================

class AnchorWorker:
    """
    Background worker for anchoring audit logs to the blockchain.

    Runs on a configurable interval and processes unanchored logs
    into Merkle trees, submitting roots to the AnchorRegistry contract.
    """

    def __init__(
        self,
        db_service: DatabaseService,
        blockchain_service: BlockchainService,
        batch_size: int = BATCH_SIZE,
        interval_seconds: int = BATCH_INTERVAL_SECONDS,
    ):
        """
        Initialize anchor worker.

        Args:
            db_service: Database service instance.
            blockchain_service: Blockchain service instance.
            batch_size: Maximum number of logs per batch.
            interval_seconds: Interval between batch runs.
        """
        self.db = db_service
        self.blockchain = blockchain_service
        self.batch_size = batch_size
        self.interval_seconds = interval_seconds
        self._running = False
        self._shutdown_event = asyncio.Event()

    async def start(self):
        """Start the worker loop."""
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

            # Wait for interval or shutdown
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.interval_seconds,
                )
                # If we get here, shutdown was requested
                break
            except asyncio.TimeoutError:
                # Normal timeout, continue loop
                pass

        logger.info("Anchor worker stopped")

    async def stop(self):
        """Stop the worker gracefully."""
        logger.info("Stopping anchor worker...")
        self._running = False
        self._shutdown_event.set()

    async def _process_batch(self):
        """Process a batch of unanchored logs."""
        # First, retry any pending proofs
        await self._retry_pending_proofs()

        # Get unanchored logs
        logs = await self.db.get_unanchored_logs(self.batch_size)

        if not logs:
            logger.debug("No unanchored logs to process")
            return

        logger.info(f"Processing batch of {len(logs)} logs")

        # Extract hashes and compute Merkle root
        log_ids = [row["id"] for row in logs]
        leaf_hashes = [row["action_hash"] for row in logs]
        start_timestamp = logs[0]["timestamp"]
        end_timestamp = logs[-1]["timestamp"]

        merkle_root = compute_merkle_root(leaf_hashes)
        logger.info(f"Computed Merkle root: {merkle_root}")

        # Create proof record in database
        proof_id = await self.db.create_merkle_proof_record(
            root_hash=merkle_root,
            leaf_hashes=leaf_hashes,
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
            contract_address=self.blockchain.contract_address,
        )

        # Mark logs as associated with this proof
        await self.db.mark_logs_as_anchored(log_ids, proof_id)

        # Submit to blockchain
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
    ):
        """Submit a Merkle root to the blockchain."""
        try:
            # Check balance
            balance = self.blockchain.get_balance()
            if balance < Decimal("0.001"):
                logger.error(f"Insufficient balance: {balance} ETH")
                await self.db.update_merkle_proof_status(
                    proof_id,
                    status="failed",
                    error_message=f"Insufficient balance: {balance} ETH",
                )
                return

            # Submit transaction
            result = await self.blockchain.anchor_batch(
                merkle_root=merkle_root,
                log_count=log_count,
                start_timestamp=start_timestamp,
                end_timestamp=end_timestamp,
            )

            # Update database
            await self.db.update_merkle_proof_status(
                proof_id,
                status=result["status"],
                transaction_hash=result["transaction_hash"],
                block_number=result["block_number"],
                gas_used=result["gas_used"],
                gas_price_gwei=result["gas_price_gwei"],
            )

            logger.info(
                f"Batch anchored successfully! "
                f"TX: {result['transaction_hash']}, "
                f"Block: {result['block_number']}"
            )

        except Exception as e:
            logger.error(f"Blockchain submission failed: {e}")
            await self.db.update_merkle_proof_status(
                proof_id,
                status="failed",
                error_message=str(e),
            )

    async def _retry_pending_proofs(self):
        """Retry any pending or failed proof submissions."""
        pending = await self.db.get_pending_proofs()

        for proof in pending:
            logger.info(f"Retrying proof {proof['id']} (attempt {proof['retry_count'] + 1})")

            await self._submit_to_blockchain(
                proof_id=proof["id"],
                merkle_root=proof["root_hash"],
                log_count=len(proof["leaf_hashes"]),
                start_timestamp=proof["start_timestamp"],
                end_timestamp=proof["end_timestamp"],
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

    db_service = await DatabaseService.create(DATABASE_URL)
    logger.info("Database connection established")

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
