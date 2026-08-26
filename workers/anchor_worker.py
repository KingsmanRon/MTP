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

import argparse
import asyncio
import logging
import os
import re
import signal
import socket
import sys
import time
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Literal, TypeVar
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import asyncpg
from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.exceptions import TransactionNotFound

from workers.circuit_breaker import (
    RpcCircuitBreaker,
    RpcCircuitOpenError,
    is_transport_error,
)

_T = TypeVar("_T")

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
    "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/inntris"
).strip()

# Blockchain
BLOCKCHAIN_PROVIDER_URL = os.getenv("BLOCKCHAIN_PROVIDER_URL", "https://base-rpc.publicnode.com")
ANCHOR_CONTRACT_ADDRESS = os.getenv("ANCHOR_CONTRACT_ADDRESS")
BLOCKCHAIN_PRIVATE_KEY = os.getenv("BLOCKCHAIN_PRIVATE_KEY")  # With or without 0x prefix

# Worker settings
BATCH_SIZE = int(os.getenv("ANCHOR_BATCH_SIZE", "1000"))
# Support both ANCHOR_INTERVAL_MINUTES (new) and ANCHOR_BATCH_INTERVAL (old, seconds)
# Default is 10 minutes: the anchor block timestamp is the trustless upper
# bound on when each audit entry existed, so a shorter interval tightens the
# provable time bound on every receipt. Base gas cost at this cadence is
# negligible; raise the interval only if anchoring cost ever matters more
# than receipt latency.
BATCH_INTERVAL_MINUTES = int(os.getenv("ANCHOR_INTERVAL_MINUTES", "10"))
BATCH_INTERVAL_SECONDS = int(os.getenv("ANCHOR_BATCH_INTERVAL", str(BATCH_INTERVAL_MINUTES * 60)))
MAX_RETRIES = int(os.getenv("ANCHOR_MAX_RETRIES", "5"))
# Exponential backoff between failed retries. retry N waits
# RETRY_BACKOFF_BASE_SECONDS * 2^(N-1), capped at RETRY_BACKOFF_MAX_SECONDS.
RETRY_BACKOFF_BASE_SECONDS = int(os.getenv("ANCHOR_RETRY_BACKOFF_BASE", "60"))
RETRY_BACKOFF_MAX_SECONDS = int(os.getenv("ANCHOR_RETRY_BACKOFF_MAX", str(60 * 60)))
REPLACEMENT_MIN_AGE_SECONDS = int(os.getenv("ANCHOR_REPLACEMENT_MIN_AGE", str(10 * 60)))
if REPLACEMENT_MIN_AGE_SECONDS < 0:
    raise ValueError("ANCHOR_REPLACEMENT_MIN_AGE must be non-negative")
METRICS_ENABLED = os.getenv("ANCHOR_METRICS_ENABLED", "true").lower() not in (
    "0",
    "false",
    "no",
)


def resolve_worker_metrics_port(environment: Mapping[str, str] = os.environ) -> int:
    """Return the dedicated worker metrics port.

    ``PORT`` belongs to the API/web process on several hosting platforms. The
    anchor worker is a separate process and must not silently bind the API
    listener's port when both services share an environment.
    """
    port = int(environment.get("ANCHOR_METRICS_PORT", "9100"))
    if not 1 <= port <= 65535:
        raise ValueError("ANCHOR_METRICS_PORT must be between 1 and 65535")
    return port


METRICS_PORT = resolve_worker_metrics_port()
METRICS_ADDRESS = os.getenv("ANCHOR_METRICS_ADDRESS", "0.0.0.0")
HEARTBEAT_INTERVAL_SECONDS = float(os.getenv("ANCHOR_HEARTBEAT_INTERVAL_SECONDS", "30"))
if HEARTBEAT_INTERVAL_SECONDS <= 0:
    raise ValueError("ANCHOR_HEARTBEAT_INTERVAL_SECONDS must be greater than zero")

# A session advisory lock serialises all anchor processing for this database.
# The value is deliberately stable across releases and fits PostgreSQL bigint.
ANCHOR_WORKER_LOCK_ID = int(os.getenv("ANCHOR_WORKER_LOCK_ID", "5282246097192575745"))
if not -(2**63) <= ANCHOR_WORKER_LOCK_ID < 2**63:
    raise ValueError("ANCHOR_WORKER_LOCK_ID must fit a signed PostgreSQL bigint")


def normalize_transaction_hash(value: Any) -> str:
    """Return an Ethereum transaction hash in database wire format."""
    tx_hash = value.hex() if hasattr(value, "hex") else str(value)
    if not tx_hash.startswith("0x"):
        tx_hash = f"0x{tx_hash}"
    if len(tx_hash) != 66:
        raise ValueError(f"Invalid transaction hash length: expected 66 chars, got {len(tx_hash)}")
    return tx_hash


class DeterministicContractRevert(RuntimeError):
    """A contract execution failure that must never trigger a fallback send."""


class RootAlreadyAnchoredError(DeterministicContractRevert):
    """The registry already contains the exact Merkle root being prepared."""


class AnchorEvidenceError(RuntimeError):
    """Chain evidence exists but does not match the proof being reconciled."""


@dataclass(frozen=True)
class PreparedAnchorTransaction:
    """Signed transaction identity persisted before any network broadcast."""

    transaction_hash: str
    nonce: int
    gas_price_gwei: Decimal
    raw_transaction: bytes = field(repr=False)


@dataclass(frozen=True)
class AnchorConfirmation:
    """Validated receipt, event, and registry state for one Merkle root."""

    transaction_hash: str
    block_number: int
    gas_used: int
    gas_price_gwei: Decimal | None
    anchored_at: datetime
    batch_id: int
    submitter: str
    source: Literal["transaction_receipt", "contract_state"]


@dataclass(frozen=True)
class ReconciliationResult:
    """Result of checking an existing transaction and the registry state."""

    confirmation: AnchorConfirmation | None
    transaction_state: Literal["none", "not_found", "reverted"]


@dataclass(frozen=True)
class EstimationFailure:
    """Semantic classification of an estimateGas exception."""

    category: Literal[
        "root_already_anchored",
        "deterministic_revert",
        "transient_rpc",
        "rpc_error",
    ]
    reason: str
    revert_data: str | None = None


_HEX_DATA_RE = re.compile(r"0x[0-9a-fA-F]{8,}")
_DETERMINISTIC_REVERT_SIGNATURES = {
    "RootAlreadyAnchored(bytes32)": "RootAlreadyAnchored",
    "InvalidMerkleRoot()": "InvalidMerkleRoot",
    "InvalidLogCount(uint256)": "InvalidLogCount",
    "InvalidTimestamps(uint256,uint256)": "InvalidTimestamps",
    "AccessControlUnauthorizedAccount(address,bytes32)": "AccessControlUnauthorizedAccount",
    "EnforcedPause()": "EnforcedPause",
}
_DETERMINISTIC_REVERT_SELECTORS = {
    Web3.keccak(text=signature)[:4].hex().removeprefix("0x").lower(): name
    for signature, name in _DETERMINISTIC_REVERT_SIGNATURES.items()
}
_ROOT_ALREADY_ANCHORED_SELECTOR = (
    Web3.keccak(text="RootAlreadyAnchored(bytes32)")[:4].hex().removeprefix("0x").lower()
)
_BATCH_ANCHORED_TOPIC = (
    Web3.keccak(text="BatchAnchored(uint256,bytes32,uint256,address)")
    .hex()
    .removeprefix("0x")
    .lower()
)


def _extract_revert_data(value: Any) -> str | None:
    """Find the longest EVM revert-data blob embedded in an exception."""

    candidates: list[str] = []
    visited: set[int] = set()

    def visit(item: Any) -> None:
        item_id = id(item)
        if item_id in visited:
            return
        visited.add(item_id)
        if isinstance(item, bytes):
            candidates.append("0x" + item.hex())
        elif isinstance(item, str):
            candidates.extend(_HEX_DATA_RE.findall(item))
        elif isinstance(item, Mapping):
            for nested in item.values():
                visit(nested)
        elif isinstance(item, (list, tuple, set)):
            for nested in item:
                visit(nested)
        elif isinstance(item, BaseException):
            visit(item.args)
            visit(getattr(item, "data", None))

    visit(value)
    if not candidates:
        return None
    return max(candidates, key=len).lower()


def _http_status_from_exception(exc: BaseException) -> int | None:
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, int):
        return status
    match = re.search(r"\bHTTP\s+(\d{3})\b", str(exc), flags=re.IGNORECASE)
    return int(match.group(1)) if match else None


def _is_transient_rpc_error(exc: BaseException) -> bool:
    if is_transport_error(exc) or isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    status = _http_status_from_exception(exc)
    if status == 429 or (status is not None and status >= 500):
        return True
    message = str(exc).lower()
    transient_fragments = (
        "timed out",
        "timeout",
        "connection reset",
        "connection aborted",
        "temporarily unavailable",
        "too many requests",
        "rate limit",
    )
    return any(fragment in message for fragment in transient_fragments)


def classify_estimation_failure(
    exc: BaseException,
    expected_root: str,
) -> EstimationFailure:
    """Separate execution reverts from transport failures.

    Only transient transport and rate-limit failures may use the controlled
    gas fallback. Any execution-level revert is terminal for this send.
    """

    revert_data = _extract_revert_data(exc)
    selector = revert_data.removeprefix("0x")[:8].lower() if revert_data is not None else None
    if selector == _ROOT_ALREADY_ANCHORED_SELECTOR:
        encoded_root = revert_data.removeprefix("0x")[8:72] if revert_data else ""
        expected = expected_root.removeprefix("0x").lower()
        if encoded_root and encoded_root != expected:
            return EstimationFailure(
                category="deterministic_revert",
                reason=(
                    "RootAlreadyAnchored revert referenced a different root; " "refusing to submit"
                ),
                revert_data=revert_data,
            )
        return EstimationFailure(
            category="root_already_anchored",
            reason="RootAlreadyAnchored",
            revert_data=revert_data,
        )
    if selector in _DETERMINISTIC_REVERT_SELECTORS:
        return EstimationFailure(
            category="deterministic_revert",
            reason=_DETERMINISTIC_REVERT_SELECTORS[selector],
            revert_data=revert_data,
        )
    message = str(exc).lower()
    if "rootalreadyanchored" in message:
        return EstimationFailure(
            category="root_already_anchored",
            reason="RootAlreadyAnchored",
            revert_data=revert_data,
        )
    decoded_error_names = {
        name.lower(): name for name in _DETERMINISTIC_REVERT_SELECTORS.values()
    }
    for decoded_name, display_name in decoded_error_names.items():
        if decoded_name in message:
            return EstimationFailure(
                category="deterministic_revert",
                reason=display_name,
                revert_data=revert_data,
            )
    if "execution reverted" in message or "revert" in message:
        return EstimationFailure(
            category="deterministic_revert",
            reason="Unclassified execution revert",
            revert_data=revert_data,
        )
    if _is_transient_rpc_error(exc):
        return EstimationFailure(
            category="transient_rpc",
            reason=type(exc).__name__,
            revert_data=revert_data,
        )
    return EstimationFailure(
        category="rpc_error",
        reason=f"{type(exc).__name__}: {exc}",
        revert_data=revert_data,
    )


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
    delay = base_seconds * (2**exponent)
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
FALLBACK_GAS_LIMIT = int(os.getenv("ANCHOR_FALLBACK_GAS_LIMIT", "500000"))
if not 21_000 <= FALLBACK_GAS_LIMIT <= 2_000_000:
    raise ValueError("ANCHOR_FALLBACK_GAS_LIMIT must be between 21000 and 2000000")

# Phase resilience — RPC circuit breaker config. See
# docs/superpowers/specs/2026-04-21-blockchain-rpc-circuit-breaker-design.md
RPC_BREAKER_ENABLED = os.getenv("ANCHOR_RPC_BREAKER_ENABLED", "true").lower() not in (
    "0",
    "false",
    "no",
)
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
        "inputs": [{"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"}],
        "name": "getBatchFull",
        "outputs": [
            {
                "components": [
                    {"internalType": "uint256", "name": "batchId", "type": "uint256"},
                    {"internalType": "uint256", "name": "logCount", "type": "uint256"},
                    {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
                    {"internalType": "uint256", "name": "blockNumber", "type": "uint256"},
                    {"internalType": "uint256", "name": "startTimestamp", "type": "uint256"},
                    {"internalType": "uint256", "name": "endTimestamp", "type": "uint256"},
                    {"internalType": "address", "name": "submitter", "type": "address"},
                ],
                "internalType": "struct AnchorRegistry.Batch",
                "name": "batch",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"}],
        "name": "isAnchored",
        "outputs": [{"internalType": "bool", "name": "anchored", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "batchId", "type": "uint256"},
            {"indexed": True, "internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"},
            {"indexed": False, "internalType": "uint256", "name": "logCount", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "submitter", "type": "address"},
        ],
        "name": "BatchAnchored",
        "type": "event",
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"}
        ],
        "name": "RootAlreadyAnchored",
        "type": "error",
    },
    {"inputs": [], "name": "InvalidMerkleRoot", "type": "error"},
    {
        "inputs": [
            {"internalType": "uint256", "name": "logCount", "type": "uint256"}
        ],
        "name": "InvalidLogCount",
        "type": "error",
    },
    {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "startTimestamp",
                "type": "uint256",
            },
            {
                "internalType": "uint256",
                "name": "endTimestamp",
                "type": "uint256",
            },
        ],
        "name": "InvalidTimestamps",
        "type": "error",
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
        proof.append(
            {
                # FIX 2: Strip '0x' prefix
                "hash": nodes[sibling_index].hex().replace("0x", ""),
                "position": 1 if index % 2 == 0 else 0,
            }
        )

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

    def _rpc(self, fn: Callable[[], _T]) -> _T:
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
        # Swallows RpcCircuitOpenError by design — this is a health-check
        # helper, and an OPEN breaker is correctly reported as "not
        # connected" for readiness probes. Submit paths call _rpc(...)
        # directly and will see the breaker error.
        try:
            return self._rpc(lambda: self.w3.is_connected())
        except Exception:
            return False

    def get_balance(self) -> Decimal:
        balance_wei = self._rpc(lambda: self.w3.eth.get_balance(self.account.address))
        return Decimal(str(self.w3.from_wei(balance_wei, "ether")))

    @staticmethod
    def _root_bytes(merkle_root: str) -> bytes:
        clean_root = merkle_root.removeprefix("0x")
        if len(clean_root) != 64:
            raise ValueError("Merkle root must be exactly 32 bytes")
        return bytes.fromhex(clean_root)

    def prepare_anchor_transaction(
        self,
        merkle_root: str,
        log_count: int,
        start_timestamp: datetime,
        end_timestamp: datetime,
        *,
        nonce: int | None = None,
    ) -> PreparedAnchorTransaction:
        """Sign a transaction without broadcasting it.

        The returned hash and nonce must be committed to Postgres before
        ``broadcast`` is called. A replacement uses the persisted nonce.
        """

        self.assert_chain_id()
        root_bytes = self._root_bytes(merkle_root)
        start_unix = int(start_timestamp.timestamp())
        end_unix = int(end_timestamp.timestamp())
        if nonce is None:
            nonce = self._rpc(
                lambda: self.w3.eth.get_transaction_count(
                    self.account.address,
                    "pending",
                )
            )
        if nonce < 0:
            raise ValueError("Transaction nonce cannot be negative")

        anchor_call = self.contract.functions.anchorBatch(
            root_bytes,
            log_count,
            start_unix,
            end_unix,
        )
        try:
            gas_estimate = self._rpc(
                lambda: anchor_call.estimate_gas({"from": self.account.address})
            )
        except Exception as exc:
            if isinstance(exc, RpcCircuitOpenError):
                raise
            failure = classify_estimation_failure(exc, merkle_root)
            if failure.category == "root_already_anchored":
                raise RootAlreadyAnchoredError(
                    "RootAlreadyAnchored during gas estimation; reconciliation required"
                ) from exc
            if failure.category == "deterministic_revert":
                raise DeterministicContractRevert(
                    f"estimateGas execution revert: {failure.reason}"
                ) from exc
            if failure.category == "rpc_error":
                raise RuntimeError(
                    f"estimateGas provider failure; refusing fallback send: {failure.reason}"
                ) from exc
            logger.warning(
                "anchor_estimate_transient_fallback root=%s stage=estimate error=%s",
                merkle_root,
                failure.reason,
            )
            gas_limit = FALLBACK_GAS_LIMIT
        else:
            gas_limit = int(gas_estimate * 1.2)

        gas_price = self._rpc(lambda: self.w3.eth.gas_price)
        gas_price_gwei = Decimal(str(self.w3.from_wei(gas_price, "gwei")))
        if gas_price_gwei > MAX_GAS_PRICE_GWEI:
            raise RuntimeError(
                f"Gas price {gas_price_gwei} gwei exceeds cap "
                f"{MAX_GAS_PRICE_GWEI} gwei. Refusing to submit."
            )

        tx = anchor_call.build_transaction(
            {
                "from": self.account.address,
                "nonce": nonce,
                "gas": gas_limit,
                "gasPrice": gas_price,
                "chainId": self.expected_chain_id,
            }
        )
        signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)
        raw_tx = getattr(signed_tx, "raw_transaction", None)
        if raw_tx is None:
            raw_tx = signed_tx.rawTransaction
        raw_bytes = bytes(raw_tx)
        transaction_hash = normalize_transaction_hash(Web3.keccak(raw_bytes))
        return PreparedAnchorTransaction(
            transaction_hash=transaction_hash,
            nonce=int(nonce),
            gas_price_gwei=gas_price_gwei,
            raw_transaction=raw_bytes,
        )

    def broadcast(self, prepared: PreparedAnchorTransaction) -> str:
        """Broadcast a previously persisted transaction identity."""

        sent_hash = normalize_transaction_hash(
            self._rpc(lambda: self.w3.eth.send_raw_transaction(prepared.raw_transaction))
        )
        if sent_hash.lower() != prepared.transaction_hash.lower():
            raise AnchorEvidenceError(
                "RPC returned a transaction hash different from the signed transaction"
            )
        return sent_hash

    @staticmethod
    def _normalise_topic(value: Any) -> str:
        text = value.hex() if hasattr(value, "hex") else str(value)
        return text.removeprefix("0x").lower()

    def _validated_event(
        self,
        receipt: Mapping[str, Any],
        merkle_root: str,
        log_count: int,
    ) -> tuple[int, str]:
        expected_root = merkle_root.removeprefix("0x").lower()
        matches: list[tuple[int, str]] = []
        for event_log in receipt.get("logs", []):
            address = str(event_log.get("address", ""))
            topics = event_log.get("topics", [])
            if address.lower() != self.contract_address.lower() or len(topics) < 4:
                continue
            normalised = [self._normalise_topic(topic) for topic in topics]
            if normalised[0] != _BATCH_ANCHORED_TOPIC or normalised[2] != expected_root:
                continue
            event_log_count = int(self._normalise_topic(event_log.get("data", "0x0")), 16)
            if event_log_count != log_count:
                raise AnchorEvidenceError(
                    f"BatchAnchored log_count mismatch: expected {log_count}, "
                    f"got {event_log_count}"
                )
            batch_id = int(normalised[1], 16)
            submitter = Web3.to_checksum_address("0x" + normalised[3][-40:])
            matches.append((batch_id, submitter))
        if len(matches) != 1:
            raise AnchorEvidenceError(
                "Confirmed receipt did not contain exactly one matching "
                f"BatchAnchored event; found {len(matches)}"
            )
        return matches[0]

    def _validated_batch(
        self,
        merkle_root: str,
        log_count: int,
        start_timestamp: datetime,
        end_timestamp: datetime,
    ) -> dict[str, Any] | None:
        root_bytes = self._root_bytes(merkle_root)
        anchored = self._rpc(lambda: self.contract.functions.isAnchored(root_bytes).call())
        if not anchored:
            return None
        result = self._rpc(lambda: self.contract.functions.getBatchFull(root_bytes).call())
        (
            batch_id,
            stored_log_count,
            timestamp,
            block_number,
            stored_start,
            stored_end,
            submitter,
        ) = result
        expected_start = int(start_timestamp.timestamp())
        expected_end = int(end_timestamp.timestamp())
        if int(stored_log_count) != log_count:
            raise AnchorEvidenceError(
                f"Registry log_count mismatch: expected {log_count}, got {stored_log_count}"
            )
        if int(stored_start) != expected_start or int(stored_end) != expected_end:
            raise AnchorEvidenceError(
                "Registry timestamp window does not match the persisted proof"
            )
        return {
            "batch_id": int(batch_id),
            "log_count": int(stored_log_count),
            "timestamp": datetime.fromtimestamp(int(timestamp), tz=UTC),
            "block_number": int(block_number),
            "start_timestamp": int(stored_start),
            "end_timestamp": int(stored_end),
            "submitter": Web3.to_checksum_address(submitter),
        }

    def _confirmation_from_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        merkle_root: str,
        log_count: int,
        start_timestamp: datetime,
        end_timestamp: datetime,
        source: Literal["transaction_receipt", "contract_state"],
    ) -> AnchorConfirmation:
        if int(receipt.get("status", 0)) != 1:
            raise AnchorEvidenceError("A reverted receipt cannot confirm an anchor")
        receipt_to = str(receipt.get("to", ""))
        if receipt_to.lower() != self.contract_address.lower():
            raise AnchorEvidenceError(
                f"Receipt target mismatch: expected {self.contract_address}, got {receipt_to}"
            )
        transaction_hash = normalize_transaction_hash(receipt["transactionHash"])
        batch_id, event_submitter = self._validated_event(
            receipt,
            merkle_root,
            log_count,
        )
        batch = self._validated_batch(
            merkle_root,
            log_count,
            start_timestamp,
            end_timestamp,
        )
        if batch is None:
            raise AnchorEvidenceError(
                "Receipt succeeded but registry does not report the root anchored"
            )
        if batch["batch_id"] != batch_id:
            raise AnchorEvidenceError("Receipt event batch ID does not match registry state")
        if batch["block_number"] != int(receipt["blockNumber"]):
            raise AnchorEvidenceError("Receipt block number does not match registry batch state")
        if batch["submitter"].lower() != event_submitter.lower():
            raise AnchorEvidenceError("Receipt submitter does not match registry state")
        effective_gas_price = receipt.get("effectiveGasPrice")
        gas_price_gwei = (
            Decimal(str(self.w3.from_wei(effective_gas_price, "gwei")))
            if effective_gas_price is not None
            else None
        )
        return AnchorConfirmation(
            transaction_hash=transaction_hash,
            block_number=int(receipt["blockNumber"]),
            gas_used=int(receipt["gasUsed"]),
            gas_price_gwei=gas_price_gwei,
            anchored_at=batch["timestamp"],
            batch_id=batch_id,
            submitter=event_submitter,
            source=source,
        )

    def _confirmation_from_contract_state(
        self,
        *,
        merkle_root: str,
        log_count: int,
        start_timestamp: datetime,
        end_timestamp: datetime,
    ) -> AnchorConfirmation | None:
        batch = self._validated_batch(
            merkle_root,
            log_count,
            start_timestamp,
            end_timestamp,
        )
        if batch is None:
            return None
        root_topic = "0x" + merkle_root.removeprefix("0x").lower()
        event_logs = self._rpc(
            lambda: self.w3.eth.get_logs(
                {
                    "fromBlock": batch["block_number"],
                    "toBlock": batch["block_number"],
                    "address": self.contract_address,
                    "topics": ["0x" + _BATCH_ANCHORED_TOPIC, None, root_topic],
                }
            )
        )
        if len(event_logs) != 1:
            raise AnchorEvidenceError(
                "Registry reports the root anchored but its block does not contain "
                f"exactly one matching event; found {len(event_logs)}"
            )
        transaction_hash = normalize_transaction_hash(event_logs[0]["transactionHash"])
        receipt = self._rpc(lambda: self.w3.eth.get_transaction_receipt(transaction_hash))
        return self._confirmation_from_receipt(
            receipt,
            merkle_root=merkle_root,
            log_count=log_count,
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
            source="contract_state",
        )

    def reconcile_anchor(
        self,
        *,
        merkle_root: str,
        log_count: int,
        start_timestamp: datetime,
        end_timestamp: datetime,
        transaction_hash: str | None,
    ) -> ReconciliationResult:
        """Check receipt then registry state before any new broadcast."""

        self.assert_chain_id()
        transaction_state: Literal["none", "not_found", "reverted"] = "none"
        if transaction_hash:
            try:
                receipt = self._rpc(lambda: self.w3.eth.get_transaction_receipt(transaction_hash))
            except TransactionNotFound:
                transaction_state = "not_found"
            else:
                if int(receipt.get("status", 0)) == 1:
                    return ReconciliationResult(
                        confirmation=self._confirmation_from_receipt(
                            receipt,
                            merkle_root=merkle_root,
                            log_count=log_count,
                            start_timestamp=start_timestamp,
                            end_timestamp=end_timestamp,
                            source="transaction_receipt",
                        ),
                        transaction_state="none",
                    )
                transaction_state = "reverted"

        confirmation = self._confirmation_from_contract_state(
            merkle_root=merkle_root,
            log_count=log_count,
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
        )
        return ReconciliationResult(
            confirmation=confirmation,
            transaction_state=transaction_state,
        )

    async def wait_for_confirmation(
        self,
        prepared: PreparedAnchorTransaction,
        *,
        merkle_root: str,
        log_count: int,
        start_timestamp: datetime,
        end_timestamp: datetime,
    ) -> ReconciliationResult:
        receipt = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._rpc(
                lambda: self.w3.eth.wait_for_transaction_receipt(
                    prepared.transaction_hash,
                    timeout=120,
                )
            ),
        )
        if int(receipt.get("status", 0)) == 1:
            return ReconciliationResult(
                confirmation=self._confirmation_from_receipt(
                    receipt,
                    merkle_root=merkle_root,
                    log_count=log_count,
                    start_timestamp=start_timestamp,
                    end_timestamp=end_timestamp,
                    source="transaction_receipt",
                ),
                transaction_state="none",
            )
        return self.reconcile_anchor(
            merkle_root=merkle_root,
            log_count=log_count,
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
            transaction_hash=prepared.transaction_hash,
        )

    def verify_batch_anchored(self, merkle_root: str) -> dict[str, Any] | None:
        """Compatibility read helper used by operator diagnostics."""

        root_bytes = self._root_bytes(merkle_root)
        result = self._rpc(lambda: self.contract.functions.getBatch(root_bytes).call())
        batch_id, log_count, timestamp, submitter = result
        if batch_id == 0:
            return None
        return {
            "batch_id": int(batch_id),
            "log_count": int(log_count),
            "timestamp": datetime.fromtimestamp(int(timestamp), tz=UTC),
            "submitter": submitter,
        }


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

    async def close(self) -> None:
        await self._pool.close()

    @asynccontextmanager
    async def anchor_cycle_lock(self) -> AsyncIterator[bool]:
        """Try to hold the database wide anchor lock for one complete cycle.

        A transaction scoped advisory lock remains safe when the deployment
        uses a transaction pooling proxy such as PgBouncer. Keep the
        transaction and its exact pooled connection open until processing
        finishes. PostgreSQL releases the lock on commit, rollback, connection
        loss, or process death, allowing another worker to take over safely.
        """
        connection = await self._pool.acquire()
        transaction = connection.transaction()
        transaction_started = False
        connection_terminated = False
        try:
            await transaction.start()
            transaction_started = True
            try:
                # The lock transaction intentionally spans RPC work. Prevent a
                # database default idle timeout from silently releasing the
                # lock while an on chain receipt is still pending.
                await connection.execute("SET LOCAL idle_in_transaction_session_timeout = 0")
                acquired = bool(
                    await connection.fetchval(
                        "SELECT pg_try_advisory_xact_lock($1::bigint)",
                        ANCHOR_WORKER_LOCK_ID,
                    )
                )
                yield acquired
            except BaseException:
                try:
                    await transaction.rollback()
                except Exception:
                    connection.terminate()
                    connection_terminated = True
                    logger.exception("Failed to roll back anchor worker lock transaction")
                raise
            else:
                try:
                    await transaction.commit()
                except Exception:
                    connection.terminate()
                    connection_terminated = True
                    logger.exception("Failed to commit anchor worker lock transaction")
                    raise
        finally:
            # A failed transaction start has no lock, but the connection still
            # belongs to the pool and must be returned. Failed commit/rollback
            # paths terminate it so a possibly lock holding session is never
            # reused.
            if transaction_started and connection_terminated:
                logger.warning("Discarded anchor worker lock connection")
            if not connection_terminated:
                await self._pool.release(connection)

    async def get_proof_failure_counts(self) -> dict[str, int]:
        """Return persistent failed and dead letter proof counts for alerts."""
        query = """
            SELECT
                count(*) FILTER (WHERE status = 'failed') AS failed,
                count(*) FILTER (WHERE status = 'dead_letter') AS dead_letter
            FROM merkle_proofs
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(query)
        return {
            "failed": int(row["failed"] or 0),
            "dead_letter": int(row["dead_letter"] or 0),
        }

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
        transaction_hash: str | None = None,
        block_number: int | None = None,
        gas_used: int | None = None,
        gas_price_gwei: Decimal | None = None,
        error_message: str | None = None,
        next_retry_at: datetime | None = None,
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

    async def record_submission_prepared(
        self,
        proof_id: UUID,
        prepared: PreparedAnchorTransaction,
    ) -> None:
        query = """
            UPDATE merkle_proofs
            SET status = 'prepared',
                transaction_hash = $2,
                submission_nonce = $3,
                gas_price_gwei = $4,
                prepared_at = NOW(),
                submitted_at = NULL,
                next_retry_at = NULL,
                error_message = NULL
            WHERE id = $1
              AND status <> 'confirmed'
        """
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                query,
                proof_id,
                prepared.transaction_hash,
                prepared.nonce,
                prepared.gas_price_gwei,
            )
        if result != "UPDATE 1":
            raise RuntimeError(f"Proof {proof_id} could not enter prepared state")

    async def mark_submission_broadcast(
        self,
        proof_id: UUID,
        transaction_hash: str,
        *,
        error_message: str | None = None,
    ) -> None:
        query = """
            UPDATE merkle_proofs
            SET status = 'submitted',
                submitted_at = COALESCE(submitted_at, NOW()),
                error_message = $3
            WHERE id = $1
              AND transaction_hash = $2
              AND status IN ('prepared', 'submitted')
        """
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                query,
                proof_id,
                transaction_hash,
                error_message,
            )
        if result != "UPDATE 1":
            raise RuntimeError(f"Proof {proof_id} lost its prepared transaction identity")

    async def record_reconciliation_attempt(self, proof_id: UUID) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE merkle_proofs
                SET last_reconciliation_at = NOW()
                WHERE id = $1
                """,
                proof_id,
            )

    async def schedule_retry(
        self,
        proof_id: UUID,
        *,
        status: Literal["failed", "prepared", "submitted"],
        error_message: str,
        next_retry_at: datetime,
    ) -> None:
        query = """
            UPDATE merkle_proofs
            SET status = $2,
                error_message = $3,
                next_retry_at = $4,
                retry_count = retry_count + 1
            WHERE id = $1
              AND status <> 'confirmed'
        """
        async with self._pool.acquire() as conn:
            await conn.execute(
                query,
                proof_id,
                status,
                error_message,
                next_retry_at,
            )

    async def mark_proof_dead_letter(
        self,
        proof_id: UUID,
        *,
        error_message: str,
        increment_retry: bool = True,
    ) -> None:
        query = """
            UPDATE merkle_proofs
            SET status = 'dead_letter',
                error_message = $2,
                next_retry_at = NULL,
                dead_lettered_at = COALESCE(dead_lettered_at, NOW()),
                retry_count = retry_count + CASE WHEN $3::boolean THEN 1 ELSE 0 END
            WHERE id = $1
              AND status <> 'confirmed'
        """
        async with self._pool.acquire() as conn:
            await conn.execute(query, proof_id, error_message, increment_retry)

    async def mark_proof_confirmed(
        self,
        proof_id: UUID,
        confirmation: AnchorConfirmation,
        *,
        reconciled: bool,
    ) -> None:
        query = """
            UPDATE merkle_proofs
            SET status = 'confirmed',
                transaction_hash = $2,
                block_number = $3,
                gas_used = $4,
                gas_price_gwei = COALESCE($5, gas_price_gwei),
                confirmed_at = $6,
                next_retry_at = NULL,
                reconciled_at = CASE WHEN $7 THEN NOW() ELSE reconciled_at END,
                reconciliation_source = $8,
                error_message = CASE
                    WHEN dead_lettered_at IS NOT NULL THEN error_message
                    ELSE NULL
                END
            WHERE id = $1
        """
        async with self._pool.acquire() as conn:
            await conn.execute(
                query,
                proof_id,
                confirmation.transaction_hash,
                confirmation.block_number,
                confirmation.gas_used,
                confirmation.gas_price_gwei,
                confirmation.anchored_at,
                reconciled,
                confirmation.source,
            )

    async def assign_logs_to_proof(
        self,
        log_ids: list[UUID],
        merkle_root_id: UUID,
    ) -> None:
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

        logger.info(
            "anchor_batch_assigned proof_id=%s log_count=%s",
            merkle_root_id,
            len(log_ids),
        )

    async def mark_logs_as_anchored(
        self,
        log_ids: list[UUID],
        merkle_root_id: UUID,
    ) -> None:
        """Backward-compatible alias; assignment does not mean confirmation."""

        await self.assign_logs_to_proof(log_ids, merkle_root_id)

    async def get_retryable_proofs(self) -> list[dict[str, Any]]:
        query = """
            SELECT id, root_hash, leaf_hashes, log_count, retry_count,
                   start_timestamp, end_timestamp, status,
                   transaction_hash, submission_nonce, prepared_at,
                   submitted_at, contract_address, chain_id
            FROM merkle_proofs
            WHERE status IN ('pending', 'prepared', 'submitted', 'failed')
              AND (
                    status IN ('prepared', 'submitted')
                    OR retry_count < $1
              )
              AND (next_retry_at IS NULL OR next_retry_at <= NOW())
            ORDER BY created_at ASC
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, MAX_RETRIES)
        return [dict(row) for row in rows]

    async def get_pending_proofs(self) -> list[dict[str, Any]]:
        """Backward-compatible name for the state-aware retry query."""

        return await self.get_retryable_proofs()

    async def get_proof_by_id(self, proof_id: UUID) -> dict[str, Any] | None:
        query = """
            SELECT id, root_hash, leaf_hashes, log_count, retry_count,
                   start_timestamp, end_timestamp, status,
                   transaction_hash, submission_nonce, prepared_at,
                   submitted_at, contract_address, chain_id,
                   dead_lettered_at, error_message
            FROM merkle_proofs
            WHERE id = $1
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(query, proof_id)
        return dict(row) if row else None


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
    ) -> None:
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

        heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(),
            name="anchor-worker-heartbeat",
        )
        try:
            while self._running:
                try:
                    await self._run_processing_cycle()
                except Exception as e:
                    self._record_cycle_error()
                    logger.exception(f"Error in batch processing: {e}")

                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=self.interval_seconds,
                    )
                    break
                except TimeoutError:
                    pass
        finally:
            heartbeat_task.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat_task

        logger.info("Anchor worker stopped")

    async def stop(self):
        logger.info("Stopping anchor worker...")
        self._running = False
        self._shutdown_event.set()

    async def _heartbeat_loop(self) -> None:
        """Publish process liveness independently of processing outcomes."""
        while self._running:
            self._record_liveness_heartbeat(time.time())
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=HEARTBEAT_INTERVAL_SECONDS,
                )
                return
            except TimeoutError:
                pass

    async def _run_processing_cycle(self) -> bool:
        """Run at most one globally serialised cycle.

        Returns ``False`` when another worker owns the advisory lock. Lock
        contention is not a successful cycle and therefore never advances the
        last success gauge.
        """
        async with self.db.anchor_cycle_lock() as acquired:
            if not acquired:
                self._record_cycle_contention()
                logger.warning(
                    "Anchor processing skipped because another worker owns the advisory lock"
                )
                return False

            await self._process_batch()
            self._record_cycle_success(time.time())
            return True

    @staticmethod
    def _record_liveness_heartbeat(timestamp: float) -> None:
        try:
            from api.observability import anchor_worker_heartbeat_timestamp_seconds

            anchor_worker_heartbeat_timestamp_seconds.set(timestamp)
        except ImportError:
            logger.warning("Anchor worker heartbeat metric is unavailable")

    @staticmethod
    def _record_cycle_success(timestamp: float) -> None:
        try:
            from api.observability import (
                anchor_worker_cycles_total,
                anchor_worker_last_success_timestamp_seconds,
            )

            anchor_worker_last_success_timestamp_seconds.set(timestamp)
            anchor_worker_cycles_total.labels(outcome="success").inc()
        except ImportError:
            logger.warning("Anchor worker success metrics are unavailable")

    @staticmethod
    def _record_cycle_error() -> None:
        try:
            from api.observability import anchor_worker_cycles_total

            anchor_worker_cycles_total.labels(outcome="error").inc()
        except ImportError:
            logger.warning("Anchor worker error metric is unavailable")

    @staticmethod
    def _record_cycle_contention() -> None:
        try:
            from api.observability import anchor_worker_cycles_total

            anchor_worker_cycles_total.labels(outcome="lock_contended").inc()
        except ImportError:
            logger.warning("Anchor worker contention metric is unavailable")

    async def _publish_failure_backlog(self) -> None:
        get_counts = getattr(self.db, "get_proof_failure_counts", None)
        if get_counts is None:
            return
        counts = await get_counts()
        try:
            from api.observability import anchor_proof_backlog

            for proof_status in ("failed", "dead_letter"):
                anchor_proof_backlog.labels(status=proof_status).set(counts.get(proof_status, 0))
        except ImportError:
            logger.warning("Anchor proof backlog metric is unavailable")

    @staticmethod
    def _record_anchor_event(outcome: str) -> None:
        try:
            from api.observability import anchor_submissions_total

            anchor_submissions_total.labels(outcome=outcome).inc()
        except ImportError:
            pass

    async def _confirm_proof(
        self,
        proof: Mapping[str, Any],
        confirmation: AnchorConfirmation,
        *,
        reconciled: bool,
    ) -> None:
        await self.db.mark_proof_confirmed(
            proof["id"],
            confirmation,
            reconciled=reconciled,
        )
        outcome = "reconciled" if reconciled else "confirmed"
        self._record_anchor_event(outcome)
        logger.info(
            "anchor_%s proof_id=%s merkle_root=%s transaction_hash=%s "
            "block_number=%s nonce=%s retry_count=%s rpc_stage=receipt",
            outcome,
            proof["id"],
            proof["root_hash"],
            confirmation.transaction_hash,
            confirmation.block_number,
            proof.get("submission_nonce"),
            proof.get("retry_count", 0),
        )

    @staticmethod
    def _replacement_nonce(
        proof: Mapping[str, Any],
        reconciliation: ReconciliationResult,
    ) -> int | None:
        if reconciliation.transaction_state == "reverted":
            return None
        nonce = proof.get("submission_nonce")
        return int(nonce) if nonce is not None else None

    @staticmethod
    def _replacement_is_due(proof: Mapping[str, Any]) -> bool:
        since = proof.get("submitted_at") or proof.get("prepared_at")
        if not isinstance(since, datetime):
            return False
        if since.tzinfo is None:
            since = since.replace(tzinfo=UTC)
        return datetime.now(UTC) - since >= timedelta(seconds=REPLACEMENT_MIN_AGE_SECONDS)

    async def _process_batch(self) -> None:
        await self._publish_failure_backlog()
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

        await self.db.assign_logs_to_proof(log_ids, proof_id)

        await self._process_proof(
            {
                "id": proof_id,
                "root_hash": merkle_root,
                "leaf_hashes": leaf_hashes,
                "log_count": len(logs),
                "start_timestamp": start_timestamp,
                "end_timestamp": end_timestamp,
                "status": "pending",
                "transaction_hash": None,
                "submission_nonce": None,
                "prepared_at": None,
                "submitted_at": None,
                "retry_count": 0,
                "contract_address": self.blockchain.contract_address,
                "chain_id": self.blockchain.expected_chain_id,
            }
        )

    async def _process_proof(
        self,
        proof: Mapping[str, Any],
        *,
        reconciliation_only: bool = False,
    ) -> bool:
        proof_id = proof["id"]
        merkle_root = proof["root_hash"]
        log_count = int(proof.get("log_count") or len(proof["leaf_hashes"]))
        current_retry_count = int(proof.get("retry_count", 0))
        if int(proof.get("chain_id") or self.blockchain.expected_chain_id) != (
            self.blockchain.expected_chain_id
        ):
            raise RuntimeError(
                f"Proof {proof_id} targets chain {proof.get('chain_id')}, but this "
                f"worker is connected to {self.blockchain.expected_chain_id}"
            )
        proof_contract = str(proof.get("contract_address") or self.blockchain.contract_address)
        if proof_contract.lower() != self.blockchain.contract_address.lower():
            raise RuntimeError(
                f"Proof {proof_id} targets contract {proof_contract}, but this "
                f"worker is configured for {self.blockchain.contract_address}"
            )

        await self.db.record_reconciliation_attempt(proof_id)
        try:
            reconciliation = self.blockchain.reconcile_anchor(
                merkle_root=merkle_root,
                log_count=log_count,
                start_timestamp=proof["start_timestamp"],
                end_timestamp=proof["end_timestamp"],
                transaction_hash=proof.get("transaction_hash"),
            )
        except Exception as exc:
            if reconciliation_only:
                logger.error(
                    "anchor_reconciliation_failed proof_id=%s merkle_root=%s "
                    "transaction_hash=%s nonce=%s retry_count=%s rpc_stage=read error=%s",
                    proof_id,
                    merkle_root,
                    proof.get("transaction_hash"),
                    proof.get("submission_nonce"),
                    current_retry_count,
                    exc,
                )
                return False
            retry_status: Literal["failed", "prepared", "submitted"] = (
                "submitted" if proof.get("transaction_hash") else "failed"
            )
            reconciliation_error = (
                f"rpc_circuit_open: {exc}"
                if isinstance(exc, RpcCircuitOpenError)
                else f"reconciliation read failed: {exc}"
            )
            await self._record_failure(
                proof_id,
                current_retry_count,
                reconciliation_error,
                status=retry_status,
            )
            return False

        if reconciliation.confirmation is not None:
            await self._confirm_proof(
                proof,
                reconciliation.confirmation,
                reconciled=(
                    reconciliation_only
                    or proof.get("status") != "pending"
                    or reconciliation.confirmation.source == "contract_state"
                ),
            )
            return True

        if reconciliation_only:
            logger.warning(
                "anchor_reconciliation_not_found proof_id=%s merkle_root=%s "
                "transaction_hash=%s nonce=%s retry_count=%s rpc_stage=read",
                proof_id,
                merkle_root,
                proof.get("transaction_hash"),
                proof.get("submission_nonce"),
                current_retry_count,
            )
            return False

        if (
            proof.get("transaction_hash")
            and reconciliation.transaction_state == "not_found"
            and not self._replacement_is_due(proof)
        ):
            waiting_status: Literal["prepared", "submitted"] = (
                "prepared"
                if proof.get("status") == "prepared" and not proof.get("submitted_at")
                else "submitted"
            )
            await self._record_failure(
                proof_id,
                current_retry_count,
                "Receipt not found and registry root absent; awaiting reconciliation window",
                status=waiting_status,
            )
            self._record_anchor_event("receipt_pending")
            return False

        try:
            balance = self.blockchain.get_balance()
            if balance < Decimal("0.0001"):
                logger.error(
                    "anchor_failed proof_id=%s merkle_root=%s transaction_hash=%s "
                    "nonce=%s retry_count=%s rpc_stage=read error=insufficient_balance",
                    proof_id,
                    merkle_root,
                    proof.get("transaction_hash"),
                    proof.get("submission_nonce"),
                    current_retry_count,
                )
                await self._record_failure(
                    proof_id,
                    current_retry_count,
                    f"Insufficient balance: {balance} ETH",
                )
                return False

            prepared = self.blockchain.prepare_anchor_transaction(
                merkle_root=merkle_root,
                log_count=log_count,
                start_timestamp=proof["start_timestamp"],
                end_timestamp=proof["end_timestamp"],
                nonce=self._replacement_nonce(proof, reconciliation),
            )
        except RootAlreadyAnchoredError:
            self._record_anchor_event("already_exists")
            try:
                reconciliation = self.blockchain.reconcile_anchor(
                    merkle_root=merkle_root,
                    log_count=log_count,
                    start_timestamp=proof["start_timestamp"],
                    end_timestamp=proof["end_timestamp"],
                    transaction_hash=proof.get("transaction_hash"),
                )
            except Exception as exc:
                await self._record_terminal_failure(
                    proof_id,
                    f"RootAlreadyAnchored could not be validated: {exc}",
                )
                return False
            if reconciliation.confirmation is None:
                await self._record_terminal_failure(
                    proof_id,
                    "RootAlreadyAnchored was returned but registry reconciliation found no root",
                )
                return False
            await self._confirm_proof(
                proof,
                reconciliation.confirmation,
                reconciled=True,
            )
            return True
        except DeterministicContractRevert as exc:
            await self._record_terminal_failure(proof_id, str(exc))
            return False
        except Exception as exc:
            await self._record_failure(
                proof_id,
                current_retry_count,
                f"transaction preparation failed: {exc}",
            )
            return False

        await self.db.record_submission_prepared(proof_id, prepared)
        self._record_anchor_event("prepare")
        logger.info(
            "anchor_prepare proof_id=%s merkle_root=%s transaction_hash=%s "
            "nonce=%s retry_count=%s rpc_stage=estimate",
            proof_id,
            merkle_root,
            prepared.transaction_hash,
            prepared.nonce,
            current_retry_count,
        )

        try:
            transaction_hash = self.blockchain.broadcast(prepared)
        except Exception as exc:
            await self.db.mark_submission_broadcast(
                proof_id,
                prepared.transaction_hash,
                error_message=f"Broadcast outcome uncertain: {exc}",
            )
            await self._record_failure(
                proof_id,
                current_retry_count,
                f"broadcast outcome uncertain: {exc}",
                status="submitted",
            )
            self._record_anchor_event("receipt_pending")
            logger.info(
                "anchor_receipt_pending proof_id=%s merkle_root=%s "
                "transaction_hash=%s nonce=%s retry_count=%s rpc_stage=send",
                proof_id,
                merkle_root,
                prepared.transaction_hash,
                prepared.nonce,
                current_retry_count,
            )
            return False

        await self.db.mark_submission_broadcast(proof_id, transaction_hash)
        self._record_anchor_event("broadcast")
        logger.info(
            "anchor_broadcast proof_id=%s merkle_root=%s transaction_hash=%s "
            "nonce=%s retry_count=%s rpc_stage=send",
            proof_id,
            merkle_root,
            transaction_hash,
            prepared.nonce,
            current_retry_count,
        )

        try:
            result = await self.blockchain.wait_for_confirmation(
                prepared,
                merkle_root=merkle_root,
                log_count=log_count,
                start_timestamp=proof["start_timestamp"],
                end_timestamp=proof["end_timestamp"],
            )
        except RpcCircuitOpenError as e:
            logger.info(
                "anchor_receipt_pending proof_id=%s merkle_root=%s "
                "transaction_hash=%s nonce=%s retry_count=%s rpc_stage=receipt "
                "cooldown_seconds=%.1f",
                proof_id,
                merkle_root,
                transaction_hash,
                prepared.nonce,
                current_retry_count,
                e.cooldown_remaining_seconds,
            )
            await self._record_failure(
                proof_id,
                current_retry_count,
                f"rpc_circuit_open: {e}",
                status="submitted",
            )
            self._record_anchor_event("receipt_pending")
            return False
        except Exception as exc:
            logger.warning(
                "anchor_receipt_pending proof_id=%s merkle_root=%s "
                "transaction_hash=%s nonce=%s retry_count=%s rpc_stage=receipt error=%s",
                proof_id,
                merkle_root,
                transaction_hash,
                prepared.nonce,
                current_retry_count,
                exc,
            )
            await self._record_failure(
                proof_id,
                current_retry_count,
                f"Receipt lookup failed for already-broadcast transaction: {exc}",
                status="submitted",
            )
            self._record_anchor_event("receipt_pending")
            return False

        if result.confirmation is not None:
            updated_proof = dict(proof)
            updated_proof["submission_nonce"] = prepared.nonce
            await self._confirm_proof(
                updated_proof,
                result.confirmation,
                reconciled=(result.confirmation.source == "contract_state"),
            )
            return True

        await self._record_failure(
            proof_id,
            current_retry_count,
            "Broadcast transaction reverted and registry root is absent",
            status="failed",
        )
        return False

    async def _record_failure(
        self,
        proof_id: UUID,
        current_retry_count: int,
        error_message: str,
        *,
        status: Literal["failed", "prepared", "submitted"] = "failed",
    ) -> None:
        # After this attempt, retry_count becomes current_retry_count + 1
        # (the SQL does the increment). Transition to dead_letter once we
        # hit the cap so the retry query stops picking this row up.
        next_retry_count = current_retry_count + 1
        transaction_outcome_unknown = status in {"prepared", "submitted"}
        if next_retry_count >= MAX_RETRIES and not transaction_outcome_unknown:
            logger.error(
                f"Proof {proof_id} exhausted {MAX_RETRIES} retries — "
                f"transitioning to dead_letter. Last error: {error_message}"
            )
            await self.db.mark_proof_dead_letter(
                proof_id,
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

        backoff = compute_retry_backoff(current_retry_count)
        next_retry_at = datetime.now(UTC) + backoff
        logger.warning(
            f"Proof {proof_id} failed (attempt {next_retry_count}/{MAX_RETRIES}). "
            f"Next retry at {next_retry_at.isoformat()} ({backoff})."
        )
        await self.db.schedule_retry(
            proof_id,
            status=status,
            error_message=error_message,
            next_retry_at=next_retry_at,
        )
        if status == "failed":
            self._record_anchor_event("failed")

    async def _record_terminal_failure(
        self,
        proof_id: UUID,
        error_message: str,
    ) -> None:
        logger.error(
            "anchor_failed proof_id=%s error=%s deterministic=true",
            proof_id,
            error_message,
        )
        await self.db.mark_proof_dead_letter(
            proof_id,
            error_message=error_message,
        )
        self._record_anchor_event("failed")
        self._record_anchor_event("dead_letter")

    async def _retry_pending_proofs(self) -> None:
        pending = await self.db.get_retryable_proofs()

        for proof in pending:
            logger.info(
                "anchor_retry proof_id=%s merkle_root=%s transaction_hash=%s "
                "nonce=%s retry_count=%s status=%s",
                proof["id"],
                proof["root_hash"],
                proof.get("transaction_hash"),
                proof.get("submission_nonce"),
                proof["retry_count"],
                proof["status"],
            )
            await self._process_proof(proof)

    async def reconcile_proof(self, proof_id: UUID) -> bool:
        """Explicit no-broadcast recovery path for any proof state."""

        async with self.db.anchor_cycle_lock() as acquired:
            if not acquired:
                raise RuntimeError("Another anchor worker owns the reconciliation lock")
            proof = await self.db.get_proof_by_id(proof_id)
            if proof is None:
                raise ValueError(f"Merkle proof not found: {proof_id}")
            return await self._process_proof(
                proof,
                reconciliation_only=True,
            )


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


async def main(reconcile_proof_id: UUID | None = None) -> int:
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

    if reconcile_proof_id is None:
        if METRICS_ENABLED:
            from api.observability import start_worker_metrics_endpoint

            start_worker_metrics_endpoint(METRICS_PORT, METRICS_ADDRESS)
            logger.info(
                "Anchor worker metrics listening on http://%s:%s/metrics",
                METRICS_ADDRESS,
                METRICS_PORT,
            )
        else:
            logger.warning(
                "Anchor worker metrics are explicitly disabled; stale worker alerts will be blind"
            )
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
        logger.critical("This is a DNS/host configuration issue, not a database password issue.")
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
        await db_service.close()
        return 1

    worker = AnchorWorker(db_service, blockchain_service)
    if reconcile_proof_id is not None:
        try:
            reconciled = await worker.reconcile_proof(reconcile_proof_id)
            return 0 if reconciled else 2
        finally:
            await db_service.close()

    balance = blockchain_service.get_balance()
    logger.info(f"Blockchain connected. Balance: {balance} ETH")

    # Handle shutdown signals
    def signal_handler(sig, _frame):
        logger.info(f"Received signal {sig}, initiating shutdown...")
        asyncio.create_task(worker.stop())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        await worker.start()
    finally:
        await db_service.close()
        logger.info("Anchor worker shutdown complete")
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the Inntris anchor worker or reconcile one proof without broadcasting",
    )
    parser.add_argument(
        "--reconcile-proof",
        type=UUID,
        help=(
            "Read receipt and AnchorRegistry state for this proof ID and repair "
            "confirmed database fields. This mode never broadcasts a transaction."
        ),
    )
    return parser.parse_args()


if __name__ == "__main__":
    arguments = _parse_args()
    raise SystemExit(asyncio.run(main(arguments.reconcile_proof)))
