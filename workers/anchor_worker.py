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
import time
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any, TypeVar
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import asyncpg
from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3

from workers.circuit_breaker import RpcCircuitBreaker, RpcCircuitOpenError

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
        raise ValueError(
            f"Invalid transaction hash length: expected 66 chars, got {len(tx_hash)}"
        )
    return tx_hash


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
            {"indexed": False, "internalType": "address", "name": "submitter", "type": "address"},
        ],
        "name": "BatchAnchored",
        "type": "event",
    },
    # Custom errors. Without these entries web3 cannot decode a revert, so
    # every deterministic rejection surfaces as an opaque exception and looks
    # identical to "the RPC could not estimate gas". That is exactly how the
    # 2026-08-25 incident kept rebroadcasting a batch that Base had already
    # anchored: RootAlreadyAnchored came back as raw selector 0xdb34c203, the
    # worker read it as a transient estimation failure, applied its fallback
    # gas limit, and sent the transaction anyway.
    {
        "inputs": [{"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"}],
        "name": "RootAlreadyAnchored",
        "type": "error",
    },
    {"inputs": [], "name": "InvalidMerkleRoot", "type": "error"},
    {
        "inputs": [{"internalType": "uint256", "name": "logCount", "type": "uint256"}],
        "name": "InvalidLogCount",
        "type": "error",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "startTimestamp", "type": "uint256"},
            {"internalType": "uint256", "name": "endTimestamp", "type": "uint256"},
        ],
        "name": "InvalidTimestamps",
        "type": "error",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"}],
        "name": "BatchNotFound",
        "type": "error",
    },
]


def _error_selector(entry: Mapping[str, Any]) -> str:
    """Return the 4-byte selector for an ABI error entry, as 0x-prefixed hex."""
    arg_types = ",".join(i["type"] for i in entry.get("inputs", []))
    signature = f"{entry['name']}({arg_types})"
    return "0x" + Web3.keccak(text=signature)[:4].hex()


# Derived from the ABI rather than hardcoded, so the map cannot drift if a
# contract error's signature changes. RootAlreadyAnchored(bytes32) is
# 0xdb34c203 — the selector observed throughout the production incident.
CONTRACT_ERROR_SELECTORS: dict[str, str] = {
    _error_selector(entry): entry["name"]
    for entry in ANCHOR_REGISTRY_ABI
    if entry.get("type") == "error"
}

ROOT_ALREADY_ANCHORED = "RootAlreadyAnchored"


class SubmissionErrorKind(Enum):
    """How a failure during anchor preparation or submission should be treated.

    The distinction that matters is whether the chain has made a decision.

    ``ROOT_ALREADY_ANCHORED`` means Base has the root. There is nothing to
    submit; the proof needs reconciling, not retrying.

    ``DETERMINISTIC`` means the contract rejected the call on its merits —
    bad inputs, missing role, paused. Sending the same transaction again
    produces the same rejection and burns gas doing it.

    ``TRANSIENT`` means we never got an answer: a timeout, a 5xx, a 429, a
    connection reset. Retrying is the correct response.
    """

    ROOT_ALREADY_ANCHORED = "root_already_anchored"
    DETERMINISTIC = "deterministic_revert"
    TRANSIENT = "transient"


def _extract_error_selectors(exc: BaseException) -> set[str]:
    """Return any known contract-error selectors mentioned by an exception.

    web3 surfaces custom errors inconsistently across versions and providers:
    sometimes as a decoded ``ContractCustomError``, sometimes as a raw hex
    payload on ``args``, sometimes only inside the string form. Rather than
    depend on one shape, scan the text of the exception and its ``data``
    attribute for selectors we know.
    """
    haystacks: list[str] = [str(exc)]
    data = getattr(exc, "data", None)
    if data is not None:
        haystacks.append(str(data))
    for arg in getattr(exc, "args", ()) or ():
        haystacks.append(str(arg))

    blob = " ".join(haystacks).lower()
    return {sel for sel in CONTRACT_ERROR_SELECTORS if sel.lower() in blob}


def classify_submission_error(exc: BaseException) -> tuple[SubmissionErrorKind, str | None]:
    """Classify a preparation/submission failure.

    Returns the kind and, when identifiable, the contract error's name.

    A revert is a decision by the chain and is never transient. Only failures
    where we did not reach a decision — transport errors — are retryable in
    the sense of "send it again".
    """
    selectors = _extract_error_selectors(exc)
    names = {CONTRACT_ERROR_SELECTORS[sel] for sel in selectors}

    if ROOT_ALREADY_ANCHORED in names:
        return SubmissionErrorKind.ROOT_ALREADY_ANCHORED, ROOT_ALREADY_ANCHORED

    if names:
        return SubmissionErrorKind.DETERMINISTIC, sorted(names)[0]

    # Also catch reverts we cannot name — a revert string, a role check, a
    # paused contract. Still a decision, still not worth resending.
    text = str(exc).lower()
    revert_markers = (
        "execution reverted",
        "revert",
        "always failing transaction",
        "unauthorized",
        "accesscontrol",
    )
    if any(marker in text for marker in revert_markers):
        return SubmissionErrorKind.DETERMINISTIC, None

    return SubmissionErrorKind.TRANSIENT, None


class AnchorRejectedError(Exception):
    """The chain refused this anchor submission on its merits.

    Carries the classification so the caller can tell the one case that means
    "already done" from the cases that mean "this will never work".
    """

    def __init__(
        self,
        kind: SubmissionErrorKind,
        error_name: str | None,
        detail: str,
    ) -> None:
        self.kind = kind
        self.error_name = error_name
        self.detail = detail
        super().__init__(f"{error_name or kind.value}: {detail}")


@dataclass(frozen=True)
class PreparedAnchor:
    """A signed anchor transaction that has not been broadcast yet.

    The hash of a signed Ethereum transaction is knowable before it reaches
    the network. Persisting it before broadcast is what makes the submission
    recoverable: if the send or the receipt poll fails, we still know which
    transaction to go looking for.
    """

    transaction_hash: str
    nonce: int
    raw_transaction: bytes
    gas_price_gwei: Decimal


@dataclass(frozen=True)
class ReconciliationResult:
    """What reading the chain told us about a proof."""

    confirmed: bool
    source: str  # "receipt" | "contract_state" | "unresolved"
    detail: str
    transaction_hash: str | None = None
    block_number: int | None = None
    gas_used: int | None = None


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
    def _root_to_bytes(merkle_root: str) -> bytes:
        """Normalise a Merkle root (with or without 0x) to 32 raw bytes."""
        hex_body = merkle_root[2:] if merkle_root.startswith("0x") else merkle_root
        root_bytes = bytes.fromhex(hex_body)
        if len(root_bytes) != 32:
            raise ValueError(
                f"Merkle root must be 32 bytes, got {len(root_bytes)}"
            )
        return root_bytes

    def prepare_anchor_transaction(
        self,
        merkle_root: str,
        log_count: int,
        start_timestamp: datetime,
        end_timestamp: datetime,
        nonce: int | None = None,
    ) -> PreparedAnchor:
        """Build and sign an anchor transaction without broadcasting it.

        Preparation is deliberately separate from broadcast so the caller can
        persist the transaction's identity — its hash and nonce — before the
        transaction reaches the network. Once persisted, no later RPC failure
        can leave us unable to find out what happened to it.

        ``nonce`` may be supplied to replace a specific in-flight transaction.
        A replacement MUST reuse the original nonce; allocating a new one
        creates a second competing transaction instead of superseding the
        first, which is what produced "nonce too low: next nonce 34, tx nonce
        33" during the incident.
        """
        # Verify the RPC still serves the chain we expect before spending gas.
        # Cheap check (one eth_chainId call), huge blast-radius if it's wrong.
        self.assert_chain_id()

        root_bytes = self._root_to_bytes(merkle_root)
        start_unix = int(start_timestamp.timestamp())
        end_unix = int(end_timestamp.timestamp())

        if nonce is None:
            # "pending" includes transactions already in the mempool. Using the
            # default ("latest") would reissue a nonce that an unconfirmed
            # transaction already holds.
            nonce = self._rpc(
                lambda: self.w3.eth.get_transaction_count(
                    self.account.address, "pending"
                )
            )

        call = self.contract.functions.anchorBatch(
            root_bytes,
            log_count,
            start_unix,
            end_unix,
        )

        try:
            gas_estimate = self._rpc(
                lambda: call.estimate_gas({"from": self.account.address})
            )
        except RpcCircuitOpenError:
            raise
        except Exception as exc:
            kind, error_name = classify_submission_error(exc)
            if kind is not SubmissionErrorKind.TRANSIENT:
                # The contract has made a decision. A fallback gas limit does
                # not change that decision, it just pays to learn it again.
                raise AnchorRejectedError(kind, error_name, str(exc)) from exc
            logger.warning(
                "Gas estimation failed transiently (stage=estimate), using default: %s",
                exc,
            )
            gas_estimate = 150000

        gas_price = self._rpc(lambda: self.w3.eth.gas_price)
        gas_price_gwei = Decimal(str(self.w3.from_wei(gas_price, "gwei")))

        # Reject suspiciously high gas prices. Trips on a broken gas oracle or
        # an RPC silently serving mainnet. A tripped cap costs nothing except a
        # retry; a burst of legitimate Base congestion above the cap also
        # retries, so operators should raise ANCHOR_MAX_GAS_PRICE_GWEI rather
        # than remove this check.
        if gas_price_gwei > MAX_GAS_PRICE_GWEI:
            raise RuntimeError(
                f"Gas price {gas_price_gwei} gwei exceeds cap "
                f"{MAX_GAS_PRICE_GWEI} gwei. Refusing to submit."
            )

        tx = call.build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": int(gas_estimate * 1.2),
            "gasPrice": gas_price,
            "chainId": self.expected_chain_id,
        })

        signed_tx = self.w3.eth.account.sign_transaction(tx, self.account.key)
        # Compatibility: web3.py v6+ uses raw_transaction, older uses rawTransaction
        raw_tx = getattr(signed_tx, "raw_transaction", None)
        if raw_tx is None:
            raw_tx = signed_tx.rawTransaction

        # The hash of a signed transaction is fixed at signing time. This is
        # the value that makes the submission recoverable.
        signed_hash = getattr(signed_tx, "hash", None)
        if signed_hash is None:
            signed_hash = self.w3.keccak(raw_tx)

        return PreparedAnchor(
            transaction_hash=normalize_transaction_hash(signed_hash),
            nonce=nonce,
            raw_transaction=raw_tx,
            gas_price_gwei=gas_price_gwei,
        )

    def broadcast(self, prepared: PreparedAnchor) -> str:
        """Broadcast a prepared transaction and return its hash.

        A transaction the node already knows about is not an error here: if we
        are replaying a broadcast whose outcome we lost, "already known" or
        "nonce too low" means the network has it, which is exactly what we
        wanted to establish.
        """
        try:
            sent = self._rpc(
                lambda: self.w3.eth.send_raw_transaction(prepared.raw_transaction)
            )
        except RpcCircuitOpenError:
            raise
        except Exception as exc:
            text = str(exc).lower()
            if "already known" in text or "already imported" in text:
                logger.info(
                    "Transaction %s already known to the node (stage=send)",
                    prepared.transaction_hash,
                )
                return prepared.transaction_hash
            raise

        return normalize_transaction_hash(sent)

    async def wait_for_confirmation(
        self, transaction_hash: str, timeout: int = 120
    ) -> dict[str, Any]:
        """Block until a receipt is available, then summarise it."""
        receipt = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._rpc(
                lambda: self.w3.eth.wait_for_transaction_receipt(
                    transaction_hash, timeout=timeout
                )
            ),
        )
        return self._summarise_receipt(receipt)

    def get_receipt_if_available(self, transaction_hash: str) -> dict[str, Any] | None:
        """Return a receipt summary, or None if the chain has no receipt yet.

        Distinguishes "the transaction is not mined" (None) from "we could not
        ask" (raises). Conflating those is what turned a receipt-poll failure
        into a redundant broadcast.
        """
        try:
            receipt = self._rpc(
                lambda: self.w3.eth.get_transaction_receipt(transaction_hash)
            )
        except RpcCircuitOpenError:
            raise
        except Exception as exc:
            text = str(exc).lower()
            if "not found" in text or "notfound" in text:
                return None
            raise

        if receipt is None:
            return None
        return self._summarise_receipt(receipt)

    def _summarise_receipt(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "transaction_hash": normalize_transaction_hash(
                receipt["transactionHash"]
            ),
            "block_number": receipt["blockNumber"],
            "gas_used": receipt["gasUsed"],
            "status": "confirmed" if receipt["status"] == 1 else "failed",
            "to": receipt.get("to"),
        }

    def is_root_anchored(self, merkle_root: str) -> bool:
        """Ask the contract whether it already holds this root."""
        root_bytes = self._root_to_bytes(merkle_root)
        return bool(self._rpc(lambda: self.contract.functions.isAnchored(root_bytes).call()))

    def reconcile_anchor(
        self,
        merkle_root: str,
        transaction_hash: str | None = None,
    ) -> ReconciliationResult:
        """Establish a proof's true state by reading Base.

        Order matters. A receipt is the strongest evidence because it carries
        the block and gas actually used. Contract state is weaker but still
        conclusive about the fact that matters: the root is anchored.

        A successful broadcast alone proves nothing, and an inability to fetch
        a receipt disproves nothing. Neither is treated as an answer here.
        """
        if transaction_hash:
            try:
                summary = self.get_receipt_if_available(transaction_hash)
            except RpcCircuitOpenError:
                raise
            except Exception as exc:
                logger.warning(
                    "Receipt lookup failed for already-broadcast transaction %s "
                    "(stage=receipt): %s",
                    transaction_hash,
                    exc,
                )
                summary = None

            if summary and summary["status"] == "confirmed":
                recipient = summary.get("to")
                if recipient and recipient.lower() != self.contract_address.lower():
                    return ReconciliationResult(
                        confirmed=False,
                        source="unresolved",
                        detail=(
                            f"Receipt {transaction_hash} targets {recipient}, "
                            f"not the expected AnchorRegistry {self.contract_address}"
                        ),
                    )
                return ReconciliationResult(
                    confirmed=True,
                    source="receipt",
                    detail=f"Receipt confirms {transaction_hash}",
                    transaction_hash=summary["transaction_hash"],
                    block_number=summary["block_number"],
                    gas_used=summary["gas_used"],
                )

        # Either there is no transaction hash, the receipt was unreachable, or
        # the transaction reverted. The root may still be anchored by an
        # earlier submission whose outcome we lost.
        try:
            anchored = self.is_root_anchored(merkle_root)
        except RpcCircuitOpenError:
            raise
        except Exception as exc:
            return ReconciliationResult(
                confirmed=False,
                source="unresolved",
                detail=f"Could not read contract state (stage=read): {exc}",
            )

        if not anchored:
            return ReconciliationResult(
                confirmed=False,
                source="unresolved",
                detail="Root is not present in the AnchorRegistry",
            )

        batch = self.verify_batch_anchored(merkle_root)
        if batch is None:
            # isAnchored said yes but getBatch disagrees. Do not guess.
            return ReconciliationResult(
                confirmed=False,
                source="unresolved",
                detail="isAnchored is true but getBatch returned no batch",
            )

        return ReconciliationResult(
            confirmed=True,
            source="contract_state",
            detail=(
                f"AnchorRegistry holds batch {batch['batch_id']} for this root "
                f"(submitter {batch['submitter']})"
            ),
            transaction_hash=transaction_hash,
        )

    def verify_batch_anchored(self, merkle_root: str) -> dict[str, Any] | None:
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
                "timestamp": datetime.fromtimestamp(timestamp, tz=UTC),
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
                await connection.execute(
                    "SET LOCAL idle_in_transaction_session_timeout = 0"
                )
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
                    logger.exception(
                        "Failed to roll back anchor worker lock transaction"
                    )
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
        # When status='submitted', the transaction is in flight and we are only
        # deferring the next receipt check. retry_count advances so the backoff
        # widens, but the retry query deliberately does not bound `submitted`
        # rows by it — a live transaction is always worth asking about again.
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
                    WHEN $2::varchar IN ('failed', 'submitted') THEN $8
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
                    WHEN $2::varchar IN ('failed', 'dead_letter', 'submitted')
                        THEN retry_count + 1
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

    async def assign_logs_to_proof(
        self,
        log_ids: list[UUID],
        merkle_root_id: UUID,
    ):
        """Bind logs to the Merkle batch that contains them.

        This records membership, NOT confirmation. ``merkle_root_id IS NOT
        NULL`` means "this log belongs to this batch"; whether that batch
        reached Base is ``merkle_proofs.status`` and nothing else.

        The binding deliberately happens before submission. Deferring it until
        after confirmation would be worse: a crash between creating the proof
        and confirming it would leave the same logs eligible for a second
        batch, producing two Merkle roots covering the same evidence. Binding
        first means a resumed worker finds the existing proof and continues it.
        """
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

        logger.info("Assigned %d logs to Merkle proof %s", len(log_ids), merkle_root_id)

    async def get_pending_proofs(self) -> list[dict[str, Any]]:
        """Return proofs whose state the worker should advance this cycle.

        ``submitted`` rows are included: their next action is reconciliation
        (fetch the receipt, read contract state), not another broadcast. They
        were previously invisible to this query, which is why a transaction
        whose receipt we failed to read was reissued instead of followed up.

        ``dead_letter`` remains terminal here. It is recovered through the
        reconciliation tooling, which reads Base before writing anything.

        ``status`` and ``transaction_hash`` come back so the caller can tell a
        proof that has a transaction in flight from one that never got that far.

        The retry cap bounds proofs that would need a *new* broadcast. It does
        not bound ``submitted`` rows: those already have a transaction on the
        network, and giving up on asking what happened to it is what stranded
        the Gate 1 receipt.
        """
        query = """
            SELECT id, root_hash, leaf_hashes, retry_count, status,
                   transaction_hash, submission_nonce,
                   start_timestamp, end_timestamp
            FROM merkle_proofs
            WHERE status IN ('pending', 'submitted', 'failed')
              AND (status = 'submitted' OR retry_count < $1)
              AND (next_retry_at IS NULL OR next_retry_at <= NOW())
            ORDER BY created_at ASC
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, MAX_RETRIES)
        return [dict(row) for row in rows]

    async def record_submission_prepared(
        self,
        proof_id: UUID,
        transaction_hash: str,
        nonce: int,
    ) -> None:
        """Persist a transaction's identity before it reaches the network.

        This is the write that makes a submission recoverable. After it, no
        RPC failure can leave us unable to find out what happened: we know
        which hash to ask about and which nonce it holds.
        """
        query = """
            UPDATE merkle_proofs
            SET transaction_hash = $2,
                submission_nonce = $3,
                status = 'submitted',
                submitted_at = COALESCE(submitted_at, NOW()),
                next_retry_at = NULL
            WHERE id = $1
        """
        async with self._pool.acquire() as conn:
            await conn.execute(query, proof_id, transaction_hash, nonce)

    async def mark_proof_confirmed(
        self,
        proof_id: UUID,
        transaction_hash: str | None,
        block_number: int | None,
        gas_used: int | None = None,
        gas_price_gwei: Decimal | None = None,
        reconciled: bool = False,
    ) -> None:
        """Record that Base holds this root.

        ``reconciled`` marks the cases where we discovered the anchor by
        reading the chain rather than by watching our own submission succeed.

        ``dead_lettered_at`` is deliberately left in place. A proof that once
        exhausted its retries keeps that fact as incident evidence even after
        it recovers; erasing it would destroy the only record that anything
        went wrong.
        """
        query = """
            UPDATE merkle_proofs
            SET status = 'confirmed',
                transaction_hash = COALESCE($2, transaction_hash),
                block_number = COALESCE($3, block_number),
                gas_used = COALESCE($4, gas_used),
                gas_price_gwei = COALESCE($5, gas_price_gwei),
                confirmed_at = COALESCE(confirmed_at, NOW()),
                reconciled_at = CASE WHEN $6 THEN COALESCE(reconciled_at, NOW())
                                     ELSE reconciled_at END,
                next_retry_at = NULL,
                error_message = NULL
            WHERE id = $1
        """
        async with self._pool.acquire() as conn:
            await conn.execute(
                query,
                proof_id,
                transaction_hash,
                block_number,
                gas_used,
                gas_price_gwei,
                reconciled,
            )


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
                anchor_proof_backlog.labels(status=proof_status).set(
                    counts.get(proof_status, 0)
                )
        except ImportError:
            logger.warning("Anchor proof backlog metric is unavailable")

    async def _process_batch(self):
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

        # Membership first, deliberately. See assign_logs_to_proof: binding
        # before submission means a crash resumes the existing proof instead of
        # minting a second batch over the same evidence.
        await self.db.assign_logs_to_proof(log_ids, proof_id)

        await self._submit_to_blockchain(
            proof_id=proof_id,
            merkle_root=merkle_root,
            log_count=len(logs),
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
        )

    async def _reconcile_proof(
        self,
        proof_id: UUID,
        merkle_root: str,
        transaction_hash: str | None,
    ) -> bool:
        """Read Base and persist the answer. Returns True if confirmed."""
        result = self.blockchain.reconcile_anchor(merkle_root, transaction_hash)

        if not result.confirmed:
            logger.info(
                "anchor_reconcile_unresolved proof_id=%s root=%s tx=%s detail=%s",
                proof_id, merkle_root, transaction_hash, result.detail,
            )
            return False

        await self.db.mark_proof_confirmed(
            proof_id,
            transaction_hash=result.transaction_hash,
            block_number=result.block_number,
            gas_used=result.gas_used,
            reconciled=result.source == "contract_state",
        )
        logger.info(
            "anchor_confirmed proof_id=%s root=%s tx=%s block=%s source=%s",
            proof_id, merkle_root, result.transaction_hash,
            result.block_number, result.source,
        )
        self._count_submission(
            "reconciled" if result.source == "contract_state" else "confirmed"
        )
        return True

    @staticmethod
    def _count_submission(outcome: str) -> None:
        try:
            from api.observability import anchor_submissions_total

            anchor_submissions_total.labels(outcome=outcome).inc()
        except ImportError:
            pass  # worker can run without the API package in some deploys

    async def _submit_to_blockchain(
        self,
        proof_id: UUID,
        merkle_root: str,
        log_count: int,
        start_timestamp: datetime,
        end_timestamp: datetime,
        current_retry_count: int = 0,
        transaction_hash: str | None = None,
        submission_nonce: int | None = None,
    ):
        """Advance one proof toward a confirmed anchor.

        The order here is the fix. Before doing anything that costs gas, ask
        the chain what it already knows. Only when neither an existing receipt
        nor contract state establishes the anchor do we prepare and broadcast —
        and even then, the transaction's identity is persisted before it is
        sent, so its outcome stays discoverable no matter what the RPC does
        next.
        """
        try:
            # 1. Does the chain already have an answer for us?
            if transaction_hash or await self._root_may_already_exist(
                proof_id, merkle_root
            ):
                if await self._reconcile_proof(
                    proof_id, merkle_root, transaction_hash
                ):
                    return
                if transaction_hash:
                    # A transaction is out there and unresolved. Do NOT issue a
                    # new one; wait for the next cycle to look again. Reissuing
                    # here is precisely what produced duplicate broadcasts and
                    # the "nonce too low" collision during the incident.
                    logger.info(
                        "anchor_receipt_pending proof_id=%s tx=%s — deferring, "
                        "not rebroadcasting",
                        proof_id, transaction_hash,
                    )
                    await self._schedule_recheck(proof_id, current_retry_count)
                    return

            # 2. Nothing on chain. Check we can afford to submit.
            balance = self.blockchain.get_balance()
            if balance < Decimal("0.0001"):
                logger.error(f"Insufficient balance: {balance} ETH")
                await self._record_failure(
                    proof_id,
                    current_retry_count,
                    f"Insufficient balance: {balance} ETH",
                )
                return

            # 3. Prepare, persist identity, then broadcast.
            prepared = self.blockchain.prepare_anchor_transaction(
                merkle_root=merkle_root,
                log_count=log_count,
                start_timestamp=start_timestamp,
                end_timestamp=end_timestamp,
                nonce=submission_nonce,
            )
            logger.info(
                "anchor_prepare proof_id=%s root=%s tx=%s nonce=%s",
                proof_id, merkle_root, prepared.transaction_hash, prepared.nonce,
            )
            await self.db.record_submission_prepared(
                proof_id,
                transaction_hash=prepared.transaction_hash,
                nonce=prepared.nonce,
            )

            sent_hash = self.blockchain.broadcast(prepared)
            logger.info(
                "anchor_broadcast proof_id=%s tx=%s nonce=%s",
                proof_id, sent_hash, prepared.nonce,
            )

            # 4. Wait for the receipt. A failure here is NOT a submission
            #    failure — the transaction is already on the network and its
            #    hash is already persisted.
            try:
                summary = await self.blockchain.wait_for_confirmation(sent_hash)
            except RpcCircuitOpenError:
                raise
            except Exception as exc:
                logger.warning(
                    "Receipt lookup failed for already-broadcast transaction %s "
                    "(proof_id=%s, stage=receipt): %s",
                    sent_hash, proof_id, exc,
                )
                self._count_submission("receipt_pending")
                await self._schedule_recheck(proof_id, current_retry_count)
                return

            if summary["status"] == "confirmed":
                await self.db.mark_proof_confirmed(
                    proof_id,
                    transaction_hash=summary["transaction_hash"],
                    block_number=summary["block_number"],
                    gas_used=summary["gas_used"],
                    gas_price_gwei=prepared.gas_price_gwei,
                )
                logger.info(
                    "anchor_confirmed proof_id=%s tx=%s block=%s source=receipt",
                    proof_id, summary["transaction_hash"], summary["block_number"],
                )
                self._count_submission("confirmed")
                return

            # Reverted on chain. The root may still have been anchored by an
            # earlier attempt, so reconcile before calling this a failure.
            if await self._reconcile_proof(proof_id, merkle_root, sent_hash):
                return
            await self._record_failure(
                proof_id,
                current_retry_count,
                f"Transaction {sent_hash} reverted on chain",
            )

        except AnchorRejectedError as exc:
            await self._handle_rejection(
                proof_id, merkle_root, transaction_hash, current_retry_count, exc
            )
        except RpcCircuitOpenError as e:
            logger.info(
                "Proof %s deferred — RPC circuit open (cooldown %.1fs)",
                proof_id, e.cooldown_remaining_seconds,
            )
            await self._record_failure(
                proof_id,
                current_retry_count,
                f"rpc_circuit_open: {e}",
            )
        except Exception as e:
            logger.error(
                "anchor_failed proof_id=%s root=%s: %s", proof_id, merkle_root, e
            )
            await self._record_failure(proof_id, current_retry_count, str(e))

    async def _root_may_already_exist(self, proof_id: UUID, merkle_root: str) -> bool:
        """Cheap pre-submission guard: is this root already on Base?

        One view call. It costs a fraction of a broadcast and removes the
        entire class of duplicate submissions.
        """
        try:
            anchored = self.blockchain.is_root_anchored(merkle_root)
        except RpcCircuitOpenError:
            raise
        except Exception as exc:
            logger.warning(
                "Pre-submission anchor check failed (proof_id=%s, stage=read): %s",
                proof_id, exc,
            )
            return False
        if anchored:
            logger.info(
                "anchor_already_exists proof_id=%s root=%s", proof_id, merkle_root
            )
            self._count_submission("already_exists")
        return anchored

    async def _handle_rejection(
        self,
        proof_id: UUID,
        merkle_root: str,
        transaction_hash: str | None,
        current_retry_count: int,
        exc: "AnchorRejectedError",
    ) -> None:
        """The contract refused. Decide between reconcile and hard failure."""
        if exc.kind is SubmissionErrorKind.ROOT_ALREADY_ANCHORED:
            logger.info(
                "anchor_already_exists proof_id=%s root=%s — reconciling instead "
                "of resubmitting", proof_id, merkle_root,
            )
            self._count_submission("already_exists")
            if await self._reconcile_proof(proof_id, merkle_root, transaction_hash):
                return
            # The contract says the root exists but we could not read the
            # batch back. Record it without broadcasting anything.
            await self._record_failure(
                proof_id,
                current_retry_count,
                f"{ROOT_ALREADY_ANCHORED} but chain state unreadable: {exc.detail}",
            )
            return

        logger.error(
            "anchor_rejected proof_id=%s root=%s error=%s — not broadcasting",
            proof_id, merkle_root, exc.error_name or "revert",
        )
        await self._record_failure(
            proof_id,
            current_retry_count,
            f"Contract rejected submission ({exc.error_name or 'revert'}): {exc.detail}",
        )

    async def _schedule_recheck(
        self, proof_id: UUID, current_retry_count: int
    ) -> None:
        """Defer a proof whose transaction is in flight.

        Distinct from ``_record_failure``: the proof keeps its ``submitted``
        status and its transaction hash. Only the backoff clock advances, so a
        long RPC outage cannot make us forget a live transaction.
        """
        backoff = compute_retry_backoff(current_retry_count + 1)
        next_retry_at = datetime.now(UTC) + backoff
        await self.db.update_merkle_proof_status(
            proof_id,
            status="submitted",
            next_retry_at=next_retry_at,
        )
        logger.info(
            "anchor_receipt_pending proof_id=%s next_check=%s",
            proof_id, next_retry_at.isoformat(),
        )

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
        next_retry_at = datetime.now(UTC) + backoff
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
        try:
            from api.observability import anchor_submissions_total

            anchor_submissions_total.labels(outcome="failed").inc()
        except ImportError:
            pass

    async def _retry_pending_proofs(self):
        pending = await self.db.get_pending_proofs()

        for proof in pending:
            status = proof.get("status")
            tx_hash = proof.get("transaction_hash")
            logger.info(
                "anchor_cycle proof_id=%s status=%s tx=%s retry_count=%s",
                proof["id"], status, tx_hash, proof["retry_count"],
            )

            await self._submit_to_blockchain(
                proof_id=proof["id"],
                merkle_root=proof["root_hash"],
                log_count=len(proof["leaf_hashes"]),
                start_timestamp=proof["start_timestamp"],
                end_timestamp=proof["end_timestamp"],
                current_retry_count=proof["retry_count"],
                transaction_hash=tx_hash,
                submission_nonce=proof.get("submission_nonce"),
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


if __name__ == "__main__":
    asyncio.run(main())
