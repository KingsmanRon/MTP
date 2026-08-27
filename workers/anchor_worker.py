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
from collections.abc import AsyncIterator, Callable, Iterator, Mapping, Sequence
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
# Read-only failover endpoints, comma or whitespace separated. The primary above
# remains the *only* endpoint that ever signs or broadcasts; these are consulted,
# in order, when the primary cannot serve a read (HTTP 403/429/5xx, transport
# failure, or an open circuit breaker). A transaction that was broadcast
# successfully must still be able to reconcile when the primary starts refusing
# receipt and contract-state reads, so reconciliation reads are allowed to leave
# the primary. Every read endpoint is chain-id verified before its answers are
# trusted, so a wrong-chain fallback can never fabricate confirmation evidence.
BLOCKCHAIN_READ_PROVIDER_URLS_RAW = os.getenv("BLOCKCHAIN_READ_PROVIDER_URLS") or os.getenv(
    "BLOCKCHAIN_READ_PROVIDER_URL", ""
)
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
# Reconciliation policy for a proof whose chain state could not be *read*.
# An unavailable provider is not a failed transaction, so those attempts do not
# consume the retry budget and never dead-letter the proof. They re-poll on this
# fixed interval instead of the exponential failure backoff, because the proof is
# waiting on the provider to come back rather than backing off a real fault.
RECONCILIATION_INTERVAL_SECONDS = int(os.getenv("ANCHOR_RECONCILIATION_INTERVAL", "60"))
if RECONCILIATION_INTERVAL_SECONDS < 1:
    raise ValueError("ANCHOR_RECONCILIATION_INTERVAL must be at least one second")
# The worker wakes early for a due retry instead of sleeping the full batch
# interval, so the reconciliation interval above is the real re-poll cadence
# rather than a value the outer loop rounds up to ANCHOR_INTERVAL_MINUTES.
# This floor stops a persistently overdue row from turning that into a spin.
MIN_CYCLE_DELAY_SECONDS = float(os.getenv("ANCHOR_MIN_CYCLE_DELAY", "5"))
if MIN_CYCLE_DELAY_SECONDS <= 0:
    raise ValueError("ANCHOR_MIN_CYCLE_DELAY must be greater than zero")
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


class RpcAvailabilityError(RuntimeError):
    """No configured RPC endpoint could serve a read.

    This is a statement about the providers, never about the transaction. A
    transaction we already broadcast is not failed, reverted, or absent merely
    because an endpoint answered ``403 Forbidden`` when asked for its receipt.
    Callers must therefore never treat this as evidence, never rebroadcast on
    it, and never dead-letter a proof because of it.
    """

    def __init__(
        self,
        operation: str,
        failures: Sequence[str],
    ) -> None:
        detail = "; ".join(failures) if failures else "no read endpoint configured"
        super().__init__(f"rpc_read_unavailable during {operation}: {detail}")
        self.operation = operation
        self.failures = tuple(failures)


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


TransactionState = Literal["none", "not_found", "reverted", "unknown"]


@dataclass(frozen=True)
class ReconciliationResult:
    """Result of checking an existing transaction and the registry state.

    ``transaction_state`` distinguishes *evidence* from *silence*:

    ``none``
        No persisted hash to check, or the receipt confirmed the anchor.
    ``not_found``
        A node looked and has no receipt for the hash.
    ``reverted``
        A node returned a receipt with a failed status.
    ``unknown``
        No endpoint could serve the receipt read. Nothing was learned about
        the transaction, so it must not be replaced or rebroadcast.
    """

    confirmation: AnchorConfirmation | None
    transaction_state: TransactionState


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


# HTTP statuses that describe the *endpoint*, not the transaction. A JSON-RPC
# node that has the receipt answers 200 with a JSON body; a node that returns one
# of these never looked at our transaction at all. 403 is the one this list
# exists for: managed and public Base endpoints return it for IP, referrer, and
# plan-level blocks, and reading it as "the transaction is gone" would rebroadcast
# a transaction that is already mined.
_RPC_AVAILABILITY_STATUS_CODES = frozenset({401, 402, 403, 404, 405, 407, 408, 429, 451})
_RPC_AVAILABILITY_MESSAGE_FRAGMENTS = (
    "forbidden",
    "access denied",
    "unauthorized",
    "not authorized",
    "too many requests",
    "rate limit",
    "quota",
    "timed out",
    "timeout",
    "connection reset",
    "connection aborted",
    "connection refused",
    "temporarily unavailable",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
    "upstream connect error",
    "cloudflare",
)


def is_rpc_availability_error(exc: BaseException) -> bool:
    """Return True when the RPC endpoint failed to answer, rather than answered.

    An availability failure carries no information about the transaction. It
    must never be read as "not mined", "reverted", or "never broadcast".
    ``TransactionNotFound`` is deliberately excluded: that is a real answer
    from a node that looked, and the reconciliation path treats it as evidence.
    """

    if isinstance(exc, (TransactionNotFound, AnchorEvidenceError, DeterministicContractRevert)):
        return False
    if isinstance(exc, (RpcAvailabilityError, RpcCircuitOpenError)):
        return True
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    if is_transport_error(exc):
        return True
    status = _http_status_from_exception(exc)
    if status is not None and (status in _RPC_AVAILABILITY_STATUS_CODES or status >= 500):
        return True
    message = str(exc).lower()
    return any(fragment in message for fragment in _RPC_AVAILABILITY_MESSAGE_FRAGMENTS)


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
# How long a read endpoint's chain-id verdict is trusted before it is checked
# again. Caching it for the life of the process would let a provider that is
# re-pointed mid-run — DNS hijack, an operator editing a load balancer — start
# supplying evidence from another chain on the strength of one old answer.
CHAIN_ID_RECHECK_SECONDS = float(os.getenv("ANCHOR_RPC_CHAIN_ID_RECHECK_SECONDS", "300"))
if CHAIN_ID_RECHECK_SECONDS < 0:
    raise ValueError("ANCHOR_RPC_CHAIN_ID_RECHECK_SECONDS must be non-negative")


def validate_rpc_url(url: str) -> str:
    """Return ``url`` when it is a usable RPC endpoint, else raise.

    Mirrors the network-URL guard the verification tooling uses: http(s) only,
    a real host, no embedded credentials, and plain http only for loopback.
    Provider API keys live in the path or query of most managed endpoints, so
    those are preserved untouched — only userinfo credentials are rejected.
    """

    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError(f"RPC URL must use http or https and include a host: {url!r}")
    if parts.username or parts.password:
        raise ValueError("RPC URL must not embed credentials in the host component")
    if parts.scheme == "http" and parts.hostname.lower() not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        raise ValueError("non-local RPC URLs must use https")
    return url


def parse_read_provider_urls(raw: str | None, *, primary_url: str) -> tuple[str, ...]:
    """Return the ordered read-failover endpoints declared by configuration.

    The primary is always the first endpoint the read path tries, so it is
    filtered out of the failover list rather than being consulted twice.
    Duplicates are collapsed while preserving the operator's ordering.
    """

    if not raw:
        return ()
    seen = {primary_url.strip()}
    endpoints: list[str] = []
    for candidate in re.split(r"[\s,]+", raw.strip()):
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        endpoints.append(validate_rpc_url(candidate))
    return tuple(endpoints)


def redacted_rpc_url(url: str) -> str:
    """Return an RPC URL safe to log: scheme, host, and port only.

    Managed providers put the API key in the path (``/v2/<key>``) or the query,
    so anything past the authority is dropped rather than printed into logs.
    """

    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable-rpc-url>"
    if not parts.hostname:
        return "<unparseable-rpc-url>"
    authority = parts.hostname
    if parts.port:
        authority = f"{authority}:{parts.port}"
    suffix = "/…" if parts.path.strip("/") or parts.query else ""
    return f"{parts.scheme}://{authority}{suffix}"


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


@dataclass(frozen=True)
class _ContractStateRead:
    """Outcome of confirming a root from AnchorRegistry state alone."""

    confirmation: "AnchorConfirmation | None"
    #: At least one healthy endpoint answered ``isAnchored``. When false, the
    #: registry was not read at all and nothing here is a finding.
    answered: bool
    #: Every healthy endpoint agreed the root is absent. Only meaningful when
    #: ``confirmation`` is None.
    absence_corroborated: bool
    failures: tuple[str, ...] = ()


@dataclass(frozen=True)
class _RegistryEvidence:
    """AnchorRegistry state for one root, and where it came from.

    ``endpoint`` is the node that reported the root anchored. Follow-up reads
    are steered back to it so a lagging node cannot supply half the evidence.
    ``absence_corroborated`` is only meaningful when ``batch`` is None: it says
    whether every healthy endpoint agreed the root is absent, or whether some
    of them simply could not be reached.
    """

    batch: dict[str, Any] | None
    endpoint: "_RpcEndpoint | None"
    absence_corroborated: bool
    answered: bool = True
    failures: tuple[str, ...] = ()


@dataclass
class _ReadLedger:
    """Which endpoints answered one question, and which could not.

    Absence is only trustworthy when it is corroborated. A single node that
    answers "no receipt" or "not anchored" may simply be lagging behind the
    chain, so the worker records *who* answered before it acts on a negative.
    """

    answered: list[str] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    def record_answer(self, endpoint: "_RpcEndpoint") -> None:
        self.answered.append(endpoint.label)

    def record_unavailable(self, endpoint: "_RpcEndpoint", detail: str) -> None:
        self.unavailable.append(endpoint.label)
        self.failures.append(f"{endpoint.label}: {detail}")

    def record_unusable(self, endpoint: "_RpcEndpoint", detail: str) -> None:
        """Note an endpoint that is not a healthy participant at all.

        A wrong-chain endpoint is excluded from the vote rather than counted
        as missing from it: it is never going to answer, so waiting for its
        corroboration would strand every proof forever.
        """

        self.failures.append(f"{endpoint.label}: {detail}")

    @property
    def corroborated(self) -> bool:
        """True when every healthy endpoint answered the question."""

        return bool(self.answered) and not self.unavailable


@dataclass
class _RpcEndpoint:
    """One RPC endpoint the read path may consult.

    Each endpoint carries its own circuit breaker so a dead fallback is not
    hammered on every read, and its own chain-id verdict so a wrong-chain
    endpoint can never contribute confirmation evidence.
    """

    label: str
    url: str
    w3: Web3
    contract: Any
    breaker: RpcCircuitBreaker
    is_primary: bool
    chain_verified_at: float | None = None
    disabled_reason: str | None = None


class BlockchainService:
    """
    Service for interacting with the Base L2 blockchain.

    Writes (gas estimation, signing, broadcast) only ever use the primary
    endpoint. Reads used for reconciliation may fail over to the configured
    read endpoints, because a transaction that was broadcast successfully must
    still be able to reach ``confirmed`` when the primary starts refusing
    receipt and contract-state reads.
    """

    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        private_key: str,
        expected_chain_id: int = BASE_CHAIN_ID,
        read_rpc_urls: Sequence[str] = (),
    ):
        # The primary URL is deployment configuration that predates this guard
        # and may legitimately be a private plaintext node, so it is taken as
        # given. The read-failover URLs are a new surface and are validated.
        self.rpc_url = rpc_url
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
        # The primary is always read endpoint #0. Its ``w3``/``contract`` are
        # refreshed from the service attributes on every read so operator
        # tooling that swaps ``service.w3`` still routes through this pool.
        self._endpoints: list[_RpcEndpoint] = [
            _RpcEndpoint(
                label="primary",
                url=self.rpc_url,
                w3=self.w3,
                contract=self.contract,
                breaker=self._breaker,
                is_primary=True,
            )
        ]
        for index, read_url in enumerate(read_rpc_urls, start=1):
            validated = validate_rpc_url(read_url)
            read_w3 = Web3(Web3.HTTPProvider(validated))
            self._endpoints.append(
                _RpcEndpoint(
                    label=f"read-{index}",
                    url=validated,
                    w3=read_w3,
                    contract=read_w3.eth.contract(
                        address=self.contract_address,
                        abi=ANCHOR_REGISTRY_ABI,
                    ),
                    breaker=RpcCircuitBreaker(
                        threshold=RPC_BREAKER_THRESHOLD,
                        open_duration_seconds=RPC_BREAKER_OPEN_SECONDS,
                        enabled=RPC_BREAKER_ENABLED,
                    ),
                    is_primary=False,
                )
            )
        logger.info(f"Blockchain service initialized. Address: {self.account.address}")
        logger.info(
            "RPC endpoints: primary=%s read_failover=%s",
            redacted_rpc_url(self.rpc_url),
            [redacted_rpc_url(endpoint.url) for endpoint in self._endpoints[1:]] or "none",
        )
        if len(self._endpoints) == 1:
            logger.warning(
                "No BLOCKCHAIN_READ_PROVIDER_URLS configured. A broadcast "
                "transaction cannot reconcile while the primary RPC refuses "
                "receipt reads (for example HTTP 403)."
            )
        logger.info(
            "RPC circuit breaker: enabled=%s threshold=%d open_seconds=%.1f",
            RPC_BREAKER_ENABLED,
            RPC_BREAKER_THRESHOLD,
            RPC_BREAKER_OPEN_SECONDS,
        )

    def _rpc(self, fn: Callable[[], _T]) -> _T:
        """Route a primary-endpoint RPC call through the circuit breaker.

        Every write — gas estimation, signing inputs, broadcast — stays here.
        Reads that must survive a degraded primary use :meth:`_read` instead.
        """
        return self._breaker.call(fn)

    # -- read failover -----------------------------------------------------

    def _read_endpoints(self) -> Iterator[_RpcEndpoint]:
        """Yield usable read endpoints, primary first."""

        primary = self._endpoints[0]
        primary.w3 = self.w3
        primary.contract = self.contract
        for endpoint in self._endpoints:
            if endpoint.disabled_reason is None:
                yield endpoint

    def _verify_endpoint_chain(self, endpoint: _RpcEndpoint) -> None:
        """Confirm an endpoint serves the expected chain before trusting it.

        A fallback pointed at the wrong chain would otherwise be able to
        manufacture a ``BatchAnchored`` event and a registry entry for a root we
        never anchored on Base. A mismatch permanently disables that endpoint
        for this process; it is a configuration fault, not a transient one.
        """

        now = time.monotonic()
        if (
            endpoint.chain_verified_at is not None
            and now - endpoint.chain_verified_at < CHAIN_ID_RECHECK_SECONDS
        ):
            return
        actual = int(endpoint.breaker.call(lambda: endpoint.w3.eth.chain_id))
        if actual != self.expected_chain_id:
            endpoint.disabled_reason = (
                f"serves chain {actual}, expected {self.expected_chain_id}"
            )
            logger.error(
                "anchor_rpc_endpoint_disabled endpoint=%s url=%s reason=%s",
                endpoint.label,
                redacted_rpc_url(endpoint.url),
                endpoint.disabled_reason,
            )
            raise RuntimeError(
                f"RPC chain-id mismatch on {endpoint.label}: expected "
                f"{self.expected_chain_id} (BASE_CHAIN_ID), got {actual}."
            )
        endpoint.chain_verified_at = now

    def _ready_endpoints(
        self,
        operation: str,
        ledger: _ReadLedger,
        *,
        prefer: _RpcEndpoint | None = None,
    ) -> Iterator[_RpcEndpoint]:
        """Yield chain-verified endpoints, recording those that cannot serve.

        ``prefer`` moves one endpoint to the front. Callers use it to keep a
        multi-read sequence on the node that already proved it has the data,
        so a lagging node cannot answer half of one question.
        """

        ordered = list(self._read_endpoints())
        if prefer is not None:
            ordered = [prefer, *(e for e in ordered if e is not prefer)]
        for endpoint in ordered:
            try:
                self._verify_endpoint_chain(endpoint)
            except BaseException as exc:
                if endpoint.disabled_reason is not None:
                    # Wrong chain. Not a healthy endpoint, so it neither
                    # answers nor withholds — it simply does not participate.
                    ledger.record_unusable(endpoint, endpoint.disabled_reason)
                    continue
                if not is_rpc_availability_error(exc):
                    raise
                ledger.record_unavailable(endpoint, f"chain-id read: {exc}")
                self._record_read_failover(endpoint, operation)
                continue
            yield endpoint

    def _read(
        self,
        operation: str,
        call: Callable[[_RpcEndpoint], _T],
        *,
        prefer: _RpcEndpoint | None = None,
    ) -> _T:
        """Run a read against the first endpoint that can serve it.

        Only availability failures advance to the next endpoint. Any answer
        that carries information about the chain — an evidence mismatch, a
        revert — is raised immediately, because failing over on it would just
        ask a second node the same answered question.

        Use this for reads whose answer is self-validating. Reads whose
        *negative* answer would drive a decision — "no receipt", "not
        anchored" — must poll every endpoint instead; see
        :meth:`_poll_transaction_receipt` and :meth:`_anchored_endpoint`.

        Raises :class:`RpcAvailabilityError` when no endpoint could answer.
        """

        ledger = _ReadLedger()
        for endpoint in self._ready_endpoints(operation, ledger, prefer=prefer):
            try:
                return endpoint.breaker.call(lambda bound=endpoint: call(bound))
            except BaseException as exc:
                if not is_rpc_availability_error(exc):
                    raise
                self._note_unavailable(endpoint, operation, ledger, exc)
        raise RpcAvailabilityError(operation, ledger.failures)

    def _note_unavailable(
        self,
        endpoint: _RpcEndpoint,
        operation: str,
        ledger: _ReadLedger,
        exc: BaseException,
    ) -> None:
        ledger.record_unavailable(endpoint, f"{type(exc).__name__}: {exc}")
        logger.warning(
            "anchor_rpc_read_unavailable endpoint=%s url=%s operation=%s error=%s",
            endpoint.label,
            redacted_rpc_url(endpoint.url),
            operation,
            exc,
        )
        self._record_read_failover(endpoint, operation)

    def _poll_transaction_receipt(
        self,
        transaction_hash: str,
    ) -> tuple[Mapping[str, Any] | None, _RpcEndpoint | None, _ReadLedger]:
        """Ask every usable endpoint for one transaction's receipt.

        Returns as soon as an endpoint produces a *successful* receipt — that
        is a positive fact and no second opinion can overturn it. Absence, by
        contrast, is only reported once every healthy endpoint has been asked:
        one lagging node has no standing to declare a mined transaction gone,
        and acting on its silence is how a broadcast transaction gets replaced.
        """

        ledger = _ReadLedger()
        reverted: tuple[Mapping[str, Any], _RpcEndpoint] | None = None
        for endpoint in self._ready_endpoints("get_transaction_receipt", ledger):
            try:
                receipt = endpoint.breaker.call(
                    lambda bound=endpoint: bound.w3.eth.get_transaction_receipt(transaction_hash)
                )
            except TransactionNotFound:
                # A real answer from a node that looked, but only one vote.
                ledger.record_answer(endpoint)
                continue
            except BaseException as exc:
                if not is_rpc_availability_error(exc):
                    raise
                self._note_unavailable(endpoint, "get_transaction_receipt", ledger, exc)
                continue
            ledger.record_answer(endpoint)
            if int(receipt.get("status", 0)) == 1:
                if len(ledger.answered) > 1:
                    logger.info(
                        "anchor_receipt_found_on_failover endpoint=%s transaction_hash=%s",
                        endpoint.label,
                        transaction_hash,
                    )
                return receipt, endpoint, ledger
            if reverted is None:
                reverted = (receipt, endpoint)
        if reverted is not None:
            return reverted[0], reverted[1], ledger
        return None, None, ledger

    def _anchored_endpoint(
        self,
        root_bytes: bytes,
        *,
        prefer: _RpcEndpoint | None = None,
    ) -> tuple[_RpcEndpoint | None, _ReadLedger]:
        """Find an endpoint that reports this root anchored.

        ``isAnchored=false`` from one node is not proof of absence either — it
        may be behind the block that anchored the root. Every healthy endpoint
        is asked before the registry is reported empty.
        """

        ledger = _ReadLedger()
        for endpoint in self._ready_endpoints("isAnchored", ledger, prefer=prefer):
            try:
                anchored = endpoint.breaker.call(
                    lambda bound=endpoint: bound.contract.functions.isAnchored(root_bytes).call()
                )
            except BaseException as exc:
                if not is_rpc_availability_error(exc):
                    raise
                self._note_unavailable(endpoint, "isAnchored", ledger, exc)
                continue
            ledger.record_answer(endpoint)
            if anchored:
                if len(ledger.answered) > 1:
                    logger.info(
                        "anchor_registry_found_on_failover endpoint=%s root=%s",
                        endpoint.label,
                        root_bytes.hex(),
                    )
                return endpoint, ledger
        return None, ledger

    @staticmethod
    def _record_read_failover(endpoint: _RpcEndpoint, operation: str) -> None:
        try:
            from api.observability import anchor_rpc_read_failover_total

            anchor_rpc_read_failover_total.labels(
                endpoint=endpoint.label,
                operation=operation,
            ).inc()
        except ImportError:  # pragma: no cover — metrics are optional
            pass

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
        *,
        prefer: _RpcEndpoint | None = None,
    ) -> _RegistryEvidence:
        """Return validated registry state for a root, polling every endpoint.

        The validation itself is unchanged: log count and the timestamp window
        must match the persisted proof exactly. What changed is who is allowed
        to answer "not anchored" — now only the whole healthy set, together.
        """

        root_bytes = self._root_bytes(merkle_root)
        anchored_at, ledger = self._anchored_endpoint(root_bytes, prefer=prefer)
        if anchored_at is None:
            return _RegistryEvidence(
                batch=None,
                endpoint=None,
                absence_corroborated=ledger.corroborated,
                answered=bool(ledger.answered),
                failures=tuple(ledger.failures),
            )
        result = self._read(
            "getBatchFull",
            lambda endpoint: endpoint.contract.functions.getBatchFull(root_bytes).call(),
            prefer=anchored_at,
        )
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
        return _RegistryEvidence(
            batch={
                "batch_id": int(batch_id),
                "log_count": int(stored_log_count),
                "timestamp": datetime.fromtimestamp(int(timestamp), tz=UTC),
                "block_number": int(block_number),
                "start_timestamp": int(stored_start),
                "end_timestamp": int(stored_end),
                "submitter": Web3.to_checksum_address(submitter),
            },
            endpoint=anchored_at,
            absence_corroborated=False,
        )

    def _confirmation_from_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        merkle_root: str,
        log_count: int,
        start_timestamp: datetime,
        end_timestamp: datetime,
        source: Literal["transaction_receipt", "contract_state"],
        prefer: _RpcEndpoint | None = None,
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
        evidence = self._validated_batch(
            merkle_root,
            log_count,
            start_timestamp,
            end_timestamp,
            prefer=prefer,
        )
        batch = evidence.batch
        if batch is None:
            if not evidence.absence_corroborated:
                # We hold a successful receipt but could not reach every node
                # to cross-check the registry. That is a read gap, not a
                # contradiction, so it must not surface as an evidence error.
                raise RpcAvailabilityError(
                    "isAnchored",
                    evidence.failures
                    or ("registry could not be cross-checked against a successful receipt",),
                )
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
        prefer: _RpcEndpoint | None = None,
    ) -> _ContractStateRead:
        """Confirm from registry state alone.

        Reports whether the registry was read at all, and whether an *absent*
        root was corroborated by every healthy endpoint. An uncorroborated
        absence is not a fact the caller may act on.
        """

        evidence = self._validated_batch(
            merkle_root,
            log_count,
            start_timestamp,
            end_timestamp,
            prefer=prefer,
        )
        batch = evidence.batch
        if batch is None:
            return _ContractStateRead(
                confirmation=None,
                answered=evidence.answered,
                absence_corroborated=evidence.absence_corroborated,
                failures=evidence.failures,
            )
        # Every follow-up read is steered to the node that reported the root
        # anchored: it demonstrably has the block, and a node that is behind
        # would answer the log query with an empty set.
        source_endpoint = evidence.endpoint
        root_topic = "0x" + merkle_root.removeprefix("0x").lower()
        event_logs = self._read(
            "get_logs",
            lambda endpoint: endpoint.w3.eth.get_logs(
                {
                    "fromBlock": batch["block_number"],
                    "toBlock": batch["block_number"],
                    "address": self.contract_address,
                    "topics": ["0x" + _BATCH_ANCHORED_TOPIC, None, root_topic],
                }
            ),
            prefer=source_endpoint,
        )
        if len(event_logs) != 1:
            raise AnchorEvidenceError(
                "Registry reports the root anchored but its block does not contain "
                f"exactly one matching event; found {len(event_logs)}"
            )
        transaction_hash = normalize_transaction_hash(event_logs[0]["transactionHash"])
        receipt, receipt_endpoint, ledger = self._poll_transaction_receipt(transaction_hash)
        if receipt is None:
            raise RpcAvailabilityError(
                "get_transaction_receipt",
                tuple(ledger.failures)
                or (
                    "registry reports the root anchored but no endpoint served "
                    f"the receipt for {transaction_hash}",
                ),
            )
        return _ContractStateRead(
            confirmation=self._confirmation_from_receipt(
                receipt,
                merkle_root=merkle_root,
                log_count=log_count,
                start_timestamp=start_timestamp,
                end_timestamp=end_timestamp,
                source="contract_state",
                prefer=receipt_endpoint or source_endpoint,
            ),
            answered=True,
            absence_corroborated=False,
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
        """Check the persisted transaction first, then registry state.

        The already-persisted hash is the strongest identity we hold, so it is
        always the first question asked. Its receipt is validated exactly as
        before — ``BatchAnchored`` event, then AnchorRegistry state — and only
        after it fails to answer do we ask the registry directly.

        Every read is served by :meth:`_read`, so a primary that answers
        ``403 Forbidden`` falls through to the configured read endpoints. If no
        endpoint can serve the receipt, the state is ``unknown``: the caller
        learns nothing about the transaction and must not replace it. Chain-id
        is verified per endpoint inside :meth:`_read`, so no wrong-chain node
        can contribute evidence here.
        """

        transaction_state: TransactionState = "none"
        receipt_absence_corroborated = True
        evidence_endpoint: _RpcEndpoint | None = None
        if transaction_hash:
            receipt, evidence_endpoint, ledger = self._poll_transaction_receipt(transaction_hash)
            if receipt is not None and int(receipt.get("status", 0)) == 1:
                return ReconciliationResult(
                    confirmation=self._confirmation_from_receipt(
                        receipt,
                        merkle_root=merkle_root,
                        log_count=log_count,
                        start_timestamp=start_timestamp,
                        end_timestamp=end_timestamp,
                        source="transaction_receipt",
                        prefer=evidence_endpoint,
                    ),
                    transaction_state="none",
                )
            if receipt is not None:
                # A node returned a receipt with a failed status. That is an
                # observation, not silence, so it stands as evidence.
                transaction_state = "reverted"
            else:
                receipt_absence_corroborated = ledger.corroborated
                # "Nobody has a receipt" only means the transaction is absent
                # if everyone healthy was asked and everyone agreed. Otherwise
                # a lagging or unreachable node is being read as a verdict.
                transaction_state = "not_found" if ledger.corroborated else "unknown"
                if not ledger.corroborated:
                    logger.warning(
                        "anchor_receipt_absence_uncorroborated transaction_hash=%s "
                        "answered=%s unavailable=%s",
                        transaction_hash,
                        ledger.answered or "none",
                        ledger.unavailable or "none",
                    )

        # An RpcAvailabilityError from inside here propagates on purpose: a
        # partial registry read is a provider outage, not an empty registry.
        registry = self._confirmation_from_contract_state(
            merkle_root=merkle_root,
            log_count=log_count,
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
            prefer=evidence_endpoint,
        )
        if registry.confirmation is not None:
            return ReconciliationResult(confirmation=registry.confirmation, transaction_state="none")

        if not registry.answered:
            # Neither the receipt nor the registry was readable anywhere. The
            # caller must see a provider outage, not an empty result it could
            # mistake for "this batch was never anchored".
            raise RpcAvailabilityError(
                "isAnchored",
                registry.failures or ("no endpoint could serve the registry read",),
            )

        if transaction_state == "not_found" and not registry.absence_corroborated:
            # The receipt is corroborated absent, but the registry could not be
            # polled in full. Replacing a broadcast transaction needs both
            # halves of the picture, so this stays "nothing was learned".
            logger.warning(
                "anchor_registry_absence_uncorroborated transaction_hash=%s merkle_root=%s",
                transaction_hash,
                merkle_root,
            )
            transaction_state = "unknown"
        if transaction_hash and not receipt_absence_corroborated:
            logger.info(
                "anchor_registry_root_absent_after_receipt_read_failure "
                "transaction_hash=%s merkle_root=%s",
                transaction_hash,
                merkle_root,
            )
        return ReconciliationResult(
            confirmation=None,
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
        loop = asyncio.get_event_loop()
        try:
            receipt = await loop.run_in_executor(
                None,
                lambda: self._rpc(
                    lambda: self.w3.eth.wait_for_transaction_receipt(
                        prepared.transaction_hash,
                        timeout=120,
                    )
                ),
            )
        except BaseException as exc:
            if not is_rpc_availability_error(exc):
                raise
            # The transaction is already on the wire. The primary refusing to
            # serve its receipt (HTTP 403, rate limit, open breaker, poll
            # timeout) is a provider problem, so ask the read endpoints for the
            # same hash instead of giving up on the broadcast.
            logger.warning(
                "anchor_receipt_wait_unavailable transaction_hash=%s error=%s",
                prepared.transaction_hash,
                exc,
            )
            return await loop.run_in_executor(
                None,
                lambda: self.reconcile_anchor(
                    merkle_root=merkle_root,
                    log_count=log_count,
                    start_timestamp=start_timestamp,
                    end_timestamp=end_timestamp,
                    transaction_hash=prepared.transaction_hash,
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
        result = self._read(
            "getBatch",
            lambda endpoint: endpoint.contract.functions.getBatch(root_bytes).call(),
        )
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
        """Return persistent proof counts that operators alert on.

        ``awaiting_reconciliation`` counts proofs that hold a transaction hash
        but no confirmation. Those never become ``failed`` or ``dead_letter``
        while only *reads* are failing, so without this count an anchor stuck
        behind an unreadable RPC would be invisible on the dashboards.
        """

        query = """
            SELECT
                count(*) FILTER (WHERE status = 'failed') AS failed,
                count(*) FILTER (WHERE status = 'dead_letter') AS dead_letter,
                count(*) FILTER (
                    WHERE status IN ('prepared', 'submitted')
                      AND transaction_hash IS NOT NULL
                ) AS awaiting_reconciliation
            FROM merkle_proofs
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(query)
        return {
            "failed": int(row["failed"] or 0),
            "dead_letter": int(row["dead_letter"] or 0),
            "awaiting_reconciliation": int(row["awaiting_reconciliation"] or 0),
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
        status: Literal["failed", "prepared", "submitted", "pending"],
        error_message: str,
        next_retry_at: datetime,
        increment_retry: bool = True,
    ) -> None:
        """Re-queue a proof.

        ``increment_retry=False`` is used when the attempt failed because the
        RPC could not be read. The retry budget exists to bound *real* faults;
        spending it on a provider outage would eventually strand a proof
        outside the ``retry_count < MAX_RETRIES`` window of
        :meth:`get_retryable_proofs` even though nothing about it ever failed.
        """

        query = """
            UPDATE merkle_proofs
            SET status = $2,
                error_message = $3,
                next_retry_at = $4,
                retry_count = retry_count + CASE WHEN $5::boolean THEN 1 ELSE 0 END
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
                increment_retry,
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

    async def get_next_retry_due_at(self) -> datetime | None:
        """Earliest ``next_retry_at`` among proofs the retry query will take.

        The predicate is deliberately identical to
        :meth:`get_retryable_proofs`. A time reported here that the retry query
        would then skip would wake the worker forever for a row it never
        touches.
        """

        query = """
            SELECT min(next_retry_at) AS due_at
            FROM merkle_proofs
            WHERE status IN ('pending', 'prepared', 'submitted', 'failed')
              AND (
                    status IN ('prepared', 'submitted')
                    OR retry_count < $1
              )
              AND next_retry_at IS NOT NULL
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(query, MAX_RETRIES)
        return row["due_at"] if row else None

    async def get_pending_proofs(self) -> list[dict[str, Any]]:
        """Backward-compatible name for the state-aware retry query."""

        return await self.get_retryable_proofs()

    async def get_reconcilable_proofs(self) -> list[dict[str, Any]]:
        """Return every proof whose on-chain outcome is still unresolved.

        Includes ``dead_letter`` rows: a proof that was dead-lettered by an
        older build, or by a fault unrelated to the chain, may still have a
        transaction sitting confirmed on Base. Reconciliation never broadcasts,
        so sweeping these is safe.
        """

        query = """
            SELECT id, root_hash, leaf_hashes, log_count, retry_count,
                   start_timestamp, end_timestamp, status,
                   transaction_hash, submission_nonce, prepared_at,
                   submitted_at, contract_address, chain_id,
                   dead_lettered_at, error_message
            FROM merkle_proofs
            WHERE status IN ('prepared', 'submitted', 'failed', 'dead_letter')
            ORDER BY created_at ASC
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query)
        return [dict(row) for row in rows]

    async def get_proof_by_transaction_hash(self, transaction_hash: str) -> dict[str, Any] | None:
        """Find a proof by the transaction identity persisted before broadcast.

        This is the lookup an operator has after reading a hash off a block
        explorer, which is usually all that is known when a broadcast
        transaction is confirmed on chain but stale in the database.
        """

        query = """
            SELECT id, root_hash, leaf_hashes, log_count, retry_count,
                   start_timestamp, end_timestamp, status,
                   transaction_hash, submission_nonce, prepared_at,
                   submitted_at, contract_address, chain_id,
                   dead_lettered_at, error_message
            FROM merkle_proofs
            WHERE lower(transaction_hash) = lower($1)
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(query, transaction_hash)
        return dict(row) if row else None

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

                if await self._wait_for_next_cycle(await self._next_cycle_delay()):
                    break
        finally:
            heartbeat_task.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat_task

        logger.info("Anchor worker stopped")

    async def stop(self):
        logger.info("Stopping anchor worker...")
        self._running = False
        self._shutdown_event.set()

    async def _next_cycle_delay(self) -> float:
        """Seconds to sleep before the next cycle.

        The batch interval paces *new* batches. A proof waiting on
        reconciliation has its own, much shorter, due time, and sleeping past
        it would make ANCHOR_RECONCILIATION_INTERVAL a fiction: a 60-second
        re-poll would really happen every ANCHOR_INTERVAL_MINUTES. So the
        worker wakes at whichever comes first, floored so a row that is
        permanently overdue cannot spin the loop.
        """

        interval = float(self.interval_seconds)
        get_due_at = getattr(self.db, "get_next_retry_due_at", None)
        if get_due_at is None:
            return interval
        try:
            due_at = await get_due_at()
        except Exception:
            logger.exception("Failed to read the next reconciliation due time")
            return interval
        if due_at is None:
            return interval
        if due_at.tzinfo is None:
            due_at = due_at.replace(tzinfo=UTC)
        remaining = (due_at - datetime.now(UTC)).total_seconds()
        delay = max(MIN_CYCLE_DELAY_SECONDS, min(interval, remaining))
        if delay < interval:
            logger.debug(
                "anchor_cycle_wake_early delay_seconds=%.1f due_at=%s batch_interval=%.1f",
                delay,
                due_at.isoformat(),
                interval,
            )
        return delay

    async def _wait_for_next_cycle(self, delay: float) -> bool:
        """Sleep for ``delay``. Return True when shutdown was requested."""

        try:
            await asyncio.wait_for(self._shutdown_event.wait(), timeout=delay)
            return True
        except TimeoutError:
            return False

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

            for proof_status in ("failed", "dead_letter", "awaiting_reconciliation"):
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
        except RpcAvailabilityError as exc:
            # No endpoint could serve the read. This says nothing about the
            # transaction, so the proof keeps its state, keeps its retry
            # budget, and is never dead-lettered on account of it.
            if reconciliation_only:
                self._log_reconciliation_read_failure(proof, current_retry_count, exc)
                return False
            await self._record_read_unavailable(proof, current_retry_count, exc)
            return False
        except Exception as exc:
            if reconciliation_only:
                self._log_reconciliation_read_failure(proof, current_retry_count, exc)
                return False
            if is_rpc_availability_error(exc):
                # An open breaker, a bare transport error — same verdict: the
                # provider did not answer, so nothing was learned.
                await self._record_read_unavailable(proof, current_retry_count, exc)
                return False
            retry_status: Literal["failed", "prepared", "submitted"] = (
                "submitted" if proof.get("transaction_hash") else "failed"
            )
            await self._record_failure(
                proof_id,
                current_retry_count,
                f"reconciliation read failed: {exc}",
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
            # "unknown" and "not_found" must not read the same in an operator's
            # log: one means nobody answered, the other means somebody did.
            event = (
                "anchor_reconciliation_read_unavailable"
                if reconciliation.transaction_state == "unknown"
                else "anchor_reconciliation_not_found"
            )
            logger.warning(
                "%s proof_id=%s merkle_root=%s transaction_hash=%s nonce=%s "
                "retry_count=%s transaction_state=%s rpc_stage=read",
                event,
                proof_id,
                merkle_root,
                proof.get("transaction_hash"),
                proof.get("submission_nonce"),
                current_retry_count,
                reconciliation.transaction_state,
            )
            return False

        if proof.get("transaction_hash") and reconciliation.transaction_state not in (
            "not_found",
            "reverted",
        ):
            # A persisted hash with no receipt evidence means the read never
            # landed. Replacing here would be rebroadcasting on the strength of
            # an HTTP 403, which is exactly the failure this path exists to
            # prevent.
            await self._record_read_unavailable(
                proof,
                current_retry_count,
                RpcAvailabilityError(
                    "get_transaction_receipt",
                    ("no endpoint returned a receipt or a not-found answer",),
                ),
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
        except Exception as exc:
            if is_rpc_availability_error(exc):
                await self._record_read_unavailable(proof, current_retry_count, exc)
                return False
            await self._record_failure(
                proof_id,
                current_retry_count,
                f"balance read failed: {exc}",
            )
            return False

        try:
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
            except RpcAvailabilityError as exc:
                # The registry says this root exists. We simply cannot read the
                # evidence right now, which is not grounds for dead-lettering.
                await self._record_read_unavailable(proof, current_retry_count, exc)
                return False
            except Exception as exc:
                if is_rpc_availability_error(exc):
                    await self._record_read_unavailable(proof, current_retry_count, exc)
                    return False
                await self._record_terminal_failure(
                    proof_id,
                    f"RootAlreadyAnchored could not be validated: {exc}",
                )
                return False
            if reconciliation.confirmation is None:
                if reconciliation.transaction_state == "unknown":
                    # The registry disagrees with estimateGas only because the
                    # receipt could not be read. That is not a contradiction we
                    # are entitled to dead-letter on.
                    await self._record_read_unavailable(
                        proof,
                        current_retry_count,
                        RpcAvailabilityError(
                            "get_transaction_receipt",
                            ("receipt unreadable while validating RootAlreadyAnchored",),
                        ),
                    )
                    return False
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
            if is_rpc_availability_error(exc):
                await self._record_read_unavailable(proof, current_retry_count, exc)
                return False
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
        except Exception as exc:
            # The transaction is on the wire and its hash is already persisted.
            # Whatever went wrong while reading the receipt, the proof stays
            # ``submitted`` and reconciles on a later cycle — it is never
            # rebroadcast and never dead-lettered because of a read.
            broadcast_proof = dict(proof)
            broadcast_proof["transaction_hash"] = transaction_hash
            broadcast_proof["submission_nonce"] = prepared.nonce
            if isinstance(exc, RpcCircuitOpenError):
                logger.info(
                    "anchor_receipt_pending proof_id=%s merkle_root=%s "
                    "transaction_hash=%s nonce=%s retry_count=%s rpc_stage=receipt "
                    "cooldown_seconds=%.1f",
                    proof_id,
                    merkle_root,
                    transaction_hash,
                    prepared.nonce,
                    current_retry_count,
                    exc.cooldown_remaining_seconds,
                )
            else:
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
            if is_rpc_availability_error(exc):
                await self._record_read_unavailable(
                    broadcast_proof,
                    current_retry_count,
                    exc,
                )
                self._record_anchor_event("receipt_pending")
                return False
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

        if result.transaction_state != "reverted":
            # The transaction is broadcast and its outcome was never actually
            # observed — the receipt read did not land. It stays ``submitted``
            # and reconciles later; it is not a failure to count or bury.
            broadcast_proof = dict(proof)
            broadcast_proof["transaction_hash"] = transaction_hash
            broadcast_proof["submission_nonce"] = prepared.nonce
            await self._record_read_unavailable(
                broadcast_proof,
                current_retry_count,
                RpcAvailabilityError(
                    "get_transaction_receipt",
                    ("no endpoint returned a receipt for the broadcast transaction",),
                ),
            )
            self._record_anchor_event("receipt_pending")
            return False

        await self._record_failure(
            proof_id,
            current_retry_count,
            "Broadcast transaction reverted and registry root is absent",
            status="failed",
        )
        return False

    @staticmethod
    def _log_reconciliation_read_failure(
        proof: Mapping[str, Any],
        current_retry_count: int,
        exc: BaseException,
    ) -> None:
        logger.error(
            "anchor_reconciliation_failed proof_id=%s merkle_root=%s "
            "transaction_hash=%s nonce=%s retry_count=%s rpc_stage=read error=%s",
            proof["id"],
            proof["root_hash"],
            proof.get("transaction_hash"),
            proof.get("submission_nonce"),
            current_retry_count,
            exc,
        )

    async def _record_read_unavailable(
        self,
        proof: Mapping[str, Any],
        current_retry_count: int,
        exc: BaseException,
    ) -> None:
        """Re-queue a proof whose chain state could not be read.

        An unreadable provider is not a failed transaction. So this path:

        * keeps the proof in a live state (``submitted`` once a hash exists),
        * does not spend the retry budget, so the proof stays selectable,
        * never dead-letters, and
        * never reaches the broadcast path.

        Re-polling uses the fixed ``ANCHOR_RECONCILIATION_INTERVAL`` rather than
        the exponential failure backoff: the proof is waiting for a provider to
        come back, not backing off a fault of its own.
        """

        proof_id = proof["id"]
        transaction_hash = proof.get("transaction_hash")
        if transaction_hash:
            status: Literal["failed", "prepared", "submitted", "pending"] = (
                "prepared"
                if proof.get("status") == "prepared" and not proof.get("submitted_at")
                else "submitted"
            )
        else:
            current_status = str(proof.get("status") or "pending")
            status = "pending" if current_status in ("pending", "confirmed") else "failed"
        next_retry_at = datetime.now(UTC) + timedelta(seconds=RECONCILIATION_INTERVAL_SECONDS)
        logger.warning(
            "anchor_read_unavailable proof_id=%s merkle_root=%s transaction_hash=%s "
            "nonce=%s retry_count=%s status=%s rpc_stage=read next_retry_at=%s error=%s",
            proof_id,
            proof["root_hash"],
            transaction_hash,
            proof.get("submission_nonce"),
            current_retry_count,
            status,
            next_retry_at.isoformat(),
            exc,
        )
        # Both markers stay greppable: operators have alerted on
        # ``rpc_circuit_open`` since the breaker shipped, and
        # ``rpc_read_unavailable`` is the wider class it now belongs to.
        markers = "rpc_read_unavailable"
        if isinstance(exc, RpcCircuitOpenError):
            markers = f"{markers} rpc_circuit_open"
        await self.db.schedule_retry(
            proof_id,
            status=status,
            error_message=f"{markers} (retryable, not a transaction failure): {exc}",
            next_retry_at=next_retry_at,
            increment_retry=False,
        )
        self._record_anchor_event("read_unavailable")

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

    async def reconcile_transaction(self, transaction_hash: str) -> bool:
        """Reconcile the proof carrying ``transaction_hash``. Never broadcasts."""

        normalised = normalize_transaction_hash(transaction_hash)
        async with self.db.anchor_cycle_lock() as acquired:
            if not acquired:
                raise RuntimeError("Another anchor worker owns the reconciliation lock")
            proof = await self.db.get_proof_by_transaction_hash(normalised)
            if proof is None:
                raise ValueError(f"No merkle proof holds transaction hash {normalised}")
            return await self._process_proof(proof, reconciliation_only=True)

    async def reconcile_unresolved_proofs(self) -> dict[str, int]:
        """Reconcile every proof whose chain outcome is still unresolved.

        The operator recovery path for a provider outage: after adding a read
        endpoint, this sweeps ``prepared``, ``submitted``, ``failed``, and
        ``dead_letter`` proofs and confirms each one that chain evidence
        supports. It never broadcasts, so it is safe to run at any time.
        """

        async with self.db.anchor_cycle_lock() as acquired:
            if not acquired:
                raise RuntimeError("Another anchor worker owns the reconciliation lock")
            proofs = await self.db.get_reconcilable_proofs()
            counts = {"examined": 0, "confirmed": 0, "unresolved": 0}
            for proof in proofs:
                counts["examined"] += 1
                logger.info(
                    "anchor_reconcile_sweep proof_id=%s merkle_root=%s "
                    "transaction_hash=%s status=%s",
                    proof["id"],
                    proof["root_hash"],
                    proof.get("transaction_hash"),
                    proof.get("status"),
                )
                if await self._process_proof(proof, reconciliation_only=True):
                    counts["confirmed"] += 1
                else:
                    counts["unresolved"] += 1
            logger.info(
                "anchor_reconcile_sweep_complete examined=%d confirmed=%d unresolved=%d",
                counts["examined"],
                counts["confirmed"],
                counts["unresolved"],
            )
            return counts


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


async def main(
    reconcile_proof_id: UUID | None = None,
    *,
    reconcile_all: bool = False,
    reconcile_transaction_hash: str | None = None,
) -> int:
    """Main entry point for the anchor worker."""
    reconcile_only = (
        reconcile_proof_id is not None or reconcile_all or reconcile_transaction_hash is not None
    )
    # Validate configuration
    if not ANCHOR_CONTRACT_ADDRESS:
        logger.error("ANCHOR_CONTRACT_ADDRESS environment variable is required")
        sys.exit(1)

    if not BLOCKCHAIN_PRIVATE_KEY:
        logger.error("BLOCKCHAIN_PRIVATE_KEY environment variable is required")
        sys.exit(1)

    # Initialize services
    logger.info("Initializing anchor worker...")

    if not reconcile_only:
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

    try:
        read_rpc_urls = parse_read_provider_urls(
            BLOCKCHAIN_READ_PROVIDER_URLS_RAW,
            primary_url=BLOCKCHAIN_PROVIDER_URL,
        )
    except ValueError as exc:
        logger.critical("BLOCKCHAIN_READ_PROVIDER_URLS is invalid: %s", exc)
        await db_service.close()
        sys.exit(1)

    blockchain_service = BlockchainService(
        rpc_url=BLOCKCHAIN_PROVIDER_URL,
        contract_address=ANCHOR_CONTRACT_ADDRESS,
        private_key=BLOCKCHAIN_PRIVATE_KEY,
        read_rpc_urls=read_rpc_urls,
    )

    if not blockchain_service.is_connected():
        if not read_rpc_urls:
            logger.error("Failed to connect to blockchain")
            await db_service.close()
            return 1
        # The primary is the only endpoint that broadcasts, but a worker that
        # cannot reach it can still reconcile transactions it already sent.
        # Exiting here is what left the incident's proof stranded.
        logger.error(
            "Primary RPC is unreachable. Continuing on the configured read "
            "endpoints so already-broadcast transactions can still reconcile."
        )

    worker = AnchorWorker(db_service, blockchain_service)
    if reconcile_proof_id is not None:
        try:
            reconciled = await worker.reconcile_proof(reconcile_proof_id)
            return 0 if reconciled else 2
        finally:
            await db_service.close()

    if reconcile_transaction_hash is not None:
        try:
            reconciled = await worker.reconcile_transaction(reconcile_transaction_hash)
            return 0 if reconciled else 2
        finally:
            await db_service.close()

    if reconcile_all:
        try:
            counts = await worker.reconcile_unresolved_proofs()
            logger.info(
                "Reconciliation sweep examined %d proof(s): %d confirmed, %d unresolved.",
                counts["examined"],
                counts["confirmed"],
                counts["unresolved"],
            )
            return 0 if counts["unresolved"] == 0 else 2
        finally:
            await db_service.close()

    try:
        balance = blockchain_service.get_balance()
    except Exception as exc:
        if not is_rpc_availability_error(exc):
            raise
        # A primary that will not serve a balance read still leaves work worth
        # doing: proofs already broadcast can reconcile through the read
        # endpoints. Starting up is strictly better than exiting here.
        logger.error(
            "Primary RPC could not serve a balance read at startup (%s). "
            "Anchoring new batches will retry; reconciliation continues on the "
            "configured read endpoints.",
            exc,
        )
    else:
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
    parser.add_argument(
        "--reconcile-transaction",
        type=str,
        help=(
            "Reconcile the proof holding this transaction hash. Use when a block "
            "explorer shows the anchor confirmed but the database does not. "
            "This mode never broadcasts a transaction."
        ),
    )
    parser.add_argument(
        "--reconcile-unresolved",
        action="store_true",
        help=(
            "Reconcile every prepared, submitted, failed, and dead-lettered proof "
            "from chain evidence. Use after adding BLOCKCHAIN_READ_PROVIDER_URLS to "
            "recover proofs stranded by a provider outage. Never broadcasts."
        ),
    )
    arguments = parser.parse_args()
    selected = sum(
        1
        for chosen in (
            arguments.reconcile_proof is not None,
            arguments.reconcile_transaction is not None,
            arguments.reconcile_unresolved,
        )
        if chosen
    )
    if selected > 1:
        parser.error("the --reconcile-* modes are mutually exclusive")
    return arguments


if __name__ == "__main__":
    arguments = _parse_args()
    raise SystemExit(
        asyncio.run(
            main(
                arguments.reconcile_proof,
                reconcile_all=arguments.reconcile_unresolved,
                reconcile_transaction_hash=arguments.reconcile_transaction,
            )
        )
    )
