"""In-process circuit breaker for blockchain RPC calls.

See docs/superpowers/specs/2026-04-21-blockchain-rpc-circuit-breaker-design.md
for the design. Threads are not supported — use one breaker per worker
process.
"""

from __future__ import annotations

import enum
from typing import Optional

import requests
import requests.exceptions

try:
    import web3.exceptions as _web3_exc

    _WEB3_PROVIDER_CONNECTION_ERROR: Optional[type[BaseException]] = getattr(
        _web3_exc, "ProviderConnectionError", None
    )
except ImportError:  # web3 not installed in this environment
    _WEB3_PROVIDER_CONNECTION_ERROR = None


class BreakerState(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class RpcCircuitOpenError(Exception):
    """Raised when a call is rejected because the breaker is OPEN."""

    def __init__(self, message: str, *, cooldown_remaining_seconds: float) -> None:
        super().__init__(message)
        self.cooldown_remaining_seconds = cooldown_remaining_seconds


def is_transport_error(exc: BaseException) -> bool:
    """Return True when `exc` indicates the RPC transport is sick.

    Per-transaction errors (reverts, gas-price cap, chain-id mismatch,
    nonce errors) are NOT transport errors and must return False —
    those have their own per-proof retry path and should never trip the
    breaker.
    """
    if isinstance(
        exc,
        (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ChunkedEncodingError,
        ),
    ):
        return True
    if _WEB3_PROVIDER_CONNECTION_ERROR is not None and isinstance(
        exc, _WEB3_PROVIDER_CONNECTION_ERROR
    ):
        return True
    if isinstance(exc, requests.exceptions.HTTPError):
        resp = getattr(exc, "response", None)
        return resp is not None and resp.status_code >= 500
    return False
