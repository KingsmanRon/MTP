"""In-process circuit breaker for blockchain RPC calls.

See docs/superpowers/specs/2026-04-21-blockchain-rpc-circuit-breaker-design.md
for the design. Threads are not supported — use one breaker per worker
process.
"""

from __future__ import annotations

import enum
import time
from typing import Callable, Optional, TypeVar

import requests

try:
    import web3.exceptions as _web3_exc

    _WEB3_PROVIDER_CONNECTION_ERROR: Optional[type[BaseException]] = getattr(
        _web3_exc, "ProviderConnectionError", None
    )
    if _WEB3_PROVIDER_CONNECTION_ERROR is not None and not isinstance(
        _WEB3_PROVIDER_CONNECTION_ERROR, type
    ):
        raise TypeError(
            "web3.exceptions.ProviderConnectionError is not a class; "
            "check your web3 version"
        )
except ImportError:  # web3 not installed in this environment
    _WEB3_PROVIDER_CONNECTION_ERROR = None

T = TypeVar("T")


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


class RpcCircuitBreaker:
    """Consecutive-failure circuit breaker for RPC transport calls."""

    def __init__(
        self,
        threshold: int,
        open_duration_seconds: float,
        enabled: bool = True,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        if open_duration_seconds < 0:
            raise ValueError("open_duration_seconds must be >= 0")
        self._threshold = threshold
        self._open_duration = open_duration_seconds
        self._enabled = enabled
        self._clock = clock
        self._state: BreakerState = BreakerState.CLOSED
        self._failure_count: int = 0
        self._opened_at: Optional[float] = None

    @property
    def state(self) -> BreakerState:
        return self._state

    def call(self, fn: Callable[[], T]) -> T:
        if not self._enabled:
            return fn()

        try:
            result = fn()
        except BaseException as exc:
            if is_transport_error(exc):
                self._failure_count += 1
                if self._failure_count >= self._threshold:
                    self._state = BreakerState.OPEN
                    self._opened_at = self._clock()
            raise
        else:
            self._failure_count = 0
            return result
