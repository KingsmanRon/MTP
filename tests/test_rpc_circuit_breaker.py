"""Tests for workers.circuit_breaker — the RPC circuit breaker.

Covers the breaker in isolation (unit), its integration with
BlockchainService (mocked Web3), and the worker-level behaviour when
the breaker is OPEN. See
docs/superpowers/specs/2026-04-21-blockchain-rpc-circuit-breaker-design.md
for the design.
"""

from __future__ import annotations

import pytest
import requests

from workers.circuit_breaker import (
    BreakerState,
    RpcCircuitOpenError,
    is_transport_error,
)


class TestTransportErrorPredicate:
    def test_connection_error_is_transport(self) -> None:
        assert is_transport_error(requests.exceptions.ConnectionError("boom"))

    def test_timeout_is_transport(self) -> None:
        assert is_transport_error(requests.exceptions.Timeout("slow"))

    def test_chunked_encoding_error_is_transport(self) -> None:
        assert is_transport_error(requests.exceptions.ChunkedEncodingError("bad"))

    def test_http_5xx_is_transport(self) -> None:
        resp = requests.models.Response()
        resp.status_code = 503
        err = requests.exceptions.HTTPError("server err")
        err.response = resp
        assert is_transport_error(err)

    def test_http_4xx_is_not_transport(self) -> None:
        resp = requests.models.Response()
        resp.status_code = 404
        err = requests.exceptions.HTTPError("not found")
        err.response = resp
        assert not is_transport_error(err)

    def test_value_error_is_not_transport(self) -> None:
        assert not is_transport_error(ValueError("bad nonce"))

    def test_runtime_error_is_not_transport(self) -> None:
        assert not is_transport_error(RuntimeError("chain id mismatch"))


class TestBreakerStateEnum:
    def test_three_states_exist(self) -> None:
        assert BreakerState.CLOSED != BreakerState.OPEN
        assert BreakerState.OPEN != BreakerState.HALF_OPEN
        assert BreakerState.CLOSED != BreakerState.HALF_OPEN


class TestRpcCircuitOpenError:
    def test_carries_cooldown_remaining(self) -> None:
        err = RpcCircuitOpenError("circuit open", cooldown_remaining_seconds=12.5)
        assert err.cooldown_remaining_seconds == 12.5
        assert "circuit open" in str(err)
