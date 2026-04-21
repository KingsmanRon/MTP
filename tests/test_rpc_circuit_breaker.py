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
    RpcCircuitBreaker,
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
        assert {s.value for s in BreakerState} == {"closed", "open", "half_open"}


class TestRpcCircuitOpenError:
    def test_carries_cooldown_remaining(self) -> None:
        err = RpcCircuitOpenError("circuit open", cooldown_remaining_seconds=12.5)
        assert err.cooldown_remaining_seconds == 12.5
        assert "circuit open" in str(err)


def _transport_exc() -> Exception:
    return requests.exceptions.Timeout("slow")


class FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def __call__(self) -> float:
        return self.now


class TestBreakerClosed:
    def _breaker(self, threshold: int = 3) -> RpcCircuitBreaker:
        return RpcCircuitBreaker(
            threshold=threshold,
            open_duration_seconds=60,
            clock=FakeClock(),
        )

    def test_closed_allows_calls(self) -> None:
        breaker = self._breaker()
        for _ in range(10):
            assert breaker.call(lambda: 42) == 42
        assert breaker.state is BreakerState.CLOSED

    def test_transport_failures_increment_counter(self) -> None:
        breaker = self._breaker(threshold=3)
        # threshold - 1 failures: still CLOSED
        for _ in range(2):
            with pytest.raises(requests.exceptions.Timeout):
                breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        assert breaker.state is BreakerState.CLOSED

    def test_trips_on_threshold(self) -> None:
        breaker = self._breaker(threshold=3)
        for _ in range(3):
            with pytest.raises(requests.exceptions.Timeout):
                breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        assert breaker.state is BreakerState.OPEN

    def test_non_transport_failure_does_not_count(self) -> None:
        breaker = self._breaker(threshold=3)
        for _ in range(5):
            with pytest.raises(ValueError):
                breaker.call(lambda: (_ for _ in ()).throw(ValueError("nope")))
        assert breaker.state is BreakerState.CLOSED

    def test_success_mid_streak_resets_counter(self) -> None:
        breaker = self._breaker(threshold=3)
        # 2 failures
        for _ in range(2):
            with pytest.raises(requests.exceptions.Timeout):
                breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        # 1 success — counter back to 0
        assert breaker.call(lambda: "ok") == "ok"
        # 2 more failures — still CLOSED, because counter restarted
        for _ in range(2):
            with pytest.raises(requests.exceptions.Timeout):
                breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        assert breaker.state is BreakerState.CLOSED
