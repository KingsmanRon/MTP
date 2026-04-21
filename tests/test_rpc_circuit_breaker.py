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


class TestBreakerOpen:
    def _tripped_breaker(
        self,
        clock: FakeClock,
        threshold: int = 3,
        open_duration: float = 60,
    ) -> RpcCircuitBreaker:
        breaker = RpcCircuitBreaker(
            threshold=threshold,
            open_duration_seconds=open_duration,
            clock=clock,
        )
        for _ in range(threshold):
            with pytest.raises(requests.exceptions.Timeout):
                breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        assert breaker.state is BreakerState.OPEN
        return breaker

    def test_open_rejects_calls_without_invoking_fn(self) -> None:
        clock = FakeClock()
        breaker = self._tripped_breaker(clock)
        calls = []
        with pytest.raises(RpcCircuitOpenError):
            breaker.call(lambda: (calls.append(1), "ok")[1])
        assert calls == []  # fn was never invoked

    def test_open_error_reports_cooldown_remaining(self) -> None:
        clock = FakeClock()
        breaker = self._tripped_breaker(clock, open_duration=60)
        clock.advance(15)
        with pytest.raises(RpcCircuitOpenError) as excinfo:
            breaker.call(lambda: "ok")
        # 60s cooldown, 15s elapsed → ~45s remaining
        assert 44.9 <= excinfo.value.cooldown_remaining_seconds <= 45.1

    def test_open_transitions_to_half_open_after_cooldown(self) -> None:
        clock = FakeClock()
        breaker = self._tripped_breaker(clock, open_duration=60)
        clock.advance(60)
        # Next call runs as a probe — fn IS invoked
        assert breaker.call(lambda: "probe-ok") == "probe-ok"
        # State remains HALF_OPEN here; HALF_OPEN→CLOSED is Task 4's responsibility.
