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


class TestBreakerHalfOpen:
    def _half_open(self, clock: FakeClock) -> RpcCircuitBreaker:
        breaker = RpcCircuitBreaker(
            threshold=3, open_duration_seconds=60, clock=clock,
        )
        for _ in range(3):
            with pytest.raises(requests.exceptions.Timeout):
                breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        clock.advance(60)
        return breaker

    def test_half_open_success_closes(self) -> None:
        clock = FakeClock()
        breaker = self._half_open(clock)
        assert breaker.call(lambda: "ok") == "ok"
        assert breaker.state is BreakerState.CLOSED
        # Counter reset — one more failure should NOT trip immediately
        with pytest.raises(requests.exceptions.Timeout):
            breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        assert breaker.state is BreakerState.CLOSED

    def test_half_open_transport_failure_reopens(self) -> None:
        clock = FakeClock()
        breaker = self._half_open(clock)
        clock.advance(1)  # move clock forward so we can assert opened_at reset
        with pytest.raises(requests.exceptions.Timeout):
            breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        assert breaker.state is BreakerState.OPEN
        # opened_at reset to new now — full cooldown applies again
        clock.advance(30)  # 30s into the new 60s cooldown
        with pytest.raises(RpcCircuitOpenError):
            breaker.call(lambda: "ok")

    def test_half_open_non_transport_closes(self) -> None:
        """The probe succeeded enough to receive a proper error — the RPC
        is responding. Treat that as healthy and close the breaker.
        """
        clock = FakeClock()
        breaker = self._half_open(clock)
        with pytest.raises(ValueError):
            breaker.call(lambda: (_ for _ in ()).throw(ValueError("revert")))
        assert breaker.state is BreakerState.CLOSED


class TestKillSwitch:
    def test_disabled_breaker_is_passthrough(self) -> None:
        breaker = RpcCircuitBreaker(
            threshold=3, open_duration_seconds=60, enabled=False,
            clock=FakeClock(),
        )
        # Many transport failures — state never changes
        for _ in range(20):
            with pytest.raises(requests.exceptions.Timeout):
                breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        assert breaker.state is BreakerState.CLOSED
        # Successes also work fine
        assert breaker.call(lambda: "ok") == "ok"


class TestBreakerMetrics:
    def test_trip_increments_trips_total(self) -> None:
        from api import observability

        before = _metric_value(observability.rpc_breaker_trips_total)
        breaker = RpcCircuitBreaker(
            threshold=3, open_duration_seconds=60, clock=FakeClock(),
        )
        for _ in range(3):
            with pytest.raises(requests.exceptions.Timeout):
                breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        after = _metric_value(observability.rpc_breaker_trips_total)
        assert after - before == 1

    def test_reject_increments_rejected_total(self) -> None:
        from api import observability

        clock = FakeClock()
        breaker = RpcCircuitBreaker(
            threshold=3, open_duration_seconds=60, clock=clock,
        )
        for _ in range(3):
            with pytest.raises(requests.exceptions.Timeout):
                breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        before = _metric_value(observability.rpc_breaker_rejected_total)
        # 3 calls while OPEN → 3 rejections
        for _ in range(3):
            with pytest.raises(RpcCircuitOpenError):
                breaker.call(lambda: "ok")
        after = _metric_value(observability.rpc_breaker_rejected_total)
        assert after - before == 3


def _metric_value(counter) -> float:
    """Return the current sample value for a prometheus_client Counter.

    Uses the public `_value` API via collect() to stay compatible with
    both the real prometheus_client and the repo's _NoopMetric fallback
    (which returns 0.0).
    """
    try:
        for sample in counter.collect()[0].samples:
            if sample.name.endswith("_total"):
                return sample.value
    except AttributeError:
        return 0.0
    return 0.0


class TestBreakerLogging:
    def test_trip_logs_opened(self, caplog) -> None:
        caplog.set_level("WARNING", logger="workers.circuit_breaker")
        breaker = RpcCircuitBreaker(
            threshold=3, open_duration_seconds=60, clock=FakeClock(),
        )
        for _ in range(3):
            with pytest.raises(requests.exceptions.Timeout):
                breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        events = [r.message for r in caplog.records]
        assert any("rpc_breaker_opened" in m for m in events)

    def test_probe_success_logs_closed(self, caplog) -> None:
        caplog.set_level("INFO", logger="workers.circuit_breaker")
        clock = FakeClock()
        breaker = RpcCircuitBreaker(
            threshold=3, open_duration_seconds=60, clock=clock,
        )
        for _ in range(3):
            with pytest.raises(requests.exceptions.Timeout):
                breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        clock.advance(60)
        caplog.clear()
        breaker.call(lambda: "ok")
        events = [r.message for r in caplog.records]
        assert any("rpc_breaker_probe" in m for m in events)
        assert any("rpc_breaker_closed" in m for m in events)

    def test_probe_failure_logs_probe_failed(self, caplog) -> None:
        caplog.set_level("WARNING", logger="workers.circuit_breaker")
        clock = FakeClock()
        breaker = RpcCircuitBreaker(
            threshold=3, open_duration_seconds=60, clock=clock,
        )
        for _ in range(3):
            with pytest.raises(requests.exceptions.Timeout):
                breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        clock.advance(60)
        caplog.clear()
        with pytest.raises(requests.exceptions.Timeout):
            breaker.call(lambda: (_ for _ in ()).throw(_transport_exc()))
        events = [r.message for r in caplog.records]
        assert any("rpc_breaker_probe_failed" in m for m in events)


try:  # web3 is optional in some Windows dev envs (lru-dict build failure)
    import web3.exceptions as _web3_exc_probe  # noqa: F401

    _WEB3_AVAILABLE = True
except ImportError:
    _WEB3_AVAILABLE = False


try:
    from unittest.mock import MagicMock

    from workers import anchor_worker

    _ANCHOR_WORKER_IMPORTABLE = True
except ImportError:
    _ANCHOR_WORKER_IMPORTABLE = False


@pytest.mark.skipif(
    not _ANCHOR_WORKER_IMPORTABLE,
    reason="workers.anchor_worker requires web3 which is unavailable here",
)
class TestBlockchainServiceIntegration:
    def _service(self, **breaker_kwargs):
        """Build a BlockchainService with everything mocked.

        We skip the real Web3/Account wiring by constructing the
        service manually and injecting a breaker + fake w3.
        """
        svc = anchor_worker.BlockchainService.__new__(
            anchor_worker.BlockchainService
        )
        svc.w3 = MagicMock()
        svc.contract = MagicMock()
        svc.contract_address = "0x" + "ab" * 20
        svc.account = MagicMock()
        svc.account.address = "0x" + "cd" * 20
        svc.expected_chain_id = 8453
        clock = FakeClock()
        svc._breaker = RpcCircuitBreaker(
            threshold=breaker_kwargs.get("threshold", 3),
            open_duration_seconds=breaker_kwargs.get("open_duration_seconds", 60),
            clock=clock,
        )
        return svc, clock

    def test_assert_chain_id_wrapped_by_breaker(self) -> None:
        svc, _clock = self._service()
        # Make w3.eth.chain_id a property-like attr that raises on every access
        type(svc.w3.eth).chain_id = property(
            lambda _self: (_ for _ in ()).throw(_transport_exc())
        )
        for _ in range(3):
            with pytest.raises(requests.exceptions.Timeout):
                svc.assert_chain_id()
        # Next call: breaker is OPEN, should short-circuit BEFORE touching w3
        assert svc._breaker.state is BreakerState.OPEN
        with pytest.raises(RpcCircuitOpenError):
            svc.assert_chain_id()

    @pytest.mark.skipif(
        not _WEB3_AVAILABLE,
        reason="web3 not installed in this environment",
    )
    def test_revert_does_not_trip_breaker(self) -> None:
        import web3.exceptions as w3exc
        svc, _ = self._service()
        # send_raw_transaction raises a ContractLogicError (non-transport).
        # 8 iterations with threshold=3: if classification were broken the
        # breaker would trip on the 3rd, and the 4th call would raise
        # RpcCircuitOpenError instead of ContractLogicError, failing the
        # pytest.raises below.
        svc.w3.eth.send_raw_transaction.side_effect = w3exc.ContractLogicError("revert")
        for _ in range(8):
            with pytest.raises(w3exc.ContractLogicError):
                svc._rpc(lambda: svc.w3.eth.send_raw_transaction(b"raw"))
        assert svc._breaker.state is BreakerState.CLOSED
