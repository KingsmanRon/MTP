# Blockchain RPC Circuit Breaker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an in-process circuit breaker around RPC calls in the anchor worker so transport-level failures from the Base L2 provider stop cascading through per-proof timeouts.

**Architecture:** A new `RpcCircuitBreaker` unit owned by `BlockchainService`. Every RPC call is routed through `self._rpc(fn)`, which delegates to `breaker.call(fn)`. Transport errors (timeouts, connection refused, HTTP 5xx, provider-connection errors) increment a consecutive-failure counter; N in a row trip the breaker to OPEN. While OPEN, calls short-circuit with `RpcCircuitOpenError` and the worker's existing `_record_failure` path requeues the proof. After a cooldown, the next `assert_chain_id` call is a half-open probe that restores normal operation on success.

**Tech Stack:** Python 3.11, pytest, web3.py, prometheus_client (already used elsewhere in the repo).

**Design doc:** `docs/superpowers/specs/2026-04-21-blockchain-rpc-circuit-breaker-design.md`

---

## File Structure

**New files:**
- `workers/circuit_breaker.py` — `BreakerState`, `RpcCircuitOpenError`, `is_transport_error`, `RpcCircuitBreaker`
- `tests/test_rpc_circuit_breaker.py` — unit + integration + smoke tests

**Modified files:**
- `workers/anchor_worker.py` — env config, `BlockchainService` wires a breaker and adds `_rpc(fn)`, worker `_process_proof` catches `RpcCircuitOpenError`
- `api/observability.py` — three new Prometheus metrics (same pattern as `anchor_submissions_total`)

---

### Task 1: Breaker data types and transport-error predicate

**Files:**
- Create: `workers/circuit_breaker.py`
- Test: `tests/test_rpc_circuit_breaker.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_rpc_circuit_breaker.py` with:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_rpc_circuit_breaker.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'workers.circuit_breaker'`.

- [ ] **Step 3: Write minimal implementation**

Create `workers/circuit_breaker.py`:

```python
"""In-process circuit breaker for blockchain RPC calls.

See docs/superpowers/specs/2026-04-21-blockchain-rpc-circuit-breaker-design.md
for the design. Threads are not supported — use one breaker per worker
process.
"""

from __future__ import annotations

import enum
from typing import Optional

import requests
import web3.exceptions


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
    if isinstance(exc, (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.ChunkedEncodingError,
    )):
        return True
    if isinstance(exc, web3.exceptions.ProviderConnectionError):
        return True
    if isinstance(exc, requests.exceptions.HTTPError):
        resp = getattr(exc, "response", None)
        return resp is not None and resp.status_code >= 500
    return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_rpc_circuit_breaker.py -v`
Expected: All 9 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/circuit_breaker.py tests/test_rpc_circuit_breaker.py
git commit -m "feat(breaker): scaffolding — state enum, exception, transport predicate"
```

---

### Task 2: Breaker CLOSED state — counter, success reset, trip at threshold

**Files:**
- Modify: `workers/circuit_breaker.py`
- Modify: `tests/test_rpc_circuit_breaker.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_rpc_circuit_breaker.py`:

```python
from workers.circuit_breaker import RpcCircuitBreaker


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_rpc_circuit_breaker.py::TestBreakerClosed -v`
Expected: FAIL — `RpcCircuitBreaker` is not yet implemented.

- [ ] **Step 3: Write minimal implementation**

Append to `workers/circuit_breaker.py`:

```python
import time
from typing import Callable, TypeVar

T = TypeVar("T")


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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_rpc_circuit_breaker.py::TestBreakerClosed -v`
Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/circuit_breaker.py tests/test_rpc_circuit_breaker.py
git commit -m "feat(breaker): CLOSED state — counter, success reset, trip at threshold"
```

---

### Task 3: Breaker OPEN state — reject calls, cooldown transition

**Files:**
- Modify: `workers/circuit_breaker.py`
- Modify: `tests/test_rpc_circuit_breaker.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_rpc_circuit_breaker.py`:

```python
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
        # Probe success → CLOSED (covered fully in Task 4, we only check no-reject here)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_rpc_circuit_breaker.py::TestBreakerOpen -v`
Expected: FAIL — `call()` currently lets everything through regardless of state.

- [ ] **Step 3: Write minimal implementation**

Edit `workers/circuit_breaker.py` — replace the `call` method with:

```python
    def call(self, fn: Callable[[], T]) -> T:
        if not self._enabled:
            return fn()

        if self._state is BreakerState.OPEN:
            now = self._clock()
            elapsed = now - (self._opened_at or now)
            if elapsed < self._open_duration:
                remaining = self._open_duration - elapsed
                raise RpcCircuitOpenError(
                    f"circuit open; opens again in {remaining:.1f}s",
                    cooldown_remaining_seconds=remaining,
                )
            # Cooldown elapsed — transition to HALF_OPEN for the probe.
            self._state = BreakerState.HALF_OPEN

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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_rpc_circuit_breaker.py -v`
Expected: All tests so far (TestTransportErrorPredicate + TestBreakerStateEnum + TestRpcCircuitOpenError + TestBreakerClosed + TestBreakerOpen) PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/circuit_breaker.py tests/test_rpc_circuit_breaker.py
git commit -m "feat(breaker): OPEN state — reject calls, half-open after cooldown"
```

---

### Task 4: Breaker HALF_OPEN state — probe success closes, probe failure re-opens

**Files:**
- Modify: `workers/circuit_breaker.py`
- Modify: `tests/test_rpc_circuit_breaker.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_rpc_circuit_breaker.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_rpc_circuit_breaker.py::TestBreakerHalfOpen -v`
Expected: `test_half_open_transport_failure_reopens` may FAIL because `opened_at` is not reset; `test_half_open_non_transport_closes` may FAIL because the current code does not reset state on non-transport after HALF_OPEN.

- [ ] **Step 3: Write minimal implementation**

Edit `workers/circuit_breaker.py` — replace `call` with this version that tracks whether we are running a probe:

```python
    def call(self, fn: Callable[[], T]) -> T:
        if not self._enabled:
            return fn()

        if self._state is BreakerState.OPEN:
            now = self._clock()
            elapsed = now - (self._opened_at or now)
            if elapsed < self._open_duration:
                remaining = self._open_duration - elapsed
                raise RpcCircuitOpenError(
                    f"circuit open; opens again in {remaining:.1f}s",
                    cooldown_remaining_seconds=remaining,
                )
            self._state = BreakerState.HALF_OPEN

        is_probe = self._state is BreakerState.HALF_OPEN

        try:
            result = fn()
        except BaseException as exc:
            if is_probe:
                if is_transport_error(exc):
                    # Probe found the RPC still broken. Re-open for a
                    # fresh cooldown window.
                    self._state = BreakerState.OPEN
                    self._opened_at = self._clock()
                else:
                    # RPC responded with a proper (non-transport) error.
                    # That's "healthy enough" — close the breaker.
                    self._state = BreakerState.CLOSED
                    self._failure_count = 0
                    self._opened_at = None
            elif is_transport_error(exc):
                self._failure_count += 1
                if self._failure_count >= self._threshold:
                    self._state = BreakerState.OPEN
                    self._opened_at = self._clock()
            raise
        else:
            if is_probe:
                self._state = BreakerState.CLOSED
                self._opened_at = None
            self._failure_count = 0
            return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_rpc_circuit_breaker.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/circuit_breaker.py tests/test_rpc_circuit_breaker.py
git commit -m "feat(breaker): HALF_OPEN probe — close on success, re-open on transport failure"
```

---

### Task 5: Kill switch — fully inert when disabled

**Files:**
- Modify: `tests/test_rpc_circuit_breaker.py`

This task is a regression pin for behaviour already present in Task 2's implementation (the early `if not self._enabled: return fn()`). The test passes immediately — we're not adding new code, we're guarding the existing kill-switch semantics against future regressions.

- [ ] **Step 1: Write the pin test**

Append to `tests/test_rpc_circuit_breaker.py`:

```python
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
```

- [ ] **Step 2: Run the test and confirm it passes**

Run: `pytest tests/test_rpc_circuit_breaker.py::TestKillSwitch -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_rpc_circuit_breaker.py
git commit -m "test(breaker): pin kill-switch passthrough behaviour"
```

---

### Task 6: Add Prometheus metrics

**Files:**
- Modify: `api/observability.py`
- Modify: `workers/circuit_breaker.py`
- Modify: `tests/test_rpc_circuit_breaker.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_rpc_circuit_breaker.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_rpc_circuit_breaker.py::TestBreakerMetrics -v`
Expected: FAIL — `observability.rpc_breaker_trips_total` does not exist yet.

- [ ] **Step 3: Add metrics in `api/observability.py`**

Find the block at `api/observability.py:142-177` (the `if _HAS_PROMETHEUS:` / `else:` pair). Inside the `if _HAS_PROMETHEUS:` block, immediately before `verify_latency_seconds = Histogram(...)`, append:

```python
    rpc_breaker_trips_total = Counter(
        "inntris_rpc_breaker_trips_total",
        "Total times the RPC circuit breaker transitioned to OPEN.",
    )
    rpc_breaker_rejected_total = Counter(
        "inntris_rpc_breaker_rejected_total",
        "Total RPC calls rejected because the breaker was OPEN.",
    )
    rpc_breaker_state = Gauge(
        "inntris_rpc_breaker_state",
        "Current state of the RPC circuit breaker (1 for the current state).",
        ["state"],  # closed | open | half_open
    )
```

Inside the matching `else:` block (the `_NoopMetric()` fallback), append:

```python
    rpc_breaker_trips_total = _NoopMetric()
    rpc_breaker_rejected_total = _NoopMetric()
    rpc_breaker_state = _NoopMetric()
```

Add `Gauge` to the import at `api/observability.py:31-35`:

```python
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )
```

- [ ] **Step 4: Wire metrics in the breaker**

Edit `workers/circuit_breaker.py` — add imports at top:

```python
from api.observability import (
    rpc_breaker_rejected_total,
    rpc_breaker_state,
    rpc_breaker_trips_total,
)
```

Add a private helper inside `RpcCircuitBreaker`:

```python
    def _set_state(self, new_state: BreakerState) -> None:
        old_state = self._state
        self._state = new_state
        if new_state is BreakerState.OPEN and old_state is not BreakerState.OPEN:
            rpc_breaker_trips_total.inc()
        rpc_breaker_state.labels(state="closed").set(
            1.0 if new_state is BreakerState.CLOSED else 0.0
        )
        rpc_breaker_state.labels(state="open").set(
            1.0 if new_state is BreakerState.OPEN else 0.0
        )
        rpc_breaker_state.labels(state="half_open").set(
            1.0 if new_state is BreakerState.HALF_OPEN else 0.0
        )
```

Replace every direct `self._state = BreakerState.X` assignment **inside `call()`** with `self._set_state(BreakerState.X)`.

In `__init__`, leave the existing `self._state: BreakerState = BreakerState.CLOSED` line exactly as it is (the helper reads `self._state` as `old_state`, so the attribute must exist first). Then add this single line at the end of `__init__` to seed the gauge labels:

```python
        self._set_state(BreakerState.CLOSED)
```

That call is a no-op on state (old CLOSED → new CLOSED), does not trigger a trip-counter increment, and correctly initialises all three gauge labels to `(0, 0, 0)` with the `closed` label set to `1`.

Inside the OPEN-reject branch of `call()`, add one line immediately before the `raise RpcCircuitOpenError(...)`:

```python
                rpc_breaker_rejected_total.inc()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_rpc_circuit_breaker.py -v`
Expected: All tests PASS, including the two new metric tests.

- [ ] **Step 6: Commit**

```bash
git add api/observability.py workers/circuit_breaker.py tests/test_rpc_circuit_breaker.py
git commit -m "feat(breaker): Prometheus metrics — trips, rejections, current state"
```

---

### Task 7: Log state transitions

**Files:**
- Modify: `workers/circuit_breaker.py`
- Modify: `tests/test_rpc_circuit_breaker.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_rpc_circuit_breaker.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_rpc_circuit_breaker.py::TestBreakerLogging -v`
Expected: FAIL — the breaker does not log anything yet.

- [ ] **Step 3: Write minimal implementation**

Edit `workers/circuit_breaker.py` — add at the top (after existing imports):

```python
import logging

logger = logging.getLogger(__name__)
```

Find every call site of `self._set_state(...)` and also the OPEN-reject branch. Add the following log calls alongside the state changes:

- When transitioning CLOSED → OPEN (inside `call()`, after threshold is hit):
  ```python
  logger.warning(
      "rpc_breaker_opened | failure_count=%d threshold=%d last_error=%r",
      self._failure_count, self._threshold, exc,
  )
  ```
- When transitioning OPEN → HALF_OPEN (inside `call()`, right before `self._set_state(BreakerState.HALF_OPEN)`):
  ```python
  logger.info(
      "rpc_breaker_probe | open_duration_s=%.1f",
      self._open_duration,
  )
  ```
- When transitioning HALF_OPEN → CLOSED (both the probe-success and probe-non-transport paths):
  ```python
  logger.info("rpc_breaker_closed")
  ```
- When transitioning HALF_OPEN → OPEN (probe-failure path):
  ```python
  logger.warning("rpc_breaker_probe_failed | error=%r", exc)
  ```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_rpc_circuit_breaker.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/circuit_breaker.py tests/test_rpc_circuit_breaker.py
git commit -m "feat(breaker): log state transitions (opened/probe/closed/probe_failed)"
```

---

### Task 8: Wire the breaker into BlockchainService

**Files:**
- Modify: `workers/anchor_worker.py`
- Modify: `tests/test_rpc_circuit_breaker.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_rpc_circuit_breaker.py`:

```python
from unittest.mock import MagicMock

from workers import anchor_worker


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

    def test_revert_does_not_trip_breaker(self) -> None:
        import web3.exceptions as w3exc
        svc, _ = self._service()
        # assert_chain_id succeeds so the breaker sees success for probes
        type(svc.w3.eth).chain_id = property(lambda _self: 8453)
        # send_raw_transaction raises a ContractLogicError (non-transport)
        svc.w3.eth.send_raw_transaction.side_effect = w3exc.ContractLogicError("revert")
        for _ in range(8):
            with pytest.raises(w3exc.ContractLogicError):
                svc._rpc(lambda: svc.w3.eth.send_raw_transaction(b"raw"))
        assert svc._breaker.state is BreakerState.CLOSED
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_rpc_circuit_breaker.py::TestBlockchainServiceIntegration -v`
Expected: FAIL — `BlockchainService` has no `_breaker` or `_rpc` attribute, and `assert_chain_id` does not go through the breaker.

- [ ] **Step 3: Add env config at the top of `workers/anchor_worker.py`**

Insert after line 94 (the existing `MAX_GAS_PRICE_GWEI` line):

```python
# Phase resilience — RPC circuit breaker config. See
# docs/superpowers/specs/2026-04-21-blockchain-rpc-circuit-breaker-design.md
RPC_BREAKER_ENABLED = os.getenv("ANCHOR_RPC_BREAKER_ENABLED", "true").lower() not in ("0", "false", "no")
RPC_BREAKER_THRESHOLD = int(os.getenv("ANCHOR_RPC_BREAKER_THRESHOLD", "5"))
RPC_BREAKER_OPEN_SECONDS = float(os.getenv("ANCHOR_RPC_BREAKER_OPEN_SECONDS", "60"))
```

- [ ] **Step 4: Add breaker to `BlockchainService.__init__`**

Find `BlockchainService.__init__` (`workers/anchor_worker.py:249-264`). Add an import at the top of the file (with the other workers imports near line 28):

```python
from workers.circuit_breaker import RpcCircuitBreaker, RpcCircuitOpenError
```

Append inside `__init__`, after `self.account = Account.from_key(private_key)`:

```python
        self._breaker = RpcCircuitBreaker(
            threshold=RPC_BREAKER_THRESHOLD,
            open_duration_seconds=RPC_BREAKER_OPEN_SECONDS,
            enabled=RPC_BREAKER_ENABLED,
        )
```

Also append the startup log after the existing `logger.info("Blockchain service initialized...")` line:

```python
        logger.info(
            "RPC circuit breaker: enabled=%s threshold=%d open_seconds=%.1f",
            RPC_BREAKER_ENABLED,
            RPC_BREAKER_THRESHOLD,
            RPC_BREAKER_OPEN_SECONDS,
        )
```

- [ ] **Step 5: Add `_rpc` helper and route every RPC call through it**

Below `__init__`, add:

```python
    def _rpc(self, fn):
        """Route an RPC call through the circuit breaker."""
        return self._breaker.call(fn)
```

Modify `assert_chain_id` (`workers/anchor_worker.py:266-281`) — replace `actual = self.w3.eth.chain_id` with:

```python
        actual = self._rpc(lambda: self.w3.eth.chain_id)
```

Modify `is_connected` (`workers/anchor_worker.py:283-287`) — replace body with:

```python
        try:
            return self._rpc(lambda: self.w3.is_connected())
        except Exception:
            return False
```

Modify `get_balance` (`workers/anchor_worker.py:289-291`) — replace body with:

```python
        balance_wei = self._rpc(lambda: self.w3.eth.get_balance(self.account.address))
        return Decimal(str(self.w3.from_wei(balance_wei, "ether")))
```

Modify `anchor_batch` (`workers/anchor_worker.py:293-365`) — wrap each RPC call:

1. Replace `nonce = self.w3.eth.get_transaction_count(self.account.address)` with:
   ```python
           nonce = self._rpc(lambda: self.w3.eth.get_transaction_count(self.account.address))
   ```
2. Replace the `gas_estimate = self.contract.functions.anchorBatch(...).estimate_gas({"from": self.account.address})` call with:
   ```python
           try:
               gas_estimate = self._rpc(lambda: self.contract.functions.anchorBatch(
                   root_bytes, log_count, start_unix, end_unix,
               ).estimate_gas({"from": self.account.address}))
           except Exception as e:
               if isinstance(e, RpcCircuitOpenError):
                   raise
               logger.warning(f"Gas estimation failed, using default: {e}")
               gas_estimate = 150000
   ```
3. Replace `gas_price = self.w3.eth.gas_price` with:
   ```python
           gas_price = self._rpc(lambda: self.w3.eth.gas_price)
   ```
4. Replace `tx_hash = self.w3.eth.send_raw_transaction(raw_tx)` with:
   ```python
           tx_hash = self._rpc(lambda: self.w3.eth.send_raw_transaction(raw_tx))
   ```
5. Replace the `receipt = await asyncio.get_event_loop().run_in_executor(...)` block with:
   ```python
           receipt = await asyncio.get_event_loop().run_in_executor(
               None,
               lambda: self._rpc(
                   lambda: self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
               ),
           )
   ```

Do NOT wrap the signing call (`self.w3.eth.account.sign_transaction`) — it is a local-only operation and does not touch the network.

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_rpc_circuit_breaker.py -v`
Expected: All tests PASS, including both `TestBlockchainServiceIntegration` tests.

- [ ] **Step 7: Run the existing worker retry tests to confirm no regression**

Run: `pytest tests/test_anchor_worker_retries.py tests/test_anchor_worker_hardening.py -v`
Expected: All existing tests PASS.

- [ ] **Step 8: Commit**

```bash
git add workers/anchor_worker.py tests/test_rpc_circuit_breaker.py
git commit -m "feat(breaker): wire RpcCircuitBreaker into BlockchainService via _rpc helper"
```

---

### Task 9: Worker-level handling of RpcCircuitOpenError

**Files:**
- Modify: `workers/anchor_worker.py`
- Modify: `tests/test_rpc_circuit_breaker.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_rpc_circuit_breaker.py`:

```python
class TestWorkerHandlesCircuitOpen:
    @pytest.mark.asyncio
    async def test_process_proof_records_failure_on_circuit_open(self) -> None:
        from unittest.mock import AsyncMock

        worker = anchor_worker.AnchorWorker.__new__(anchor_worker.AnchorWorker)
        worker.db_pool = MagicMock()
        worker.blockchain = MagicMock()
        # anchor_batch raises RpcCircuitOpenError before touching the RPC
        async def _raise_open(*args, **kwargs):
            raise RpcCircuitOpenError(
                "circuit open", cooldown_remaining_seconds=42,
            )
        worker.blockchain.anchor_batch = _raise_open
        worker._record_failure = AsyncMock()
        proof = {
            "id": "00000000-0000-0000-0000-000000000001",
            "root_hash": "ab" * 32,
            "leaf_hashes": [],
            "retry_count": 0,
        }
        # The worker must not let RpcCircuitOpenError propagate out of _process_proof
        await worker._process_proof(
            proof_id=proof["id"],
            root_hash=proof["root_hash"],
            leaf_hashes=proof["leaf_hashes"],
            current_retry_count=proof["retry_count"],
        )
        # Must have called _record_failure with an error string that mentions
        # the breaker, so operators can grep for it.
        assert worker._record_failure.await_count == 1
        args, kwargs = worker._record_failure.await_args
        err_message = kwargs.get("error_message") or (args[2] if len(args) >= 3 else "")
        assert "circuit" in err_message.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_rpc_circuit_breaker.py::TestWorkerHandlesCircuitOpen -v`
Expected: FAIL — `RpcCircuitOpenError` propagates from `_process_proof` because the existing `except` clause in `_process_proof` may not classify it correctly, or its error message may not include "circuit".

- [ ] **Step 3: Update `_process_proof`**

Find `_process_proof` in `workers/anchor_worker.py` (search for `async def _process_proof`). Currently:

```python
            await self._record_failure(proof_id, current_retry_count, str(e))
```

Replace the `except Exception as e:` block with one that explicitly handles the circuit-open case:

```python
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
            logger.error(f"Failed to process proof {proof_id}: {e}", exc_info=True)
            await self._record_failure(proof_id, current_retry_count, str(e))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_rpc_circuit_breaker.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Run the full worker test suite**

Run: `pytest tests/test_anchor_worker_retries.py tests/test_anchor_worker_hardening.py tests/test_rpc_circuit_breaker.py -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add workers/anchor_worker.py tests/test_rpc_circuit_breaker.py
git commit -m "feat(breaker): _process_proof defers proof with rpc_circuit_open marker"
```

---

### Task 10: Final validation — full test suite and deployment config

**Files:**
- Modify: `DEPLOYMENT_GUIDE.md`

- [ ] **Step 1: Run the full test suite**

Run: `pytest tests/ -v --ignore=tests/test_alembic_baseline.py`
Expected: All tests PASS. (The alembic baseline test is skipped because it requires `INNTRIS_DB_INTEGRATION=1`.)

- [ ] **Step 2: Document the env vars**

Open `DEPLOYMENT_GUIDE.md`. Find the existing anchor-worker env var table (search for `ANCHOR_MAX_GAS_PRICE_GWEI` — the circuit breaker vars belong next to it). Add three rows to that table:

| Env var | Default | Meaning |
|---|---|---|
| `ANCHOR_RPC_BREAKER_ENABLED` | `true` | Kill switch for the RPC circuit breaker. Set `false` to disable. |
| `ANCHOR_RPC_BREAKER_THRESHOLD` | `5` | Consecutive transport failures required to trip the breaker. |
| `ANCHOR_RPC_BREAKER_OPEN_SECONDS` | `60` | Cooldown (seconds) before the next call becomes a half-open probe. |

If no existing table is present, add a new "Circuit breaker" subsection under the existing anchor-worker configuration section, with the same three rows.

- [ ] **Step 3: Verify the design → plan trace**

Ensure every requirement in the design doc has a corresponding implementation and test. Walk through `docs/superpowers/specs/2026-04-21-blockchain-rpc-circuit-breaker-design.md` section by section:

- Architecture → Task 1 (types), Task 8 (`BlockchainService` wiring).
- State machine table (all 10 rows) → Tasks 2, 3, 4, 5.
- Transport-error predicate → Task 1.
- `_rpc` helper + every RPC call wrapped → Task 8.
- Configuration (three env vars) → Task 8 Step 3, Task 10 Step 2.
- Data flow (normal, degraded, recovery) → Tasks 4, 8, 9 end-to-end tests.
- Error handling (re-raise original exception, synthetic `RpcCircuitOpenError`, non-transport bypass) → Tasks 3, 4, 8.
- Logs (four keys) → Task 7.
- Metrics (three series) → Task 6.
- Kill switch fully inert → Task 5.
- Testing (17 cases in spec) → Tasks 1–9 (count covered per section).

If a gap is found, stop and add a task for it before proceeding.

- [ ] **Step 4: Commit**

```bash
git add DEPLOYMENT_GUIDE.md
git commit -m "docs(breaker): document ANCHOR_RPC_BREAKER_* env vars in deployment guide"
```

- [ ] **Step 5: Run the complete worker + breaker suite one final time**

Run: `pytest tests/test_anchor_worker_retries.py tests/test_anchor_worker_hardening.py tests/test_rpc_circuit_breaker.py tests/test_observability.py -v`
Expected: All PASS.

---

## Notes for the implementer

- **No real RPC in tests.** Every test uses either a fake callable or a `MagicMock`-ed `BlockchainService`. The existing worker integration tests (under `INNTRIS_DB_INTEGRATION=1`) are untouched.
- **`FakeClock` is intentionally a plain class**, not `freezegun` — the breaker takes a `clock` callable so tests can advance time without patching globals.
- **`is_transport_error` is deliberately conservative.** If you're tempted to add a new exception type to the predicate, ask whether that failure is actually "the upstream is sick" or "this transaction is bad". If the latter, don't add it — it will cause false trips.
- **Do not wrap signing calls.** `sign_transaction` is local; wrapping it adds no value and could mis-attribute signing errors to transport failures.
- **Respect `RpcCircuitOpenError` in `anchor_batch`'s gas-estimation fallback.** The existing `try/except Exception` around `estimate_gas` would swallow a circuit-open error and fall back to the default gas limit, silently burning attempts. Task 8 Step 5 item 2 explicitly re-raises `RpcCircuitOpenError` in that branch.
