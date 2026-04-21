# Blockchain RPC Circuit Breaker — Design

**Status:** Draft
**Date:** 2026-04-21
**Owner:** anchor-worker
**Addresses:** Enterprise-readiness blocker #3 (RPC failures cascade through the worker; retries hammer a degraded upstream instead of isolating it)

## Context

The anchor worker (`workers/anchor_worker.py`) talks to a single Base L2 RPC endpoint via `Web3(Web3.HTTPProvider(BLOCKCHAIN_PROVIDER_URL))` (`anchor_worker.py:256`). When the RPC degrades:

- Each pending proof spends a full socket/read timeout before falling through to the existing per-proof exponential backoff.
- With N pending proofs, the worker's loop is dominated by waiting on a dead upstream.
- Existing per-proof retry/dead-letter machinery handles eventual consistency, but does not isolate the worker from the upstream failure.

Chain-id assertion (`assert_chain_id`) and gas-price cap (`MAX_GAS_PRICE_GWEI`) already defend against *wrong* RPC; they do nothing for *slow/down* RPC.

## Goal

Introduce a circuit breaker that:

1. Detects sustained transport-level RPC failures.
2. Short-circuits subsequent calls during the failure window (no dead-socket waits).
3. Probes cheaply and recovers automatically.
4. Leaves all other failure modes (reverts, gas caps, chain-id mismatches) on the existing per-proof retry path untouched.

## Non-goals

- Multi-endpoint fallback (separate future change; see "Future work").
- Shared breaker state across worker processes.
- Per-call HTTP timeouts, jittered backoff, or broader resilience hardening.
- Changes to database schema, worker orchestration, or proof-processing semantics.

## Architecture

One new unit, `RpcCircuitBreaker`, owned by `BlockchainService`. State lives in-memory on the worker process. Each worker process tracks its own socket pool, so per-process state is correct for single-instance and multi-instance deploys alike.

The breaker wraps the RPC call boundary inside `BlockchainService`. Nothing else changes:

- No schema changes.
- No changes to `_process_proof`, `_record_failure`, `_retry_pending_proofs`.
- The breaker raises a distinct `RpcCircuitOpenError` that the worker catches like any other transport failure. The proof is recorded `failed`, backed off, and requeued by the existing path.

The breaker never swallows exceptions. Transport failures re-raise after the counter/state update; non-transport exceptions pass through untouched.

## Components

### `workers/circuit_breaker.py` (new)

```python
class RpcCircuitBreaker:
    def __init__(
        self,
        threshold: int,
        open_duration_seconds: float,
        enabled: bool = True,
        clock: Callable[[], float] = time.monotonic,
    ): ...

    def call(self, fn: Callable[[], T]) -> T: ...

    @property
    def state(self) -> BreakerState: ...  # CLOSED | OPEN | HALF_OPEN


class RpcCircuitOpenError(Exception):
    """Raised when a call is rejected because the breaker is OPEN."""
    cooldown_remaining_seconds: float
```

### State machine

| From | Event | To | Side effect |
|---|---|---|---|
| CLOSED | transport failure, counter < threshold | CLOSED | counter++ |
| CLOSED | transport failure, counter == threshold - 1 | OPEN | counter = threshold; opened_at = now; emit `rpc_breaker_opened`; trips_total++ |
| CLOSED | success | CLOSED | counter = 0 |
| CLOSED | non-transport exception | CLOSED | (no change) |
| OPEN | call attempted, now < opened_at + open_duration | OPEN | raise `RpcCircuitOpenError`; rejected_total++ |
| OPEN | call attempted, now >= opened_at + open_duration | HALF_OPEN | emit `rpc_breaker_probe`; run wrapped fn as probe |
| HALF_OPEN | probe success | CLOSED | counter = 0; emit `rpc_breaker_closed` |
| HALF_OPEN | probe transport failure | OPEN | opened_at = now; emit `rpc_breaker_probe_failed`; trips_total++ |
| HALF_OPEN | probe non-transport exception | CLOSED | counter = 0 (RPC responded — not a transport issue) |
| *any* | kill switch disabled (`ENABLED=false`) | passthrough | `call(fn)` returns `fn()` directly. No state transitions, no counter updates, no metrics — the breaker is fully inert. |

### Transport-error predicate

```python
def is_transport_error(exc: BaseException) -> bool:
    if isinstance(exc, (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.ChunkedEncodingError,
    )):
        return True
    if isinstance(exc, web3.exceptions.ProviderConnectionError):
        return True
    # HTTP 5xx from the provider also counts as transport
    if isinstance(exc, requests.exceptions.HTTPError):
        resp = getattr(exc, "response", None)
        return resp is not None and resp.status_code >= 500
    return False
```

Explicitly NOT transport (pass through unchanged):

- `web3.exceptions.ContractLogicError` (revert)
- `ValueError` raised by web3 for nonce / replacement-underpriced / etc.
- `RuntimeError` from `assert_chain_id` (chain-id mismatch — a hard-fail, not a breaker concern)
- `RuntimeError` from the gas-price cap
- Any other application-level exception

### Integration in `BlockchainService`

- `__init__` instantiates one `RpcCircuitBreaker` with env-driven config.
- A small helper routes every RPC call through the breaker:
  ```python
  def _rpc(self, fn: Callable[[], T]) -> T:
      return self._breaker.call(fn)
  ```
- Every call that touches the RPC is wrapped via `self._rpc(...)`:
  - `assert_chain_id()` — `self._rpc(lambda: self.w3.eth.chain_id)`
  - Inside `anchor_batch()`:
    - `self._rpc(lambda: self.w3.eth.get_transaction_count(...))`
    - `self._rpc(lambda: self.contract.functions.anchorBatch(...).estimate_gas(...))`
    - `self._rpc(lambda: self.w3.eth.gas_price)`
    - `self._rpc(lambda: self.w3.eth.send_raw_transaction(raw_tx))`
    - `self._rpc(lambda: self.w3.eth.wait_for_transaction_receipt(tx_hash))`
  - `get_balance()` — `self._rpc(lambda: self.w3.eth.get_balance(...))`
  - `is_connected()` — `self._rpc(lambda: self.w3.is_connected())`, with exceptions swallowed to preserve the existing `bool` return contract.
- Application-level logic (signing, building the tx dict, gas-cap comparison) stays outside the breaker.
- The `assert_chain_id()` wrap is the natural half-open probe point: it is already called first in `anchor_batch`, it is cheap, and it does not spend gas. After a cooldown, the next attempt's `assert_chain_id` call is the probe; if it succeeds, the rest of `anchor_batch` proceeds through the same (now-closed) breaker.
- Transport errors from any of these wrapped calls increment the breaker counter and trip it at threshold. Non-transport errors (reverts, gas cap, chain-id mismatch, nonce errors) bypass the counter and propagate as before.

### Configuration

| Env var | Default | Meaning |
|---|---|---|
| `ANCHOR_RPC_BREAKER_ENABLED` | `true` | Kill switch. When false, `call(fn)` is a passthrough. |
| `ANCHOR_RPC_BREAKER_THRESHOLD` | `5` | Consecutive transport failures to trip. |
| `ANCHOR_RPC_BREAKER_OPEN_SECONDS` | `60` | Cooldown before the next call becomes a half-open probe. |

Logged at worker startup (with redaction applied to any URL).

## Data flow

### Normal (CLOSED)

1. Worker calls `blockchain.anchor_batch(...)`.
2. `_breaker.call(assert_chain_id)` — succeeds, counter stays 0.
3. Gas estimation, tx build, gas-cap check — unwrapped.
4. `_breaker.call(_send_and_wait, tx)` — success, return receipt.

### Degraded (RPC starts timing out)

1. Attempts 1..(threshold-1) fail with `requests.Timeout`. Counter increments. Each proof follows the existing `_record_failure` → backoff → requeue path.
2. Threshold-th failure trips the breaker to OPEN. `opened_at = now`.
3. Next proof picked up by `_retry_pending_proofs` calls `anchor_batch`, which calls `_breaker.call(assert_chain_id)`. Breaker raises `RpcCircuitOpenError` immediately — **no socket touched**.
4. Worker catches in `_process_proof`, logs `"RPC circuit open, deferring proof X"`, calls `_record_failure` with a circuit-open error string. Proof requeues with normal backoff.
5. Further pending proofs short-circuit the same way. Worker loop keeps ticking instead of waiting on dead sockets.

### Recovery

1. `open_duration_seconds` elapses. Next anchor attempt triggers the HALF_OPEN transition.
2. `assert_chain_id()` runs as the probe.
   - **Success:** state → CLOSED, counter → 0. `anchor_batch` continues through gas estimation and tx submission normally.
   - **Transport failure:** state → OPEN, `opened_at` resets. Proof records failure and requeues as usual.
   - **Non-transport failure** (e.g., chain-id mismatch): state → CLOSED but the error still propagates. The RPC is responding — that is the signal the breaker cares about.

## Error handling

- Transport failure: breaker updates state/counter, then **re-raises the original exception**. Callers see the true root cause in logs. No wrapping.
- OPEN rejection: synthetic `RpcCircuitOpenError`. Worker's existing `_record_failure` path handles it like any other failure — no proof is silently dropped.
- Non-transport exceptions: breaker is transparent. Counter unaffected.

## Observability

### Logs (JSON, via `api/observability.py` patterns)

| Event | Level | Payload |
|---|---|---|
| `rpc_breaker_opened` | WARNING | `{failure_count, threshold, last_error}` |
| `rpc_breaker_probe` | INFO | `{open_duration_s}` |
| `rpc_breaker_closed` | INFO | `{}` |
| `rpc_breaker_probe_failed` | WARNING | `{error}` |
| per-proof deferred-while-open | DEBUG | `{proof_id, cooldown_remaining_s}` |

DEBUG for the per-proof case prevents log spam when many proofs are pending during an OPEN window.

### Metrics (Prometheus)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `inntris_rpc_breaker_state` | gauge | `state={closed,open,half_open}` | 1 for the current state, 0 otherwise |
| `inntris_rpc_breaker_trips_total` | counter | — | Incremented on every OPEN transition (including probe-failed re-opens) |
| `inntris_rpc_breaker_rejected_total` | counter | — | Incremented on every call rejected while OPEN |

Ops-side alert guidance (text only, not coded): `increase(inntris_rpc_breaker_trips_total[5m]) > 0`. Alert thresholds live in a future ops runbook, out of scope here.

### Kill switch

`ANCHOR_RPC_BREAKER_ENABLED=false` makes the breaker a passthrough. Lets ops disable it in place without redeploying code if it ever misbehaves. Logged at startup.

## Testing

All tests in `tests/test_rpc_circuit_breaker.py` (new file). No real Web3, no real network; unit-level use of fake callables, integration-level use of mocked `BlockchainService`.

### Unit — `RpcCircuitBreaker` in isolation

1. `test_closed_allows_calls` — 10 successful calls, state stays CLOSED.
2. `test_transport_failures_increment_counter` — (threshold - 1) transport failures, state still CLOSED.
3. `test_trips_on_threshold` — threshold-th consecutive transport failure → OPEN, `opened_at` set.
4. `test_non_transport_failure_does_not_count` — `ValueError` raised threshold times, state stays CLOSED.
5. `test_open_rejects_calls` — OPEN breaker short-circuits; wrapped fn is not invoked.
6. `test_open_transitions_to_half_open_after_cooldown` — monkeypatch clock; next call becomes probe.
7. `test_half_open_success_closes` — probe succeeds → CLOSED, counter reset.
8. `test_half_open_failure_reopens` — probe transport failure → OPEN with fresh `opened_at`.
9. `test_success_mid_streak_resets_counter` — 3 failures then 1 success → counter 0.
10. `test_kill_switch_disables_breaker` — enabled=false → passthrough regardless of failure count.

### Integration — `BlockchainService` with mocked Web3

11. `test_assert_chain_id_wrapped_by_breaker` — mock `w3.eth.chain_id` to raise `requests.Timeout` threshold times; subsequent `anchor_batch` raises `RpcCircuitOpenError`.
12. `test_revert_does_not_trip_breaker` — mock `send_raw_transaction` to raise `ContractLogicError` (threshold + 5) times; breaker stays CLOSED.
13. `test_gas_cap_bypasses_breaker` — mock `eth.gas_price` above cap threshold times; `RuntimeError` propagates; breaker stays CLOSED.
14. `test_recovery_after_cooldown` — trip → cooldown elapses → chain_id probe succeeds → `anchor_batch` completes end-to-end (all mocked).

### Worker-level smoke

15. `test_worker_continues_processing_when_breaker_open` — breaker stuck OPEN; worker loop doesn't hang; proofs get `_record_failure` with circuit-open error; backoff applied.

### Metrics / logs

16. `test_trip_increments_metrics` — `trips_total` increments exactly once on trip; `rejected_total` increments on each rejected call.
17. `test_log_events_on_state_transitions` — caplog assertions for the four state-transition keys.

### Out of scope for tests

- Real Web3/RPC calls (existing worker integration tests remain gated behind `INNTRIS_DB_INTEGRATION`).
- Multi-worker / shared-state behavior.

## Deployment & rollout

1. Code change is additive — existing behavior is preserved when the breaker stays CLOSED.
2. Deploy with defaults (`ENABLED=true`, `THRESHOLD=5`, `OPEN_SECONDS=60`).
3. Monitor `inntris_rpc_breaker_trips_total` for the first week. Zero trips is normal. A single trip during an RPC incident is the intended outcome.
4. If the breaker misbehaves in prod, set `ANCHOR_RPC_BREAKER_ENABLED=false` and restart the worker — no code change required.

## Future work

- **Multi-endpoint fallback:** a list of RPC URLs, one breaker per endpoint, fail over to the next healthy endpoint instead of deferring the proof. Natural next step once the breaker has stabilized in prod.
- **Alert runbook:** wire `inntris_rpc_breaker_trips_total` into the alert-thresholds runbook when that doc is written.
- **Per-call HTTP timeouts:** the `requests` default timeout is infinite. Shrinking it (e.g., 10s) would shorten time-to-trip under a hung upstream. Separate change.
