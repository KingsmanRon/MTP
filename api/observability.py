"""Observability — structured logging, request IDs, Prometheus metrics (Phase 2C).

Three loosely-coupled building blocks, each optional:

* ``JsonFormatter``: a ``logging.Formatter`` that emits one JSON object per
  record. Stdout becomes directly scrape-able by any log aggregator.
* ``request_id_var``: a ``ContextVar`` that carries the current request's
  correlation ID into every log record on the task. The FastAPI middleware
  (``RequestIdMiddleware``) sets it from the incoming ``X-Request-ID``
  header (or a fresh UUID) and echoes it back to the client.
* ``metrics``: a small registry of counters / histograms for the hot-path
  events we care about — verify calls, signature failures, nonce replays,
  rate-limit trips, anchor submissions. Scraped at ``/metrics`` by the
  ``prometheus-client`` ASGI app.

All three are gated on ``prometheus_client`` being importable. If it is
not, metrics become no-op stubs and the API still serves — useful for
local runs without the observability stack.
"""

from __future__ import annotations

import json
import logging
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import Response

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
        start_http_server,
    )
    _HAS_PROMETHEUS = True
except ImportError:  # pragma: no cover — exercised in no-prom environments
    _HAS_PROMETHEUS = False


# -----------------------------------------------------------------------------
# Request ID correlation
# -----------------------------------------------------------------------------

# ContextVar, not thread-local: FastAPI is asyncio, and each task gets its own
# copy. Missing = "no request in scope" (e.g. worker startup logs).
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


def current_request_id() -> str | None:
    return request_id_var.get()


# -----------------------------------------------------------------------------
# Structured JSON logging
# -----------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    """One-record-per-line JSON formatter.

    Emits the standard fields plus:
      * ``request_id`` when set on the current context.
      * Any extras passed via ``logger.info("...", extra={"key": value})``.

    Stdlib ``logging.Formatter`` already handles exc_info; we just move
    that into the JSON payload alongside the message.
    """

    # The set of LogRecord attributes we do NOT want to leak into the JSON
    # (they are either internal state or rendered separately).
    _STANDARD_ATTRS = frozenset({
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "message", "module",
        "msecs", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName", "taskName",
    })

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        rid = request_id_var.get()
        if rid is not None:
            payload["request_id"] = rid

        # Anything the caller attached via extra={...}.
        for key, value in record.__dict__.items():
            if key in self._STANDARD_ATTRS or key in payload:
                continue
            try:
                json.dumps(value)  # only include JSON-serializable extras
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_json_logging(level: int = logging.INFO) -> None:
    """Replace the root logger's handlers with a JSON-formatted stdout handler.

    Safe to call multiple times — we clear existing handlers first so the
    ``basicConfig`` call in ``api/main.py`` does not double up.
    """
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)


# -----------------------------------------------------------------------------
# Prometheus metrics
# -----------------------------------------------------------------------------

class _NoopMetric:
    """Stand-in for prom metrics when prometheus_client is not installed.

    Every call is a no-op so the API code does not need to branch on
    ``_HAS_PROMETHEUS`` at every increment.
    """

    def labels(self, *_a: Any, **_kw: Any) -> _NoopMetric:
        return self

    def inc(self, _amount: float = 1.0) -> None:
        return None

    def observe(self, _amount: float) -> None:
        return None

    def set(self, _value: float) -> None:
        return None


if _HAS_PROMETHEUS:
    verify_requests_total = Counter(
        "inntris_verify_requests_total",
        "Total /verify calls by outcome.",
        ["verdict"],  # approved | blocked | invalid_signature | replay | rate_limited
    )
    signature_failures_total = Counter(
        "inntris_signature_failures_total",
        "Total signatures that failed Ed25519 verification.",
    )
    nonce_replays_total = Counter(
        "inntris_nonce_replays_total",
        "Total /verify calls rejected because the nonce was seen before.",
    )
    rate_limit_trips_total = Counter(
        "inntris_rate_limit_trips_total",
        "Total requests rejected by a rate-limit window.",
        ["window"],  # public_verify | admin_login | tenant_minute
    )
    anchor_submissions_total = Counter(
        "inntris_anchor_submissions_total",
        "Total anchor transactions attempted by the worker.",
        ["outcome"],  # confirmed | failed | dead_letter
    )
    anchor_worker_heartbeat_timestamp_seconds = Gauge(
        "inntris_anchor_worker_heartbeat_timestamp_seconds",
        "Unix timestamp when the anchor worker process last reported liveness.",
    )
    anchor_worker_last_success_timestamp_seconds = Gauge(
        "inntris_anchor_worker_last_success_timestamp_seconds",
        "Unix timestamp of the anchor worker's most recent successful cycle.",
    )
    anchor_worker_cycles_total = Counter(
        "inntris_anchor_worker_cycles_total",
        "Total anchor worker processing cycles by outcome.",
        ["outcome"],  # success | error | lock_contended
    )
    anchor_proof_backlog = Gauge(
        "inntris_anchor_proof_backlog",
        "Current number of anchor proofs requiring operator attention.",
        ["status"],  # failed | dead_letter
    )
    webhook_delivery_attempts_total = Counter(
        "inntris_webhook_delivery_attempts_total",
        "Total webhook delivery attempts by outcome.",
        ["outcome"],  # delivered | retry | dead_letter | security_rejected
    )
    webhook_delivery_latency_seconds = Histogram(
        "inntris_webhook_delivery_latency_seconds",
        "Wall time for one outbound webhook attempt, seconds.",
        buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    )
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
    verify_latency_seconds = Histogram(
        "inntris_verify_latency_seconds",
        "Wall time for /verify end-to-end, seconds.",
        buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    )
    verify_stage_latency_seconds = Histogram(
        "inntris_verify_stage_latency_seconds",
        "Wall time for one named /verify stage, seconds.",
        ["stage"],
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
    )
    verify_unavailable_total = Counter(
        "inntris_verify_unavailable_total",
        "Total /verify requests refused fail-closed because a security "
        "dependency (Redis) was unavailable. Any increase is an outage.",
        ["component"],  # abuse_limiter | agent_limiter | signature_slots | nonce_cache
    )
else:  # pragma: no cover — exercised in stub mode
    verify_requests_total = _NoopMetric()
    signature_failures_total = _NoopMetric()
    nonce_replays_total = _NoopMetric()
    rate_limit_trips_total = _NoopMetric()
    anchor_submissions_total = _NoopMetric()
    anchor_worker_heartbeat_timestamp_seconds = _NoopMetric()
    anchor_worker_last_success_timestamp_seconds = _NoopMetric()
    anchor_worker_cycles_total = _NoopMetric()
    anchor_proof_backlog = _NoopMetric()
    webhook_delivery_attempts_total = _NoopMetric()
    webhook_delivery_latency_seconds = _NoopMetric()
    rpc_breaker_trips_total = _NoopMetric()
    rpc_breaker_rejected_total = _NoopMetric()
    rpc_breaker_state = _NoopMetric()
    verify_latency_seconds = _NoopMetric()
    verify_stage_latency_seconds = _NoopMetric()
    verify_unavailable_total = _NoopMetric()


async def metrics_endpoint() -> Response:
    """FastAPI handler that returns the Prometheus exposition payload.

    Deliberately a free function (not a class) so ``api/main.py`` can wire
    it with ``app.add_route("/metrics", metrics_endpoint)`` without
    importing Starlette here.
    """
    from fastapi import Response  # local import keeps this module import-light

    if not _HAS_PROMETHEUS:
        return Response(
            content="# prometheus_client not installed — metrics disabled\n",
            media_type="text/plain",
            status_code=501,
        )
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


def start_worker_metrics_endpoint(port: int, addr: str = "0.0.0.0") -> Any:
    """Start the anchor worker's Prometheus HTTP endpoint.

    The worker is a separate process from FastAPI, so it needs its own scrape
    listener. Failure is explicit: silently running without a heartbeat would
    make a dead worker indistinguishable from a quiet one.
    """
    if not _HAS_PROMETHEUS:
        raise RuntimeError(
            "prometheus-client is required for the anchor worker metrics endpoint"
        )
    return start_http_server(port=port, addr=addr)


# -----------------------------------------------------------------------------
# FastAPI middleware for request IDs
# -----------------------------------------------------------------------------

class RequestIdMiddleware:
    """ASGI middleware: attach an X-Request-ID to every request.

    If the client sent ``X-Request-ID``, we propagate it (makes trace
    correlation across services trivial). Otherwise we mint a UUID4. The
    ID is set on ``request_id_var`` for the duration of the request so
    every ``logger.info(...)`` call inside the handler carries it.

    We also write the header back into the response so a caller can look
    it up in server logs with a single grep.
    """

    def __init__(self, app):  # type: ignore[no-untyped-def]
        self.app = app

    async def __call__(self, scope, receive, send):  # type: ignore[no-untyped-def]
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        incoming = headers.get(b"x-request-id")
        rid = incoming.decode("latin-1") if incoming else uuid.uuid4().hex

        token = request_id_var.set(rid)

        async def _send(message):  # type: ignore[no-untyped-def]
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                message["headers"] = list(message["headers"]) + [
                    (b"x-request-id", rid.encode("latin-1")),
                    (b"x-inntris-api-version", b"1.0.0"),
                ]
            await send(message)

        try:
            await self.app(scope, receive, _send)
        finally:
            request_id_var.reset(token)
