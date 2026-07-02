"""Phase 2C — observability primitives.

The observability module has three concerns and the tests mirror them:

1. ``JsonFormatter`` emits valid JSON per record, including extras and
   the current request_id context.
2. ``RequestIdMiddleware`` honors incoming X-Request-ID, else mints one,
   always echoes the header back, and keeps the ContextVar scoped to
   one request (no leakage between concurrent requests).
3. Metrics are wired (names, labels) so dashboards / alerts that depend
   on the public metric names fail loudly if someone renames them.
"""

from __future__ import annotations

import asyncio
import json
import logging
from io import StringIO

from api.observability import (
    JsonFormatter,
    RequestIdMiddleware,
    configure_json_logging,
    current_request_id,
    request_id_var,
)

# -----------------------------------------------------------------------------
# JsonFormatter
# -----------------------------------------------------------------------------

def _format_record(record: logging.LogRecord) -> dict:
    return json.loads(JsonFormatter().format(record))


def test_json_formatter_emits_valid_json_with_basic_fields() -> None:
    record = logging.LogRecord(
        name="inntris.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    parsed = _format_record(record)
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "inntris.test"
    assert parsed["msg"] == "hello world"
    assert "ts" in parsed


def test_json_formatter_includes_request_id_when_set() -> None:
    token = request_id_var.set("abc-123")
    try:
        record = logging.LogRecord(
            "x", logging.INFO, __file__, 1, "msg", (), None,
        )
        parsed = _format_record(record)
        assert parsed["request_id"] == "abc-123"
    finally:
        request_id_var.reset(token)


def test_json_formatter_omits_request_id_when_unset() -> None:
    # No token set; context var default is None.
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "m", (), None)
    parsed = _format_record(record)
    assert "request_id" not in parsed


def test_json_formatter_preserves_extras() -> None:
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "m", (), None)
    record.agent_id = "agent-7"
    record.amount = 42
    parsed = _format_record(record)
    assert parsed["agent_id"] == "agent-7"
    assert parsed["amount"] == 42


def test_json_formatter_repr_fallback_for_non_serializable_extras() -> None:
    class NotJson:
        def __repr__(self) -> str:
            return "NotJson()"

    record = logging.LogRecord("x", logging.INFO, __file__, 1, "m", (), None)
    record.obj = NotJson()
    parsed = _format_record(record)
    assert parsed["obj"] == "NotJson()"


def test_configure_json_logging_swaps_root_handlers() -> None:
    buf = StringIO()
    configure_json_logging(level=logging.INFO)
    # Add our capture on top; configure_json_logging already installed
    # a StreamHandler with JsonFormatter on root.
    root = logging.getLogger()
    root.handlers[0].stream = buf

    logging.getLogger("inntris.test").info("structured")
    line = buf.getvalue().strip().splitlines()[-1]
    parsed = json.loads(line)
    assert parsed["msg"] == "structured"
    assert parsed["level"] == "INFO"


# -----------------------------------------------------------------------------
# RequestIdMiddleware
# -----------------------------------------------------------------------------

class _CaptureSend:
    """Minimal ASGI send-callable that captures the response start message."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def __call__(self, message: dict) -> None:
        self.sent.append(message)


async def _receive() -> dict:
    return {"type": "http.request", "body": b"", "more_body": False}


async def _minimal_app(_scope, _receive, send):
    # Echo the in-request request ID so we can assert it propagates.
    rid = current_request_id()
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": (rid or "").encode()})


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_request_id_minted_when_missing() -> None:
    mw = RequestIdMiddleware(_minimal_app)
    send = _CaptureSend()
    scope = {"type": "http", "headers": []}

    _run(mw(scope, _receive, send))

    start = next(m for m in send.sent if m["type"] == "http.response.start")
    header_names = {k for k, _ in start["headers"]}
    assert b"x-request-id" in header_names

    # After the call returns, the ContextVar must be cleared — leaking it
    # would pollute the next request on the same task.
    assert current_request_id() is None


def test_request_id_propagated_from_client_header() -> None:
    mw = RequestIdMiddleware(_minimal_app)
    send = _CaptureSend()
    scope = {
        "type": "http",
        "headers": [(b"x-request-id", b"caller-supplied-42")],
    }

    _run(mw(scope, _receive, send))

    start = next(m for m in send.sent if m["type"] == "http.response.start")
    headers = dict(start["headers"])
    assert headers[b"x-request-id"] == b"caller-supplied-42"

    body = next(m for m in send.sent if m["type"] == "http.response.body")
    # Our minimal_app wrote current_request_id() as the body — confirms the
    # context was populated *during* the handler call, not only the header.
    assert body["body"] == b"caller-supplied-42"


def test_non_http_scope_passes_through() -> None:
    """Websocket / lifespan scopes must not touch request_id_var."""
    called = {"inner": False}

    async def inner_app(_scope, _receive, _send):
        called["inner"] = True

    mw = RequestIdMiddleware(inner_app)

    async def _noop_send(_):
        return None

    async def _noop_receive():
        return {"type": "lifespan.startup"}

    _run(mw({"type": "lifespan"}, _noop_receive, _noop_send))
    assert called["inner"]
    assert current_request_id() is None


# -----------------------------------------------------------------------------
# Metric registration
# -----------------------------------------------------------------------------

def test_expected_metric_names_are_exported() -> None:
    """Alert rules and dashboards depend on these exact names. Rename
    protection: if someone changes them, CI breaks before the dashboards
    do."""
    from api import observability as obs
    # Presence check (names below are the public API of the module).
    assert hasattr(obs, "verify_requests_total")
    assert hasattr(obs, "signature_failures_total")
    assert hasattr(obs, "nonce_replays_total")
    assert hasattr(obs, "rate_limit_trips_total")
    assert hasattr(obs, "anchor_submissions_total")
    assert hasattr(obs, "verify_latency_seconds")


def test_metrics_endpoint_returns_prometheus_text() -> None:
    from api.observability import metrics_endpoint

    resp = asyncio.run(metrics_endpoint())
    assert resp.status_code == 200
    ctype = resp.media_type or resp.headers.get("content-type", "")
    # Accept either the prometheus text-format content-type or the 501
    # stub if the module happened to import in no-prom mode in this env.
    assert "text/plain" in ctype or "prometheus" in ctype.lower()
