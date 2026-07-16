"""Trusted-proxy client identity derivation (api/proxy_headers.py).

The rate limiters and audit forensics key on ``request.client.host``. These
tests pin the two security properties of the forwarded-header model:

* With ``hops=N`` trusted proxies, a caller-supplied X-Forwarded-For prefix
  can never influence the selected address — only the entries appended by
  the trusted chain are used.
* Anything unparseable fails closed to the socket peer instead of trusting
  a malformed header.
"""

from __future__ import annotations

import pytest

from api.proxy_headers import (
    MAX_TRUSTED_PROXY_HOPS,
    TrustedProxyClientMiddleware,
    forwarded_client_ip,
)

# ---------------------------------------------------------------------------
# forwarded_client_ip — pure selection logic
# ---------------------------------------------------------------------------


def test_single_hop_takes_rightmost_entry():
    assert forwarded_client_ip("203.0.113.7", 1) == "203.0.113.7"


def test_spoofed_prefix_is_ignored_with_one_trusted_hop():
    # The client sent a forged header; the edge appended the real peer.
    header = "1.2.3.4, 10.0.0.9, 203.0.113.7"
    assert forwarded_client_ip(header, 1) == "203.0.113.7"


def test_two_hops_selects_second_from_right():
    header = "1.2.3.4, 198.51.100.20, 192.0.2.1"
    assert forwarded_client_ip(header, 2) == "198.51.100.20"


def test_fewer_entries_than_hops_fails_closed():
    assert forwarded_client_ip("203.0.113.7", 2) is None


def test_missing_or_empty_header_fails_closed():
    assert forwarded_client_ip(None, 1) is None
    assert forwarded_client_ip("", 1) is None
    assert forwarded_client_ip(" , ,", 1) is None


def test_invalid_selected_entry_fails_closed():
    assert forwarded_client_ip("1.2.3.4, not-an-ip", 1) is None
    assert forwarded_client_ip("1.2.3.4, evil.example.com", 1) is None


def test_hostname_never_accepted_even_alone():
    assert forwarded_client_ip("localhost", 1) is None


def test_whitespace_is_stripped():
    assert forwarded_client_ip("  203.0.113.7  ", 1) == "203.0.113.7"


def test_ipv4_with_port_is_normalised():
    assert forwarded_client_ip("203.0.113.7:4711", 1) == "203.0.113.7"


def test_bare_ipv6_is_accepted():
    assert forwarded_client_ip("2001:db8::1", 1) == "2001:db8::1"


def test_bracketed_ipv6_with_port_is_normalised():
    assert forwarded_client_ip("[2001:db8::1]:443", 1) == "2001:db8::1"


def test_malformed_bracketed_ipv6_fails_closed():
    assert forwarded_client_ip("[2001:db8::1", 1) is None
    assert forwarded_client_ip("[2001:db8::1]junk", 1) is None


def test_scoped_ipv6_fails_closed():
    assert forwarded_client_ip("fe80::1%eth0", 1) is None


def test_out_of_range_hops_fail_closed():
    assert forwarded_client_ip("203.0.113.7", 0) is None
    assert forwarded_client_ip("203.0.113.7", MAX_TRUSTED_PROXY_HOPS + 1) is None


# ---------------------------------------------------------------------------
# TrustedProxyClientMiddleware — ASGI behaviour
# ---------------------------------------------------------------------------


class _CaptureApp:
    def __init__(self) -> None:
        self.scope = None

    async def __call__(self, scope, _receive, _send):
        self.scope = scope


async def _run(middleware: TrustedProxyClientMiddleware, scope: dict) -> dict:
    async def receive():  # pragma: no cover — never awaited by capture app
        return {"type": "http.request"}

    async def send(_message):  # pragma: no cover
        return None

    await middleware(scope, receive, send)
    return middleware.app.scope


@pytest.mark.asyncio
async def test_middleware_rewrites_client_from_forwarded_header():
    middleware = TrustedProxyClientMiddleware(_CaptureApp(), hops=1)
    seen = await _run(
        middleware,
        {
            "type": "http",
            "client": ("10.0.0.2", 55000),
            "headers": [(b"x-forwarded-for", b"1.2.3.4, 203.0.113.7")],
        },
    )
    assert seen["client"] == ("203.0.113.7", 0)


@pytest.mark.asyncio
async def test_middleware_keeps_socket_peer_without_header():
    middleware = TrustedProxyClientMiddleware(_CaptureApp(), hops=1)
    seen = await _run(
        middleware,
        {"type": "http", "client": ("10.0.0.2", 55000), "headers": []},
    )
    assert seen["client"] == ("10.0.0.2", 55000)


@pytest.mark.asyncio
async def test_middleware_keeps_socket_peer_on_unparseable_header():
    middleware = TrustedProxyClientMiddleware(_CaptureApp(), hops=1)
    seen = await _run(
        middleware,
        {
            "type": "http",
            "client": ("10.0.0.2", 55000),
            "headers": [(b"x-forwarded-for", b"garbage")],
        },
    )
    assert seen["client"] == ("10.0.0.2", 55000)


@pytest.mark.asyncio
async def test_middleware_joins_repeated_forwarded_headers_in_order():
    middleware = TrustedProxyClientMiddleware(_CaptureApp(), hops=2)
    seen = await _run(
        middleware,
        {
            "type": "http",
            "client": ("10.0.0.2", 55000),
            "headers": [
                (b"x-forwarded-for", b"1.2.3.4"),
                (b"x-forwarded-for", b"198.51.100.20, 192.0.2.1"),
            ],
        },
    )
    assert seen["client"] == ("198.51.100.20", 0)


@pytest.mark.asyncio
async def test_middleware_ignores_lifespan_scope():
    middleware = TrustedProxyClientMiddleware(_CaptureApp(), hops=1)
    seen = await _run(middleware, {"type": "lifespan"})
    assert seen == {"type": "lifespan"}


def test_middleware_rejects_out_of_range_hops():
    with pytest.raises(ValueError):
        TrustedProxyClientMiddleware(_CaptureApp(), hops=0)
    with pytest.raises(ValueError):
        TrustedProxyClientMiddleware(_CaptureApp(), hops=MAX_TRUSTED_PROXY_HOPS + 1)
