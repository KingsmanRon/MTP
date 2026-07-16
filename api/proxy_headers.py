"""Trusted-proxy client identity for deployments behind a platform edge.

Every abuse limit and forensic ``request_ip`` in the API keys on
``request.client.host``. When the service runs behind a reverse proxy
(Railway's edge, a load balancer), the raw socket peer is the proxy — so
"per-source" budgets collapse into one shared bucket and audit rows record
the proxy's address instead of the caller's.

This middleware rewrites the ASGI ``client`` from ``X-Forwarded-For`` using
a *trusted hop count*, the same model as Express's ``trust proxy: 1``:

* The platform edge appends the real peer address to whatever
  ``X-Forwarded-For`` the client sent, so with one trusted proxy the
  **rightmost** entry is authoritative and cannot be spoofed by the caller.
* ``hops=N`` selects the Nth entry from the right for chains
  (CDN -> edge -> app is ``hops=2``).

Fail-closed direction: the middleware is off unless ``TRUST_PROXY_HEADERS``
is explicitly enabled, and any header it cannot parse into a valid IP for
the configured hop leaves the socket peer untouched rather than trusting a
malformed value.
"""

from __future__ import annotations

import ipaddress

MAX_TRUSTED_PROXY_HOPS = 10


def _canonical_ip(candidate: str) -> str | None:
    """Return the canonical text form of one XFF entry, or ``None``.

    Accepts bare IPv4/IPv6, bracketed IPv6, and ``host:port`` forms (some
    proxies append the peer port). Scoped/zoned addresses and anything else
    that does not parse are rejected.
    """
    candidate = candidate.strip()
    if not candidate or "%" in candidate:
        return None

    if candidate.startswith("["):
        # [v6] or [v6]:port
        closing = candidate.find("]")
        if closing == -1:
            return None
        remainder = candidate[closing + 1 :]
        if remainder and not remainder.startswith(":"):
            return None
        candidate = candidate[1:closing]
    elif candidate.count(":") == 1:
        # v4:port — a bare IPv6 address always contains more than one colon.
        candidate = candidate.split(":", 1)[0]

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def forwarded_client_ip(header_value: str | None, hops: int) -> str | None:
    """Select the client IP a chain of ``hops`` trusted proxies vouches for.

    Returns ``None`` — meaning "keep the socket peer" — when the header is
    missing, has fewer entries than trusted hops, or the selected entry is
    not a valid IP address.
    """
    if not header_value or not 1 <= hops <= MAX_TRUSTED_PROXY_HOPS:
        return None
    entries = [entry for entry in header_value.split(",") if entry.strip()]
    if len(entries) < hops:
        return None
    return _canonical_ip(entries[-hops])


class TrustedProxyClientMiddleware:
    """ASGI middleware: rewrite ``scope['client']`` from X-Forwarded-For.

    Must wrap the application outermost so rate limiters, source-identity
    hashing, and audit logging all observe the derived caller address.
    Only enable this when the service is reachable exclusively through the
    trusted proxy chain — a directly reachable listener would let callers
    forge the header.
    """

    def __init__(self, app, hops: int = 1):  # type: ignore[no-untyped-def]
        if not 1 <= hops <= MAX_TRUSTED_PROXY_HOPS:
            raise ValueError(
                f"hops must be between 1 and {MAX_TRUSTED_PROXY_HOPS}"
            )
        self.app = app
        self.hops = hops

    async def __call__(self, scope, receive, send):  # type: ignore[no-untyped-def]
        if scope["type"] in ("http", "websocket"):
            # A proxy may split X-Forwarded-For across repeated headers;
            # RFC 7230 says joining them with commas preserves semantics.
            raw_values = [
                value.decode("latin-1")
                for name, value in scope.get("headers", [])
                if name == b"x-forwarded-for"
            ]
            client_ip = forwarded_client_ip(",".join(raw_values), self.hops)
            if client_ip is not None:
                scope = dict(scope)
                scope["client"] = (client_ip, 0)
        await self.app(scope, receive, send)
