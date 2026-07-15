"""Secure, tenant scoped webhook delivery.

This module owns the outbound security boundary for organisation webhooks.  A
destination is parsed and resolved before delivery, resolved again immediately
before opening the socket, and the HTTP transport connects to the validated IP
address instead of asking the operating system to resolve the hostname again.
TLS certificate verification and SNI still use the original hostname.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import ssl
import time
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import SplitResult, urlsplit, urlunsplit
from uuid import UUID

import httpcore
import httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from api.observability import webhook_delivery_attempts_total, webhook_delivery_latency_seconds

logger = logging.getLogger(__name__)

MAX_WEBHOOK_URL_LENGTH = 2048
MAX_WEBHOOK_RESPONSE_BYTES = 64 * 1024
MAX_WEBHOOK_ATTEMPTS = 3
WEBHOOK_RETRY_DELAYS_SECONDS = (1.0, 5.0)
WEBHOOK_CONNECT_TIMEOUT_SECONDS = 3.0
WEBHOOK_READ_TIMEOUT_SECONDS = 5.0
WEBHOOK_WRITE_TIMEOUT_SECONDS = 5.0
WEBHOOK_RECOVERY_POLL_SECONDS = float(os.getenv("WEBHOOK_RECOVERY_POLL_SECONDS", "5"))
WEBHOOK_RECOVERY_BATCH_SIZE = int(os.getenv("WEBHOOK_RECOVERY_BATCH_SIZE", "50"))

if WEBHOOK_RECOVERY_POLL_SECONDS <= 0:
    raise RuntimeError("WEBHOOK_RECOVERY_POLL_SECONDS must be greater than zero")
if not 1 <= WEBHOOK_RECOVERY_BATCH_SIZE <= 500:
    raise RuntimeError("WEBHOOK_RECOVERY_BATCH_SIZE must be between 1 and 500")

_SECRET_ENVELOPE_PREFIX = b"IWS1"
_SECRET_NONCE_BYTES = 12
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_DISALLOWED_DNS_SUFFIXES = (
    ".arpa",
    ".example",
    ".home",
    ".internal",
    ".invalid",
    ".local",
    ".localhost",
    ".test",
)


class WebhookSecurityError(ValueError):
    """The destination or secret violates a fail closed security rule."""


class WebhookDeliveryError(RuntimeError):
    """A delivery failed with an explicit retry classification."""

    def __init__(self, message: str, *, retryable: bool, status_code: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code


class _Resolver(Protocol):
    async def __call__(self, hostname: str, port: int) -> Sequence[str]: ...


class _WebhookDatabase(Protocol):
    async def enqueue_webhook_delivery(
        self,
        org_id: UUID,
        event: str,
        payload: dict[str, Any],
    ) -> UUID | None: ...

    async def begin_webhook_delivery_attempt(self, delivery_id: UUID) -> Any | None: ...

    async def mark_webhook_delivery_delivered(
        self,
        delivery_id: UUID,
        response_status: int,
    ) -> None: ...

    async def mark_webhook_delivery_retry(
        self,
        delivery_id: UUID,
        error: str,
        response_status: int | None,
        retry_delay_seconds: float,
    ) -> None: ...

    async def mark_webhook_delivery_dead_letter(
        self,
        delivery_id: UUID,
        error: str,
        response_status: int | None,
    ) -> None: ...

    async def list_due_webhook_delivery_ids(self, limit: int) -> list[UUID]: ...


@dataclass(frozen=True, slots=True)
class ParsedWebhookDestination:
    """Canonical HTTPS URL and origin fields used by the pinned transport."""

    url: str
    hostname: str
    port: int


@dataclass(frozen=True, slots=True)
class ResolvedWebhookDestination(ParsedWebhookDestination):
    """A parsed destination plus its preflight DNS result."""

    addresses: tuple[str, ...]


def _canonical_public_ip(raw_address: str) -> str:
    """Return a canonical globally routable address or fail closed."""

    if "%" in raw_address:
        raise WebhookSecurityError("Scoped IPv6 addresses are not valid webhook destinations")
    try:
        address = ipaddress.ip_address(raw_address)
    except ValueError as exc:
        raise WebhookSecurityError("Webhook DNS returned an invalid IP address") from exc

    mapped = getattr(address, "ipv4_mapped", None)
    effective_address = mapped or address
    unsafe = (
        not effective_address.is_global
        or effective_address.is_loopback
        or effective_address.is_private
        or effective_address.is_link_local
        or effective_address.is_multicast
        or effective_address.is_unspecified
        or effective_address.is_reserved
    )
    if getattr(effective_address, "is_site_local", False):
        unsafe = True
    if unsafe:
        raise WebhookSecurityError(
            "Webhook destinations must resolve only to globally routable addresses"
        )
    return str(address)


def _canonical_hostname(parsed: SplitResult) -> str:
    hostname = parsed.hostname
    if not hostname:
        raise WebhookSecurityError("Webhook URL must include a hostname")
    if hostname.endswith("."):
        raise WebhookSecurityError("A trailing dot is not allowed in webhook hostnames")
    if "%" in hostname:
        raise WebhookSecurityError("Encoded or scoped webhook hostnames are not allowed")
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError as exc:
        raise WebhookSecurityError("Webhook hostnames must use their ASCII IDNA form") from exc

    hostname = hostname.lower()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if ":" in hostname or re.fullmatch(r"[0-9.]+", hostname):
            raise WebhookSecurityError("Webhook IP literals must use canonical notation")
        if len(hostname) > 253:
            raise WebhookSecurityError("Webhook hostname is too long")
        labels = hostname.split(".")
        if any(not _HOST_LABEL.fullmatch(label) for label in labels):
            raise WebhookSecurityError("Webhook hostname contains an invalid DNS label")
        if hostname == "localhost" or hostname.endswith(_DISALLOWED_DNS_SUFFIXES):
            raise WebhookSecurityError("Local or reserved DNS names are not allowed")
    else:
        _canonical_public_ip(hostname)
    return hostname


def parse_webhook_url(raw_url: str) -> ParsedWebhookDestination:
    """Parse and canonicalise a webhook URL without performing DNS I/O."""

    if not isinstance(raw_url, str):
        raise WebhookSecurityError("Webhook URL must be a string")
    candidate = raw_url.strip()
    if not candidate or len(candidate) > MAX_WEBHOOK_URL_LENGTH:
        raise WebhookSecurityError("Webhook URL must be between 1 and 2048 characters")
    if candidate != raw_url or any(ord(character) < 32 for character in candidate):
        raise WebhookSecurityError("Webhook URL must not contain whitespace or control characters")
    if "\\" in candidate:
        raise WebhookSecurityError("Backslashes are not allowed in webhook URLs")

    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise WebhookSecurityError("Webhook URL is malformed") from exc
    if parsed.scheme.lower() != "https":
        raise WebhookSecurityError("Webhook URL must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise WebhookSecurityError("Credentials are not allowed in webhook URLs")
    if parsed.fragment:
        raise WebhookSecurityError("Fragments are not allowed in webhook URLs")
    if parsed.path.startswith("//"):
        raise WebhookSecurityError("Network path references are not allowed in webhook URLs")

    hostname = _canonical_hostname(parsed)
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise WebhookSecurityError("Webhook URL contains an invalid port") from exc
    if port != 443:
        raise WebhookSecurityError("Webhook URL must use the standard HTTPS port 443")

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        canonical_netloc = hostname
    else:
        canonical_netloc = f"[{literal}]" if literal.version == 6 else str(literal)
    path = parsed.path or "/"
    canonical_url = urlunsplit(("https", canonical_netloc, path, parsed.query, ""))
    return ParsedWebhookDestination(
        url=canonical_url,
        hostname=hostname,
        port=port,
    )


async def _system_resolver(hostname: str, port: int) -> Sequence[str]:
    loop = asyncio.get_running_loop()
    try:
        records = await loop.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise WebhookDeliveryError("Webhook hostname could not be resolved", retryable=True) from exc
    return [str(record[4][0]) for record in records]


async def _resolve_public_addresses(
    hostname: str,
    port: int,
    resolver: _Resolver,
) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        raw_addresses = await resolver(hostname, port)
    else:
        raw_addresses = [str(literal)]
    if not raw_addresses:
        raise WebhookDeliveryError("Webhook hostname returned no addresses", retryable=True)
    return tuple(sorted({_canonical_public_ip(address) for address in raw_addresses}))


async def resolve_webhook_destination(
    raw_url: str,
    *,
    resolver: _Resolver | None = None,
) -> ResolvedWebhookDestination:
    """Validate URL structure and require every DNS answer to be public."""

    parsed = parse_webhook_url(raw_url)
    active_resolver = resolver or _system_resolver
    addresses = await _resolve_public_addresses(parsed.hostname, parsed.port, active_resolver)
    return ResolvedWebhookDestination(
        url=parsed.url,
        hostname=parsed.hostname,
        port=parsed.port,
        addresses=addresses,
    )


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Network backend that performs a second DNS check and pins the socket."""

    def __init__(
        self,
        destination: ResolvedWebhookDestination,
        resolver: _Resolver,
        delegate: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self._destination = destination
        self._resolver = resolver
        self._delegate = delegate or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if host.lower() != self._destination.hostname or port != self._destination.port:
            raise WebhookSecurityError("Pinned webhook transport rejected an unexpected origin")

        current_addresses = await _resolve_public_addresses(host, port, self._resolver)
        stable_addresses = sorted(set(current_addresses).intersection(self._destination.addresses))
        if not stable_addresses:
            raise WebhookSecurityError("Webhook DNS answers changed before connection")
        selected_address = stable_addresses[0]

        stream = await self._delegate.connect_tcp(
            host=selected_address,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        peer = stream.get_extra_info("server_addr")
        try:
            peer_address = _canonical_public_ip(str(peer[0])) if peer else None
        except (IndexError, TypeError, WebhookSecurityError):
            await stream.aclose()
            raise WebhookSecurityError("Connected webhook peer address was not safe")
        if peer_address != selected_address:
            await stream.aclose()
            raise WebhookSecurityError("Connected webhook peer did not match the pinned address")
        return stream

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del path, timeout, socket_options
        raise WebhookSecurityError("Unix sockets are not valid webhook destinations")

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


class _CoreResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: Any) -> None:
        self._stream = stream

    async def __aiter__(self):  # type: ignore[no-untyped-def]
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class _PinnedHTTPSAsyncTransport(httpx.AsyncBaseTransport):
    """Small public API bridge between httpx and httpcore's pinned backend."""

    def __init__(
        self,
        destination: ResolvedWebhookDestination,
        resolver: _Resolver,
        *,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        backend = _PinnedNetworkBackend(destination, resolver, network_backend)
        self._destination = destination
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=1,
            max_keepalive_connections=0,
            keepalive_expiry=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=backend,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        request_port = _effective_url_port(request.url)
        if (
            request.url.scheme != "https"
            or request.url.host.lower() != self._destination.hostname
            or request_port != self._destination.port
        ):
            raise WebhookSecurityError("Pinned webhook transport rejected an unexpected request")
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request_port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        core_response = await self._pool.handle_async_request(core_request)
        return httpx.Response(
            status_code=core_response.status,
            headers=core_response.headers,
            stream=_CoreResponseStream(core_response.stream),
            extensions=core_response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


def _webhook_encryption_key(server_secret: bytes) -> bytes:
    return hashlib.sha256(b"inntris:webhook-secret-encryption:v1\x00" + server_secret).digest()


def generate_webhook_signing_secret() -> str:
    """Generate a high entropy secret in a receiver friendly format."""

    return f"whsec_{secrets.token_urlsafe(32)}"


def encrypt_webhook_signing_secret(secret: str, org_id: UUID, server_secret: bytes) -> bytes:
    """Encrypt a tenant secret under the server key encryption key."""

    nonce = secrets.token_bytes(_SECRET_NONCE_BYTES)
    ciphertext = AESGCM(_webhook_encryption_key(server_secret)).encrypt(
        nonce,
        secret.encode("utf-8"),
        b"inntris:webhook:" + org_id.bytes,
    )
    return _SECRET_ENVELOPE_PREFIX + nonce + ciphertext


def decrypt_webhook_signing_secret(
    envelope: bytes,
    org_id: UUID,
    server_secrets: Sequence[bytes],
) -> str:
    """Decrypt with the current key or an explicitly configured previous key."""

    envelope = bytes(envelope)
    if not envelope.startswith(_SECRET_ENVELOPE_PREFIX):
        raise WebhookSecurityError("Webhook signing secret has an unsupported format")
    start = len(_SECRET_ENVELOPE_PREFIX)
    nonce = envelope[start : start + _SECRET_NONCE_BYTES]
    ciphertext = envelope[start + _SECRET_NONCE_BYTES :]
    if len(nonce) != _SECRET_NONCE_BYTES or len(ciphertext) < 16:
        raise WebhookSecurityError("Webhook signing secret is corrupt")

    for server_secret in server_secrets:
        try:
            plaintext = AESGCM(_webhook_encryption_key(server_secret)).decrypt(
                nonce,
                ciphertext,
                b"inntris:webhook:" + org_id.bytes,
            )
            return plaintext.decode("utf-8")
        except (InvalidTag, UnicodeDecodeError):
            continue
    raise WebhookSecurityError("Webhook signing secret could not be decrypted")


def canonical_webhook_body(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _effective_url_port(url: httpx.URL) -> int | None:
    if url.port is not None:
        return url.port
    if url.scheme == "https":
        return 443
    if url.scheme == "http":
        return 80
    return None


def canonical_webhook_signature_payload(
    canonical_body: str,
    delivery_id: UUID,
    event: str,
    secret_version: int,
) -> str:
    """Bind receiver deduplication and routing headers to the exact body."""
    return json.dumps(
        {
            "body": canonical_body,
            "delivery_id": str(delivery_id),
            "event": event,
            "secret_version": secret_version,
            "version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sign_webhook_delivery(
    canonical_body: str,
    signing_secret: str,
    *,
    delivery_id: UUID,
    event: str,
    secret_version: int,
) -> str:
    signature_payload = canonical_webhook_signature_payload(
        canonical_body,
        delivery_id,
        event,
        secret_version,
    )
    return hmac.new(
        signing_secret.encode("utf-8"),
        signature_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


async def post_webhook_once(
    webhook_url: str,
    canonical_body: str,
    headers: dict[str, str],
    *,
    resolver: _Resolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    max_response_bytes: int = MAX_WEBHOOK_RESPONSE_BYTES,
) -> int:
    """Perform one no redirect, response bounded, IP pinned HTTPS POST."""

    active_resolver = resolver or _system_resolver
    destination = await resolve_webhook_destination(webhook_url, resolver=active_resolver)
    active_transport = transport or _PinnedHTTPSAsyncTransport(destination, active_resolver)
    timeout = httpx.Timeout(
        WEBHOOK_READ_TIMEOUT_SECONDS,
        connect=WEBHOOK_CONNECT_TIMEOUT_SECONDS,
        read=WEBHOOK_READ_TIMEOUT_SECONDS,
        write=WEBHOOK_WRITE_TIMEOUT_SECONDS,
        pool=WEBHOOK_CONNECT_TIMEOUT_SECONDS,
    )
    async with (
        httpx.AsyncClient(
            transport=active_transport,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client,
        client.stream(
            "POST",
            destination.url,
            content=canonical_body.encode("utf-8"),
            headers=headers,
        ) as response,
    ):
        if 300 <= response.status_code < 400:
            raise WebhookDeliveryError(
                "Webhook redirects are disabled",
                retryable=False,
                status_code=response.status_code,
            )

        content_encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if content_encoding not in {"", "identity"}:
            raise WebhookDeliveryError(
                "Compressed webhook responses are not accepted",
                retryable=False,
                status_code=response.status_code,
            )

        content_length = response.headers.get("content-length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = 0
            if declared_length > max_response_bytes:
                raise WebhookDeliveryError(
                    "Webhook response exceeded the size limit",
                    retryable=False,
                    status_code=response.status_code,
                )

        received = 0
        async for chunk in response.aiter_raw():
            received += len(chunk)
            if received > max_response_bytes:
                raise WebhookDeliveryError(
                    "Webhook response exceeded the size limit",
                    retryable=False,
                    status_code=response.status_code,
                )

        if 200 <= response.status_code < 300:
            return response.status_code
        retryable = response.status_code in {408, 425, 429} or response.status_code >= 500
        raise WebhookDeliveryError(
            f"Webhook returned HTTP {response.status_code}",
            retryable=retryable,
            status_code=response.status_code,
        )


def _row_value(row: Any, key: str, default: Any = None) -> Any:
    try:
        return row[key]
    except (KeyError, TypeError):
        return default


def _delivery_error_details(exc: Exception) -> tuple[bool, int | None, str]:
    if isinstance(exc, WebhookSecurityError):
        return False, None, str(exc)
    if isinstance(exc, WebhookDeliveryError):
        return exc.retryable, exc.status_code, str(exc)
    if isinstance(
        exc,
        (
            httpcore.NetworkError,
            httpcore.TimeoutException,
            httpx.NetworkError,
            httpx.TimeoutException,
        ),
    ):
        return True, None, f"{type(exc).__name__}: {exc}"
    return True, None, f"{type(exc).__name__}: {exc}"


async def deliver_queued_webhook(
    database: _WebhookDatabase,
    delivery_id: UUID,
    server_secrets: Sequence[bytes],
    *,
    sender: Callable[..., Awaitable[int]] = post_webhook_once,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    """Deliver one queued webhook with bounded retries and a dead letter state."""

    for _ in range(MAX_WEBHOOK_ATTEMPTS):
        row = await database.begin_webhook_delivery_attempt(delivery_id)
        if row is None:
            return
        attempt_count = int(_row_value(row, "attempt_count", 0) or 0)
        org_id = _row_value(row, "org_id")
        webhook_url = _row_value(row, "webhook_url")
        envelope = _row_value(row, "webhook_secret_ciphertext")
        secret_version = int(_row_value(row, "webhook_secret_version", 0) or 0)
        payload = _row_value(row, "payload", {})
        if isinstance(payload, str):
            payload = json.loads(payload)

        started = time.monotonic()
        try:
            if not webhook_url or not envelope or secret_version < 1:
                raise WebhookSecurityError("Organisation webhook configuration is incomplete")
            signing_secret = decrypt_webhook_signing_secret(
                envelope,
                org_id,
                server_secrets,
            )
            canonical_body = canonical_webhook_body(payload)
            event = str(_row_value(row, "event", ""))
            signature = sign_webhook_delivery(
                canonical_body,
                signing_secret,
                delivery_id=delivery_id,
                event=event,
                secret_version=secret_version,
            )
            response_status = await sender(
                webhook_url,
                canonical_body,
                {
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Content-Type": "application/json",
                    "User-Agent": "Inntris-Webhook/1.0",
                    "X-Inntris-Delivery-ID": str(delivery_id),
                    "X-Inntris-Event": event,
                    "X-Inntris-Secret-Version": str(secret_version),
                    "X-Inntris-Signature": signature,
                    "X-Inntris-Signature-Algorithm": "hmac-sha256",
                    "X-Inntris-Signature-Version": "1",
                },
            )
        except Exception as exc:
            retryable, response_status, error = _delivery_error_details(exc)
            error = error[:1000]
            final_attempt = attempt_count >= MAX_WEBHOOK_ATTEMPTS
            if not retryable or final_attempt:
                await database.mark_webhook_delivery_dead_letter(
                    delivery_id,
                    error,
                    response_status,
                )
                outcome = "security_rejected" if isinstance(exc, WebhookSecurityError) else "dead_letter"
                webhook_delivery_attempts_total.labels(outcome=outcome).inc()
                logger.warning(
                    "Webhook delivery dead lettered",
                    extra={
                        "delivery_id": str(delivery_id),
                        "org_id": str(org_id),
                        "attempt": attempt_count,
                        "error_type": type(exc).__name__,
                    },
                )
                return

            retry_delay = WEBHOOK_RETRY_DELAYS_SECONDS[
                min(max(attempt_count - 1, 0), len(WEBHOOK_RETRY_DELAYS_SECONDS) - 1)
            ]
            await database.mark_webhook_delivery_retry(
                delivery_id,
                error,
                response_status,
                retry_delay,
            )
            webhook_delivery_attempts_total.labels(outcome="retry").inc()
            await sleep(retry_delay)
        else:
            await database.mark_webhook_delivery_delivered(delivery_id, response_status)
            webhook_delivery_attempts_total.labels(outcome="delivered").inc()
            return
        finally:
            webhook_delivery_latency_seconds.observe(time.monotonic() - started)


async def recover_due_webhook_deliveries_once(
    database: _WebhookDatabase,
    server_secrets: Sequence[bytes],
    *,
    limit: int = WEBHOOK_RECOVERY_BATCH_SIZE,
) -> int:
    """Recover one batch of due or abandoned durable delivery rows."""

    delivery_ids = await database.list_due_webhook_delivery_ids(limit)
    if not delivery_ids:
        return 0
    await asyncio.gather(
        *(
            deliver_queued_webhook(database, delivery_id, server_secrets)
            for delivery_id in delivery_ids
        )
    )
    return len(delivery_ids)


async def run_webhook_delivery_recovery(
    database: _WebhookDatabase,
    server_secrets: Sequence[bytes],
    *,
    poll_seconds: float = WEBHOOK_RECOVERY_POLL_SECONDS,
) -> None:
    """Continuously recover persisted deliveries after restarts or crashes."""

    while True:
        try:
            await recover_due_webhook_deliveries_once(database, server_secrets)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Webhook delivery recovery cycle failed")
        await asyncio.sleep(poll_seconds)


_BACKGROUND_DELIVERIES: set[asyncio.Task[None]] = set()


def _finalize_background_delivery(task: asyncio.Task[None]) -> None:
    _BACKGROUND_DELIVERIES.discard(task)
    if task.cancelled():
        return
    exception = task.exception()
    if exception is not None:
        logger.error(
            "Background webhook delivery task failed; durable recovery will retry",
            exc_info=(type(exception), exception, exception.__traceback__),
        )


async def dispatch_verdict_webhook(
    database: _WebhookDatabase,
    org_id: UUID,
    event: str,
    agent_id: UUID,
    audit_id: UUID | None,
    action_type: str,
    verdict: str,
    verdict_reason: str | None,
    server_secrets: Sequence[bytes],
) -> UUID | None:
    """Persist a delivery before scheduling its bounded background attempt."""

    payload = {
        "event": event,
        "org_id": str(org_id),
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "data": {
            "agent_id": str(agent_id),
            "audit_id": str(audit_id) if audit_id else None,
            "action_type": action_type,
            "verdict": verdict,
            "verdict_reason": verdict_reason,
        },
    }
    delivery_id = await database.enqueue_webhook_delivery(org_id, event, payload)
    if delivery_id is None:
        return None
    task = asyncio.create_task(
        deliver_queued_webhook(database, delivery_id, server_secrets),
        name=f"webhook-delivery-{delivery_id}",
    )
    _BACKGROUND_DELIVERIES.add(task)
    task.add_done_callback(_finalize_background_delivery)
    return delivery_id
