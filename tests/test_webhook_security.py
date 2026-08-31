"""Webhook SSRF, tenant signing, retry, and recovery security contracts."""

from __future__ import annotations

import gzip
import hmac
from collections.abc import Sequence
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from api.main import app, get_db, verify_api_key, verify_master_admin_key
from api.tenant_boundary import get_admin_tenant_database
from api.webhooks import (
    MAX_WEBHOOK_RESPONSE_BYTES,
    ParsedWebhookDestination,
    ResolvedWebhookDestination,
    WebhookDeliveryError,
    WebhookSecurityError,
    _effective_url_port,
    _PinnedNetworkBackend,
    decrypt_webhook_signing_secret,
    deliver_queued_webhook,
    encrypt_webhook_signing_secret,
    generate_webhook_signing_secret,
    parse_webhook_url,
    post_webhook_once,
    recover_due_webhook_deliveries_once,
    resolve_webhook_destination,
    sign_webhook_delivery,
)

client = TestClient(app)


@pytest.mark.parametrize(
    "url",
    [
        "http://8.8.8.8/callback",
        "https://user:password@8.8.8.8/callback",
        "https://8.8.8.8/callback#fragment",
        "https://127.0.0.1/callback",
        "https://10.0.0.1/callback",
        "https://169.254.169.254/latest/meta-data",
        "https://224.0.0.1/callback",
        "https://0.0.0.0/callback",
        "https://192.0.2.1/callback",
        "https://[::1]/callback",
        "https://[fe80::1]/callback",
        "https://[::ffff:127.0.0.1]/callback",
        "https://localhost/callback",
        "https://service.internal/callback",
        "https://service.local/callback",
        "https://8.8.8.8:8443/callback",
        " https://8.8.8.8/callback",
        "https://8.8.8.8\\@127.0.0.1/callback",
    ],
)
def test_parse_webhook_url_rejects_unsafe_destinations(url: str) -> None:
    with pytest.raises(WebhookSecurityError):
        parse_webhook_url(url)


def test_parse_webhook_url_canonicalises_safe_https() -> None:
    destination = parse_webhook_url("https://HOOKS.EXAMPLE.COM/events?source=inntris")
    assert destination == ParsedWebhookDestination(
        url="https://hooks.example.com/events?source=inntris",
        hostname="hooks.example.com",
        port=443,
    )


@pytest.mark.asyncio
async def test_dns_resolution_rejects_any_private_answer() -> None:
    async def resolver(_hostname: str, _port: int) -> Sequence[str]:
        return ["8.8.8.8", "10.0.0.7"]

    with pytest.raises(WebhookSecurityError, match="globally routable"):
        await resolve_webhook_destination(
            "https://hooks.example.com/events",
            resolver=resolver,
        )


@pytest.mark.asyncio
async def test_dns_resolution_accepts_only_public_answers() -> None:
    async def resolver(_hostname: str, _port: int) -> Sequence[str]:
        return ["1.1.1.1", "2606:4700:4700::1111"]

    destination = await resolve_webhook_destination(
        "https://hooks.example.com/events",
        resolver=resolver,
    )
    assert destination.addresses == ("1.1.1.1", "2606:4700:4700::1111")


class _FakeStream:
    def __init__(self, peer: str) -> None:
        self.peer = peer
        self.closed = False

    def get_extra_info(self, name: str):
        assert name == "server_addr"
        return (self.peer, 443)

    async def aclose(self) -> None:
        self.closed = True


class _FakeNetworkBackend:
    def __init__(self, peer: str = "8.8.8.8") -> None:
        self.peer = peer
        self.calls: list[dict] = []
        self.stream: _FakeStream | None = None

    async def connect_tcp(self, **kwargs):
        self.calls.append(kwargs)
        self.stream = _FakeStream(self.peer)
        return self.stream

    async def sleep(self, _seconds: float) -> None:
        return None


def _resolved_destination() -> ResolvedWebhookDestination:
    return ResolvedWebhookDestination(
        url="https://hooks.example.com/events",
        hostname="hooks.example.com",
        port=443,
        addresses=("8.8.8.8",),
    )


def test_effective_https_port_survives_httpx_default_port_normalisation() -> None:
    assert _effective_url_port(httpx.URL("https://hooks.example.com/events")) == 443
    assert _effective_url_port(httpx.URL("https://hooks.example.com:443/events")) == 443


@pytest.mark.asyncio
async def test_connection_time_dns_recheck_blocks_rebinding() -> None:
    async def rebound(_hostname: str, _port: int) -> Sequence[str]:
        return ["127.0.0.1"]

    delegate = _FakeNetworkBackend()
    backend = _PinnedNetworkBackend(_resolved_destination(), rebound, delegate)  # type: ignore[arg-type]
    with pytest.raises(WebhookSecurityError):
        await backend.connect_tcp("hooks.example.com", 443)
    assert delegate.calls == []


@pytest.mark.asyncio
async def test_connected_peer_must_match_pinned_address() -> None:
    async def stable(_hostname: str, _port: int) -> Sequence[str]:
        return ["8.8.8.8"]

    delegate = _FakeNetworkBackend(peer="1.1.1.1")
    backend = _PinnedNetworkBackend(_resolved_destination(), stable, delegate)  # type: ignore[arg-type]
    with pytest.raises(WebhookSecurityError, match="did not match"):
        await backend.connect_tcp("hooks.example.com", 443)
    assert delegate.stream is not None and delegate.stream.closed is True


async def _public_resolver(_hostname: str, _port: int) -> Sequence[str]:
    return ["8.8.8.8"]


@pytest.mark.asyncio
async def test_delivery_disables_redirects() -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(302, headers={"location": "https://127.0.0.1"})
    )
    with pytest.raises(WebhookDeliveryError, match="redirects") as exc:
        await post_webhook_once(
            "https://hooks.example.com/events",
            "{}",
            {},
            resolver=_public_resolver,
            transport=transport,
        )
    assert exc.value.retryable is False


@pytest.mark.asyncio
async def test_delivery_bounds_streamed_response_size() -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(200, content=b"x" * (MAX_WEBHOOK_RESPONSE_BYTES + 1))
    )
    with pytest.raises(WebhookDeliveryError, match="size limit") as exc:
        await post_webhook_once(
            "https://hooks.example.com/events",
            "{}",
            {},
            resolver=_public_resolver,
            transport=transport,
        )
    assert exc.value.retryable is False


@pytest.mark.asyncio
async def test_delivery_rejects_compressed_response_before_decoding() -> None:
    encoded = gzip.compress(b"x" * (MAX_WEBHOOK_RESPONSE_BYTES * 20))
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={"content-encoding": "gzip"},
            content=encoded,
        )
    )
    with pytest.raises(WebhookDeliveryError, match="Compressed") as exc:
        await post_webhook_once(
            "https://hooks.example.com/events",
            "{}",
            {},
            resolver=_public_resolver,
            transport=transport,
        )
    assert exc.value.retryable is False


def test_per_organisation_secrets_are_encrypted_and_tenant_bound() -> None:
    org_a = uuid4()
    org_b = uuid4()
    server_secret = b"s" * 32
    signing_secret = generate_webhook_signing_secret()
    envelope = encrypt_webhook_signing_secret(signing_secret, org_a, server_secret)

    assert signing_secret.encode() not in envelope
    assert decrypt_webhook_signing_secret(envelope, org_a, [server_secret]) == signing_secret
    with pytest.raises(WebhookSecurityError, match="could not be decrypted"):
        decrypt_webhook_signing_secret(envelope, org_b, [server_secret])


class _DeliveryDatabase:
    def __init__(
        self,
        *,
        org_id: UUID,
        envelope: bytes,
        initial_attempt_count: int = 0,
    ) -> None:
        self.org_id = org_id
        self.envelope = envelope
        self.attempt_count = initial_attempt_count
        self.retries: list[tuple] = []
        self.delivered: list[tuple] = []
        self.dead_letters: list[tuple] = []

    async def begin_webhook_delivery_attempt(self, delivery_id: UUID):
        self.attempt_count += 1
        return {
            "id": delivery_id,
            "org_id": self.org_id,
            "event": "verification.approved",
            "payload": {"event": "verification.approved", "data": {"amount": 42}},
            "attempt_count": self.attempt_count,
            "webhook_url": "https://hooks.example.com/events",
            "webhook_secret_ciphertext": self.envelope,
            "webhook_secret_version": 1,
        }

    async def mark_webhook_delivery_retry(self, *args) -> None:
        self.retries.append(args)

    async def mark_webhook_delivery_delivered(self, *args) -> None:
        self.delivered.append(args)

    async def mark_webhook_delivery_dead_letter(self, *args) -> None:
        self.dead_letters.append(args)


@pytest.mark.asyncio
async def test_retry_then_success_uses_tenant_secret_and_bounded_backoff() -> None:
    org_id = uuid4()
    server_secret = b"k" * 32
    tenant_secret = "whsec_tenant_a"
    database = _DeliveryDatabase(
        org_id=org_id,
        envelope=encrypt_webhook_signing_secret(tenant_secret, org_id, server_secret),
    )
    calls: list[tuple[str, dict[str, str]]] = []

    async def sender(_url: str, body: str, headers: dict[str, str]) -> int:
        calls.append((body, headers))
        if len(calls) == 1:
            raise WebhookDeliveryError("temporary", retryable=True, status_code=503)
        return 204

    sleeps: list[float] = []

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    await deliver_queued_webhook(
        database,  # type: ignore[arg-type]
        uuid4(),
        [server_secret],
        sender=sender,
        sleep=sleep,
    )

    assert len(database.retries) == 1
    assert sleeps == [1.0]
    assert len(database.delivered) == 1
    body, headers = calls[-1]
    delivery_id = UUID(headers["X-Inntris-Delivery-ID"])
    expected = sign_webhook_delivery(
        body,
        tenant_secret,
        delivery_id=delivery_id,
        event=headers["X-Inntris-Event"],
        secret_version=int(headers["X-Inntris-Secret-Version"]),
    )
    assert hmac.compare_digest(headers["X-Inntris-Signature"], expected)
    changed_delivery_signature = sign_webhook_delivery(
        body,
        tenant_secret,
        delivery_id=uuid4(),
        event=headers["X-Inntris-Event"],
        secret_version=int(headers["X-Inntris-Secret-Version"]),
    )
    assert not hmac.compare_digest(expected, changed_delivery_signature)
    assert headers["X-Inntris-Secret-Version"] == "1"
    assert headers["X-Inntris-Signature-Version"] == "1"


@pytest.mark.asyncio
async def test_recovered_delivery_honours_cumulative_attempt_limit() -> None:
    org_id = uuid4()
    server_secret = b"z" * 32
    database = _DeliveryDatabase(
        org_id=org_id,
        envelope=encrypt_webhook_signing_secret("whsec_tenant", org_id, server_secret),
        initial_attempt_count=2,
    )

    async def sender(*_args, **_kwargs) -> int:
        raise WebhookDeliveryError("still down", retryable=True, status_code=503)

    await deliver_queued_webhook(
        database,  # type: ignore[arg-type]
        uuid4(),
        [server_secret],
        sender=sender,
        sleep=AsyncMock(),
    )

    assert database.attempt_count == 3
    assert database.retries == []
    assert len(database.dead_letters) == 1


@pytest.mark.asyncio
async def test_recovery_processes_persisted_due_deliveries() -> None:
    delivery_ids = [uuid4(), uuid4()]
    database = MagicMock()
    database.list_due_webhook_delivery_ids = AsyncMock(return_value=delivery_ids)

    with patch("api.webhooks.deliver_queued_webhook", new_callable=AsyncMock) as deliver:
        count = await recover_due_webhook_deliveries_once(database, [b"s" * 32])

    assert count == 2
    assert {call.args[1] for call in deliver.await_args_list} == set(delivery_ids)


def test_operator_creation_rejects_unsafe_webhook_before_database_work() -> None:
    database = MagicMock()
    app.dependency_overrides[get_db] = lambda: database
    app.dependency_overrides[verify_master_admin_key] = lambda: None
    try:
        response = client.post(
            "/admin/organizations",
            json={
                "name": "Unsafe Org",
                "contact_email": "security@example.com",
                "webhook_url": "http://127.0.0.1/callback",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    database.acquire.assert_not_called()


def test_tenant_update_rejects_private_webhook_before_database_work() -> None:
    org_id = uuid4()
    database = MagicMock()
    app.dependency_overrides[get_db] = lambda: database
    app.dependency_overrides[get_admin_tenant_database] = lambda: database
    app.dependency_overrides[verify_api_key] = lambda: {
        "org_id": org_id,
        "scopes": ["admin"],
    }
    try:
        response = client.patch(
            "/admin/organization",
            json={"webhook_url": "https://127.0.0.1/callback"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    database.acquire.assert_not_called()
