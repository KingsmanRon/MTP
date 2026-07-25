"""D1 — the MCP adapter cannot hand out an unconsumed approval.

The adapter used to POST ``/verify``, return the approval token to the model,
and say "You may proceed with the action". That made the MCP path advisory
while presenting as an enforcement boundary — the single-use gate
(``/verify-token`` with ``consume=true``) was never called, so nothing stopped
the same approval authorizing two executions, or none.

It now spends the approval in the same round trip and never returns the token.
These tests pin the two halves of that:

1. on success, the token is consumed and does not appear in the result;
2. on *every* failure mode — timeout, transport error, non-2xx, unreadable
   body, ``valid: false``, missing token — the call raises rather than
   returning something a model would read as permission.

The second half is the one worth testing exhaustively. A gate that fails open
on one path out of six is not a gate.
"""

from __future__ import annotations

import httpx
import pytest

from mcp_server.server import InntrisClient, InntrisVerificationError

AGENT_ID = "0be76c5e-93d2-4d4a-a86e-53c8a1d3f6b1"
SEED = b"\x24" * 32

APPROVAL = {
    "verdict": "approved",
    "trust_score": 80,
    "audit_id": "11111111-1111-4111-8111-111111111111",
    "approval_token": "token-abc",
    "limits_remaining": {},
}
REQUEST_BODY = {
    "agent_id": AGENT_ID,
    "action_type": "financial_transaction",
    "payload": {"amount": 10},
    "nonce": "n",
    "timestamp": "2026-07-25T12:00:00Z",
    "sig_version": 3,
}


class _StubResponse:
    def __init__(self, status_code: int, body=None, raise_on_json: bool = False):
        self.status_code = status_code
        self._body = body
        self._raise = raise_on_json
        self.text = str(body)

    def json(self):
        if self._raise:
            raise ValueError("not json")
        return self._body


class _StubHttp:
    """Stands in for the adapter's httpx client on the /verify-token call."""

    def __init__(self, outcome):
        self._outcome = outcome
        self.calls: list[dict] = []

    async def post(self, url, json=None):  # noqa: A002 - mirrors httpx signature
        self.calls.append({"url": url, "json": json})
        if isinstance(self._outcome, Exception):
            raise self._outcome
        return self._outcome


@pytest.fixture
def client() -> InntrisClient:
    return InntrisClient(api_url="http://api.test", agent_id=AGENT_ID, private_key=SEED)


async def _consume(client: InntrisClient, outcome):
    client._http_client = _StubHttp(outcome)
    return await client._consume_approval(dict(APPROVAL), dict(REQUEST_BODY))


class TestConsumptionSucceeds:
    @pytest.mark.asyncio
    async def test_token_is_spent_and_consumption_recorded(
        self, client: InntrisClient
    ) -> None:
        body = {"valid": True, "consumption_audit_id": "cafe"}
        result = await _consume(client, _StubResponse(200, body))
        assert result["consumption_audit_id"] == "cafe"

    @pytest.mark.asyncio
    async def test_consume_flag_and_full_action_are_sent(
        self, client: InntrisClient
    ) -> None:
        """A bare check is not a gate — consume must be true and bound."""
        client._http_client = _StubHttp(_StubResponse(200, {"valid": True}))
        await client._consume_approval(dict(APPROVAL), dict(REQUEST_BODY))

        sent = client._http_client.calls[0]
        assert sent["url"].endswith("/verify-token")
        assert sent["json"]["consume"] is True
        assert sent["json"]["approval_token"] == "token-abc"
        # The token authorizes THIS action; all four binding fields travel.
        for field in ("action_type", "payload", "nonce", "timestamp"):
            assert sent["json"][field] == REQUEST_BODY[field]


class TestGateFailsClosed:
    """Every non-success path must raise. None may return."""

    @pytest.mark.asyncio
    async def test_transport_error_blocks(self, client: InntrisClient) -> None:
        with pytest.raises(InntrisVerificationError) as exc:
            await _consume(client, httpx.ConnectError("refused"))
        assert exc.value.verdict == "blocked"

    @pytest.mark.asyncio
    async def test_timeout_blocks(self, client: InntrisClient) -> None:
        with pytest.raises(InntrisVerificationError) as exc:
            await _consume(client, httpx.ReadTimeout("timed out"))
        assert exc.value.verdict == "blocked"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [400, 401, 403, 409, 500, 503])
    async def test_non_success_status_blocks(
        self, client: InntrisClient, status: int
    ) -> None:
        with pytest.raises(InntrisVerificationError) as exc:
            await _consume(client, _StubResponse(status, {"valid": True}))
        assert exc.value.verdict == "blocked"

    @pytest.mark.asyncio
    async def test_valid_false_blocks(self, client: InntrisClient) -> None:
        body = {"valid": False, "reason": "Token already used (single-use)"}
        with pytest.raises(InntrisVerificationError) as exc:
            await _consume(client, _StubResponse(200, body))
        assert exc.value.verdict == "blocked"
        assert "single-use" in exc.value.reason

    @pytest.mark.asyncio
    async def test_missing_valid_field_blocks(self, client: InntrisClient) -> None:
        """Absent is not true. A body without `valid` must not pass."""
        with pytest.raises(InntrisVerificationError):
            await _consume(client, _StubResponse(200, {"consumption_audit_id": "x"}))

    @pytest.mark.asyncio
    async def test_unreadable_body_blocks(self, client: InntrisClient) -> None:
        with pytest.raises(InntrisVerificationError):
            await _consume(client, _StubResponse(200, None, raise_on_json=True))

    @pytest.mark.asyncio
    async def test_approval_without_a_token_blocks(self, client: InntrisClient) -> None:
        client._http_client = _StubHttp(_StubResponse(200, {"valid": True}))
        approval = {k: v for k, v in APPROVAL.items() if k != "approval_token"}
        with pytest.raises(InntrisVerificationError):
            await client._consume_approval(approval, dict(REQUEST_BODY))
