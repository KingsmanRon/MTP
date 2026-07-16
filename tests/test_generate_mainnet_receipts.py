"""Production lifecycle tests for the mainnet receipt utility."""

from nacl.signing import SigningKey

from scripts import generate_mainnet_receipts


class _Response:
    def __init__(self, body, status_code=200):
        self.status_code = status_code
        self._body = body
        self.text = str(body)

    def json(self):
        return self._body


def test_receipt_agent_uses_audited_production_promotion(monkeypatch):
    posts = []

    def fake_get(url, **_kwargs):
        assert url.endswith("/admin/organization")
        return _Response({"id": "00000000-0000-0000-0000-000000000002"})

    def fake_post(url, **kwargs):
        posts.append((url, kwargs["json"]))
        if url.endswith("/admin/agents"):
            return _Response(
                {"agent_id": "00000000-0000-0000-0000-000000000001"},
                status_code=201,
            )
        return _Response({"sandbox": False})

    monkeypatch.setattr(generate_mainnet_receipts.requests, "get", fake_get)
    monkeypatch.setattr(generate_mainnet_receipts.requests, "post", fake_post)
    monkeypatch.setattr(
        generate_mainnet_receipts.requests,
        "patch",
        lambda *_args, **_kwargs: _Response({"updated": ["trust_score"]}),
    )

    agent_id = generate_mainnet_receipts.setup_agent(
        "https://api.inntris.com",
        "admin-key",
        SigningKey.generate(),
    )

    assert agent_id == "00000000-0000-0000-0000-000000000001"
    assert len(posts) == 2
    assert posts[-1][0].endswith(f"/admin/agents/{agent_id}/promote")
    assert posts[-1][1]["approval_reference"].startswith(
        "mainnet-receipt-generation:"
    )


def test_blocked_receipt_lookup_uses_tenant_admin_search(monkeypatch):
    def fake_get(url, **kwargs):
        assert url.endswith("/admin/audit/search")
        assert kwargs["headers"] == {"X-API-Key": "admin-key"}
        assert kwargs["params"]["verdict"] == "blocked"
        return _Response({"logs": [{"id": "receipt-id"}]})

    monkeypatch.setattr(generate_mainnet_receipts.requests, "get", fake_get)

    assert (
        generate_mainnet_receipts.fetch_latest_audit_id(
            "https://api.inntris.com", "admin-key", "agent-id", "blocked"
        )
        == "receipt-id"
    )
