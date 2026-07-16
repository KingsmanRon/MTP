"""Security contracts for the screen-recordable use-case driver."""

import pytest

from scripts import usecase_poc_demo
from scripts.usecase_poc_demo import _safe_cli_substitution


class _Response:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body or {}
        self.text = str(self._body)

    def json(self):
        return self._body


@pytest.mark.parametrize("value", ["--config=attacker.toml", "-1", "bad\x00value"])
def test_moonpay_payload_value_cannot_become_cli_option(value):
    with pytest.raises(ValueError, match="unsafe MoonPay CLI value"):
        _safe_cli_substitution("vendor", value)


def test_normal_moonpay_payload_value_is_preserved():
    assert _safe_cli_substitution("vendor", "github.com") == "github.com"
    assert _safe_cli_substitution("amount", 49.99) == "49.99"


@pytest.mark.parametrize("production_demo, expected_post_count", [(False, 1), (True, 2)])
def test_agent_promotion_requires_explicit_production_mode(
    monkeypatch, production_demo, expected_post_count
):
    posts = []

    def fake_post(url, **kwargs):
        posts.append((url, kwargs.get("json")))
        if url.endswith("/admin/agents"):
            return _Response(
                body={
                    "agent_id": "00000000-0000-0000-0000-000000000001",
                    "public_key_fingerprint": "a" * 64,
                }
            )
        return _Response(body={"sandbox": False})

    def fake_patch(*_args, **_kwargs):
        return _Response()

    monkeypatch.setattr(usecase_poc_demo, "PRODUCTION_DEMO", production_demo)
    monkeypatch.setattr(usecase_poc_demo.requests, "post", fake_post)
    monkeypatch.setattr(
        usecase_poc_demo.requests,
        "patch",
        fake_patch,
    )

    usecase_poc_demo.provision_agent(
        "admin-key",
        "00000000-0000-0000-0000-000000000002",
        "Demo agent",
        allowed=["tool_call"],
    )

    assert len(posts) == expected_post_count
    if production_demo:
        assert posts[-1][0].endswith("/promote")
        assert posts[-1][1]["approval_reference"].startswith("recorded-demo:")
