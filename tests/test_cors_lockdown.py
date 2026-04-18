"""Phase 2D.2 — CORS origin resolution.

The rule we care about is that a misconfigured ALLOWED_ORIGINS in prod
fails at boot instead of silently accepting every origin. These tests
target ``_resolve_cors_origins`` directly so they run without spinning
up the full FastAPI app and touching Redis/Postgres.
"""

from __future__ import annotations

import pytest

from api.main import _resolve_cors_origins


# -----------------------------------------------------------------------------
# development convenience
# -----------------------------------------------------------------------------

def test_development_default_allows_wildcard() -> None:
    assert _resolve_cors_origins("development", "") == ["*"]


def test_development_with_explicit_wildcard_allows_wildcard() -> None:
    assert _resolve_cors_origins("development", "*") == ["*"]


def test_development_honors_explicit_list() -> None:
    got = _resolve_cors_origins("development", "http://localhost:3000,http://127.0.0.1:3000")
    assert got == ["http://localhost:3000", "http://127.0.0.1:3000"]


# -----------------------------------------------------------------------------
# production lockdown: wildcard / empty -> fatal
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("env", ["production", "staging", "prod", "test"])
def test_non_dev_rejects_empty(env: str) -> None:
    with pytest.raises(SystemExit, match="ALLOWED_ORIGINS is required"):
        _resolve_cors_origins(env, "")


@pytest.mark.parametrize("env", ["production", "staging"])
def test_non_dev_rejects_bare_wildcard(env: str) -> None:
    with pytest.raises(SystemExit, match="not permitted outside development"):
        _resolve_cors_origins(env, "*")


def test_non_dev_rejects_wildcard_mixed_with_origins() -> None:
    # Someone appending * to an existing list to "quickly fix a client" is
    # the most common way this regresses — must still fail.
    with pytest.raises(SystemExit, match="not permitted outside development"):
        _resolve_cors_origins("production", "https://app.inntris.com,*")


# -----------------------------------------------------------------------------
# production lockdown: per-origin validation
# -----------------------------------------------------------------------------

def test_non_dev_rejects_missing_scheme() -> None:
    with pytest.raises(SystemExit, match="invalid CORS origin"):
        _resolve_cors_origins("production", "app.inntris.com")


def test_non_dev_rejects_wildcard_in_host() -> None:
    with pytest.raises(SystemExit, match="invalid CORS origin"):
        _resolve_cors_origins("production", "https://*.inntris.com")


def test_non_dev_rejects_origin_with_path() -> None:
    with pytest.raises(SystemExit, match="must not include a path"):
        _resolve_cors_origins("production", "https://app.inntris.com/api")


def test_non_dev_rejects_null_origin() -> None:
    # The literal string "null" appears in CORS as a sentinel for sandboxed
    # iframes — never a legitimate trusted origin for our API.
    with pytest.raises(SystemExit, match="invalid CORS origin"):
        _resolve_cors_origins("production", "null")


def test_non_dev_accepts_explicit_https_origin() -> None:
    assert _resolve_cors_origins("production", "https://app.inntris.com") == [
        "https://app.inntris.com"
    ]


def test_non_dev_accepts_multiple_origins_with_ports() -> None:
    got = _resolve_cors_origins(
        "production",
        "https://app.inntris.com,https://admin.inntris.com:8443",
    )
    assert got == ["https://app.inntris.com", "https://admin.inntris.com:8443"]


def test_non_dev_accepts_trailing_slash_only_path() -> None:
    # urlparse puts a lone "/" in path; this is common when admins copy
    # from a browser bar and should be allowed through.
    assert _resolve_cors_origins("production", "https://app.inntris.com/") == [
        "https://app.inntris.com/"
    ]


def test_non_dev_strips_whitespace_between_entries() -> None:
    got = _resolve_cors_origins(
        "production",
        "  https://a.example.com  , https://b.example.com  ",
    )
    assert got == ["https://a.example.com", "https://b.example.com"]
