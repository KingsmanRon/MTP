import pytest

from evidence_pack.pack_contents import verify_pack
from scripts import verify_receipt


@pytest.mark.parametrize(
    "url",
    [
        "https://api.inntris.com/path",
        "http://localhost:8545",
        "http://127.0.0.1:8545",
        "http://[::1]:8545",
    ],
)
def test_network_url_guards_allow_https_and_local_http(url: str) -> None:
    assert verify_receipt._network_url(url) == url
    assert verify_pack._network_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/file",
        "http://example.com/path",
        "https://user:password@example.com/path",
        "not-a-url",
    ],
)
def test_receipt_network_url_guard_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(SystemExit):
        verify_receipt._network_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/file",
        "http://example.com/path",
        "https://user:password@example.com/path",
        "not-a-url",
    ],
)
def test_evidence_pack_network_url_guard_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(ValueError):
        verify_pack._network_url(url)
