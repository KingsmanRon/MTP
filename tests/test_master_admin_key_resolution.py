from api.main import _resolve_master_admin_key


def test_unset_master_admin_key_disables_provisioning() -> None:
    assert _resolve_master_admin_key(None) is None


def test_whitespace_master_admin_key_disables_provisioning() -> None:
    assert _resolve_master_admin_key("   ") is None


def test_short_master_admin_key_disables_provisioning() -> None:
    assert _resolve_master_admin_key("short-key") is None


def test_valid_master_admin_key_is_trimmed() -> None:
    raw = "  " + ("a" * 32) + "  "
    assert _resolve_master_admin_key(raw) == "a" * 32
