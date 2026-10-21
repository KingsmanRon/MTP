"""Provisioning must not turn the tenant credential into a privileged login."""

from unittest.mock import MagicMock

import pytest

from scripts import configure_tenant_role as provision


def _env(**overrides):
    password = "tenant-only-" + "a" * 40
    result = {
        "ALEMBIC_DATABASE_URL": "postgresql://owner:owner-only@localhost/inntris",
        "DATABASE_URL": "postgresql://inntris_worker:worker-only@localhost/inntris",
        "TENANT_DATABASE_URL": f"postgresql://inntris_tenant_login:{password}@localhost/inntris",
        "TENANT_DATABASE_PASSWORD": password,
    }
    result.update(overrides)
    return result


@pytest.mark.parametrize(
    "name",
    [
        "ALEMBIC_DATABASE_URL",
        "DATABASE_URL",
        "TENANT_DATABASE_URL",
        "TENANT_DATABASE_PASSWORD",
    ],
)
def test_missing_configuration_does_not_open_connection(name, monkeypatch):
    connect = MagicMock()
    monkeypatch.setattr(provision.psycopg2, "connect", connect)
    with pytest.raises(provision.TenantRoleConfigurationError):
        provision.configure_tenant_role(_env(**{name: ""}))
    connect.assert_not_called()


@pytest.mark.parametrize(
    "overrides",
    [
        {"TENANT_DATABASE_PASSWORD": "short"},
        {"TENANT_DATABASE_PASSWORD": "a" * 40 + "\n"},
        {"TENANT_DATABASE_URL": "postgresql://inntris_worker:wrong@localhost/inntris"},
        {"TENANT_DATABASE_URL": "postgresql://inntris_tenant_login:wrong@localhost/inntris"},
        {"ALEMBIC_DATABASE_URL": "postgresql://inntris_worker:owner@localhost/inntris"},
        {"DATABASE_URL": "postgresql://owner:owner@localhost/inntris"},
    ],
)
def test_unsafe_configuration_is_rejected(overrides):
    with pytest.raises(provision.TenantRoleConfigurationError):
        provision._validate_configuration(_env(**overrides))


@pytest.mark.parametrize("name", ["ALEMBIC_DATABASE_URL", "DATABASE_URL"])
def test_tenant_cannot_share_other_role_password(name):
    env = _env()
    role = "owner" if name == "ALEMBIC_DATABASE_URL" else "inntris_worker"
    env[name] = f"postgresql://{role}:{env['TENANT_DATABASE_PASSWORD']}@localhost/inntris"
    with pytest.raises(provision.TenantRoleConfigurationError, match="must differ"):
        provision._validate_configuration(env)


@pytest.mark.parametrize(
    "role",
    [
        None,
        (True, False, False, False, False, False, True),
        (False, True, False, False, False, False, True),
        (False, False, True, False, False, False, True),
        (False, False, False, True, False, False, True),
        (False, False, False, False, True, False, True),
        (False, False, False, False, False, True, True),
        (False, False, False, False, False, False, False),
    ],
)
def test_unsafe_role_gets_no_password(role, monkeypatch):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = role
    monkeypatch.setattr(provision.psycopg2, "connect", lambda *_a, **_k: connection)
    with pytest.raises(provision.TenantRoleConfigurationError):
        provision.configure_tenant_role(_env())
    assert cursor.execute.call_count == 2
    connection.close.assert_called_once()


def test_only_scram_verifier_is_sent_to_postgres(monkeypatch):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (False, False, False, False, False, False, True)
    monkeypatch.setattr(provision.psycopg2, "connect", lambda *_a, **_k: connection)
    verifier = "SCRAM-SHA-256$example-verifier"
    monkeypatch.setattr(provision, "encrypt_password", lambda *_a: verifier)
    provision.configure_tenant_role(_env())
    assert cursor.execute.call_args.args == (
        "ALTER ROLE inntris_tenant_login WITH LOGIN PASSWORD %s",
        (verifier,),
    )
    assert _env()["TENANT_DATABASE_PASSWORD"] not in str(cursor.execute.call_args_list)
    connection.close.assert_called_once()


def test_explicit_empty_environment_is_not_replaced_by_process_environment():
    with pytest.raises(provision.TenantRoleConfigurationError):
        provision.configure_tenant_role({})
