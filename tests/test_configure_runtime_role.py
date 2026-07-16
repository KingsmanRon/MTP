"""Deployment credential separation for the runtime database role."""

from __future__ import annotations

from typing import Any

import pytest

from scripts import configure_runtime_role as runtime_role


def _environment(**overrides: str) -> dict[str, str]:
    password = "runtime-only-4b5ed8ae5aa9f1c22f81"
    environment = {
        "ALEMBIC_DATABASE_URL": (
            "postgresql://inntris_migrator:migration-only-8d3a9f2f@postgres:5432/inntris"
        ),
        "DATABASE_URL": f"postgresql://inntris_worker:{password}@postgres:5432/inntris",
        "RUNTIME_DATABASE_PASSWORD": password,
    }
    environment.update(overrides)
    return environment


class _Cursor:
    def __init__(self, role: tuple[bool, bool, bool, bool] | None) -> None:
        self.role = role
        self.calls: list[tuple[Any, Any]] = []

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: Any, parameters: Any = None) -> None:
        self.calls.append((query, parameters))

    def fetchone(self) -> tuple[bool, bool, bool, bool] | None:
        return self.role


class _Connection:
    def __init__(self, role: tuple[bool, bool, bool, bool] | None) -> None:
        self.autocommit = False
        self.closed = False
        self.cursor_instance = _Cursor(role)

    def cursor(self) -> _Cursor:
        return self.cursor_instance

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("ALEMBIC_DATABASE_URL", ""),
        ("DATABASE_URL", ""),
        ("RUNTIME_DATABASE_PASSWORD", ""),
        ("RUNTIME_DATABASE_PASSWORD", "too-short"),
    ],
)
def test_required_secrets_fail_closed(variable: str, value: str) -> None:
    with pytest.raises(runtime_role.RuntimeRoleConfigurationError):
        runtime_role._validate_configuration(_environment(**{variable: value}))


def test_explicit_empty_environment_does_not_fall_back_to_process_secrets() -> None:
    with pytest.raises(runtime_role.RuntimeRoleConfigurationError, match="ALEMBIC_DATABASE_URL"):
        runtime_role.configure_runtime_role({})


def test_privileged_and_runtime_roles_must_be_separate() -> None:
    password = _environment()["RUNTIME_DATABASE_PASSWORD"]
    with pytest.raises(runtime_role.RuntimeRoleConfigurationError, match="privileged migration role"):
        runtime_role._validate_configuration(
            _environment(
                ALEMBIC_DATABASE_URL=(
                    "postgresql://inntris_worker:migration-only@postgres:5432/inntris"
                )
            )
        )
    with pytest.raises(runtime_role.RuntimeRoleConfigurationError, match="must use the"):
        runtime_role._validate_configuration(
            _environment(
                DATABASE_URL=f"postgresql://postgres:{password}@postgres:5432/inntris"
            )
        )


def test_runtime_url_password_must_match_provisioned_password() -> None:
    with pytest.raises(runtime_role.RuntimeRoleConfigurationError, match="does not match"):
        runtime_role._validate_configuration(
            _environment(
                DATABASE_URL=(
                    "postgresql://inntris_worker:different-runtime-password-123456@postgres:5432/inntris"
                )
            )
        )


def test_configures_existing_unprivileged_role(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _Connection((False, False, False, False))
    monkeypatch.setattr(runtime_role.psycopg2, "connect", lambda *_args, **_kwargs: connection)
    verifier = "SCRAM-SHA-256$4096:test-salt$stored-key:server-key"
    monkeypatch.setattr(runtime_role, "encrypt_password", lambda *_args: verifier)

    runtime_role.configure_runtime_role(_environment())

    assert connection.autocommit is True
    assert connection.closed is True
    assert len(connection.cursor_instance.calls) == 3
    alter_query, parameters = connection.cursor_instance.calls[-1]
    assert "ALTER ROLE" in str(alter_query)
    assert "inntris_worker" in str(alter_query)
    assert parameters == (verifier,)
    assert _environment()["RUNTIME_DATABASE_PASSWORD"] not in str(parameters)


@pytest.mark.parametrize(
    "role",
    [
        None,
        (True, True, False, False),
        (True, False, True, False),
        (True, False, False, True),
    ],
)
def test_refuses_missing_or_privileged_runtime_role(
    monkeypatch: pytest.MonkeyPatch,
    role: tuple[bool, bool, bool, bool] | None,
) -> None:
    connection = _Connection(role)
    monkeypatch.setattr(runtime_role.psycopg2, "connect", lambda *_args, **_kwargs: connection)

    with pytest.raises(runtime_role.RuntimeRoleConfigurationError):
        runtime_role.configure_runtime_role(_environment())

    assert connection.closed is True
    assert len(connection.cursor_instance.calls) == 2
