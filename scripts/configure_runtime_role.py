"""Provision the locked down database login used by the API and workers.

Alembic creates ``inntris_worker`` without embedding a password in migration
history.  Deployments run this script immediately after ``alembic upgrade
head`` using the privileged migration DSN, then start application services
with the separate runtime DSN.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from urllib.parse import unquote, urlsplit

import psycopg2
from psycopg2 import sql
from psycopg2.extensions import encrypt_password

RUNTIME_ROLE = "inntris_worker"
MIN_PASSWORD_LENGTH = 32


class RuntimeRoleConfigurationError(RuntimeError):
    """Raised when deployment credentials cannot preserve role separation."""


def _required(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name, "")
    if not value:
        raise RuntimeRoleConfigurationError(f"{name} must be set")
    return value


def _dsn_username(dsn: str, variable_name: str) -> str:
    parsed = urlsplit(dsn)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname:
        raise RuntimeRoleConfigurationError(
            f"{variable_name} must be a postgresql:// connection URL"
        )
    if parsed.username is None:
        raise RuntimeRoleConfigurationError(f"{variable_name} must include a database user")
    return unquote(parsed.username)


def _validate_configuration(environ: Mapping[str, str]) -> tuple[str, str]:
    migration_dsn = _required(environ, "ALEMBIC_DATABASE_URL")
    runtime_dsn = _required(environ, "DATABASE_URL")
    runtime_password = _required(environ, "RUNTIME_DATABASE_PASSWORD")

    if len(runtime_password) < MIN_PASSWORD_LENGTH:
        raise RuntimeRoleConfigurationError(
            f"RUNTIME_DATABASE_PASSWORD must contain at least {MIN_PASSWORD_LENGTH} characters"
        )
    if runtime_password != runtime_password.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in runtime_password
    ):
        raise RuntimeRoleConfigurationError(
            "RUNTIME_DATABASE_PASSWORD must not contain surrounding whitespace or control characters"
        )

    migration_user = _dsn_username(migration_dsn, "ALEMBIC_DATABASE_URL")
    runtime_user = _dsn_username(runtime_dsn, "DATABASE_URL")
    if migration_user == RUNTIME_ROLE:
        raise RuntimeRoleConfigurationError(
            "ALEMBIC_DATABASE_URL must use a privileged migration role, not inntris_worker"
        )
    if runtime_user != RUNTIME_ROLE:
        raise RuntimeRoleConfigurationError("DATABASE_URL must use the inntris_worker role")
    if migration_dsn == runtime_dsn:
        raise RuntimeRoleConfigurationError(
            "ALEMBIC_DATABASE_URL and DATABASE_URL must be separate connection URLs"
        )

    parsed_runtime_dsn = urlsplit(runtime_dsn)
    if parsed_runtime_dsn.password is None:
        raise RuntimeRoleConfigurationError("DATABASE_URL must include the runtime role password")
    if unquote(parsed_runtime_dsn.password) != runtime_password:
        raise RuntimeRoleConfigurationError(
            "DATABASE_URL password does not match RUNTIME_DATABASE_PASSWORD"
        )

    parsed_migration_dsn = urlsplit(migration_dsn)
    if (
        parsed_migration_dsn.password is not None
        and unquote(parsed_migration_dsn.password) == runtime_password
    ):
        raise RuntimeRoleConfigurationError(
            "the migration role and runtime role must not share a password"
        )

    return migration_dsn, runtime_password


def configure_runtime_role(environ: Mapping[str, str] | None = None) -> None:
    """Set the runtime login password without granting deployment privileges."""

    resolved_environment = os.environ if environ is None else environ
    migration_dsn, runtime_password = _validate_configuration(resolved_environment)
    connection = psycopg2.connect(migration_dsn, connect_timeout=10)
    try:
        connection.autocommit = True
        with connection.cursor() as cursor:
            cursor.execute("SET statement_timeout = '10s'")
            cursor.execute(
                """
                SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole
                FROM pg_roles
                WHERE rolname = %s
                """,
                (RUNTIME_ROLE,),
            )
            role = cursor.fetchone()
            if role is None:
                raise RuntimeRoleConfigurationError(
                    "inntris_worker does not exist; run Alembic migrations first"
                )
            _, is_superuser, can_create_db, can_create_role = role
            if is_superuser or can_create_db or can_create_role:
                raise RuntimeRoleConfigurationError(
                    "inntris_worker has unexpected privileged role attributes"
                )

            password_verifier = encrypt_password(
                runtime_password,
                RUNTIME_ROLE,
                connection,
                "scram-sha-256",
            )
            if not password_verifier.startswith("SCRAM-SHA-256$"):
                raise RuntimeRoleConfigurationError(
                    "PostgreSQL did not produce a SCRAM-SHA-256 password verifier"
                )
            cursor.execute(
                sql.SQL(
                    "ALTER ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE PASSWORD %s"
                ).format(sql.Identifier(RUNTIME_ROLE)),
                (password_verifier,),
            )
    finally:
        connection.close()


def main() -> int:
    configure_runtime_role()
    print("Configured locked down database login for inntris_worker")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
