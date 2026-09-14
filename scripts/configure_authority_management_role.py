"""Provision the trusted authority-configuration management login.

Migration 031 creates ``inntris_authority_admin`` without a password, the
same way Alembic creates ``inntris_worker`` without one: migration history is
replayed into environments that must not share a credential. Deployment runs
this immediately after ``alembic upgrade head``, alongside
``configure_runtime_role.py``.

This role is NOT the runtime role and must never be given to the API or the
workers. It may change ``authority_requirements`` / ``authority_controls``
and append to ``administrative_audit_events``; the runtime role stays
SELECT-only on all three, which is the property migration 028 exists to
provide.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from urllib.parse import unquote, urlsplit

import psycopg2
from psycopg2 import sql
from psycopg2.extensions import encrypt_password

MANAGEMENT_ROLE = "inntris_authority_admin"
RUNTIME_ROLE = "inntris_worker"
MIN_PASSWORD_LENGTH = 32


class AuthorityManagementRoleError(RuntimeError):
    """Raised when the management credential cannot preserve role separation."""


def _required(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name, "")
    if not value:
        raise AuthorityManagementRoleError(f"{name} must be set")
    return value


def _dsn_username(dsn: str, variable_name: str) -> str:
    parsed = urlsplit(dsn)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname:
        raise AuthorityManagementRoleError(
            f"{variable_name} must be a postgresql:// connection URL"
        )
    if parsed.username is None:
        raise AuthorityManagementRoleError(
            f"{variable_name} must include a database user"
        )
    return unquote(parsed.username)


def _validate_configuration(environ: Mapping[str, str]) -> tuple[str, str]:
    migration_dsn = _required(environ, "ALEMBIC_DATABASE_URL")
    management_dsn = _required(environ, "AUTHORITY_MANAGEMENT_DATABASE_URL")
    management_password = _required(environ, "AUTHORITY_MANAGEMENT_DATABASE_PASSWORD")

    if len(management_password) < MIN_PASSWORD_LENGTH:
        raise AuthorityManagementRoleError(
            "AUTHORITY_MANAGEMENT_DATABASE_PASSWORD must contain at least "
            f"{MIN_PASSWORD_LENGTH} characters"
        )
    if management_password != management_password.strip() or any(
        ord(character) < 32 or ord(character) == 127
        for character in management_password
    ):
        raise AuthorityManagementRoleError(
            "AUTHORITY_MANAGEMENT_DATABASE_PASSWORD must not contain "
            "surrounding whitespace or control characters"
        )

    migration_user = _dsn_username(migration_dsn, "ALEMBIC_DATABASE_URL")
    management_user = _dsn_username(
        management_dsn, "AUTHORITY_MANAGEMENT_DATABASE_URL"
    )
    if management_user != MANAGEMENT_ROLE:
        raise AuthorityManagementRoleError(
            f"AUTHORITY_MANAGEMENT_DATABASE_URL must use the {MANAGEMENT_ROLE} role"
        )
    if migration_user == MANAGEMENT_ROLE:
        raise AuthorityManagementRoleError(
            "ALEMBIC_DATABASE_URL must use a privileged migration role, not "
            f"{MANAGEMENT_ROLE}"
        )

    parsed_management = urlsplit(management_dsn)
    if parsed_management.password is None:
        raise AuthorityManagementRoleError(
            "AUTHORITY_MANAGEMENT_DATABASE_URL must include the role password"
        )
    if unquote(parsed_management.password) != management_password:
        raise AuthorityManagementRoleError(
            "AUTHORITY_MANAGEMENT_DATABASE_URL password does not match "
            "AUTHORITY_MANAGEMENT_DATABASE_PASSWORD"
        )

    # The management identity exists to be separable from the runtime one. A
    # shared credential would make them the same identity in practice.
    runtime_dsn = environ.get("DATABASE_URL", "")
    if runtime_dsn:
        if runtime_dsn == management_dsn:
            raise AuthorityManagementRoleError(
                "DATABASE_URL and AUTHORITY_MANAGEMENT_DATABASE_URL must be "
                "separate connection URLs"
            )
        if _dsn_username(runtime_dsn, "DATABASE_URL") != RUNTIME_ROLE:
            raise AuthorityManagementRoleError(
                f"DATABASE_URL must use the {RUNTIME_ROLE} role"
            )
    runtime_password = environ.get("RUNTIME_DATABASE_PASSWORD", "")
    if runtime_password and runtime_password == management_password:
        raise AuthorityManagementRoleError(
            "the runtime role and the management role must not share a password"
        )

    return migration_dsn, management_password


def configure_authority_management_role(
    environ: Mapping[str, str] | None = None,
) -> None:
    """Set the management login password without granting it anything more."""

    resolved_environment = os.environ if environ is None else environ
    migration_dsn, management_password = _validate_configuration(
        resolved_environment
    )
    connection = psycopg2.connect(migration_dsn, connect_timeout=10)
    try:
        connection.autocommit = True
        with connection.cursor() as cursor:
            cursor.execute("SET statement_timeout = '10s'")
            cursor.execute(
                """
                SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
                       rolbypassrls
                FROM pg_roles
                WHERE rolname = %s
                """,
                (MANAGEMENT_ROLE,),
            )
            role = cursor.fetchone()
            if role is None:
                raise AuthorityManagementRoleError(
                    f"{MANAGEMENT_ROLE} does not exist; run Alembic migrations first"
                )
            _, is_superuser, can_create_db, can_create_role, bypasses_rls = role
            if is_superuser or can_create_db or can_create_role or bypasses_rls:
                raise AuthorityManagementRoleError(
                    f"{MANAGEMENT_ROLE} has unexpected privileged role attributes"
                )

            password_verifier = encrypt_password(
                management_password,
                MANAGEMENT_ROLE,
                connection,
                "scram-sha-256",
            )
            if not password_verifier.startswith("SCRAM-SHA-256$"):
                raise AuthorityManagementRoleError(
                    "PostgreSQL did not produce a SCRAM-SHA-256 password verifier"
                )
            cursor.execute(
                sql.SQL(
                    "ALTER ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOBYPASSRLS PASSWORD %s"
                ).format(sql.Identifier(MANAGEMENT_ROLE)),
                (password_verifier,),
            )
    finally:
        connection.close()

    print(f"Configured trusted authority management login for {MANAGEMENT_ROLE}")


if __name__ == "__main__":
    configure_authority_management_role()
