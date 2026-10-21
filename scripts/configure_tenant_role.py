"""Provision the existing tenant login after migrations, without granting roles.

The owner DSN belongs only in the migration job. API processes receive the
tenant DSN, never the migration credential or this provisioning password field.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from urllib.parse import unquote, urlsplit

import psycopg2
from psycopg2.extensions import encrypt_password

TENANT_ROLE = "inntris_tenant_login"


class TenantRoleConfigurationError(RuntimeError):
    """The tenant credential or role cannot preserve isolation."""


def _validate_configuration(environ: Mapping[str, str]) -> tuple[str, str]:
    names = (
        "ALEMBIC_DATABASE_URL",
        "DATABASE_URL",
        "TENANT_DATABASE_URL",
        "TENANT_DATABASE_PASSWORD",
    )
    for name in names:
        if not environ.get(name):
            raise TenantRoleConfigurationError(f"{name} must be set")
    password = environ["TENANT_DATABASE_PASSWORD"]
    if (
        len(password) < 32
        or password != password.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in password)
    ):
        raise TenantRoleConfigurationError(
            "TENANT_DATABASE_PASSWORD needs at least 32 characters without control "
            "characters or surrounding whitespace"
        )
    parsed = {}
    for name in names[:3]:
        dsn = urlsplit(environ[name])
        if dsn.scheme not in {"postgres", "postgresql"} or not dsn.hostname or not dsn.username:
            raise TenantRoleConfigurationError(f"{name} must be a PostgreSQL URL with a user")
        parsed[name] = dsn
    tenant = parsed["TENANT_DATABASE_URL"]
    if unquote(tenant.username) != TENANT_ROLE:
        raise TenantRoleConfigurationError("TENANT_DATABASE_URL must use inntris_tenant_login")
    if unquote(tenant.password or "") != password:
        raise TenantRoleConfigurationError("TENANT_DATABASE_URL password does not match")
    if unquote(parsed["DATABASE_URL"].username) != "inntris_worker":
        raise TenantRoleConfigurationError("DATABASE_URL must use inntris_worker")
    owner = parsed["ALEMBIC_DATABASE_URL"]
    if unquote(owner.username) in {TENANT_ROLE, "inntris_api", "inntris_worker"}:
        raise TenantRoleConfigurationError("ALEMBIC_DATABASE_URL must use a migration identity")
    for name in ("ALEMBIC_DATABASE_URL", "DATABASE_URL"):
        if unquote(parsed[name].password or "") == password:
            raise TenantRoleConfigurationError("Tenant, system and migration passwords must differ")
    return environ["ALEMBIC_DATABASE_URL"], password


def configure_tenant_role(environ: Mapping[str, str] | None = None) -> None:
    dsn, password = _validate_configuration(os.environ if environ is None else environ)
    connection = psycopg2.connect(dsn, connect_timeout=10)
    try:
        connection.autocommit = True
        with connection.cursor() as cursor:
            cursor.execute("SET statement_timeout = '10s'")
            cursor.execute(
                """
                SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolinherit,
                       pg_has_role(oid, 'inntris_worker', 'MEMBER'),
                       pg_has_role(oid, 'inntris_api', 'MEMBER')
                FROM pg_roles WHERE rolname = %s
                """,
                (TENANT_ROLE,),
            )
            role = cursor.fetchone()
            if role is None or any(role[:6]) or not role[6]:
                raise TenantRoleConfigurationError(
                    "Tenant role is missing or unsafe; apply and verify tenant isolation migrations"
                )
            verifier = encrypt_password(password, TENANT_ROLE, connection, "scram-sha-256")
            if not verifier.startswith("SCRAM-SHA-256$"):
                raise TenantRoleConfigurationError("PostgreSQL did not produce a SCRAM verifier")
            cursor.execute("ALTER ROLE inntris_tenant_login WITH LOGIN PASSWORD %s", (verifier,))
    finally:
        connection.close()


def main() -> int:
    try:
        configure_tenant_role()
    except (TenantRoleConfigurationError, psycopg2.Error, ValueError):
        # Connection exceptions can contain connection details. Do not expose
        # credentials or SCRAM material in migration-job logs.
        raise SystemExit(
            "Tenant login provisioning failed; check configuration and role isolation"
        ) from None
    print("Configured isolated database login for inntris_tenant_login")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
