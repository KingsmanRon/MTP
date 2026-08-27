"""Alembic environment (Phase 1D.1).

We do not own any SQLAlchemy ORM models — the application talks to Postgres
through asyncpg directly. Migrations therefore run as straight DDL (``op.execute``
against raw SQL) and we leave ``target_metadata`` empty; there is nothing
to autogenerate against.

DSN resolution order:
    1. ``sqlalchemy.url`` in ``alembic.ini`` (empty by default).
    2. ``ALEMBIC_DATABASE_URL`` environment variable. Migrations need an
       owner/privileged role (DDL + access to ``alembic_version``), whereas the
       runtime app connects as the locked-down ``inntris_worker`` role for RLS
       (see database/migrations/005_rls_policies.sql). Set this so the two never
       share a DSN; without it we fall back to ``DATABASE_URL``.
    3. ``DATABASE_URL`` environment variable.
    4. Fail with a clear error — we refuse to run against an accidental
       default like localhost.

Note: asyncpg-style DSNs (``postgresql://``) need to be rewritten to
``postgresql+psycopg2://`` for Alembic's sync engine. We do that
transparently so operators can point the same DATABASE_URL at both the
runtime API and ``alembic upgrade``.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool, text

from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None

# Railway deploys the API and worker from the same commit. Both services run
# ``alembic upgrade head`` before replacing their containers, so they can reach
# ``alembic_version`` at the same time. A transaction-scoped Postgres advisory
# lock serialises that critical section. The process waiting on the lock reads
# the revision only after the first migration commits and therefore exits as a
# clean no-op instead of racing the version-row update.
_MIGRATION_LOCK_KEY = 4_803_921_115_399_370_837


def _resolve_dsn() -> str:
    dsn = (
        config.get_main_option("sqlalchemy.url")
        or os.getenv("ALEMBIC_DATABASE_URL")
        or os.getenv("DATABASE_URL", "")
    )
    if not dsn:
        raise RuntimeError(
            "Alembic requires a database DSN. Set ALEMBIC_DATABASE_URL (preferred "
            "for a privileged migration role) or DATABASE_URL in the environment, "
            "or sqlalchemy.url in alembic.ini."
        )
    # asyncpg DSN -> psycopg2 DSN for Alembic's sync engine.
    if dsn.startswith("postgresql://") and "+" not in dsn.split("://", 1)[0]:
        dsn = "postgresql+psycopg2://" + dsn[len("postgresql://") :]
    elif dsn.startswith("postgres://"):
        dsn = "postgresql+psycopg2://" + dsn[len("postgres://") :]
    return dsn


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting.

    Useful for producing a review artifact in CI / change management.
    """
    context.configure(
        url=_resolve_dsn(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect and run migrations against the live database."""
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _resolve_dsn()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:lock_key)"),
                {"lock_key": _MIGRATION_LOCK_KEY},
            )
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
