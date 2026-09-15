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
# ``alembic_version`` at the same time. A Postgres advisory lock serialises
# that critical section: the process waiting on it reads the revision only
# after the first migration commits, and therefore exits as a clean no-op
# instead of racing the version-row update.
#
# The lock is SESSION scoped (``pg_advisory_lock``) and held on a connection
# of its own. It used to be transaction scoped (``pg_advisory_xact_lock``) on
# the migration connection, which forced the whole revision series into ONE
# transaction -- and that is what made an upgrade of an existing database
# impossible: a transaction-scoped lock taken by one migration survived into
# the next, and migration 030's drift guard correctly refused when it found
# a lock migration 029 had left behind. See
# docs/releases/GATE1_STAGING_MIGRATION.md.
#
# A session lock is released when the session ends, so a migrator that dies
# mid-series frees it without operator intervention.
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
    """Connect and run migrations against the live database.

    The transaction model is::

        session migration lock   (its own connection, AUTOCOMMIT)
            revision N   -> COMMIT
            revision N+1 -> COMMIT
            ...
        release session migration lock   (finally)

    ONE REVISION PER TRANSACTION. ``transaction_per_migration=True`` is what
    makes an upgrade of an existing database possible at all: a migration
    that takes a transaction-scoped lock -- as the authority-configuration
    write trigger does -- must not still be holding it when the next
    migration runs. Sharing one transaction across the series is what broke
    Gate 1.

    THE INVOCATION LOCK IS ON ITS OWN CONNECTION. Two reasons. It must
    outlive every individual migration transaction, which a transaction-
    scoped lock on the migration connection cannot; and acquiring it must not
    open a transaction that Alembic then inherits, so that connection runs in
    AUTOCOMMIT. The lock connection issues no DDL and holds no transaction
    open, so it does not hold back vacuum while a long migration runs.

    A session lock dies with its session, so a migrator killed mid-series
    releases it without anyone having to intervene -- and the database is
    left at the last revision that committed, not in a half-applied state.
    """
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _resolve_dsn()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    lock_connection = connectable.connect().execution_options(
        isolation_level="AUTOCOMMIT"
    )
    try:
        # Blocks until any other migrator in this deployment has finished and
        # committed. The waiter then reads alembic_version afresh and finds
        # the work already done.
        lock_connection.execute(
            text("SELECT pg_advisory_lock(:lock_key)"),
            {"lock_key": _MIGRATION_LOCK_KEY},
        )
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                transaction_per_migration=True,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        # Released explicitly so a pooled or long-lived session cannot keep
        # the next deployment waiting. Ending the session would release it
        # too; this makes the intent visible.
        try:
            lock_connection.execute(
                text("SELECT pg_advisory_unlock(:lock_key)"),
                {"lock_key": _MIGRATION_LOCK_KEY},
            )
        finally:
            lock_connection.close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
