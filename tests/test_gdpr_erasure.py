"""GDPR erasure unit and real Postgres integration tests.

The integration tier creates an empty temporary database, replays Alembic to
head, and exercises the guarded erasure function through the same asyncpg
boundary used by the application. It is enabled only when
INNTRIS_DB_INTEGRATION=1 and a privileged database URL is configured.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest

from api.erasure import ErasureResult, erase_personal_data, is_row_erased


class _FakeConn:
    """Minimal stub that records the SQL issued by the Python wrapper."""

    def __init__(
        self,
        fake_request_id: uuid.UUID | None = None,
        fake_rows: int = 0,
    ) -> None:
        self.calls: list[tuple[str, tuple]] = []
        self._request_id = fake_request_id or uuid.uuid4()
        self._rows = fake_rows

    async def fetchval(self, query: str, *args):
        self.calls.append((query, args))
        if "app.erase_personal_data" in query:
            return self._request_id
        if "rows_affected" in query:
            return self._rows
        raise AssertionError(f"unexpected query: {query}")


async def test_erase_rejects_unknown_legal_basis() -> None:
    conn = _FakeConn()
    with pytest.raises(ValueError, match="unsupported legal_basis"):
        await erase_personal_data(
            conn,  # type: ignore[arg-type]
            organization_id=uuid.uuid4(),
            requested_by="ops@inntris.com",
            legal_basis="gdpr_17",
        )
    assert conn.calls == []


async def test_erase_requires_requested_by() -> None:
    conn = _FakeConn()
    with pytest.raises(ValueError, match="requested_by is required"):
        await erase_personal_data(
            conn,  # type: ignore[arg-type]
            organization_id=uuid.uuid4(),
            requested_by="   ",
            legal_basis="gdpr_art17",
        )
    assert conn.calls == []


async def test_erase_happy_path_returns_request_id_and_rows() -> None:
    expected_id = uuid.uuid4()
    conn = _FakeConn(fake_request_id=expected_id, fake_rows=17)
    result = await erase_personal_data(
        conn,  # type: ignore[arg-type]
        organization_id=uuid.uuid4(),
        requested_by="dpo@inntris.com",
        legal_basis="ccpa_1798_105",
        reason="Data subject request #4821",
    )
    assert isinstance(result, ErasureResult)
    assert result.request_id == expected_id
    assert result.rows_affected == 17
    assert len(conn.calls) == 2
    assert "app.erase_personal_data" in conn.calls[0][0]
    assert "rows_affected" in conn.calls[1][0]


async def test_erase_trims_requested_by() -> None:
    conn = _FakeConn(fake_rows=0)
    await erase_personal_data(
        conn,  # type: ignore[arg-type]
        organization_id=uuid.uuid4(),
        requested_by="  ops@inntris.com  ",
        legal_basis="operator_request",
    )
    _, args = conn.calls[0]
    assert args[2] == "ops@inntris.com"


def test_is_row_erased_true_for_tombstone() -> None:
    assert is_row_erased({"erased": True, "erased_at": "2026-04-18"})


def test_is_row_erased_false_for_live_payload() -> None:
    assert not is_row_erased({"action_type": "web_fetch", "url": "https://example.com"})


def test_is_row_erased_false_for_empty_dict() -> None:
    assert not is_row_erased({})


_REPO = Path(__file__).resolve().parents[1]
_MIGRATION_DATABASE_URL = os.getenv("ALEMBIC_DATABASE_URL") or os.getenv("DATABASE_URL")
_integration = pytest.mark.skipif(
    os.getenv("INNTRIS_DB_INTEGRATION") != "1" or not _MIGRATION_DATABASE_URL,
    reason=(
        "erasure integration test requires INNTRIS_DB_INTEGRATION=1 and "
        "ALEMBIC_DATABASE_URL or DATABASE_URL"
    ),
)


def _normalise_postgres_url(value: str) -> str:
    """Return a URL accepted by both psycopg2 and asyncpg."""
    for scheme in (
        "postgresql+asyncpg://",
        "postgresql+psycopg2://",
        "postgres://",
    ):
        if value.startswith(scheme):
            return "postgresql://" + value[len(scheme) :]
    return value


def _database_url_for_name(value: str, database_name: str) -> str:
    parsed = urlsplit(_normalise_postgres_url(value))
    return urlunsplit(parsed._replace(path=f"/{database_name}"))


@pytest.fixture(scope="module")
def migrated_database_url() -> Iterator[str]:
    """Create an empty database and replay the complete Alembic chain.

    The configured migration role must have CREATEDB. The database is dropped
    as a whole because audit rows are intentionally undeletable.
    """
    import psycopg2
    from psycopg2 import sql

    assert _MIGRATION_DATABASE_URL is not None
    source_url = _normalise_postgres_url(_MIGRATION_DATABASE_URL)
    database_name = f"inntris_gdpr_{uuid.uuid4().hex}"
    migrated_url = _database_url_for_name(source_url, database_name)
    admin_conn = psycopg2.connect(source_url)
    admin_conn.autocommit = True
    created = False

    try:
        with admin_conn.cursor() as cursor:
            cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database_name)))
        created = True

        migration_env = os.environ.copy()
        migration_env["ALEMBIC_DATABASE_URL"] = migrated_url
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                str(_REPO / "alembic.ini"),
                "upgrade",
                "head",
            ],
            cwd=_REPO,
            env=migration_env,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"clean Alembic replay failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )

        yield migrated_url
    finally:
        if created:
            with admin_conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = %s
                      AND pid <> pg_backend_pid()
                    """,
                    (database_name,),
                )
                cursor.execute(
                    sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(database_name))
                )
        admin_conn.close()


@_integration
def test_integration_clean_postgres_migration_replay(
    migrated_database_url: str,
) -> None:
    """A greenfield Postgres reaches head with the repaired function active."""
    import psycopg2
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(_REPO / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO / "alembic"))
    expected_head = ScriptDirectory.from_config(config).get_current_head()

    with (
        psycopg2.connect(migrated_database_url) as conn,
        conn.cursor() as cursor,
    ):
        cursor.execute("SELECT version_num FROM alembic_version")
        assert cursor.fetchone()[0] == expected_head

        cursor.execute(
            """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'agents'
                """
        )
        agent_columns = {row[0] for row in cursor.fetchall()}
        assert "org_id" in agent_columns
        assert "organization_id" not in agent_columns

        cursor.execute(
            """
                SELECT pg_get_functiondef(
                    'app.erase_personal_data(uuid,uuid,text,text,text)'::regprocedure
                )
                """
        )
        erasure_source = cursor.fetchone()[0]
        assert "a.org_id = p_org_id" in erasure_source
        assert "app.erasure_request_id" in erasure_source

        cursor.execute(
            """
                SELECT pg_get_functiondef(
                    'public.prevent_audit_log_modification()'::regprocedure
                )
                """
        )
        trigger_source = cursor.fetchone()[0]
        assert "matching pending ledger row" in trigger_source
        assert "Erasure cannot modify forensic audit fields" in trigger_source

        cursor.execute(
            """
                SELECT
                    has_function_privilege(
                        'inntris_worker',
                        'app.erase_personal_data(uuid,uuid,text,text,text)',
                        'EXECUTE'
                    ),
                    has_table_privilege(
                        'inntris_worker', 'public.erasure_requests', 'INSERT'
                    )
                """
        )
        can_execute, can_insert_ledger = cursor.fetchone()
        assert can_execute is False
        assert can_insert_ledger is False


@_integration
@pytest.mark.asyncio
async def test_integration_erasure_is_scoped_and_preserves_forensics(
    migrated_database_url: str,
) -> None:
    """Exercise denial cases and the legitimate erasure through Postgres."""
    import asyncpg

    conn = await asyncpg.connect(migrated_database_url)
    try:
        org_id = await conn.fetchval(
            """
            INSERT INTO organizations (name, contact_email, api_key_hash)
            VALUES ('erasure-test-org', 'dpo@example.com', decode('00', 'hex'))
            RETURNING id
            """
        )
        agent_id = await conn.fetchval(
            """
            INSERT INTO agents (
                org_id, name, public_key, public_key_fingerprint, status
            ) VALUES (
                $1, 'erasure-test-agent', $2, repeat('1', 64), 'active'
            )
            RETURNING id
            """,
            org_id,
            bytes(range(32)),
        )
        unaffected_agent_id = await conn.fetchval(
            """
            INSERT INTO agents (
                org_id, name, public_key, public_key_fingerprint, status
            ) VALUES (
                $1, 'unaffected-agent', $2, repeat('2', 64), 'active'
            )
            RETURNING id
            """,
            org_id,
            b"2" * 32,
        )

        log_id = await conn.fetchval(
            """
            INSERT INTO audit_logs (
                agent_id, action_type, action_hash, payload, verdict,
                verdict_reason, signature, signature_valid,
                request_ip, request_user_agent, response_time_ms,
                trust_score_at_time, merkle_root_id, merkle_leaf_index,
                chain_previous_hash, effective_controls_hash, metadata
            ) VALUES (
                $1, 'web_fetch', repeat('a', 64), $2::jsonb, 'approved',
                'policy allowed', $3, true,
                '203.0.113.42', 'curl/8.1.2', 17,
                88, $4, 42, repeat('b', 64), repeat('c', 64), $5::jsonb
            )
            RETURNING id
            """,
            agent_id,
            json.dumps(
                {
                    "erased": True,
                    "url": "https://example.com",
                    "user_email": "subject@example.com",
                }
            ),
            b"signed-action",
            uuid.uuid4(),
            json.dumps(
                {
                    "test_request": True,
                    "customer_reference": "personal-data",
                }
            ),
        )
        unaffected_log_id = await conn.fetchval(
            """
            INSERT INTO audit_logs (
                agent_id, action_type, action_hash, payload, verdict,
                signature, signature_valid, trust_score_at_time
            ) VALUES (
                $1, 'web_fetch', repeat('d', 64), $2::jsonb, 'approved',
                $3, true, 75
            )
            RETURNING id
            """,
            unaffected_agent_id,
            json.dumps({"user_email": "other@example.com"}),
            b"other-signature",
        )

        forensic_columns = """
            id, agent_id, timestamp, action_type, action_hash, verdict,
            verdict_reason, signature, signature_valid, response_time_ms,
            trust_score_at_time, merkle_root_id, merkle_leaf_index,
            chain_previous_hash, effective_controls_hash
        """
        before = dict(
            await conn.fetchrow(
                f"SELECT {forensic_columns} FROM audit_logs WHERE id = $1",
                log_id,
            )
        )

        fake_request_id = uuid.uuid4()
        with pytest.raises(
            asyncpg.PostgresError,
            match="no matching pending ledger row",
        ):
            async with conn.transaction():
                await conn.execute(
                    "SELECT set_config('app.erasure_request_id', $1, true)",
                    str(fake_request_id),
                )
                await conn.execute(
                    """
                    UPDATE audit_logs
                    SET payload = jsonb_build_object(
                            'erased', true,
                            'erased_at', clock_timestamp(),
                            'erasure_request_id', $1::uuid
                        ),
                        metadata = '{"test_request": true, "erased": true}',
                        request_ip = NULL,
                        request_user_agent = NULL
                    WHERE id = $2
                    """,
                    fake_request_id,
                    log_id,
                )

        with pytest.raises(
            asyncpg.PostgresError,
            match="cannot modify forensic audit fields",
        ):
            async with conn.transaction():
                pending_request_id = await conn.fetchval(
                    """
                    INSERT INTO erasure_requests (
                        organization_id, subject_agent_id, requested_by,
                        legal_basis, reason
                    ) VALUES ($1, $2, 'security-test', 'operator_request', 'guard')
                    RETURNING id
                    """,
                    org_id,
                    agent_id,
                )
                await conn.execute(
                    "SELECT set_config('app.erasure_request_id', $1, true)",
                    str(pending_request_id),
                )
                await conn.execute(
                    """
                    UPDATE audit_logs
                    SET payload = jsonb_build_object(
                            'erased', true,
                            'erased_at', clock_timestamp(),
                            'erasure_request_id', $1::uuid
                        ),
                        metadata = '{"test_request": true, "erased": true}',
                        request_ip = NULL,
                        request_user_agent = NULL,
                        action_hash = repeat('f', 64)
                    WHERE id = $2
                    """,
                    pending_request_id,
                    log_id,
                )

        result = await erase_personal_data(
            conn,
            organization_id=org_id,
            requested_by="dpo@example.com",
            legal_basis="gdpr_art17",
            agent_id=agent_id,
            reason="DSR-2026-001",
        )
        assert result.rows_affected == 1

        after = dict(
            await conn.fetchrow(
                f"SELECT {forensic_columns} FROM audit_logs WHERE id = $1",
                log_id,
            )
        )
        assert after == before

        redacted = await conn.fetchrow(
            """
            SELECT payload, metadata, request_ip, request_user_agent
            FROM audit_logs
            WHERE id = $1
            """,
            log_id,
        )
        payload = json.loads(redacted["payload"])
        metadata = json.loads(redacted["metadata"])
        assert set(payload) == {"erased", "erased_at", "erasure_request_id"}
        assert payload["erased"] is True
        assert payload["erasure_request_id"] == str(result.request_id)
        assert "subject@example.com" not in redacted["payload"]
        assert metadata == {"test_request": True, "erased": True}
        assert redacted["request_ip"] is None
        assert redacted["request_user_agent"] is None

        assert (
            await conn.fetchval(
                "SELECT payload->>'user_email' FROM audit_logs WHERE id = $1",
                unaffected_log_id,
            )
            == "other@example.com"
        )

        ledger = await conn.fetchrow(
            """
            SELECT organization_id, subject_agent_id, requested_by,
                   legal_basis, reason, rows_affected, completed_at
            FROM erasure_requests
            WHERE id = $1
            """,
            result.request_id,
        )
        assert ledger["organization_id"] == org_id
        assert ledger["subject_agent_id"] == agent_id
        assert ledger["requested_by"] == "dpo@example.com"
        assert ledger["legal_basis"] == "gdpr_art17"
        assert ledger["reason"] == "DSR-2026-001"
        assert ledger["rows_affected"] == 1
        assert ledger["completed_at"] is not None

        assert (
            await conn.fetchval(
                "SELECT NULLIF(current_setting('app.erasure_request_id', true), '')"
            )
            is None
        )
        with pytest.raises(asyncpg.PostgresError, match="immutable outside"):
            await conn.execute(
                "UPDATE audit_logs SET verdict_reason = 'tampered' WHERE id = $1",
                log_id,
            )

        again = await erase_personal_data(
            conn,
            organization_id=org_id,
            requested_by="dpo@example.com",
            legal_basis="gdpr_art17",
            agent_id=agent_id,
            reason="DSR-2026-001 retry",
        )
        assert again.rows_affected == 0
    finally:
        await conn.close()
