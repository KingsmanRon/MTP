"""Tests for /v1/events synthetic-agent activation and activity counters.

Regression coverage for the admin dashboard reporting ``Active Agents: 0/N``
despite ingested events: the synthetic ``events-v1-ingest`` agent must be
created with ``status = 'active'`` (it never goes through /verify's activation
path) and must have ``last_action_at`` / ``total_actions_count`` bumped on each
ingested event.
"""
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from fastapi.testclient import TestClient

from api.main import app, get_db

client = TestClient(app)

EVENT_BODY = {"event_type": "page_view", "data": {"path": "/pricing"}}


def _make_db_mock(existing_agent_id=None):
    """Database-like mock for the /v1/events path.

    ``acquire()`` yields a shared ``conn`` whose ``fetchrow`` answers the
    ``api_keys`` bearer lookup and whose ``fetchval`` answers the
    ``events-v1-ingest`` agent lookup. Pass ``existing_agent_id`` to simulate an
    already-provisioned agent (which skips the create + activation path).
    """
    org_id = uuid4()
    key_id = uuid4()
    new_agent_id = uuid4()
    audit_id = uuid4()

    conn = AsyncMock()
    conn.fetchrow = AsyncMock(
        return_value={
            "id": key_id,
            "org_id": org_id,
            "is_active": True,
            "expires_at": None,
        }
    )
    conn.fetchval = AsyncMock(return_value=existing_agent_id)
    conn.execute = AsyncMock(return_value="UPDATE 1")

    # acquire() must be a sync callable returning an async context manager.
    acm = MagicMock()
    acm.__aenter__ = AsyncMock(return_value=conn)
    acm.__aexit__ = AsyncMock(return_value=False)

    db = MagicMock()
    db.acquire = MagicMock(return_value=acm)
    db.create_agent = AsyncMock(return_value=new_agent_id)
    db.get_last_audit_hash = AsyncMock(return_value=None)
    db.insert_audit_log = AsyncMock(return_value=audit_id)

    return db, conn


def _executed_sql(conn):
    """Flatten every conn.execute(...) call into one searchable string."""
    return " ".join(
        " ".join(str(arg) for arg in call.args) for call in conn.execute.call_args_list
    )


def _post_event(db_mock):
    app.dependency_overrides[get_db] = lambda: db_mock
    try:
        return client.post(
            "/v1/events",
            json=EVENT_BODY,
            headers={"Authorization": "Bearer testtoken"},
        )
    finally:
        app.dependency_overrides.clear()


class TestEventsV1Counters:
    def test_new_agent_created_active(self):
        db_mock, conn = _make_db_mock(existing_agent_id=None)

        resp = _post_event(db_mock)

        assert resp.status_code == 201, resp.text
        assert resp.json()["status"] == "accepted"
        # Agent was created and immediately promoted to active.
        db_mock.create_agent.assert_awaited_once()
        assert "status = 'active'" in _executed_sql(conn)

    def test_counters_bumped_on_ingest(self):
        db_mock, conn = _make_db_mock(existing_agent_id=None)

        resp = _post_event(db_mock)

        assert resp.status_code == 201, resp.text
        sql = _executed_sql(conn)
        assert "total_actions_count = total_actions_count + 1" in sql
        assert "last_action_at = NOW()" in sql

    def test_existing_agent_not_recreated_but_counters_bump(self):
        db_mock, conn = _make_db_mock(existing_agent_id=uuid4())

        resp = _post_event(db_mock)

        assert resp.status_code == 201, resp.text
        # Existing agent is reused; no second create and no re-activation UPDATE,
        # but its activity counters still advance.
        db_mock.create_agent.assert_not_awaited()
        sql = _executed_sql(conn)
        assert "status = 'active'" not in sql
        assert "total_actions_count = total_actions_count + 1" in sql
