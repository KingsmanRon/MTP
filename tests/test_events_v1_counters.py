"""Tests for /v1/events synthetic-agent activation and activity ownership.

Regression coverage for the admin dashboard reporting ``Active Agents: 0/N``
despite ingested events: the synthetic ``events-v1-ingest`` agent must be
created with ``status = 'active'`` (it never goes through /verify's activation
path). Activity counters are owned by the audit insert trigger, not by a
manual pre-insert UPDATE in the handler.
"""
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from fastapi.testclient import TestClient

from api.main import app, get_db
from api.tenant_boundary import get_events_tenant_database

client = TestClient(app)

EVENT_BODY = {"event_type": "page_view", "data": {"path": "/pricing"}}


def _make_db_mock(existing_agent_id=None, *, existing_agent_metadata=None):
    """Database-like mock for the tenant-scoped /v1/events handler.

    The FastAPI dependency performs the trusted SYSTEM bearer lookup before it
    returns a tenant-scoped database. The handler then re-validates the bearer
    key through that tenant-scoped database, so the shared connection returns
    the API-key row first and the event-agent trust row second.
    """
    org_id = uuid4()
    key_id = uuid4()
    new_agent_id = uuid4()
    audit_id = uuid4()

    conn = AsyncMock()
    conn.fetchval = AsyncMock(return_value=existing_agent_id)
    conn.fetchrow = AsyncMock(
        side_effect=[
            {
                "id": key_id,
                "org_id": org_id,
                "scopes": ["verify"],
                "is_active": True,
                "expires_at": None,
            },
            {
                "trust_score": 73,
                "metadata": existing_agent_metadata or {"sandbox": True},
            },
        ]
    )
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
    """Flatten every conn.execute(...) and conn.fetchval(...) call into one
    searchable string. The counter UPDATE moved to fetchval (... RETURNING
    trust_score), so both call sinks must be inspected."""
    calls = list(conn.execute.call_args_list) + list(conn.fetchval.call_args_list)
    return " ".join(" ".join(str(arg) for arg in call.args) for call in calls)


def _post_event(db_mock):
    app.dependency_overrides[get_db] = lambda: db_mock
    app.dependency_overrides[get_events_tenant_database] = lambda: db_mock
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
        assert db_mock.create_agent.await_args.kwargs["metadata"]["sandbox"] is True
        assert "status = 'active'" in _executed_sql(conn)

    def test_activity_is_recorded_by_audit_insert_not_manual_counter_update(self):
        db_mock, conn = _make_db_mock(existing_agent_id=None)

        resp = _post_event(db_mock)

        assert resp.status_code == 201, resp.text
        sql = _executed_sql(conn)
        assert "total_actions_count = total_actions_count + 1" not in sql
        assert "last_action_at = NOW()" not in sql
        db_mock.insert_audit_log.assert_awaited_once()

    def test_existing_agent_not_recreated_but_counters_bump(self):
        db_mock, conn = _make_db_mock(existing_agent_id=uuid4())

        resp = _post_event(db_mock)

        assert resp.status_code == 201, resp.text
        # Existing agent is reused; no second create and no re-activation UPDATE,
        # but its activity counters still advance.
        db_mock.create_agent.assert_not_awaited()
        sql = _executed_sql(conn)
        assert "status = 'active'" not in sql
        assert "total_actions_count = total_actions_count + 1" not in sql
        db_mock.insert_audit_log.assert_awaited_once()


class TestEventsV1Truthfulness:
    """Ingested events must not masquerade as cryptographically verified.

    Regression for the forensic-integrity bug where /v1/events wrote rows with
    ``signature_valid=True`` and a fabricated ``trust_score_at_time=100`` while
    still flowing into the publicly-anchored Merkle batches.
    """

    def _ingested_entry(self, existing_agent_id):
        db_mock, _conn = _make_db_mock(existing_agent_id=existing_agent_id)
        resp = _post_event(db_mock)
        assert resp.status_code == 201, resp.text
        db_mock.insert_audit_log.assert_awaited_once()
        call = db_mock.insert_audit_log.call_args
        return call.args[0], call

    def test_signature_not_marked_valid(self):
        entry, _call = self._ingested_entry(existing_agent_id=uuid4())
        assert entry.signature_valid is False

    def test_trust_score_is_real_not_fabricated(self):
        # The mocked counter UPDATE returns 73 (the agent's real score), never
        # the old hard-coded 100.
        entry, _call = self._ingested_entry(existing_agent_id=uuid4())
        assert entry.trust_score_at_time == 73

    def test_metadata_marks_unsigned_attestation(self):
        entry, _call = self._ingested_entry(existing_agent_id=uuid4())
        assert entry.metadata.get("attestation_type") == "unsigned_ingestion"
        assert entry.metadata.get("non_cryptographic") is True
        assert entry.metadata.get("source") == "events_v1"
        assert entry.metadata.get("sandbox") is True
        assert entry.metadata.get("test_request") is True

    def test_promoted_same_name_agent_cannot_make_unsigned_event_anchorable(self):
        db_mock, _conn = _make_db_mock(
            existing_agent_id=uuid4(),
            existing_agent_metadata={
                "source": "events_v1_bootstrap",
                "non_cryptographic": True,
                "sandbox": False,
                "production_approval_reference": "legacy-approval",
            },
        )
        resp = _post_event(db_mock)
        assert resp.status_code == 201, resp.text
        entry = db_mock.insert_audit_log.await_args.args[0]
        assert entry.metadata.get("sandbox") is True
        assert entry.metadata.get("test_request") is True

    def test_chain_hash_derived_atomically(self):
        # derive_chain_hash=True routes the insert through the per-agent
        # advisory-locked path so concurrent partner posts can't fork the chain.
        _entry, call = self._ingested_entry(existing_agent_id=uuid4())
        assert call.kwargs.get("derive_chain_hash") is True
