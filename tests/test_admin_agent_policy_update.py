from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from fastapi.testclient import TestClient

from api.main import app, get_db, verify_api_key
from api.models import AgentRecord, AgentStatus

client = TestClient(app)


def _agent_record(**overrides):
    now = datetime.now(UTC)
    data = {
        "id": uuid4(),
        "org_id": uuid4(),
        "name": "Policy Agent",
        "public_key": b"x" * 32,
        "public_key_fingerprint": "ab:cd",
        "trust_score": 80,
        "status": AgentStatus.ACTIVE,
        "daily_limit_usd": Decimal("1000"),
        "per_action_limit_usd": Decimal("100"),
        "allowed_actions": ["financial_transaction", "api_call"],
        "blocked_actions": ["admin_action"],
        "rate_limit_per_minute": 60,
        "last_action_at": None,
        "total_actions_count": 0,
        "total_blocked_count": 0,
        "metadata": {},
        "created_at": now,
        "updated_at": now,
    }
    data.update(overrides)
    return AgentRecord(**data)


def _acquire_returning(conn):
    acm = MagicMock()
    acm.__aenter__ = AsyncMock(return_value=conn)
    acm.__aexit__ = AsyncMock(return_value=False)
    db = MagicMock()
    db.acquire = MagicMock(return_value=acm)
    return db


def test_update_agent_policy_controls_are_validated_and_saved():
    org_id = uuid4()
    agent_id = uuid4()
    agent = _agent_record(id=agent_id, org_id=org_id)
    now = datetime.now(UTC)

    updated_row = {
        "id": agent_id,
        "org_id": org_id,
        "name": "Policy Agent",
        "public_key_fingerprint": "ab:cd",
        "trust_score": 80,
        "status": "active",
        "daily_limit_usd": Decimal("500"),
        "per_action_limit_usd": Decimal("50"),
        "allowed_actions": ["financial_transaction", "tool_call", "api_call"],
        "blocked_actions": ["data_export", "admin_action"],
        "rate_limit_per_minute": 30,
        "last_action_at": None,
        "total_actions_count": 0,
        "total_blocked_count": 0,
        "metadata": {},
        "created_at": now,
        "updated_at": now,
    }

    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=updated_row)
    db_mock = _acquire_returning(conn)
    db_mock.get_agent_by_id = AsyncMock(return_value=agent)

    app.dependency_overrides[get_db] = lambda: db_mock
    app.dependency_overrides[verify_api_key] = lambda: {
        "org_id": org_id,
        "scopes": ["write"],
    }
    try:
        response = client.patch(
            f"/admin/agents/{agent_id}",
            json={
                "daily_limit_usd": 500,
                "per_action_limit_usd": 50,
                "allowed_actions": ["financial_transaction", "tool_call", "api_call"],
                "blocked_actions": ["data_export", "admin_action"],
                "rate_limit_per_minute": 30,
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["daily_limit_usd"] == 500.0
    assert body["per_action_limit_usd"] == 50.0
    assert body["allowed_actions"] == ["financial_transaction", "tool_call", "api_call"]
    assert body["blocked_actions"] == ["data_export", "admin_action"]


def test_update_agent_metadata_is_merged_not_replaced():
    org_id = uuid4()
    agent_id = uuid4()
    agent = _agent_record(
        id=agent_id, org_id=org_id, metadata={"source": "public_registration"}
    )
    now = datetime.now(UTC)
    updated_row = {
        "id": agent_id, "org_id": org_id, "name": "Policy Agent",
        "public_key_fingerprint": "ab:cd", "trust_score": 80, "status": "active",
        "daily_limit_usd": Decimal("1000"), "per_action_limit_usd": Decimal("100"),
        "allowed_actions": ["api_call"], "blocked_actions": [],
        "rate_limit_per_minute": 60, "last_action_at": None,
        "total_actions_count": 0, "total_blocked_count": 0,
        # The real DB || merge keeps "source"; the mock returns the merged shape.
        "metadata": {"source": "public_registration", "customer_label": "finance"},
        "created_at": now, "updated_at": now,
    }
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=updated_row)
    db_mock = _acquire_returning(conn)
    db_mock.get_agent_by_id = AsyncMock(return_value=agent)

    app.dependency_overrides[get_db] = lambda: db_mock
    app.dependency_overrides[verify_api_key] = lambda: {"org_id": org_id, "scopes": ["write"]}
    try:
        response = client.patch(
            f"/admin/agents/{agent_id}",
            json={"metadata": {"customer_label": "finance"}},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    # The UPDATE must MERGE metadata (|| operator), not overwrite it.
    query_used = conn.fetchrow.await_args.args[0]
    assert "COALESCE(metadata, '{}'::jsonb) ||" in query_used
    assert response.json()["metadata"] == {
        "source": "public_registration",
        "customer_label": "finance",
    }


def test_update_agent_rejects_per_action_limit_above_resulting_daily_limit():
    org_id = uuid4()
    agent_id = uuid4()
    agent = _agent_record(id=agent_id, org_id=org_id)
    db_mock = _acquire_returning(AsyncMock())
    db_mock.get_agent_by_id = AsyncMock(return_value=agent)

    app.dependency_overrides[get_db] = lambda: db_mock
    app.dependency_overrides[verify_api_key] = lambda: {
        "org_id": org_id,
        "scopes": ["write"],
    }
    try:
        response = client.patch(
            f"/admin/agents/{agent_id}",
            json={"daily_limit_usd": 25, "per_action_limit_usd": 50},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422


def test_update_agent_rejects_action_overlap_against_existing_policy():
    org_id = uuid4()
    agent_id = uuid4()
    agent = _agent_record(id=agent_id, org_id=org_id, blocked_actions=["admin_action"])
    db_mock = _acquire_returning(AsyncMock())
    db_mock.get_agent_by_id = AsyncMock(return_value=agent)

    app.dependency_overrides[get_db] = lambda: db_mock
    app.dependency_overrides[verify_api_key] = lambda: {
        "org_id": org_id,
        "scopes": ["write"],
    }
    try:
        response = client.patch(
            f"/admin/agents/{agent_id}",
            json={"allowed_actions": ["financial_transaction", "admin_action"]},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    assert "admin_action" in response.json()["detail"]


def test_update_agent_rejects_explicit_null_controls():
    org_id = uuid4()
    agent_id = uuid4()
    db_mock = _acquire_returning(AsyncMock())
    db_mock.get_agent_by_id = AsyncMock(return_value=_agent_record(id=agent_id, org_id=org_id))

    app.dependency_overrides[get_db] = lambda: db_mock
    app.dependency_overrides[verify_api_key] = lambda: {
        "org_id": org_id,
        "scopes": ["write"],
    }
    try:
        response = client.patch(
            f"/admin/agents/{agent_id}",
            json={"daily_limit_usd": None},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    assert "daily_limit_usd cannot be null" in response.text
