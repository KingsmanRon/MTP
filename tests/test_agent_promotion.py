"""Security contract for moving a sandbox agent into production."""

import base64
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from fastapi.testclient import TestClient

from api.main import app, get_db, verify_api_key
from api.models import AgentRecord, AgentStatus

client = TestClient(app)


def _agent_record(agent_id, org_id, *, sandbox=True):
    now = datetime.now(UTC)
    metadata = {"source": "public_registration", "sandbox": sandbox}
    if not sandbox:
        metadata.update(
            {
                "production_approval_reference": "SEC-123",
                "production_approved_at": now.isoformat(),
                "production_approved_by": f"org_admin:{org_id}",
            }
        )
    return AgentRecord(
        id=agent_id,
        org_id=org_id,
        name="Sandbox agent",
        public_key=b"x" * 32,
        public_key_fingerprint="a" * 64,
        trust_score=50,
        status=AgentStatus.ACTIVE,
        daily_limit_usd=Decimal("1000"),
        per_action_limit_usd=Decimal("100"),
        allowed_actions=["tool_call"],
        blocked_actions=[],
        rate_limit_per_minute=60,
        last_action_at=None,
        total_actions_count=0,
        total_blocked_count=0,
        metadata=metadata,
        created_at=now,
        updated_at=now,
    )


def _database(agent):
    database = MagicMock()
    database.get_agent_by_id = AsyncMock(return_value=agent)
    database.get_organization_by_id = AsyncMock(
        return_value=SimpleNamespace(name="Verified Organisation")
    )
    database.promote_agent_to_production = AsyncMock(
        return_value={
            "sandbox": False,
            "production_approval_reference": "SEC-123",
        }
    )
    return database


def test_organisation_admin_can_explicitly_promote_sandbox_agent():
    org_id = uuid4()
    agent_id = uuid4()
    database = _database(_agent_record(agent_id, org_id))

    app.dependency_overrides[get_db] = lambda: database
    app.dependency_overrides[verify_api_key] = lambda: {
        "org_id": org_id,
        "scopes": ["admin"],
    }
    try:
        response = client.post(
            f"/admin/agents/{agent_id}/promote",
            json={"approval_reference": "SEC-123"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    assert response.json()["sandbox"] is False
    database.promote_agent_to_production.assert_awaited_once()
    kwargs = database.promote_agent_to_production.await_args.kwargs
    assert kwargs["agent_id"] == agent_id
    assert kwargs["org_id"] == org_id
    assert kwargs["approval_reference"] == "SEC-123"


def test_non_cryptographic_ingestion_agent_cannot_be_promoted():
    org_id = uuid4()
    agent_id = uuid4()
    agent = _agent_record(agent_id, org_id)
    agent.metadata.update(
        {"source": "events_v1_bootstrap", "non_cryptographic": True}
    )
    database = _database(agent)

    app.dependency_overrides[get_db] = lambda: database
    app.dependency_overrides[verify_api_key] = lambda: {
        "org_id": org_id,
        "scopes": ["admin"],
    }
    try:
        response = client.post(
            f"/admin/agents/{agent_id}/promote",
            json={"approval_reference": "SEC-123"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    assert "non-cryptographic" in response.json()["detail"].lower()
    database.promote_agent_to_production.assert_not_awaited()


def test_write_scope_alone_cannot_promote_sandbox_agent():
    org_id = uuid4()
    agent_id = uuid4()
    database = _database(_agent_record(agent_id, org_id))

    app.dependency_overrides[get_db] = lambda: database
    app.dependency_overrides[verify_api_key] = lambda: {
        "org_id": org_id,
        "scopes": ["write"],
    }
    try:
        response = client.post(
            f"/admin/agents/{agent_id}/promote",
            json={"approval_reference": "SEC-123"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    database.promote_agent_to_production.assert_not_called()


def test_generic_agent_patch_cannot_clear_sandbox():
    org_id = uuid4()
    agent_id = uuid4()
    database = _database(_agent_record(agent_id, org_id))

    app.dependency_overrides[get_db] = lambda: database
    app.dependency_overrides[verify_api_key] = lambda: {
        "org_id": org_id,
        "scopes": ["write"],
    }
    try:
        response = client.patch(
            f"/admin/agents/{agent_id}",
            json={"metadata": {"sandbox": False}},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    assert "promote" in response.json()["detail"].lower()
    database.promote_agent_to_production.assert_not_called()


def test_authenticated_registration_cannot_create_production_agent():
    org_id = uuid4()
    agent_id = uuid4()
    database = MagicMock()
    database.create_agent = AsyncMock(return_value=agent_id)

    app.dependency_overrides[get_db] = lambda: database
    app.dependency_overrides[verify_api_key] = lambda: {
        "org_id": org_id,
        "scopes": ["write"],
    }
    try:
        response = client.post(
            "/admin/agents",
            json={
                "org_id": str(org_id),
                "name": "Production bypass attempt",
                "public_key": base64.b64encode(b"k" * 32).decode("ascii"),
                "metadata": {
                    "sandbox": False,
                    "production_approval_reference": "spoofed",
                    "customer_label": "preserved",
                },
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201, response.text
    assert response.json()["sandbox"] is True
    metadata = database.create_agent.await_args.kwargs["metadata"]
    assert metadata == {"customer_label": "preserved", "sandbox": True}


def test_public_sandbox_agent_is_not_presented_as_verified():
    org_id = uuid4()
    agent_id = uuid4()
    database = _database(_agent_record(agent_id, org_id, sandbox=True))
    app.dependency_overrides[get_db] = lambda: database
    try:
        response = client.get(f"/public/agent/{agent_id}")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["sandbox"] is True
    assert body["production_approved"] is False
    assert body["is_verified"] is False
    assert body["organization_name"] == "Sandbox"
    assert body["verified_since"] is None


def test_public_promoted_agent_is_presented_as_verified():
    org_id = uuid4()
    agent_id = uuid4()
    database = _database(_agent_record(agent_id, org_id, sandbox=False))
    app.dependency_overrides[get_db] = lambda: database
    try:
        response = client.get(f"/public/agent/{agent_id}")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["sandbox"] is False
    assert body["production_approved"] is True
    assert body["is_verified"] is True
    assert body["organization_name"] == "Verified Organisation"
