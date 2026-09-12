"""The principal binding is server-owned; no caller may write it.

``agents.metadata["authority_principal_binding"]`` names the delegate keys
and the audience a principal's delegated authority is bound to.
``api/services/authority_service.py`` reads it as trusted, and the
Verifiable Intent provider prefers a binding carried on the execution
context over its own injected resolver -- so whoever can write it decides
which delegate key may act for that principal, and whether a revoked key
stays revoked.

Before this remediation every caller-controlled metadata ingress accepted
it: neither ``AGENT_LIFECYCLE_METADATA_KEYS`` nor
``PUBLIC_REGISTRATION_METADATA_BLOCKLIST`` listed it, so an ordinary
org-scoped ``write`` key could bind its own delegate key to itself or empty
``revoked_agent_key_thumbprints``.

These tests pin every ingress shut. They are written against the shared
boundary constants rather than one route each, because the failure mode
being prevented is a NEW ingress picking up half the rules.

Storage, shape, reader and provider precedence are all deliberately
unchanged: after this fix the context value is itself server-owned.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from api.connectors.mastercard_vi.binding import binding_from_principal_binding
from api.legacy_main import (
    AGENT_LIFECYCLE_METADATA_KEYS,
    CALLER_BLOCKED_AGENT_METADATA_KEYS,
    PUBLIC_REGISTRATION_METADATA_BLOCKLIST,
    SERVER_OWNED_AGENT_METADATA_KEYS,
    _public_registration_metadata,
)
from api.main import app, get_db, verify_api_key
from api.models import AgentRecord, AgentStatus
from api.services.authority_service import (
    PRINCIPAL_BINDING_METADATA_KEY,
    _principal_binding_for,
)
from api.tenant_boundary import get_admin_tenant_database

client = TestClient(app)

#: What a trusted operator provisions out of band.
TRUSTED_BINDING = {
    "mastercard_vi": {
        "expected_audience": "urn:inntris:operator-provisioned",
        "agent_key_thumbprints": ["TRUSTED-DELEGATE-KEY"],
        "revoked_agent_key_thumbprints": ["RETIRED-DELEGATE-KEY"],
    }
}

#: What an attacker would rather it said.
ATTACKER_BINDING = {
    "mastercard_vi": {
        "expected_audience": "urn:attacker-chosen",
        "agent_key_thumbprints": ["ATTACKER-DELEGATE-KEY"],
        # Emptying this cancels a revocation.
        "revoked_agent_key_thumbprints": [],
    }
}


def _agent_record(**overrides) -> AgentRecord:
    now = datetime.now(UTC)
    data = {
        "id": uuid4(),
        "org_id": uuid4(),
        "name": "Binding Agent",
        "public_key": b"x" * 32,
        "public_key_fingerprint": "ab:cd",
        "trust_score": 80,
        "status": AgentStatus.ACTIVE,
        "daily_limit_usd": Decimal("1000"),
        "per_action_limit_usd": Decimal("100"),
        "allowed_actions": ["financial_transaction"],
        "blocked_actions": [],
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


def _patch_agent(agent: AgentRecord, body: dict):
    """Drive the real PATCH route as an ordinary org-scoped 'write' key."""
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(
        return_value={
            "id": agent.id,
            "org_id": agent.org_id,
            "name": agent.name,
            "public_key_fingerprint": agent.public_key_fingerprint,
            "trust_score": agent.trust_score,
            "status": "active",
            "daily_limit_usd": agent.daily_limit_usd,
            "per_action_limit_usd": agent.per_action_limit_usd,
            "allowed_actions": agent.allowed_actions,
            "blocked_actions": agent.blocked_actions,
            "rate_limit_per_minute": agent.rate_limit_per_minute,
            "last_action_at": None,
            "total_actions_count": 0,
            "total_blocked_count": 0,
            "metadata": agent.metadata,
            "created_at": agent.created_at,
            "updated_at": agent.updated_at,
        }
    )
    acm = MagicMock()
    acm.__aenter__ = AsyncMock(return_value=conn)
    acm.__aexit__ = AsyncMock(return_value=False)
    db_mock = MagicMock()
    db_mock.acquire = MagicMock(return_value=acm)
    db_mock.get_agent_by_id = AsyncMock(return_value=agent)

    app.dependency_overrides[get_db] = lambda: db_mock
    app.dependency_overrides[get_admin_tenant_database] = lambda: db_mock
    app.dependency_overrides[verify_api_key] = lambda: {
        "org_id": agent.org_id,
        "scopes": ["write"],
    }
    try:
        return client.patch(f"/admin/agents/{agent.id}", json=body), conn
    finally:
        app.dependency_overrides.clear()


class TestTheBoundaryItself:
    """The shared sets, so a new ingress inherits the whole rule."""

    def test_the_binding_key_is_declared_server_owned(self) -> None:
        assert PRINCIPAL_BINDING_METADATA_KEY in SERVER_OWNED_AGENT_METADATA_KEYS

    def test_every_caller_blocked_set_contains_it(self) -> None:
        assert PRINCIPAL_BINDING_METADATA_KEY in CALLER_BLOCKED_AGENT_METADATA_KEYS
        assert PRINCIPAL_BINDING_METADATA_KEY in PUBLIC_REGISTRATION_METADATA_BLOCKLIST

    def test_lifecycle_protection_is_not_weakened_by_the_addition(self) -> None:
        assert AGENT_LIFECYCLE_METADATA_KEYS <= CALLER_BLOCKED_AGENT_METADATA_KEYS
        for key in AGENT_LIFECYCLE_METADATA_KEYS:
            assert key in PUBLIC_REGISTRATION_METADATA_BLOCKLIST


class TestRegistrationIngress:
    """1-2: neither registration path may carry a binding in."""

    def test_1_public_registration_cannot_set_the_binding(self) -> None:
        surviving = _public_registration_metadata(
            {PRINCIPAL_BINDING_METADATA_KEY: ATTACKER_BINDING, "source": "partner"}
        )
        assert PRINCIPAL_BINDING_METADATA_KEY not in surviving

    def test_2_org_scoped_registration_cannot_set_the_binding(self) -> None:
        # The filter the admin registration route applies, verbatim.
        submitted = {PRINCIPAL_BINDING_METADATA_KEY: ATTACKER_BINDING, "source": "tenant"}
        surviving = {
            key: value
            for key, value in submitted.items()
            if key not in CALLER_BLOCKED_AGENT_METADATA_KEYS
        }
        assert PRINCIPAL_BINDING_METADATA_KEY not in surviving

    def test_6a_unrelated_registration_metadata_is_still_accepted(self) -> None:
        submitted = {"source": "partner", "team": "risk", "cost_centre": "42"}
        assert _public_registration_metadata(submitted) == submitted
        assert {
            k: v for k, v in submitted.items() if k not in CALLER_BLOCKED_AGENT_METADATA_KEYS
        } == submitted


class TestPatchIngress:
    """3-6, 9-11: the generic metadata surface refuses, and says so."""

    def test_3_patch_cannot_set_the_binding(self) -> None:
        agent = _agent_record()
        response, conn = _patch_agent(
            agent, {"metadata": {PRINCIPAL_BINDING_METADATA_KEY: ATTACKER_BINDING}}
        )
        assert response.status_code == 400, response.text
        assert PRINCIPAL_BINDING_METADATA_KEY in response.text
        # Refused before any write, not filtered after one.
        conn.fetchrow.assert_not_awaited()

    def test_4_patch_cannot_replace_an_existing_trusted_binding(self) -> None:
        agent = _agent_record(
            metadata={PRINCIPAL_BINDING_METADATA_KEY: TRUSTED_BINDING}
        )
        response, conn = _patch_agent(
            agent, {"metadata": {PRINCIPAL_BINDING_METADATA_KEY: ATTACKER_BINDING}}
        )
        assert response.status_code == 400
        conn.fetchrow.assert_not_awaited()
        # The trusted value is what the authority path still reads.
        assert _principal_binding_for(agent) == TRUSTED_BINDING

    def test_5_patch_cannot_delete_an_existing_trusted_binding(self) -> None:
        agent = _agent_record(
            metadata={PRINCIPAL_BINDING_METADATA_KEY: TRUSTED_BINDING}
        )
        # Explicit emptying is refused...
        response, conn = _patch_agent(
            agent, {"metadata": {PRINCIPAL_BINDING_METADATA_KEY: {}}}
        )
        assert response.status_code == 400
        conn.fetchrow.assert_not_awaited()

        # ...and omission cannot delete it either, because the route
        # shallow-merges rather than replacing the metadata document.
        ok, _conn = _patch_agent(agent, {"metadata": {"source": "tenant"}})
        assert ok.status_code == 200, ok.text
        assert _principal_binding_for(agent) == TRUSTED_BINDING

    def test_6b_unrelated_patch_metadata_is_still_writable(self) -> None:
        agent = _agent_record()
        response, conn = _patch_agent(
            agent, {"metadata": {"source": "tenant", "team": "risk"}}
        )
        assert response.status_code == 200, response.text
        conn.fetchrow.assert_awaited()

    @pytest.mark.parametrize(
        ("case", "payload"),
        [
            ("9_expected_audience", {"mastercard_vi": {"expected_audience": "urn:evil"}}),
            (
                "10_agent_key_thumbprints",
                {"mastercard_vi": {"agent_key_thumbprints": ["ATTACKER-DELEGATE-KEY"]}},
            ),
            (
                "11_clear_revocations",
                {"mastercard_vi": {"revoked_agent_key_thumbprints": []}},
            ),
        ],
    )
    def test_9_to_11_no_field_of_the_binding_is_caller_writable(
        self, case: str, payload: dict
    ) -> None:
        agent = _agent_record(
            metadata={PRINCIPAL_BINDING_METADATA_KEY: TRUSTED_BINDING}
        )
        response, conn = _patch_agent(
            agent, {"metadata": {PRINCIPAL_BINDING_METADATA_KEY: payload}}
        )
        assert response.status_code == 400, f"{case}: {response.text}"
        conn.fetchrow.assert_not_awaited()
        assert _principal_binding_for(agent) == TRUSTED_BINDING


class TestTrustedProvisioningIsUnaffected:
    """7-8: blocking callers must not block the operator, or the provider."""

    def test_7_out_of_band_provisioning_still_reaches_the_reader(self) -> None:
        # An operator writes the agent record directly -- the route filters
        # are the boundary, not the storage.
        agent = _agent_record(
            metadata={"source": "tenant", PRINCIPAL_BINDING_METADATA_KEY: TRUSTED_BINDING}
        )
        assert _principal_binding_for(agent) == TRUSTED_BINDING

    def test_8_the_phase5_provider_still_reads_a_provisioned_binding(self) -> None:
        agent = _agent_record(
            metadata={PRINCIPAL_BINDING_METADATA_KEY: TRUSTED_BINDING}
        )
        binding = binding_from_principal_binding(
            _principal_binding_for(agent),
            organisation_id=str(agent.org_id),
            principal_id=str(agent.id),
        )
        assert binding is not None
        assert binding.expected_audience == "urn:inntris:operator-provisioned"
        assert "TRUSTED-DELEGATE-KEY" in binding.agent_key_thumbprints
        # The revocation the attacker wanted cleared is still in force.
        assert "RETIRED-DELEGATE-KEY" in binding.revoked_agent_key_thumbprints
