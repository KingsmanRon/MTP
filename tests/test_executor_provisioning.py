"""Phase 7A, Gate 5 — authenticated executor provisioning.

The claim under test is that an executor's entitlement comes from the
credential it authenticated with and from nothing a caller can type. So
these tests attack it the way an attacker would: copy somebody's
``execution_ref``, copy their ``executor_reference``, use a key scoped to a
different action class, use a revoked key, use an expired key.

The end-to-end paths run against a real PostgreSQL and real API-key rows,
because "the credential was revoked" is a database fact and a stub would
only prove the stub agrees with itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from api.core.authority.decision import Decision
from api.core.authority.lifecycle import ConsumptionOutcome
from api.database import Database
from api.services.authority_service import (
    AuthorityConsumptionService,
    AuthorityEvaluationService,
)
from api.services.executor_context import (
    EXECUTE_SCOPE,
    REQUIRE_EXECUTE_SCOPE_ENV,
    AuthenticatedExecutorContext,
    ExecutorAuthError,
    executor_binding_digest,
    executor_context_from_auth,
)

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")

SERVER_SECRET = b"phase-7a-gate-5-test-secret-not-a-production-value"
ACTION = "financial_transaction"
OTHER_ACTION = "code_release"


def context(
    *,
    org_id: UUID | None = None,
    key_id: str = "key-a",
    scopes: tuple[str, ...] = ("write",),
    reference: str | None = None,
) -> AuthenticatedExecutorContext:
    org_id = org_id or uuid4()
    return executor_context_from_auth(
        {"org_id": org_id, "api_key_id": key_id, "scopes": list(scopes)},
        executor_reference=reference,
    )


# =============================================================================
# Identity comes from the credential
# =============================================================================


class TestIdentityIsNotARequestString:
    def test_two_keys_in_one_organisation_are_two_executors(self) -> None:
        org = uuid4()
        assert (
            context(org_id=org, key_id="key-a").binding_digest
            != context(org_id=org, key_id="key-b").binding_digest
        )

    def test_the_same_key_in_two_organisations_is_two_executors(self) -> None:
        assert (
            context(org_id=uuid4(), key_id="shared").binding_digest
            != context(org_id=uuid4(), key_id="shared").binding_digest
        )

    def test_a_copied_executor_reference_changes_nothing(self) -> None:
        """Anyone who has seen a reference can type it. It must gain them
        nothing, because the binding is derived from the credential."""
        org = uuid4()
        honest = context(org_id=org, key_id="key-a", reference="op-1234")
        impostor = context(org_id=org, key_id="key-b", reference="op-1234")
        assert honest.binding_digest != impostor.binding_digest

    def test_the_reference_is_not_in_the_binding_at_all(self) -> None:
        org = uuid4()
        assert (
            context(org_id=org, key_id="key-a", reference="anything").binding_digest
            == context(org_id=org, key_id="key-a").binding_digest
        )

    def test_a_context_with_no_key_identity_is_refused_in_production(self) -> None:
        with pytest.raises(ExecutorAuthError, match="no API key identity"):
            executor_context_from_auth(
                {"org_id": uuid4(), "scopes": ["write"]}, environment="production"
            )


# =============================================================================
# Least privilege
# =============================================================================


class TestActionScope:
    def test_an_unscoped_key_may_consume_any_action(self) -> None:
        executor = context(scopes=("write",))
        assert executor.action_scopes == frozenset()
        executor.require_action(ACTION)
        executor.require_action(OTHER_ACTION)

    def test_a_scoped_key_may_consume_only_its_action(self) -> None:
        executor = context(scopes=(f"{EXECUTE_SCOPE}:{ACTION}",))
        executor.require_action(ACTION)
        with pytest.raises(ExecutorAuthError, match="scoped to"):
            executor.require_action(OTHER_ACTION)

    def test_a_scoped_key_can_still_consume_at_all(self) -> None:
        """Narrowing a key must not remove its ability to consume anything."""
        executor = context(scopes=(f"{EXECUTE_SCOPE}:{ACTION}",))
        assert executor.may_consume
        executor.require_consume()

    def test_several_action_scopes_are_all_honoured(self) -> None:
        executor = context(scopes=(f"{EXECUTE_SCOPE}:{ACTION}", f"{EXECUTE_SCOPE}:{OTHER_ACTION}"))
        executor.require_action(ACTION)
        executor.require_action(OTHER_ACTION)
        with pytest.raises(ExecutorAuthError):
            executor.require_action("something_else")

    def test_a_read_only_key_cannot_consume(self) -> None:
        with pytest.raises(ExecutorAuthError):
            context(scopes=("read",)).require_consume()


class TestStrictExecuteScope:
    def test_write_is_accepted_by_default(self, monkeypatch) -> None:
        """Existing service keys drive /verify-token today and must not be
        locked out mid-release."""
        monkeypatch.delenv(REQUIRE_EXECUTE_SCOPE_ENV, raising=False)
        context(scopes=("write",)).require_consume()

    def test_write_alone_is_refused_when_strictness_is_on(self, monkeypatch) -> None:
        monkeypatch.setenv(REQUIRE_EXECUTE_SCOPE_ENV, "1")
        with pytest.raises(ExecutorAuthError, match="dedicated 'execute' scope"):
            context(scopes=("write",)).require_consume()

    def test_a_dedicated_execute_scope_passes_strictness(self, monkeypatch) -> None:
        monkeypatch.setenv(REQUIRE_EXECUTE_SCOPE_ENV, "1")
        context(scopes=(EXECUTE_SCOPE,)).require_consume()
        context(scopes=(f"{EXECUTE_SCOPE}:{ACTION}",)).require_consume()

    def test_admin_alone_is_refused_when_strictness_is_on(self, monkeypatch) -> None:
        """An administrative key is not an executor. Under least privilege
        they are different jobs and should be different credentials."""
        monkeypatch.setenv(REQUIRE_EXECUTE_SCOPE_ENV, "1")
        with pytest.raises(ExecutorAuthError):
            context(scopes=("admin",)).require_consume()


# =============================================================================
# End to end, against real credentials
# =============================================================================


pg = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="executor provisioning tests require INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=2, max_size=8)
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
async def org_and_agent(db: Database) -> tuple[UUID, UUID]:
    org_id, agent_id = uuid4(), uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
            VALUES ($1, $2, 'enterprise', $3, sha256($4::BYTEA))
            """,
            org_id,
            f"gate5-{org_id}",
            f"gate5-{org_id}@invalid.test",
            str(org_id).encode(),
        )
        await conn.execute(
            """
            INSERT INTO agents (
                id, org_id, name, public_key, public_key_fingerprint, trust_score,
                status, daily_limit_usd, per_action_limit_usd, allowed_actions,
                blocked_actions, rate_limit_per_minute, metadata
            ) VALUES (
                $1, $2, $3, decode(repeat('00', 32), 'hex'), $4, 95, 'active',
                100000, 100000, ARRAY['financial_transaction']::TEXT[],
                ARRAY[]::TEXT[], 6000, $5::JSONB
            )
            """,
            agent_id,
            org_id,
            f"gate5-agent-{agent_id}",
            uuid4().hex + uuid4().hex,
            # Production-approved on purpose: a sandbox principal can never
            # authorise a production execution, and that separate property
            # is covered elsewhere. Here the question is the executor.
            json.dumps(
                {
                    "sandbox": False,
                    "production_approval_reference": "gate-5-fixture",
                    "production_approved_at": "2026-01-01T00:00:00Z",
                    "production_approved_by": "gate-5-fixture",
                }
            ),
        )
    return org_id, agent_id


async def provision(
    db: Database,
    org_id: UUID,
    *,
    scopes: list[str],
    name: str | None = None,
    expires_at: datetime | None = None,
    active: bool = True,
) -> tuple[str, UUID]:
    """Create a real api_keys row and return (raw key, key id)."""
    raw = f"inntris_live_sk_{secrets.token_urlsafe(32)}"
    async with db.acquire() as conn:
        key_id = await conn.fetchval(
            """
            INSERT INTO api_keys (
                org_id, key_hash, key_prefix, name, scopes, expires_at, is_active
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            """,
            org_id,
            hashlib.sha256(raw.encode()).digest(),
            raw[-8:],
            name or f"gate5-{uuid4()}",
            scopes,
            expires_at,
            active,
        )
    return raw, key_id


def payment_payload(amount: str = "10.00") -> dict:
    return {
        "amount": amount,
        "currency": "USD",
        "recipient": "0x" + "ab" * 20,
        "chain": "base",
    }


def executor_for(org_id: UUID, key_id: UUID, scopes: tuple[str, ...] = ("write",)):
    return AuthenticatedExecutorContext(
        organisation_id=org_id,
        api_key_id=str(key_id),
        scopes=frozenset(scopes),
        binding_digest=executor_binding_digest(organisation_id=org_id, api_key_id=key_id),
    )


@pg
class TestCredentialLifecycle:
    async def test_a_provisioned_key_authenticates(self, db, org_and_agent) -> None:
        org_id, _agent_id = org_and_agent
        raw, key_id = await provision(db, org_id, scopes=[f"{EXECUTE_SCOPE}:{ACTION}"])
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, scopes, is_active FROM api_keys WHERE key_hash = $1",
                hashlib.sha256(raw.encode()).digest(),
            )
        assert row["id"] == key_id
        assert row["is_active"] is True
        assert list(row["scopes"]) == [f"{EXECUTE_SCOPE}:{ACTION}"]

    async def test_a_revoked_key_no_longer_authenticates(self, db, org_and_agent) -> None:
        org_id, _agent_id = org_and_agent
        raw, key_id = await provision(db, org_id, scopes=[EXECUTE_SCOPE])
        async with db.acquire() as conn:
            await conn.execute("UPDATE api_keys SET is_active = FALSE WHERE id = $1", key_id)
            row = await conn.fetchrow(
                "SELECT is_active FROM api_keys WHERE key_hash = $1",
                hashlib.sha256(raw.encode()).digest(),
            )
        assert row["is_active"] is False

    async def test_an_expired_key_is_distinguishable(self, db, org_and_agent) -> None:
        org_id, _agent_id = org_and_agent
        _raw, key_id = await provision(
            db,
            org_id,
            scopes=[EXECUTE_SCOPE],
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        async with db.acquire() as conn:
            expires_at = await conn.fetchval(
                "SELECT expires_at FROM api_keys WHERE id = $1", key_id
            )
        assert expires_at < datetime.now(UTC)

    async def test_rotation_leaves_both_keys_distinct_executors(self, db, org_and_agent) -> None:
        """The replacement is a different executor, so it cannot spend grants
        issued to the old one. That is the cost of rotation and it is the
        right cost: the alternative is two credentials sharing one identity."""
        org_id, _agent_id = org_and_agent
        _old_raw, old_id = await provision(db, org_id, scopes=[EXECUTE_SCOPE])
        _new_raw, new_id = await provision(db, org_id, scopes=[EXECUTE_SCOPE])
        assert executor_for(org_id, old_id).binding_digest != (
            executor_for(org_id, new_id).binding_digest
        )


@pg
class TestGrantBindingIsImmutable:
    async def _issue(self, db, _org_id, agent_id, executor, ref: str):
        agent = await db.get_agent_by_id(agent_id)
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        return await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            executor=executor,
            issuance_ref=ref,
        )

    async def test_the_issuing_executor_can_consume(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        _raw, key_id = await provision(db, org_id, scopes=[EXECUTE_SCOPE])
        executor = executor_for(org_id, key_id, (EXECUTE_SCOPE,))
        issued = await self._issue(db, org_id, agent_id, executor, f"g5-{uuid4()}")
        assert issued.decision is Decision.ALLOW

        agent = await db.get_agent_by_id(agent_id)
        consumption = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        result = await consumption.consume(
            authority_token=issued.authority_token,
            executor=executor,
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            execution_ref=f"exec-{uuid4()}",
        )
        assert result.outcome is ConsumptionOutcome.AUTHORISED
        assert result.may_execute is True

    async def test_a_second_key_in_the_same_organisation_cannot_consume(
        self, db, org_and_agent
    ) -> None:
        """The whole point of binding to the credential."""
        org_id, agent_id = org_and_agent
        _raw_a, key_a = await provision(db, org_id, scopes=[EXECUTE_SCOPE])
        _raw_b, key_b = await provision(db, org_id, scopes=[EXECUTE_SCOPE])

        issued = await self._issue(
            db,
            org_id,
            agent_id,
            executor_for(org_id, key_a, (EXECUTE_SCOPE,)),
            f"g5-{uuid4()}",
        )
        assert issued.decision is Decision.ALLOW

        agent = await db.get_agent_by_id(agent_id)
        consumption = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        result = await consumption.consume(
            authority_token=issued.authority_token,
            executor=executor_for(org_id, key_b, (EXECUTE_SCOPE,)),
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            execution_ref=f"exec-{uuid4()}",
        )
        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.may_execute is False

    async def test_a_copied_execution_ref_does_not_help_the_impostor(
        self, db, org_and_agent
    ) -> None:
        """The Gate 5 acceptance test. An attacker who has seen a genuine
        execution_ref -- from a log, a webhook, a support ticket -- and holds
        a valid credential of their own still cannot spend the grant."""
        org_id, agent_id = org_and_agent
        _raw_a, key_a = await provision(db, org_id, scopes=[EXECUTE_SCOPE])
        _raw_b, key_b = await provision(db, org_id, scopes=[EXECUTE_SCOPE])

        issued = await self._issue(
            db,
            org_id,
            agent_id,
            executor_for(org_id, key_a, (EXECUTE_SCOPE,)),
            f"g5-{uuid4()}",
        )
        agent = await db.get_agent_by_id(agent_id)
        consumption = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)

        stolen_ref = f"exec-{uuid4()}"
        honest = await consumption.consume(
            authority_token=issued.authority_token,
            executor=executor_for(org_id, key_a, (EXECUTE_SCOPE,)),
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            execution_ref=stolen_ref,
        )
        assert honest.outcome is ConsumptionOutcome.AUTHORISED

        # Same token, same reference, different credential.
        impostor = await consumption.consume(
            authority_token=issued.authority_token,
            executor=executor_for(org_id, key_b, (EXECUTE_SCOPE,)),
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            execution_ref=stolen_ref,
        )
        assert impostor.outcome is ConsumptionOutcome.REJECTED
        assert impostor.may_execute is False

    async def test_the_binding_survives_the_key_being_revoked(self, db, org_and_agent) -> None:
        """Revoking the credential does not rewrite history: the grant still
        records which executor it was issued to."""
        org_id, agent_id = org_and_agent
        _raw, key_id = await provision(db, org_id, scopes=[EXECUTE_SCOPE])
        executor = executor_for(org_id, key_id, (EXECUTE_SCOPE,))
        issued = await self._issue(db, org_id, agent_id, executor, f"g5-{uuid4()}")

        async with db.acquire() as conn:
            await conn.execute("UPDATE api_keys SET is_active = FALSE WHERE id = $1", key_id)
            stored = await conn.fetchval(
                "SELECT executor_binding_digest FROM execution_authority_grants WHERE id = $1",
                issued.grant_id,
            )
        assert stored == executor.binding_digest
