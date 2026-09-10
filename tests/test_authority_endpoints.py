"""Phase 4 — the authority services and their HTTP surface.

Both HTTP surfaces call these services, so the assertions here are about
one evaluation path and one consumption path: the executor is
established from credentials, a grant id alone is not authority, and a
copied executor reference buys nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest

asyncpg = pytest.importorskip("asyncpg")

from api.core.authority.decision import Decision, DecisionReason  # noqa: E402
from api.core.authority.lifecycle import ConsumptionOutcome  # noqa: E402
from api.crypto import CryptoService  # noqa: E402
from api.database import Database  # noqa: E402
from api.services.authority_service import (  # noqa: E402
    AUTHORITY_REQUIRED_ORGS_ENV,
    AUTHORITY_TOKEN_VERSION,
    AuthorityConsumptionService,
    AuthorityEvaluationService,
    legacy_authority_gate,
)
from api.services.executor_context import (  # noqa: E402
    ExecutorAuthError,
    executor_binding_digest,
    executor_context_from_auth,
)

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="authority endpoint tests require INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)

SERVER_SECRET = b"phase-4-test-secret-not-a-production-value"


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=2, max_size=8)
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
async def org_and_agent(db: Database):
    org_id, agent_id = uuid4(), uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
            VALUES ($1, $2, 'enterprise', $3, $4)
            """,
            org_id,
            f"phase4-{org_id}",
            f"phase4-{org_id}@example.test",
            hashlib.sha256(str(org_id).encode()).digest(),
        )
        await conn.execute(
            """
            INSERT INTO agents (
                id, org_id, name, public_key, public_key_fingerprint,
                trust_score, status, daily_limit_usd, per_action_limit_usd,
                allowed_actions, blocked_actions, rate_limit_per_minute, metadata
            ) VALUES (
                $1, $2, $3, $4, $5, 80, 'active', 10000, 10000,
                ARRAY['financial_transaction']::TEXT[], ARRAY[]::TEXT[], 1000, $6::JSONB
            )
            """,
            agent_id,
            org_id,
            f"phase4-agent-{agent_id}",
            secrets.token_bytes(32),
            hashlib.sha256(str(agent_id).encode()).hexdigest(),
            json.dumps(
                {
                    "sandbox": False,
                    "production_approval_reference": "phase-4-test",
                    "production_approved_at": "2026-01-01T00:00:00Z",
                    "production_approved_by": "phase-4-fixture",
                }
            ),
        )
        agent = await db.get_agent_by_id(agent_id)
    yield org_id, agent


def executor(org_id, *, key_id=None, scopes=("write",), reference=None):
    return executor_context_from_auth(
        {
            "org_id": org_id,
            "api_key_id": key_id or f"key-{org_id}",
            "scopes": list(scopes),
        },
        executor_reference=reference,
    )


def payment_payload(amount="10.00", recipient="acct_123"):
    return {"amount": amount, "currency": "USD", "recipient": recipient}


class TestEvaluationService:
    async def test_allow_issues_a_grant_and_a_token(self, db, org_and_agent) -> None:
        org_id, agent = org_and_agent
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        result = await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="eval-1",
        )
        assert result.decision is Decision.ALLOW
        assert result.authorises_execution
        assert result.grant_id is not None
        assert result.authority_token is not None
        assert len(result.policy_snapshot_digest) == 64

    async def test_block_returns_a_typed_reason_and_no_grant(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        result = await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(amount="50000.00"),
            executor=executor(org_id),
            issuance_ref="eval-2",
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.PER_ACTION_LIMIT_EXCEEDED in result.reasons
        assert result.grant_id is None
        assert result.authority_token is None
        assert not result.authorises_execution

    async def test_a_caller_outside_the_organisation_is_refused(
        self, db, org_and_agent
    ) -> None:
        _org_id, agent = org_and_agent
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        result = await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(uuid4()),
            issuance_ref="eval-3",
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_PRINCIPAL_MISMATCH in result.reasons

    async def test_issuance_is_idempotent_on_the_same_reference(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        kwargs = {
            "agent": agent,
            "action_type": "financial_transaction",
            "payload": payment_payload(),
            "executor": executor(org_id),
            "issuance_ref": "eval-4",
        }
        first = await service.evaluate(**kwargs)
        second = await service.evaluate(**kwargs)
        assert second.grant_id == first.grant_id

    async def test_the_token_binds_grant_act_and_version(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        result = await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="eval-5",
        )
        claims = CryptoService.verify_approval_token(result.authority_token, SERVER_SECRET)
        assert claims["token_version"] == AUTHORITY_TOKEN_VERSION
        assert claims["grant_id"] == str(result.grant_id)
        assert claims["execution_action_hash"] == result.execution_action_hash

    async def test_a_token_signed_with_another_secret_is_refused(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        result = await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="eval-6",
        )
        foreign = AuthorityEvaluationService(db, server_secret=b"a-different-secret-entirely")
        assert foreign.read_authority_token(result.authority_token) is None


class TestConsumptionService:
    async def _granted(self, db, org_id, agent, ref, *, exec_ctx=None):
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        return await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=exec_ctx or executor(org_id),
            issuance_ref=ref,
        )

    async def test_the_exact_action_consumes(self, db, org_and_agent) -> None:
        org_id, agent = org_and_agent
        issued = await self._granted(db, org_id, agent, "c-1")
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        result = await consume.consume(
            authority_token=issued.authority_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-c1",
        )
        assert result.outcome is ConsumptionOutcome.AUTHORISED
        assert result.may_execute

    async def test_a_tampered_action_is_refused_and_does_not_burn(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        issued = await self._granted(db, org_id, agent, "c-2")
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        tampered = await consume.consume(
            authority_token=issued.authority_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(amount="9999.00"),
            execution_ref="exec-c2",
        )
        assert tampered.rejection_reason is DecisionReason.GRANT_ACTION_MISMATCH

        original = await consume.consume(
            authority_token=issued.authority_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-c2-ok",
        )
        assert original.outcome is ConsumptionOutcome.AUTHORISED

    async def test_a_different_executor_is_refused_and_does_not_burn(
        self, db, org_and_agent
    ) -> None:
        """Same organisation, different API key: a different binding."""
        org_id, agent = org_and_agent
        issued = await self._granted(
            db, org_id, agent, "c-3", exec_ctx=executor(org_id, key_id="key-A")
        )
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        wrong = await consume.consume(
            authority_token=issued.authority_token,
            executor=executor(org_id, key_id="key-B"),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-c3",
        )
        assert wrong.rejection_reason is DecisionReason.GRANT_EXECUTOR_MISMATCH

        right = await consume.consume(
            authority_token=issued.authority_token,
            executor=executor(org_id, key_id="key-A"),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-c3-ok",
        )
        assert right.outcome is ConsumptionOutcome.AUTHORISED

    async def test_a_copied_executor_reference_does_not_confer_identity(
        self, db, org_and_agent
    ) -> None:
        """The attack the reference/identity split exists to stop."""
        org_id, agent = org_and_agent
        issued = await self._granted(
            db,
            org_id,
            agent,
            "c-4",
            exec_ctx=executor(org_id, key_id="key-A", reference="settlement-worker-7"),
        )
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        impostor = await consume.consume(
            authority_token=issued.authority_token,
            # Same reference string, different credential.
            executor=executor(org_id, key_id="key-EVIL", reference="settlement-worker-7"),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-c4",
        )
        assert impostor.rejection_reason is DecisionReason.GRANT_EXECUTOR_MISMATCH

    async def test_a_bare_grant_id_is_not_authority(self, db, org_and_agent) -> None:
        """Possession of the identifier must not authorise anything."""
        org_id, agent = org_and_agent
        issued = await self._granted(db, org_id, agent, "c-5")
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        forged = await consume.consume(
            authority_token=str(issued.grant_id),
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-c5",
        )
        assert forged.outcome is ConsumptionOutcome.REJECTED
        assert forged.rejection_reason is DecisionReason.GRANT_NOT_FOUND

    async def test_a_self_minted_token_is_refused(self, db, org_and_agent) -> None:
        org_id, agent = org_and_agent
        issued = await self._granted(db, org_id, agent, "c-6")
        attacker_token = CryptoService.generate_approval_token(
            agent_id=str(agent.id),
            action_hash="a" * 64,
            verdict="approved",
            server_secret=b"attacker-secret",
            extra_claims={
                "token_version": AUTHORITY_TOKEN_VERSION,
                "grant_id": str(issued.grant_id),
                "execution_action_hash": issued.execution_action_hash,
            },
        )
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        result = await consume.consume(
            authority_token=attacker_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-c6",
        )
        assert result.rejection_reason is DecisionReason.GRANT_NOT_FOUND

    async def test_a_replay_with_a_different_reference_is_refused(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        issued = await self._granted(db, org_id, agent, "c-7")
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        await consume.consume(
            authority_token=issued.authority_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-c7",
        )
        replay = await consume.consume(
            authority_token=issued.authority_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-c7-different",
        )
        assert replay.outcome is ConsumptionOutcome.REJECTED
        assert replay.rejection_reason in (
            DecisionReason.GRANT_ALREADY_CONSUMED,
            DecisionReason.EXECUTION_REF_CONFLICT,
        )

    async def test_the_same_reference_recovers_the_original(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        issued = await self._granted(db, org_id, agent, "c-8")
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        first = await consume.consume(
            authority_token=issued.authority_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-c8",
        )
        again = await consume.consume(
            authority_token=issued.authority_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-c8",
        )
        assert again.outcome is ConsumptionOutcome.RECOVERED
        assert again.consumption_audit_id == first.consumption_audit_id
        assert not again.may_execute

    async def test_a_read_only_key_cannot_consume(self, db, org_and_agent) -> None:
        org_id, agent = org_and_agent
        issued = await self._granted(db, org_id, agent, "c-9")
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        with pytest.raises(ExecutorAuthError):
            await consume.consume(
                authority_token=issued.authority_token,
                executor=executor(org_id, scopes=("read",)),
                agent=agent,
                action_type="financial_transaction",
                payload=payment_payload(),
                execution_ref="exec-c9",
            )

    async def test_a_suspended_principal_cannot_consume(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        issued = await self._granted(db, org_id, agent, "c-10")
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET status = 'suspended' WHERE id = $1", agent.id
            )
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        result = await consume.consume(
            authority_token=issued.authority_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-c10",
        )
        assert result.rejection_reason is DecisionReason.AGENT_NOT_ACTIVE


class TestExecutorBinding:
    def test_the_binding_is_derived_only_from_trusted_identity(self) -> None:
        org = uuid4()
        assert executor_binding_digest(organisation_id=org, api_key_id="k1") != (
            executor_binding_digest(organisation_id=org, api_key_id="k2")
        )
        assert executor_binding_digest(organisation_id=org, api_key_id="k1") == (
            executor_binding_digest(organisation_id=org, api_key_id="k1")
        )

    def test_the_reference_does_not_participate_in_the_binding(self) -> None:
        org = uuid4()
        with_ref = executor_context_from_auth(
            {"org_id": org, "api_key_id": "k1", "scopes": ["write"]},
            executor_reference="anything-at-all",
        )
        without = executor_context_from_auth(
            {"org_id": org, "api_key_id": "k1", "scopes": ["write"]}
        )
        assert with_ref.binding_digest == without.binding_digest

    def test_an_unauthenticated_context_is_refused(self) -> None:
        with pytest.raises(ExecutorAuthError):
            executor_context_from_auth({"scopes": ["write"]})


class TestServerControlledAuthorityRequirement:
    def test_no_organisation_is_enrolled_by_default(self, monkeypatch) -> None:
        monkeypatch.delenv(AUTHORITY_REQUIRED_ORGS_ENV, raising=False)
        assert (
            legacy_authority_gate(
                organisation_id=uuid4(),
                principal_id=uuid4(),
                action_type="financial_transaction",
            )
            is None
        )

    def test_an_enrolled_organisation_blocks_the_legacy_route(
        self, monkeypatch
    ) -> None:
        """/verify has no field for authority, so it must fail closed."""
        org = uuid4()
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(org))
        assert (
            legacy_authority_gate(
                organisation_id=org,
                principal_id=uuid4(),
                action_type="financial_transaction",
            )
            is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING
        )

    def test_another_organisation_is_unaffected(self, monkeypatch) -> None:
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(uuid4()))
        assert (
            legacy_authority_gate(
                organisation_id=uuid4(),
                principal_id=uuid4(),
                action_type="financial_transaction",
            )
            is None
        )

    def test_verified_authority_satisfies_the_requirement(self, monkeypatch) -> None:
        org = uuid4()
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(org))
        assert (
            legacy_authority_gate(
                organisation_id=org,
                principal_id=uuid4(),
                action_type="financial_transaction",
                has_verified_authority=True,
            )
            is None
        )

    async def test_an_enrolled_organisation_gets_no_grant_without_authority(
        self, db, org_and_agent, monkeypatch
    ) -> None:
        org_id, agent = org_and_agent
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(org_id))
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        result = await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="req-1",
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING in result.reasons
        assert result.authority_token is None


class TestFailuresFailClosed:
    async def test_a_broken_database_yields_no_authority(
        self, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        broken = await Database.create(DATABASE_URL, min_size=1, max_size=2)
        await broken.close()
        service = AuthorityEvaluationService(broken, server_secret=SERVER_SECRET)
        with pytest.raises((asyncpg.PostgresError, asyncpg.InterfaceError, RuntimeError)):
            await service.evaluate(
                agent=agent,
                action_type="financial_transaction",
                payload=payment_payload(),
                executor=executor(org_id),
                issuance_ref="fail-1",
            )

    async def test_an_ungoverned_action_type_is_blocked(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        result = await service.evaluate(
            agent=agent,
            action_type="api_call",
            payload={"operation": "read"},
            executor=executor(org_id),
            issuance_ref="fail-2",
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.ACTION_TYPE_UNKNOWN in result.reasons
        assert result.authority_token is None
