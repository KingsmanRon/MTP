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
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

asyncpg = pytest.importorskip("asyncpg")

from api.core.authority.authority import DelegatedAuthorityClaim  # noqa: E402
from api.core.authority.decision import Decision, DecisionReason  # noqa: E402
from api.core.authority.lifecycle import ConsumptionOutcome  # noqa: E402
from api.crypto import CryptoService  # noqa: E402
from api.database import Database  # noqa: E402
from api.persistence.authority_store import AuthorityStore, OutcomeState  # noqa: E402
from api.receipts.evidence_builder import (  # noqa: E402
    build_decision_evidence,
    build_evidence_chain,
    consumption_event_id,
    decision_event_id,
    outcome_event_id,
)
from api.receipts.v3 import (  # noqa: E402
    EVIDENCE_SIGNING_KEY_ENV,
    EvidenceError,
    load_evidence_signing_key,
    verify_evidence_event,
)
from api.services.authority_service import (  # noqa: E402
    AUTHORITY_REQUIRED_ORGS_ENV,
    AUTHORITY_TOKEN_VERSION,
    AuthorityConsumptionService,
    AuthorityEvaluationService,
    legacy_authority_gate,
)
from api.services.core_evaluation import CorePolicyInputs, evaluate_core_policy  # noqa: E402
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

    async def test_an_action_the_agent_may_not_take_is_blocked_by_core(
        self, db, org_and_agent
    ) -> None:
        """Core runs first, so its allowed-actions rule is what fires here."""
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
        assert DecisionReason.ACTION_NOT_ALLOWED in result.reasons
        assert result.authority_token is None

    async def test_an_ungoverned_action_type_is_blocked_after_core_passes(
        self, db, org_and_agent
    ) -> None:
        """The domain gate still fires for an action Core is happy with.

        ``api_call`` is a registered Core action type, so once the agent is
        permitted to take it Core allows it — and no domain policy governs
        it, which is its own refusal rather than a silent allow.
        """
        org_id, agent = org_and_agent
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET allowed_actions = $2::TEXT[] WHERE id = $1",
                agent.id,
                ["financial_transaction", "api_call"],
            )
        permitted = await db.get_agent_by_id(agent.id)

        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        result = await service.evaluate(
            agent=permitted,
            action_type="api_call",
            payload={"operation": "read"},
            executor=executor(org_id),
            issuance_ref="fail-2b",
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.ACTION_TYPE_UNKNOWN in result.reasons
        assert result.authority_token is None
        assert result.grant_id is None


class TestCorePolicyCannotBeBypassed:
    """The new endpoint must never be the weaker path to the same act.

    PaymentDomainPolicy knows about money and delegated scope. It does
    not know about agent status, allowed/blocked actions, action-type
    registration, trust thresholds, timestamp skew or rate limits. Those
    live in the Core engine, and both surfaces run it.
    """

    async def _evaluate(self, db, org_id, agent, ref, **kwargs):
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        return await service.evaluate(
            agent=agent,
            action_type=kwargs.pop("action_type", "financial_transaction"),
            payload=kwargs.pop("payload", payment_payload()),
            executor=executor(org_id),
            issuance_ref=ref,
            **kwargs,
        )

    async def test_a_suspended_principal_gets_no_authority(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET status = 'suspended' WHERE id = $1", agent.id
            )
        refreshed = await db.get_agent_by_id(agent.id)
        result = await self._evaluate(db, org_id, refreshed, "core-1")
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AGENT_NOT_ACTIVE in result.reasons
        assert result.authority_token is None

    async def test_an_explicitly_blocked_action_gets_no_authority(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET blocked_actions = ARRAY['financial_transaction']::TEXT[] WHERE id = $1",
                agent.id,
            )
        refreshed = await db.get_agent_by_id(agent.id)
        result = await self._evaluate(db, org_id, refreshed, "core-2")
        assert result.decision is Decision.BLOCK
        assert DecisionReason.ACTION_BLOCKED in result.reasons
        assert result.authority_token is None

    async def test_an_action_absent_from_allowed_actions_gets_no_authority(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET allowed_actions = ARRAY['email_send']::TEXT[] WHERE id = $1",
                agent.id,
            )
        refreshed = await db.get_agent_by_id(agent.id)
        result = await self._evaluate(db, org_id, refreshed, "core-3")
        assert result.decision is Decision.BLOCK
        assert DecisionReason.ACTION_NOT_ALLOWED in result.reasons
        assert result.authority_token is None

    async def test_an_insufficient_trust_score_gets_no_authority(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        async with db.acquire() as conn:
            await conn.execute("UPDATE agents SET trust_score = 5 WHERE id = $1", agent.id)
        refreshed = await db.get_agent_by_id(agent.id)
        result = await self._evaluate(db, org_id, refreshed, "core-4")
        assert result.decision is Decision.BLOCK
        assert DecisionReason.TRUST_SCORE_TOO_LOW in result.reasons
        assert result.authority_token is None

    async def test_an_unregistered_action_type_gets_no_authority(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET allowed_actions = ARRAY['financial_transactions']::TEXT[] WHERE id = $1",
                agent.id,
            )
        refreshed = await db.get_agent_by_id(agent.id)
        result = await self._evaluate(
            db, org_id, refreshed, "core-5", action_type="financial_transactions"
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.ACTION_TYPE_UNKNOWN in result.reasons
        assert result.authority_token is None

    async def test_a_stale_timestamp_gets_no_authority(self, db, org_and_agent) -> None:
        org_id, agent = org_and_agent
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        result = await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="core-6",
            at=datetime.now(UTC) + timedelta(hours=2),
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.TIMESTAMP_INVALID in result.reasons
        assert result.authority_token is None

    async def test_an_exceeded_rate_limit_gets_no_authority(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        result = await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="core-7",
            minute_request_count=agent.rate_limit_per_minute + 1,
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.RATE_LIMIT_EXCEEDED in result.reasons
        assert result.authority_token is None

    async def test_a_malformed_amount_gets_no_authority(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        result = await self._evaluate(
            db, org_id, agent, "core-8", payload={"amount": "NaN", "currency": "USD"}
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AMOUNT_INVALID in result.reasons


class TestVerifyAndAuthorityReachTheSameDecision:
    """Parity: the same canonical act, the same policy answer."""

    def _core(self, agent, action_type, payload, **kw):
        return evaluate_core_policy(
            CorePolicyInputs(
                agent=agent,
                action_type=action_type,
                payload=payload,
                timestamp=datetime.now(UTC),
                **kw,
            )
        )

    @pytest.mark.parametrize(
        ("payload", "expect_allowed"),
        [
            ({"amount": "10.00", "currency": "USD", "recipient": "acct_1"}, True),
            ({"amount": "50000.00", "currency": "USD", "recipient": "acct_1"}, False),
            ({"amount": "NaN", "currency": "USD", "recipient": "acct_1"}, False),
        ],
    )
    async def test_the_same_act_gets_the_same_verdict_on_both_surfaces(
        self, db, org_and_agent, payload, expect_allowed
    ) -> None:
        org_id, agent = org_and_agent
        legacy = self._core(agent, "financial_transaction", payload)
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        authority = await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payload,
            executor=executor(org_id),
            issuance_ref=f"parity-{payload['amount']}",
        )
        assert legacy.allowed is expect_allowed
        assert (authority.decision is Decision.ALLOW) is expect_allowed

    async def test_a_core_violation_surfaces_with_the_identical_code(
        self, db, org_and_agent
    ) -> None:
        """The vocabularies are the same strings, so this is a lookup."""
        org_id, agent = org_and_agent
        payload = {"amount": "50000.00", "currency": "USD", "recipient": "acct_1"}
        legacy = self._core(agent, "financial_transaction", payload)
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        authority = await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payload,
            executor=executor(org_id),
            issuance_ref="parity-code",
        )
        assert legacy.violation.value in [r.value for r in authority.reasons]


class TestRealApiKeyExecutorBinding:
    """Two real api_keys rows in one organisation are two executors."""

    async def _make_key(self, db, org_id, scopes=("write",)):
        raw = f"inntris_live_sk_{secrets.token_urlsafe(24)}"
        key_hash = hashlib.sha256(raw.encode()).digest()
        async with db.acquire() as conn:
            key_id = await conn.fetchval(
                """
                INSERT INTO api_keys (
                    org_id, key_hash, key_prefix, name, scopes, is_active
                )
                VALUES ($1, $2, $3, $4, $5::TEXT[], TRUE)
                RETURNING id
                """,
                org_id,
                key_hash,
                raw[:8],
                f"key-{secrets.token_hex(4)}",
                list(scopes),
            )
        return str(key_id), raw

    async def test_two_production_keys_bind_to_different_executors(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        key_a, _ = await self._make_key(db, org_id)
        key_b, _ = await self._make_key(db, org_id)
        assert key_a != key_b

        ctx_a = executor_context_from_auth(
            {"org_id": org_id, "api_key_id": key_a, "scopes": ["write"]},
            executor_reference="settlement-worker",
        )
        ctx_b = executor_context_from_auth(
            {"org_id": org_id, "api_key_id": key_b, "scopes": ["write"]},
            # Same labels, right down to the reference string.
            executor_reference="settlement-worker",
        )
        assert ctx_a.binding_digest != ctx_b.binding_digest

        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=ctx_a,
            issuance_ref="keys-1",
        )
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)

        stolen = await consume.consume(
            authority_token=issued.authority_token,
            executor=ctx_b,
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-keys-1",
        )
        assert stolen.rejection_reason is DecisionReason.GRANT_EXECUTOR_MISMATCH

        owner = await consume.consume(
            authority_token=issued.authority_token,
            executor=ctx_a,
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-keys-1-ok",
        )
        assert owner.outcome is ConsumptionOutcome.AUTHORISED

    async def test_the_auth_dependency_returns_the_real_key_id(
        self, db, org_and_agent
    ) -> None:
        """Not a synthetic dict: the production SELECT must expose ak.id."""
        import api.legacy_main as legacy

        org_id, _agent = org_and_agent
        key_id, raw = await self._make_key(db, org_id)

        async def _fake_get_db():
            return db

        auth = await legacy.verify_api_key(x_api_key=raw, database=db)
        assert auth["api_key_id"] == key_id
        assert auth["org_id"] == org_id
        assert _fake_get_db is not None

    async def test_a_context_without_a_key_id_is_refused_in_production(self) -> None:
        with pytest.raises(ExecutorAuthError, match="no API key identity"):
            executor_context_from_auth(
                {"org_id": uuid4(), "scopes": ["write"]}, environment="production"
            )


class TestExpiredTokenRecovery:
    """Authenticity and expiry are separate questions."""

    async def _issue_and_consume(self, db, agent, ref, exec_ctx):
        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=exec_ctx,
            issuance_ref=ref,
        )
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        first = await consume.consume(
            authority_token=issued.authority_token,
            executor=exec_ctx,
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref=f"exec-{ref}",
        )
        return issued, consume, first

    def _expired_token(self, issued, agent):
        claims = CryptoService.verify_approval_token(issued.authority_token, SERVER_SECRET)
        return CryptoService.generate_approval_token(
            agent_id=str(agent.id),
            action_hash=claims["action_hash"],
            verdict="approved",
            server_secret=SERVER_SECRET,
            token_id=claims["token_id"],
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
            extra_claims={
                "token_version": claims["token_version"],
                "grant_id": claims["grant_id"],
                "execution_action_hash": claims["execution_action_hash"],
            },
        )

    async def test_an_unexpired_token_authorises_a_first_consumption(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        _issued, _consume, first = await self._issue_and_consume(
            db, agent, "exp-1", executor(org_id)
        )
        assert first.outcome is ConsumptionOutcome.AUTHORISED
        assert first.may_execute

    async def test_an_expired_token_recovers_a_committed_consumption(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        ctx = executor(org_id)
        issued, consume, first = await self._issue_and_consume(
            db, agent, "exp-2", ctx
        )
        recovered = await consume.consume(
            authority_token=self._expired_token(issued, agent),
            executor=ctx,
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-exp-2",
        )
        assert recovered.outcome is ConsumptionOutcome.RECOVERED
        assert recovered.consumption_audit_id == first.consumption_audit_id
        assert not recovered.may_execute

    async def test_an_expired_token_with_no_committed_consumption_is_refused(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        ctx = executor(org_id)
        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=ctx,
            issuance_ref="exp-3",
        )
        consume = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        result = await consume.consume(
            authority_token=self._expired_token(issued, agent),
            executor=ctx,
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-exp-3",
        )
        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.rejection_reason is DecisionReason.GRANT_EXPIRED
        assert not result.may_execute

    async def test_recovery_remains_executor_bound(self, db, org_and_agent) -> None:
        """Recovery returns history; history still belongs to one executor."""
        org_id, agent = org_and_agent
        ctx_a = executor(org_id, key_id="key-A", reference="worker-7")
        ctx_b = executor(org_id, key_id="key-B", reference="worker-7")
        issued, consume, first = await self._issue_and_consume(
            db, agent, "exp-4", ctx_a
        )

        impostor = await consume.consume(
            authority_token=issued.authority_token,
            executor=ctx_b,
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-exp-4",
        )
        assert impostor.outcome is ConsumptionOutcome.REJECTED
        assert impostor.rejection_reason is DecisionReason.GRANT_EXECUTOR_MISMATCH
        assert impostor.consumption_audit_id is None

        owner = await consume.consume(
            authority_token=issued.authority_token,
            executor=ctx_a,
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-exp-4",
        )
        assert owner.outcome is ConsumptionOutcome.RECOVERED
        assert owner.consumption_audit_id == first.consumption_audit_id
        assert not owner.may_execute


class TestServerSecretRotation:
    async def test_a_token_signed_with_the_previous_secret_still_verifies(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        previous, current = b"previous-secret-value-abc", b"current-secret-value-xyz"

        issued = await AuthorityEvaluationService(
            db, server_secret=previous
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="rot-1",
        )
        # Rotation window: current signs, previous still verifies.
        during = AuthorityConsumptionService(db, server_secret=[current, previous])
        ok = await during.consume(
            authority_token=issued.authority_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-rot-1",
        )
        assert ok.outcome is ConsumptionOutcome.AUTHORISED

    async def test_once_the_previous_secret_is_removed_old_tokens_fail(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        previous, current = b"previous-secret-value-abc", b"current-secret-value-xyz"
        issued = await AuthorityEvaluationService(
            db, server_secret=previous
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="rot-2",
        )
        after = AuthorityConsumptionService(db, server_secret=[current])
        result = await after.consume(
            authority_token=issued.authority_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-rot-2",
        )
        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.rejection_reason is DecisionReason.GRANT_NOT_FOUND

    async def test_new_tokens_are_signed_with_the_current_secret(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        current, previous = b"current-secret-value-xyz", b"previous-secret-value-abc"
        issued = await AuthorityEvaluationService(
            db, server_secret=[current, previous]
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="rot-3",
        )
        assert CryptoService.verify_approval_token(issued.authority_token, current)
        assert CryptoService.verify_approval_token(issued.authority_token, previous) is None


class TestSignedActionHashSemantics:
    def test_the_new_request_model_has_no_signed_action_hash_field(self) -> None:
        """A caller-typed hash is not a hash an agent signed."""
        from api.routes.authority import ConsumeRequest, EvaluateRequest

        assert "signed_action_hash" not in EvaluateRequest.model_fields
        assert "signed_action_hash" not in ConsumeRequest.model_fields

    async def test_evidence_from_the_service_path_claims_no_agent_signature(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="sig-sem-1",
        )
        async with db.acquire() as conn:
            stored = await conn.fetchval(
                "SELECT signed_action_hash FROM execution_authority_grants WHERE id = $1",
                issued.grant_id,
            )
        assert stored is None, (
            "the service-authenticated surface verified no agent signature, so "
            "it must not record one"
        )


class TestDurableEvidenceLifecycle:
    """Receipt v3 built from the real lifecycle rows, not from a fixture.

    Every input is a durable column, so evidence for one history is the
    same bytes on every read, and a decision receipt is never rewritten
    when consumption or outcome arrive later.
    """

    @staticmethod
    def _key():
        return load_evidence_signing_key(environment="test")

    async def _grant(self, db, agent, ctx, ref, *, consume_it=False):
        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=ctx,
            issuance_ref=ref,
        )
        if consume_it:
            await AuthorityConsumptionService(db, server_secret=SERVER_SECRET).consume(
                authority_token=issued.authority_token,
                executor=ctx,
                agent=agent,
                action_type="financial_transaction",
                payload=payment_payload(),
                execution_ref=f"exec-{ref}",
            )
        return issued, await AuthorityStore(db).get(issued.grant_id)

    async def test_a_decision_event_is_built_from_durable_columns(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        key = self._key()
        _issued, grant = await self._grant(db, agent, executor(org_id), "ev-1")

        event = build_decision_evidence(grant, key=key)
        assert verify_evidence_event(event, public_key_b64=key.public_key_b64)
        # recorded_at is the durable issuance time, never "now".
        assert event.recorded_at == grant["issued_at"].astimezone(UTC)
        assert event.event_id == decision_event_id(grant["id"])
        assert event.payload["body"]["execution_action_hash"] == (
            grant["execution_action_hash"]
        )
        assert event.payload["body"]["executor_binding_digest"] == (
            grant["executor_binding_digest"]
        )

    async def test_rebuilding_the_same_history_is_byte_identical(
        self, db, org_and_agent
    ) -> None:
        """Two reads of one event return the same signed bytes."""
        org_id, agent = org_and_agent
        key = self._key()
        _issued, grant = await self._grant(
            db, agent, executor(org_id), "ev-2", consume_it=True
        )
        reread = await AuthorityStore(db).get(grant["id"])

        first = build_evidence_chain(grant, key=key)
        second = build_evidence_chain(reread, key=key)
        assert [e.as_public_dict() for e in first.events()] == [
            e.as_public_dict() for e in second.events()
        ]
        assert first.decision.signature_b64 == second.decision.signature_b64
        assert first.consumption.signature_b64 == second.consumption.signature_b64

    async def test_no_consumption_evidence_before_the_authority_is_spent(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        key = self._key()
        _issued, grant = await self._grant(db, agent, executor(org_id), "ev-3")

        chain = build_evidence_chain(grant, key=key)
        assert grant["status"] == "active"
        assert chain.consumption is None
        assert chain.outcome is None
        assert verify_evidence_event(chain.decision, public_key_b64=key.public_key_b64)

    async def test_a_refused_attempt_produces_no_consumption_evidence(
        self, db, org_and_agent
    ) -> None:
        """Evidence describes what happened, not what was attempted."""
        org_id, agent = org_and_agent
        key = self._key()
        issued, _grant = await self._grant(db, agent, executor(org_id), "ev-4")

        refused = await AuthorityConsumptionService(
            db, server_secret=SERVER_SECRET
        ).consume(
            authority_token=issued.authority_token,
            executor=executor(org_id, key_id="other-key"),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-ev-4",
        )
        assert refused.outcome is ConsumptionOutcome.REJECTED

        grant = await AuthorityStore(db).get(issued.grant_id)
        assert build_evidence_chain(grant, key=key).consumption is None

    async def test_the_decision_event_is_unchanged_by_later_events(
        self, db, org_and_agent
    ) -> None:
        """A decision receipt already quoted stays quotable."""
        org_id, agent = org_and_agent
        key = self._key()
        ctx = executor(org_id)
        issued, before = await self._grant(db, agent, ctx, "ev-5")
        decision_before = build_decision_evidence(before, key=key)

        await AuthorityConsumptionService(db, server_secret=SERVER_SECRET).consume(
            authority_token=issued.authority_token,
            executor=ctx,
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-ev-5",
        )
        store = AuthorityStore(db)
        await store.record_outcome(
            grant_id=issued.grant_id,
            outcome_state=OutcomeState.SUCCEEDED,
            outcome_reference="rail-tx-1",
        )
        after = await store.get(issued.grant_id)

        chain = build_evidence_chain(after, key=key)
        assert chain.decision.as_public_dict() == decision_before.as_public_dict()
        assert chain.consumption is not None
        assert chain.outcome is not None
        assert chain.verify(public_key_b64=key.public_key_b64)

    async def test_the_chain_links_decision_to_consumption_to_outcome(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        key = self._key()
        ctx = executor(org_id)
        issued, _ = await self._grant(db, agent, ctx, "ev-6", consume_it=True)
        store = AuthorityStore(db)
        await store.record_outcome(
            grant_id=issued.grant_id,
            outcome_state=OutcomeState.SUCCEEDED,
            outcome_reference="rail-tx-2",
        )
        grant = await store.get(issued.grant_id)

        chain = build_evidence_chain(grant, key=key)
        assert chain.consumption.parent_event_id == chain.decision.event_id
        assert chain.consumption.parent_payload_hash == (
            chain.decision.evidence_payload_hash
        )
        assert chain.outcome.parent_event_id == chain.consumption.event_id
        assert chain.outcome.parent_payload_hash == (
            chain.consumption.evidence_payload_hash
        )
        assert chain.consumption.event_id == consumption_event_id(
            grant["consumption_audit_id"]
        )
        assert chain.outcome.event_id == outcome_event_id(grant["id"])

    async def test_an_unknown_outcome_is_not_published_as_evidence(
        self, db, org_and_agent
    ) -> None:
        """Signing "we do not know" would be worse than publishing nothing."""
        org_id, agent = org_and_agent
        key = self._key()
        issued, _ = await self._grant(
            db, agent, executor(org_id), "ev-7", consume_it=True
        )
        store = AuthorityStore(db)
        await store.record_outcome(
            grant_id=issued.grant_id, outcome_state=OutcomeState.OUTCOME_UNKNOWN
        )
        grant = await store.get(issued.grant_id)

        chain = build_evidence_chain(grant, key=key)
        assert grant["outcome_state"] == "outcome_unknown"
        assert chain.outcome is None
        assert chain.consumption is not None
        assert chain.verify(public_key_b64=key.public_key_b64)

    async def test_a_failed_final_outcome_is_published(self, db, org_and_agent) -> None:
        """Proven failure is knowledge, and is published as such."""
        org_id, agent = org_and_agent
        key = self._key()
        issued, _ = await self._grant(
            db, agent, executor(org_id), "ev-8", consume_it=True
        )
        store = AuthorityStore(db)
        await store.record_outcome(
            grant_id=issued.grant_id,
            outcome_state=OutcomeState.FAILED_FINAL,
            outcome_reference="rail-decline-1",
        )
        grant = await store.get(issued.grant_id)

        chain = build_evidence_chain(grant, key=key)
        assert chain.outcome is not None
        assert chain.outcome.payload["body"]["outcome_state"] == "failed_final"
        assert chain.verify(public_key_b64=key.public_key_b64)

    async def test_service_path_evidence_claims_no_agent_signature(
        self, db, org_and_agent
    ) -> None:
        """A surface that verified no signature must not publish one."""
        org_id, agent = org_and_agent
        key = self._key()
        _issued, grant = await self._grant(db, agent, executor(org_id), "ev-9")
        event = build_decision_evidence(grant, key=key)
        assert grant["signed_action_hash"] is None
        assert event.payload["body"]["signed_action_hash"] is None


class TestNoFailureProducesExecutableAuthority:
    """Phase 4 failure semantics, one class per failing component.

    The invariant under test is single: whatever breaks, the caller never
    ends up holding something it can execute with. Either an explicit
    refusal with no token, or an exception the surface turns into an
    error — never a grant, and never ``may_execute``.
    """

    async def test_a_failing_authority_provider_yields_no_authority(
        self, db, org_and_agent
    ) -> None:
        """A provider that raises must not be read as "nothing required"."""

        class _ExplodingProvider:
            def resolve(self, claim, context):  # noqa: ARG002
                raise RuntimeError("issuer unreachable")

        org_id, agent = org_and_agent
        service = AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET, authority_provider=_ExplodingProvider()
        )
        with pytest.raises(RuntimeError):
            await service.evaluate(
                agent=agent,
                action_type="financial_transaction",
                payload=payment_payload(),
                executor=executor(org_id),
                issuance_ref="nf-1",
                authority_claim=DelegatedAuthorityClaim(
                    issuer="external", external_reference_id="ref-nf-1"
                ),
            )
        # Nothing was written: no grant exists for that reference.
        async with db.acquire() as conn:
            count = await conn.fetchval(
                "SELECT count(*) FROM execution_authority_grants WHERE issuance_ref = $1",
                "nf-1",
            )
        assert count == 0

    async def test_an_unverified_claim_where_authority_is_required_yields_none(
        self, db, org_and_agent, monkeypatch
    ) -> None:
        class _UnverifiedResolution:
            is_verified = False
            issuer = "external"
            external_reference_id = "ref-nf-2"
            scope_digest = None
            expires_at = None

        class _Provider:
            def resolve(self, claim, context):  # noqa: ARG002
                return _UnverifiedResolution()

        org_id, agent = org_and_agent
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(org_id))
        service = AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET, authority_provider=_Provider()
        )
        result = await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="nf-2",
            authority_claim=DelegatedAuthorityClaim(
                issuer="external", external_reference_id="ref-nf-2"
            ),
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_VERIFICATION_FAILED in result.reasons
        assert result.authority_token is None
        assert result.grant_id is None

    async def test_a_policy_failure_yields_no_authority(
        self, db, org_and_agent, monkeypatch
    ) -> None:
        """A domain policy that throws must not be treated as an allow."""
        import api.services.authority_service as svc

        def _explode(*args, **kwargs):  # noqa: ARG001
            raise RuntimeError("policy evaluation failed")

        org_id, agent = org_and_agent
        monkeypatch.setattr(svc, "evaluate_core_policy", _explode)
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        with pytest.raises(RuntimeError):
            await service.evaluate(
                agent=agent,
                action_type="financial_transaction",
                payload=payment_payload(),
                executor=executor(org_id),
                issuance_ref="nf-3",
            )
        async with db.acquire() as conn:
            count = await conn.fetchval(
                "SELECT count(*) FROM execution_authority_grants WHERE issuance_ref = $1",
                "nf-3",
            )
        assert count == 0

    @pytest.mark.parametrize(
        "token",
        ["", "not-a-token", "YWJj", "eyJhIjoxfQ=="],
        ids=["empty", "garbage", "short-b64", "unsigned-json"],
    )
    async def test_a_token_that_does_not_verify_yields_no_execution(
        self, db, org_and_agent, token
    ) -> None:
        org_id, agent = org_and_agent
        result = await AuthorityConsumptionService(
            db, server_secret=SERVER_SECRET
        ).consume(
            authority_token=token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-nf-4",
        )
        assert result.outcome is ConsumptionOutcome.REJECTED
        assert not result.may_execute
        assert result.grant_id is None

    async def test_an_executor_that_cannot_be_identified_never_consumes(
        self, db, org_and_agent
    ) -> None:
        """Executor auth fails before any state is touched."""
        org_id, agent = org_and_agent
        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="nf-5",
        )
        with pytest.raises(ExecutorAuthError):
            executor_context_from_auth(
                {"org_id": org_id, "scopes": ["write"]}, environment="production"
            )
        grant = await AuthorityStore(db).get(issued.grant_id)
        assert grant["status"] == "active"
        assert grant["consumption_audit_id"] is None

    async def test_a_database_failure_during_consumption_never_authorises(
        self, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        working = await Database.create(DATABASE_URL, min_size=1, max_size=4)
        try:
            issued = await AuthorityEvaluationService(
                working, server_secret=SERVER_SECRET
            ).evaluate(
                agent=agent,
                action_type="financial_transaction",
                payload=payment_payload(),
                executor=executor(org_id),
                issuance_ref="nf-6",
            )
        finally:
            await working.close()

        broken = await Database.create(DATABASE_URL, min_size=1, max_size=2)
        await broken.close()
        service = AuthorityConsumptionService(broken, server_secret=SERVER_SECRET)
        with pytest.raises(
            (asyncpg.PostgresError, asyncpg.InterfaceError, RuntimeError)
        ):
            await service.consume(
                authority_token=issued.authority_token,
                executor=executor(org_id),
                agent=agent,
                action_type="financial_transaction",
                payload=payment_payload(),
                execution_ref="exec-nf-6",
            )

        checker = await Database.create(DATABASE_URL, min_size=1, max_size=2)
        try:
            grant = await AuthorityStore(checker).get(issued.grant_id)
            assert grant["status"] == "active"
            assert grant["consumption_audit_id"] is None
        finally:
            await checker.close()

    def test_evidence_signing_refuses_to_invent_a_production_key(
        self, monkeypatch
    ) -> None:
        """Unsigned evidence is not evidence, so it is not produced."""
        monkeypatch.delenv(EVIDENCE_SIGNING_KEY_ENV, raising=False)
        with pytest.raises(EvidenceError, match="required outside development"):
            load_evidence_signing_key(environment="production")

    def test_a_malformed_evidence_key_is_refused_rather_than_replaced(
        self, monkeypatch
    ) -> None:
        monkeypatch.setenv(EVIDENCE_SIGNING_KEY_ENV, "not-base64!!")
        with pytest.raises(EvidenceError):
            load_evidence_signing_key(environment="production")

    async def test_a_block_never_carries_a_token_on_the_wire(
        self, db, org_and_agent
    ) -> None:
        """The refusal shape itself: no partial success."""
        org_id, agent = org_and_agent
        result = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(amount="999999.00"),
            executor=executor(org_id),
            issuance_ref="nf-7",
        )
        assert result.decision is Decision.BLOCK
        assert result.authority_token is None
        assert result.grant_id is None
        assert not result.authorises_execution


class TestTheEndpointItselfEnforcesCorePolicy:
    """Route-level, not service-level.

    Every other Core test in this file calls the service and passes the
    live state in by hand. That proves the service enforces the rule; it
    does not exercise the endpoint's own wiring. These drive the route
    body, so a future edit that stops feeding it live state is caught
    here rather than in production.

    On rate limiting specifically there are two independent enforcers:
    the Core pre-check, and the atomic reserve-and-increment inside
    issuance. The second is authoritative and is what makes concurrent
    requests safe; the first only refuses earlier and more cheaply.
    Removing the route's Core inputs today changes neither the verdict
    nor the counter — the assertions below hold on the verdict, which is
    what a caller can observe.
    """

    @staticmethod
    def _route(path: str):
        import api.main  # noqa: F401 - importing registers the routes
        from api.routes.authority import router

        for route in router.routes:
            if route.path == path:
                return route.endpoint
        raise AssertionError(f"no route registered at {path}")

    @staticmethod
    def _auth(org_id, key_id="route-key"):
        return {"org_id": org_id, "api_key_id": key_id, "scopes": ["write", "admin"]}

    async def _get_agent_or_404(self, database, agent_id):
        return await database.get_agent_by_id(agent_id)

    async def _evaluate(self, db, org_id, agent, ref, **overrides):
        from api.routes.authority import EvaluateRequest

        endpoint = self._route("/authority/evaluate")
        body = EvaluateRequest(
            agent_id=agent.id,
            action_type=overrides.pop("action_type", "financial_transaction"),
            payload=overrides.pop("payload", payment_payload()),
            issuance_ref=ref,
            **overrides,
        )
        return await endpoint(body=body, database=db, auth=self._auth(org_id))

    async def test_the_endpoint_allows_a_clean_act(self, db, org_and_agent) -> None:
        org_id, agent = org_and_agent
        response = await self._evaluate(db, org_id, agent, "route-1")
        assert response["decision"] == "allow"
        assert response["authority_token"]

    async def test_the_endpoint_refuses_an_over_limit_act(
        self, db, org_and_agent
    ) -> None:
        """Over the limit, the endpoint issues nothing and reserves nothing."""
        org_id, agent = org_and_agent
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET rate_limit_per_minute = 1 WHERE id = $1", agent.id
            )
            # Five requests already recorded in the current minute.
            await conn.execute(
                """
                INSERT INTO rate_limit_windows (
                    agent_id, window_type, window_start, request_count
                )
                VALUES ($1, 'minute', date_trunc('minute', NOW()), 5)
                ON CONFLICT (agent_id, window_type, window_start)
                DO UPDATE SET request_count = 5
                """,
                agent.id,
            )
        limited = await db.get_agent_by_id(agent.id)
        assert limited.rate_limit_per_minute == 1

        response = await self._evaluate(db, org_id, limited, "route-2")
        assert response["decision"] == "block"
        assert response["authority_token"] is None
        assert response["grant_id"] is None
        assert "rate_limit_exceeded" in response["reasons"]
        # A refusal leaves no reservation behind and burns no capacity.
        async with db.acquire() as conn:
            assert (
                await conn.fetchval(
                    "SELECT count(*) FROM spend_reservations WHERE agent_id = $1",
                    agent.id,
                )
                == 0
            )

    async def test_the_endpoint_reads_the_registered_policy(
        self, db, org_and_agent
    ) -> None:
        """The endpoint supplies the same policy input /verify supplies.

        The binding it feeds governs the CI/release action types, which no
        payment domain policy covers, so it changes no verdict on this
        surface today. It is wired anyway: the endpoint should not be the
        one that quietly stops passing a Core input.
        """
        org_id, agent = org_and_agent
        # No policy registered for this agent: the lookup returns None and
        # the decision is unchanged, which is the documented rollout state.
        assert await db.get_active_agent_policy(agent.id) is None
        response = await self._evaluate(db, org_id, agent, "route-3")
        assert response["decision"] == "allow"

        # And the endpoint really does perform the lookup.
        calls = []
        original = type(db).get_active_agent_policy

        async def _spy(self, agent_id):
            calls.append(agent_id)
            return await original(self, agent_id)

        type(db).get_active_agent_policy = _spy
        try:
            # A different act: an identical one still holds a reservation.
            await self._evaluate(
                db,
                org_id,
                agent,
                "route-4",
                payload=payment_payload(amount="11.00", recipient="acct_route_4"),
            )
        finally:
            type(db).get_active_agent_policy = original
        assert calls == [agent.id]

    async def test_a_suspended_principal_is_refused_at_the_endpoint(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET status = 'suspended' WHERE id = $1", agent.id
            )
        suspended = await db.get_agent_by_id(agent.id)

        response = await self._evaluate(db, org_id, suspended, "route-5")
        assert response["decision"] == "block"
        assert response["authority_token"] is None
