"""Phase 4 — the authority services and their HTTP surface.

Both HTTP surfaces call these services, so the assertions here are about
one evaluation path and one consumption path: the executor is
established from credentials, a grant id alone is not authority, and a
copied executor reference buys nothing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
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
from api.persistence.authority_decisions import (  # noqa: E402
    get_authority_decision,
    get_authority_decision_audit_row,
)
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
    AuthorityEvidenceChain,
    ConsumptionEvidenceV3,
    DecisionEvidenceV3,
    EvidenceError,
    EvidenceEventType,
    OutcomeEvidenceV3,
    evidence_chain_continuity_failures,
    load_evidence_signing_key,
    sign_evidence_event,
    verify_evidence_event,
)


@pytest.fixture
def key():
    return load_evidence_signing_key(environment="test")
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
    """Receipt v3 built from the durable decision record and grant rows.

    Every input is a column. The builders take a record and a key and
    nothing else, so two reads of one history cannot disagree.
    """

    @staticmethod
    def _key():
        return load_evidence_signing_key(environment="test")

    async def _evaluate(self, db, agent, ctx, ref, **overrides):
        return await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type=overrides.pop("action_type", "financial_transaction"),
            payload=overrides.pop("payload", payment_payload()),
            executor=ctx,
            issuance_ref=ref,
            **overrides,
        )

    async def _decision(self, db, result):
        return await get_authority_decision(db, result.decision_audit_id)

    async def _allow(self, db, agent, ctx, ref, *, consume_it=False):
        issued = await self._evaluate(db, agent, ctx, ref)
        assert issued.decision is Decision.ALLOW
        if consume_it:
            await AuthorityConsumptionService(db, server_secret=SERVER_SECRET).consume(
                authority_token=issued.authority_token,
                executor=ctx,
                agent=agent,
                action_type="financial_transaction",
                payload=payment_payload(),
                execution_ref=f"exec-{ref}",
            )
        return issued

    async def test_an_allow_decision_is_persisted_and_verifies(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        key = self._key()
        issued = await self._allow(db, agent, executor(org_id), "ev-1")
        record = await self._decision(db, issued)

        event = build_decision_evidence(record, key=key)
        assert verify_evidence_event(event, public_key_b64=key.public_key_b64)
        assert event.event_id == decision_event_id(issued.decision_audit_id)
        assert event.recorded_at == record["recorded_at"].astimezone(UTC)
        body = event.payload["body"]
        assert body["decision"] == "allow"
        assert body["grant_id"] == str(issued.grant_id)
        assert body["execution_action_hash"] == issued.execution_action_hash

    async def test_a_block_decision_is_persisted_and_verifies(
        self, db, org_and_agent
    ) -> None:
        """A refusal is a decision, and gets a receipt of its own."""
        org_id, agent = org_and_agent
        key = self._key()
        blocked = await self._evaluate(
            db,
            agent,
            executor(org_id),
            "ev-block",
            payload=payment_payload(amount="999999.00"),
        )
        assert blocked.decision is Decision.BLOCK
        assert blocked.authority_token is None
        assert blocked.grant_id is None
        assert blocked.decision_audit_id is not None

        record = await self._decision(db, blocked)
        audit_row = await get_authority_decision_audit_row(
            db, blocked.decision_audit_id
        )
        assert audit_row["verdict"] == "blocked"
        # No executable authority was created for the refusal.
        async with db.acquire() as conn:
            assert (
                await conn.fetchval(
                    "SELECT count(*) FROM execution_authority_grants "
                    "WHERE issuance_ref = $1 AND agent_id = $2",
                    "ev-block",
                    agent.id,
                )
                == 0
            )

        event = build_decision_evidence(record, key=key)
        assert verify_evidence_event(event, public_key_b64=key.public_key_b64)
        assert event.payload["body"]["decision"] == "block"
        assert event.payload["body"]["grant_id"] is None
        assert event.payload["body"]["reasons"]

    async def test_rebuilding_the_same_decision_is_byte_identical(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        key = self._key()
        issued = await self._allow(db, agent, executor(org_id), "ev-2")
        first = build_decision_evidence(await self._decision(db, issued), key=key)
        second = build_decision_evidence(await self._decision(db, issued), key=key)
        assert first.as_public_dict() == second.as_public_dict()
        assert first.signature_b64 == second.signature_b64

    async def test_no_build_argument_can_rewrite_historical_evidence(
        self, db, org_and_agent
    ) -> None:
        """The builder's whole signature is (record, key). That is the proof.

        There is no parameter a caller could pass differently on a second
        read, because the only inputs are the immutable row and the key.
        """
        import inspect

        signature = inspect.signature(build_decision_evidence)
        assert list(signature.parameters) == ["decision_record", "key"]

        org_id, agent = org_and_agent
        key = self._key()
        issued = await self._allow(db, agent, executor(org_id), "ev-args")
        record = await self._decision(db, issued)
        baseline = build_decision_evidence(record, key=key).as_public_dict()

        # A caller who mutates their own copy of the row changes their own
        # view and nothing else: the stored row is what the next read sees.
        mutated = dict(record)
        mutated["decision_body"] = json.dumps(
            {
                **json.loads(record["decision_body"]),
                "authority_scope_digest": "0" * 64,
            }
        )
        assert (
            build_decision_evidence(mutated, key=key).as_public_dict() != baseline
        )
        reread = await self._decision(db, issued)
        assert build_decision_evidence(reread, key=key).as_public_dict() == baseline

    async def test_the_decision_row_is_immutable(self, db, org_and_agent) -> None:
        """Append-only by trigger, so history cannot be edited after the fact."""
        org_id, agent = org_and_agent
        issued = await self._allow(db, agent, executor(org_id), "ev-immutable")
        with pytest.raises(asyncpg.PostgresError):
            async with db.acquire() as conn:
                await conn.execute(
                    "UPDATE audit_logs SET verdict_reason = 'tampered' WHERE id = $1",
                    issued.decision_audit_id,
                )

    async def test_v3_publishes_the_scope_digest_and_no_invented_facts(
        self, db, org_and_agent
    ) -> None:
        """Only what Phase 3 actually persists reaches the receipt."""
        org_id, agent = org_and_agent
        key = self._key()
        issued = await self._allow(db, agent, executor(org_id), "ev-fields")
        body = build_decision_evidence(
            await self._decision(db, issued), key=key
        ).payload["body"]

        assert "authority_scope_digest" in body
        for invented in (
            "authority_artefact_digest",
            "authority_issuer",
            "authority_reference_id",
            "legacy_policy_hash",
        ):
            assert invented not in body
        # No delegation was presented, so there is nothing to commit to.
        assert body["authority_scope_digest"] is None
        # And this surface verified no agent signature.
        assert body["signed_action_hash"] is None

    async def test_no_consumption_evidence_before_the_authority_is_spent(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        key = self._key()
        issued = await self._allow(db, agent, executor(org_id), "ev-3")
        grant = await AuthorityStore(db).get(issued.grant_id)

        chain = build_evidence_chain(
            await self._decision(db, issued), key=key, grant=grant
        )
        assert grant["status"] == "active"
        assert chain.consumption is None
        assert chain.outcome is None
        assert chain.verify(public_key_b64=key.public_key_b64)

    async def test_a_refused_attempt_produces_no_consumption_evidence(
        self, db, org_and_agent
    ) -> None:
        """Evidence describes what happened, not what was attempted."""
        org_id, agent = org_and_agent
        key = self._key()
        issued = await self._allow(db, agent, executor(org_id), "ev-4")

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
        chain = build_evidence_chain(
            await self._decision(db, issued), key=key, grant=grant
        )
        assert chain.consumption is None

    async def test_the_decision_event_is_unchanged_by_later_events(
        self, db, org_and_agent
    ) -> None:
        """A decision receipt already quoted stays quotable."""
        org_id, agent = org_and_agent
        key = self._key()
        ctx = executor(org_id)
        issued = await self._allow(db, agent, ctx, "ev-5")
        before = build_decision_evidence(
            await self._decision(db, issued), key=key
        ).as_public_dict()

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

        chain = build_evidence_chain(
            await self._decision(db, issued),
            key=key,
            grant=await store.get(issued.grant_id),
        )
        assert chain.decision.as_public_dict() == before
        assert chain.consumption is not None
        assert chain.outcome is not None
        assert chain.verify(public_key_b64=key.public_key_b64)

    async def test_the_chain_links_decision_to_consumption_to_outcome(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        key = self._key()
        ctx = executor(org_id)
        issued = await self._allow(db, agent, ctx, "ev-6", consume_it=True)
        store = AuthorityStore(db)
        await store.record_outcome(
            grant_id=issued.grant_id,
            outcome_state=OutcomeState.SUCCEEDED,
            outcome_reference="rail-tx-2",
        )
        grant = await store.get(issued.grant_id)

        chain = build_evidence_chain(
            await self._decision(db, issued), key=key, grant=grant
        )
        assert chain.consumption.parent_event_id == chain.decision.event_id
        assert chain.consumption.parent_payload_hash == (
            chain.decision.evidence_payload_hash
        )
        assert chain.outcome.parent_event_id == chain.consumption.event_id
        assert chain.consumption.event_id == consumption_event_id(
            grant["consumption_audit_id"]
        )
        assert chain.outcome.event_id == outcome_event_id(grant["id"])
        assert chain.verify(public_key_b64=key.public_key_b64)

    async def test_an_unknown_outcome_is_not_published_as_evidence(
        self, db, org_and_agent
    ) -> None:
        """Signing "we do not know" would be worse than publishing nothing."""
        org_id, agent = org_and_agent
        key = self._key()
        issued = await self._allow(db, agent, executor(org_id), "ev-7", consume_it=True)
        store = AuthorityStore(db)
        await store.record_outcome(
            grant_id=issued.grant_id, outcome_state=OutcomeState.OUTCOME_UNKNOWN
        )
        grant = await store.get(issued.grant_id)

        chain = build_evidence_chain(
            await self._decision(db, issued), key=key, grant=grant
        )
        assert grant["outcome_state"] == "outcome_unknown"
        assert chain.outcome is None
        assert chain.consumption is not None
        assert chain.verify(public_key_b64=key.public_key_b64)

    async def test_a_failed_final_outcome_is_published(self, db, org_and_agent) -> None:
        """Proven failure is knowledge, and is published as such."""
        org_id, agent = org_and_agent
        key = self._key()
        issued = await self._allow(db, agent, executor(org_id), "ev-8", consume_it=True)
        store = AuthorityStore(db)
        await store.record_outcome(
            grant_id=issued.grant_id,
            outcome_state=OutcomeState.FAILED_FINAL,
            outcome_reference="rail-decline-1",
        )

        chain = build_evidence_chain(
            await self._decision(db, issued),
            key=key,
            grant=await store.get(issued.grant_id),
        )
        assert chain.outcome is not None
        assert chain.outcome.payload["body"]["outcome_state"] == "failed_final"
        assert chain.verify(public_key_b64=key.public_key_b64)

    async def test_a_block_chain_is_decision_only(self, db, org_and_agent) -> None:
        org_id, agent = org_and_agent
        key = self._key()
        blocked = await self._evaluate(
            db,
            agent,
            executor(org_id),
            "ev-block-chain",
            payload=payment_payload(amount="999999.00"),
        )
        chain = build_evidence_chain(await self._decision(db, blocked), key=key)
        assert chain.consumption is None
        assert chain.outcome is None
        assert chain.verify(public_key_b64=key.public_key_b64)



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
        result = await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref="nf-1",
            authority_claim=DelegatedAuthorityClaim(
                issuer="external", external_reference_id="ref-nf-1"
            ),
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_PROVIDER_UNAVAILABLE in result.reasons
        assert result.authority_token is None
        # Nothing executable was written for that reference.
        async with db.acquire() as conn:
            count = await conn.fetchval(
                "SELECT count(*) FROM execution_authority_grants "
                "WHERE issuance_ref = $1 AND agent_id = $2",
                "nf-1",
                agent.id,
            )
        assert count == 0
        # The refusal itself IS recorded: a block is a decision.
        assert result.decision_audit_id is not None

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
                "SELECT count(*) FROM execution_authority_grants "
                "WHERE issuance_ref = $1 AND agent_id = $2",
                "nf-3",
                agent.id,
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


class TestUnrelatedAuditActivityDoesNotVoidAGrant:
    """A statistic is not a policy change.

    ``audit_logs`` has an AFTER INSERT trigger that bumps the agent's
    action counters, and ``agents`` has a BEFORE UPDATE trigger that bumps
    ``updated_at``. If ``updated_at`` were part of the policy digest, any
    audit row written between issuance and consumption -- one ``/verify``
    call, or the authority decision record itself -- would re-derive a
    different digest and refuse the grant as POLICY_HASH_MISMATCH.
    """

    async def test_a_later_audit_row_leaves_the_grant_consumable(
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
            issuance_ref="stats-1",
        )
        assert issued.authority_token

        before = await db.get_agent_by_id(agent.id)
        async with db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_logs (
                    agent_id, action_type, action_hash, payload, verdict,
                    verdict_reason, signature, signature_valid,
                    trust_score_at_time, metadata
                ) VALUES ($1, 'api_call', $2, '{}'::JSONB, 'approved', 'unrelated',
                          'X', FALSE, 50, '{"non_cryptographic": true}'::JSONB)
                """,
                agent.id,
                "b" * 64,
            )
        after = await db.get_agent_by_id(agent.id)
        # The trigger really did move the row, so this is not a no-op test.
        assert after.updated_at > before.updated_at

        result = await AuthorityConsumptionService(
            db, server_secret=SERVER_SECRET
        ).consume(
            authority_token=issued.authority_token,
            executor=ctx,
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-stats-1",
        )
        assert result.outcome is ConsumptionOutcome.AUTHORISED

    async def test_a_real_policy_change_still_voids_the_grant(
        self, db, org_and_agent
    ) -> None:
        """The digest must still fire on things that ARE policy."""
        org_id, agent = org_and_agent
        ctx = executor(org_id)
        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=ctx,
            issuance_ref="stats-2",
        )
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET per_action_limit_usd = 1 WHERE id = $1", agent.id
            )

        result = await AuthorityConsumptionService(
            db, server_secret=SERVER_SECRET
        ).consume(
            authority_token=issued.authority_token,
            executor=ctx,
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            execution_ref="exec-stats-2",
        )
        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.rejection_reason is DecisionReason.POLICY_HASH_MISMATCH


class _StubProvider:
    """A provider whose answer the test chooses."""

    def __init__(self, answer=None, raises=None):
        self._answer, self._raises = answer, raises
        self.calls = 0

    def resolve(self, claim, context):  # noqa: ARG002
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return self._answer


class _Unverified:
    """A resolution that says, plainly, that it did not verify."""

    is_verified = False
    issues = ("not_verified",)


def _claim(reference="vi-ref-1"):
    return DelegatedAuthorityClaim(
        issuer="mastercard-vi", external_reference_id=reference
    )


class TestPresentedDelegationIsNeverSilentlyIgnored:
    """Two shapes, and only two.

        no delegation presented -> the organisation's existing path
        delegation presented    -> organisation policy AND delegated scope

    There is no third shape where the server keeps the caller's request
    and discards the constraint they attached to it. Falling back to the
    non-delegated path grants MORE than was asked for, which is the one
    direction a fallback must never go.
    """

    async def _evaluate(self, db, org_id, agent, ref, *, provider=None, claim=None):
        service = AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET, authority_provider=provider
        )
        return await service.evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref=ref,
            authority_claim=claim,
        )

    async def test_no_delegation_takes_the_existing_path(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        result = await self._evaluate(db, org_id, agent, "del-1")
        assert result.decision is Decision.ALLOW
        assert result.authority_token

    async def test_a_payment_the_organisation_allows_is_blocked_when_its_delegation_cannot_be_resolved(
        self, db, org_and_agent
    ) -> None:
        """The exact fail-open this closes.

        The organisation permits this payment outright — the identical act
        with no delegation is allowed above. Presenting a delegation that
        cannot be resolved must BLOCK, not fall back to that allow.
        """
        org_id, agent = org_and_agent
        result = await self._evaluate(
            db, org_id, agent, "del-2", provider=None, claim=_claim()
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_PROVIDER_UNAVAILABLE in result.reasons
        assert result.authority_token is None
        assert result.grant_id is None
        async with db.acquire() as conn:
            assert (
                await conn.fetchval(
                    "SELECT count(*) FROM execution_authority_grants "
                    "WHERE issuance_ref = $1 AND agent_id = $2",
                    "del-2",
                    agent.id,
                )
                == 0
            )

    async def test_a_provider_that_throws_blocks(self, db, org_and_agent) -> None:
        org_id, agent = org_and_agent
        provider = _StubProvider(raises=TimeoutError("issuer unreachable"))
        result = await self._evaluate(
            db, org_id, agent, "del-3", provider=provider, claim=_claim()
        )
        assert provider.calls == 1
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_PROVIDER_UNAVAILABLE in result.reasons
        assert result.authority_token is None

    async def test_a_provider_that_returns_nothing_blocks(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        result = await self._evaluate(
            db,
            org_id,
            agent,
            "del-4",
            provider=_StubProvider(answer=None),
            claim=_claim(),
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_VERIFICATION_FAILED in result.reasons
        assert result.authority_token is None

    async def test_an_unverified_resolution_blocks_even_when_not_required(
        self, db, org_and_agent
    ) -> None:
        """Not required does not mean not enforced once it is presented."""
        org_id, agent = org_and_agent
        result = await self._evaluate(
            db,
            org_id,
            agent,
            "del-5",
            provider=_StubProvider(answer=_Unverified()),
            claim=_claim(),
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_VERIFICATION_FAILED in result.reasons
        assert result.authority_token is None

    async def test_the_block_is_recorded_durably(self, db, org_and_agent) -> None:
        org_id, agent = org_and_agent
        result = await self._evaluate(
            db, org_id, agent, "del-6", provider=None, claim=_claim()
        )
        audit_row = await get_authority_decision_audit_row(
            db, result.decision_audit_id
        )
        assert audit_row is not None
        assert audit_row["verdict"] == "blocked"
        record = await get_authority_decision(db, result.decision_audit_id)
        body = json.loads(record["decision_body"])
        assert body["decision"] == "block"
        assert "authority_provider_unavailable" in body["reasons"]

    async def test_the_endpoint_refuses_an_unresolvable_delegation(
        self, db, org_and_agent
    ) -> None:
        """Through the route, where a caller would actually present one."""
        from api.routes.authority import AuthorityClaimBody, EvaluateRequest

        org_id, agent = org_and_agent
        endpoint = TestTheEndpointItselfEnforcesCorePolicy._route("/authority/evaluate")
        body = EvaluateRequest(
            agent_id=agent.id,
            action_type="financial_transaction",
            payload=payment_payload(),
            issuance_ref="del-7",
            delegated_authority=AuthorityClaimBody(
                issuer="mastercard-vi", external_reference_id="vi-ref-7"
            ),
        )
        response = await endpoint(
            body=body,
            database=db,
            auth={"org_id": org_id, "api_key_id": "k", "scopes": ["write"]},
        )
        assert response["decision"] == "block"
        assert response["authority_token"] is None
        assert response["grant_id"] is None
        assert "authority_provider_unavailable" in response["reasons"]


class TestCallerTimestampIsASecurityInput:
    """A field accepted on the wire but excluded from the freshness check
    would be worse than no field: it reads as a control and is not one."""

    @staticmethod
    def _endpoint():
        return TestTheEndpointItselfEnforcesCorePolicy._route("/authority/evaluate")

    async def _post(self, db, org_id, agent, ref, timestamp, recipient="acct_ts"):
        from api.routes.authority import EvaluateRequest

        body = EvaluateRequest(
            agent_id=agent.id,
            action_type="financial_transaction",
            payload=payment_payload(recipient=recipient),
            issuance_ref=ref,
            timestamp=timestamp,
        )
        return await self._endpoint()(
            body=body,
            database=db,
            auth={"org_id": org_id, "api_key_id": "k", "scopes": ["write"]},
        )

    async def test_a_fresh_timestamp_is_allowed(self, db, org_and_agent) -> None:
        org_id, agent = org_and_agent
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        response = await self._post(db, org_id, agent, "ts-1", now, "acct_ts_1")
        assert response["decision"] == "allow"
        assert response["authority_token"]

    async def test_a_stale_timestamp_is_refused_through_the_endpoint(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        stale = (datetime.now(UTC) - timedelta(hours=6)).isoformat().replace(
            "+00:00", "Z"
        )
        response = await self._post(db, org_id, agent, "ts-2", stale, "acct_ts_2")
        assert response["decision"] == "block"
        assert response["reasons"] == ["timestamp_invalid"]
        assert response["authority_token"] is None
        assert response["grant_id"] is None

    async def test_a_future_timestamp_is_refused(self, db, org_and_agent) -> None:
        org_id, agent = org_and_agent
        ahead = (datetime.now(UTC) + timedelta(hours=6)).isoformat().replace(
            "+00:00", "Z"
        )
        response = await self._post(db, org_id, agent, "ts-3", ahead, "acct_ts_3")
        assert response["decision"] == "block"
        assert response["reasons"] == ["timestamp_invalid"]

    async def test_a_naive_timestamp_is_refused_not_reinterpreted(
        self, db, org_and_agent
    ) -> None:
        """Omitting the offset must not shift the window by a timezone."""
        org_id, agent = org_and_agent
        naive = datetime.now(UTC).replace(tzinfo=None).isoformat()
        response = await self._post(db, org_id, agent, "ts-4", naive, "acct_ts_4")
        assert response["decision"] == "block"
        assert response["reasons"] == ["timestamp_invalid"]
        assert "offset" in (response.get("detail") or "")

    async def test_a_malformed_timestamp_is_refused_cleanly(
        self, db, org_and_agent
    ) -> None:
        """A refusal, not an unhandled adapter error."""
        org_id, agent = org_and_agent
        response = await self._post(db, org_id, agent, "ts-5", "yesterday", "acct_ts_5")
        assert response["decision"] == "block"
        assert response["reasons"] == ["timestamp_invalid"]

    async def test_no_timestamp_means_server_time_is_authoritative(
        self, db, org_and_agent
    ) -> None:
        org_id, agent = org_and_agent
        response = await self._post(db, org_id, agent, "ts-6", None, "acct_ts_6")
        assert response["decision"] == "allow"

    async def test_the_same_stale_timestamp_is_refused_by_verify_too(
        self, db, org_and_agent
    ) -> None:
        """Both surfaces apply the one Core freshness rule."""
        org_id, agent = org_and_agent
        stale = datetime.now(UTC) - timedelta(hours=6)
        legacy = evaluate_core_policy(
            CorePolicyInputs(
                agent=agent,
                action_type="financial_transaction",
                payload=payment_payload(),
                timestamp=stale,
            )
        )
        assert not legacy.allowed
        assert legacy.violation.value == "timestamp_invalid"

        response = await self._post(
            db,
            org_id,
            agent,
            "ts-7",
            stale.isoformat().replace("+00:00", "Z"),
            "acct_ts_7",
        )
        assert response["reasons"] == [legacy.violation.value]


async def _make_agent(db, *, sandbox: bool, org_id=None):
    """A principal whose sandbox state the test chooses."""
    org_id = org_id or uuid4()
    agent_id = uuid4()
    metadata = {"sandbox": sandbox}
    if not sandbox:
        metadata.update(
            {
                "production_approval_reference": "phase-4-test",
                "production_approved_at": "2026-01-01T00:00:00Z",
                "production_approved_by": "phase-4-fixture",
            }
        )
    async with db.acquire() as conn:
        exists = await conn.fetchval(
            "SELECT 1 FROM organizations WHERE id = $1", org_id
        )
        if not exists:
            await conn.execute(
                """
                INSERT INTO organizations (
                    id, name, billing_tier, contact_email, api_key_hash
                ) VALUES ($1, $2, 'enterprise', $3, $4)
                """,
                org_id,
                f"sb-{org_id}",
                f"sb-{org_id}@example.test",
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
            f"sb-agent-{agent_id}",
            secrets.token_bytes(32),
            hashlib.sha256(str(agent_id).encode()).hexdigest(),
            json.dumps(metadata),
        )
    return org_id, await db.get_agent_by_id(agent_id)


def _token_claims(token: str) -> dict:
    """Read a token's claims without verifying — for inspection only."""
    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    return json.loads(raw.rsplit(b".", 1)[0])


class TestSandboxProvenanceSurvivesTheAuthorityLifecycle:
    """Sandbox activity must never become production authority.

    The legacy path derives sandbox from agent metadata, signs it into the
    approval token, marks the audit row as test activity so it stays off
    the mainnet anchor path, and refuses consumption. The v0.5 path has to
    do all four, or promoting an agent would launder old test authority
    into production authority.
    """

    async def _issue(self, db, org_id, agent, ref, amount="10.00"):
        return await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(amount=amount, recipient=f"acct-{ref}"),
            executor=executor(org_id),
            issuance_ref=ref,
        )

    async def test_a_sandbox_principal_is_still_evaluated(self, db) -> None:
        """Sandbox is not a refusal to evaluate; it bounds what results."""
        org_id, agent = await _make_agent(db, sandbox=True)
        result = await self._issue(db, org_id, agent, "sbx-1")
        assert result.decision is Decision.ALLOW
        assert result.authority_token

    async def test_the_token_carries_sandbox_provenance(self, db) -> None:
        org_id, agent = await _make_agent(db, sandbox=True)
        result = await self._issue(db, org_id, agent, "sbx-2")
        assert _token_claims(result.authority_token)["sandbox"] is True

    async def test_sandbox_authority_cannot_execute_even_once(self, db) -> None:
        """Not "single use then refused" — refused on the FIRST attempt."""
        org_id, agent = await _make_agent(db, sandbox=True)
        result = await self._issue(db, org_id, agent, "sbx-3")

        consumed = await AuthorityConsumptionService(
            db, server_secret=SERVER_SECRET
        ).consume(
            authority_token=result.authority_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(recipient="acct-sbx-3"),
            execution_ref="exec-sbx-3",
        )
        assert consumed.outcome is ConsumptionOutcome.REJECTED
        assert consumed.rejection_reason is (
            DecisionReason.GRANT_SANDBOX_EXECUTION_DENIED
        )
        assert not consumed.may_execute
        assert consumed.consumption_audit_id is None

    async def test_promotion_cannot_launder_old_sandbox_authority(self, db) -> None:
        """The provenance was SIGNED, so promoting the agent cannot edit it."""
        org_id, agent = await _make_agent(db, sandbox=True)
        result = await self._issue(db, org_id, agent, "sbx-4")

        # Promote the principal to production, exactly as an operator would.
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET metadata = $2::JSONB WHERE id = $1",
                agent.id,
                json.dumps(
                    {
                        "sandbox": False,
                        "production_approval_reference": "promoted",
                        "production_approved_at": "2026-02-01T00:00:00Z",
                        "production_approved_by": "operator",
                    }
                ),
            )
        promoted = await db.get_agent_by_id(agent.id)
        assert not promoted.metadata.get("sandbox")

        consumed = await AuthorityConsumptionService(
            db, server_secret=SERVER_SECRET
        ).consume(
            authority_token=result.authority_token,
            executor=executor(org_id),
            agent=promoted,
            action_type="financial_transaction",
            payload=payment_payload(recipient="acct-sbx-4"),
            execution_ref="exec-sbx-4",
        )
        assert consumed.outcome is ConsumptionOutcome.REJECTED
        assert consumed.rejection_reason is (
            DecisionReason.GRANT_SANDBOX_EXECUTION_DENIED
        )

    async def test_demotion_also_stops_consumption(self, db) -> None:
        """The check runs in both directions: current state counts too."""
        org_id, agent = await _make_agent(db, sandbox=False)
        result = await self._issue(db, org_id, agent, "sbx-5")
        assert _token_claims(result.authority_token)["sandbox"] is False

        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET metadata = '{\"sandbox\": true}'::JSONB WHERE id = $1",
                agent.id,
            )
        sandboxed = await db.get_agent_by_id(agent.id)

        consumed = await AuthorityConsumptionService(
            db, server_secret=SERVER_SECRET
        ).consume(
            authority_token=result.authority_token,
            executor=executor(org_id),
            agent=sandboxed,
            action_type="financial_transaction",
            payload=payment_payload(recipient="acct-sbx-5"),
            execution_ref="exec-sbx-5",
        )
        assert consumed.outcome is ConsumptionOutcome.REJECTED
        assert consumed.rejection_reason is (
            DecisionReason.GRANT_SANDBOX_EXECUTION_DENIED
        )

    async def test_the_sandbox_decision_audit_is_excluded_from_anchoring(
        self, db
    ) -> None:
        """test_request is the anchor worker's existing exclusion key."""
        org_id, agent = await _make_agent(db, sandbox=True)
        result = await self._issue(db, org_id, agent, "sbx-6")

        audit_row = await get_authority_decision_audit_row(
            db, result.decision_audit_id
        )
        metadata = json.loads(audit_row["metadata"])
        assert metadata["test_request"] is True
        assert metadata["sandbox"] is True

    async def test_a_production_principal_is_unaffected(self, db) -> None:
        """The whole point is that ordinary agents keep working."""
        org_id, agent = await _make_agent(db, sandbox=False)
        result = await self._issue(db, org_id, agent, "sbx-7")
        assert _token_claims(result.authority_token)["sandbox"] is False

        consumed = await AuthorityConsumptionService(
            db, server_secret=SERVER_SECRET
        ).consume(
            authority_token=result.authority_token,
            executor=executor(org_id),
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(recipient="acct-sbx-7"),
            execution_ref="exec-sbx-7",
        )
        assert consumed.outcome is ConsumptionOutcome.AUTHORISED
        assert consumed.may_execute

        audit_row = await get_authority_decision_audit_row(
            db, result.decision_audit_id
        )
        metadata = json.loads(audit_row["metadata"])
        assert "test_request" not in metadata
        assert "sandbox" not in metadata


class TestRealHttpIssuanceIdempotency:
    """Two real requests, each reloading the agent from the database.

    The stale-in-memory shortcut hides the defect this covers: the FIRST
    request writes an authority decision audit row, an AFTER INSERT trigger
    bumps the agent's counters, and a retry that reloads the agent would
    compute a different policy revision — which ``issuance_digest`` binds —
    and be refused as a *different* request.
    """

    @staticmethod
    def _endpoint():
        return TestTheEndpointItselfEnforcesCorePolicy._route("/authority/evaluate")

    async def _post(self, db, org_id, agent_id, ref, payload):
        from api.routes.authority import EvaluateRequest

        return await self._endpoint()(
            body=EvaluateRequest(
                agent_id=agent_id,
                action_type="financial_transaction",
                payload=payload,
                issuance_ref=ref,
            ),
            database=db,
            auth={"org_id": org_id, "api_key_id": "k", "scopes": ["write"]},
        )

    async def test_an_identical_retry_recovers_the_same_grant(self, db) -> None:
        org_id, agent = await _make_agent(db, sandbox=False)
        body = payment_payload(recipient="acct-idem")

        first = await self._post(db, org_id, agent.id, "IDEM-1", body)
        assert first["decision"] == "allow"
        assert first["grant_id"]

        # The agent is reloaded inside the endpoint, so the retry sees the
        # row as the first request left it — counters bumped and all.
        reloaded = await db.get_agent_by_id(agent.id)
        assert reloaded.total_actions_count > 0

        second = await self._post(db, org_id, agent.id, "IDEM-1", body)
        assert second["decision"] == "allow"
        assert second["grant_id"] == first["grant_id"]
        assert second["reasons"] == []

        async with db.acquire() as conn:
            reservations = await conn.fetchval(
                "SELECT count(*) FROM spend_reservations WHERE agent_id = $1", agent.id
            )
            grants = await conn.fetchval(
                "SELECT count(*) FROM execution_authority_grants WHERE agent_id = $1",
                agent.id,
            )
        assert reservations == 1
        assert grants == 1

    async def test_a_third_identical_retry_is_still_the_same_grant(self, db) -> None:
        """Not a one-off: the property has to hold on every retry."""
        org_id, agent = await _make_agent(db, sandbox=False)
        body = payment_payload(recipient="acct-idem-3")
        seen = [
            (await self._post(db, org_id, agent.id, "IDEM-2", body))["grant_id"]
            for _ in range(3)
        ]
        assert len(set(seen)) == 1
        async with db.acquire() as conn:
            assert (
                await conn.fetchval(
                    "SELECT count(*) FROM spend_reservations WHERE agent_id = $1",
                    agent.id,
                )
                == 1
            )

    async def test_changed_material_on_the_same_reference_still_conflicts(
        self, db
    ) -> None:
        """Idempotency must not become "reuse a reference for anything"."""
        org_id, agent = await _make_agent(db, sandbox=False)
        first = await self._post(
            db, org_id, agent.id, "IDEM-3", payment_payload(recipient="acct-a")
        )
        assert first["decision"] == "allow"

        second = await self._post(
            db, org_id, agent.id, "IDEM-3", payment_payload(recipient="acct-b")
        )
        assert second["decision"] == "block"
        assert second["authority_token"] is None
        assert second["grant_id"] is None

    async def test_a_real_policy_change_prevents_unsafe_reuse(self, db) -> None:
        """A genuine policy change must NOT be absorbed by idempotency."""
        org_id, agent = await _make_agent(db, sandbox=False)
        body = payment_payload(amount="500.00", recipient="acct-policy")
        first = await self._post(db, org_id, agent.id, "IDEM-4", body)
        assert first["decision"] == "allow"

        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET per_action_limit_usd = 1 WHERE id = $1", agent.id
            )

        second = await self._post(db, org_id, agent.id, "IDEM-4", body)
        assert second["decision"] == "block"
        assert second["authority_token"] is None

        # And the grant issued under the old policy is no longer spendable.
        # The route minted that token with the application's own secret, so
        # consumption has to present the same one.
        import api.legacy_main as legacy

        consumed = await AuthorityConsumptionService(
            db, server_secret=list(legacy.SERVER_SECRETS)
        ).consume(
            authority_token=first["authority_token"],
            # The same credential identity the route bound the grant to.
            executor=executor(org_id, key_id="k"),
            agent=await db.get_agent_by_id(agent.id),
            action_type="financial_transaction",
            payload=body,
            execution_ref="exec-idem-4",
        )
        assert consumed.outcome is ConsumptionOutcome.REJECTED
        assert consumed.rejection_reason is DecisionReason.POLICY_HASH_MISMATCH


#: The grant these hand-built events describe, and one that they do not.
#: Named rather than inlined so the fixture bodies and the assertions cannot
#: drift apart, and so no call site reads like a credential assignment.
_CHAIN_GRANT = "grant-1"
_UNRELATED_GRANT = "grant-OTHER"


class TestEvidenceChainSemanticContinuity:
    """A valid parent hash proves ORDER, not that it is one story.

    A consumption of grant B can be signed as a child of the decision for
    grant A: every hash checks out and the history is a fabrication. So
    both the producer and an independent verifier compare the facts.
    """

    @staticmethod
    def _key():
        return load_evidence_signing_key(environment="test")

    async def _grant(self, db, org_id, agent, ref, *, consume_it=True):
        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(recipient=f"acct-{ref}"),
            executor=executor(org_id),
            issuance_ref=ref,
        )
        assert issued.decision is Decision.ALLOW
        if consume_it:
            await AuthorityConsumptionService(db, server_secret=SERVER_SECRET).consume(
                authority_token=issued.authority_token,
                executor=executor(org_id),
                agent=agent,
                action_type="financial_transaction",
                payload=payment_payload(recipient=f"acct-{ref}"),
                execution_ref=f"exec-{ref}",
            )
        return (
            issued,
            await get_authority_decision(db, issued.decision_audit_id),
            await AuthorityStore(db).get(issued.grant_id),
        )

    async def test_the_producer_refuses_to_graft_one_grant_onto_another(
        self, db, org_and_agent
    ) -> None:
        """The adversarial case, with two genuinely independent grants."""
        org_id, agent = org_and_agent
        key = self._key()
        _a, decision_a, _grant_a = await self._grant(
            db, org_id, agent, "sem-A", consume_it=False
        )
        _b, _decision_b, grant_b = await self._grant(db, org_id, agent, "sem-B")

        with pytest.raises(EvidenceError, match="different histories"):
            build_evidence_chain(decision_a, key=key, grant=grant_b)

    async def test_the_correct_chain_still_verifies(self, db, org_and_agent) -> None:
        org_id, agent = org_and_agent
        key = self._key()
        _b, decision_b, grant_b = await self._grant(db, org_id, agent, "sem-C")
        chain = build_evidence_chain(decision_b, key=key, grant=grant_b)
        assert chain.verify(public_key_b64=key.public_key_b64)

    # -- the verifier, tested WITHOUT trusting the builder ----------------

    @staticmethod
    def _sign(key, event_type, body, parent=None, event_id="ev"):
        return sign_evidence_event(
            event_id=event_id,
            event_type=event_type,
            body=body,
            key=key,
            recorded_at=datetime(2026, 4, 17, 12, 0, tzinfo=UTC),
            parent=parent,
        )

    def _decision_body(self, **overrides):
        body = {
            "audit_id": "aaaaaaaa-0000-0000-0000-000000000001",
            "agent_id": "11111111-2222-3333-4444-555555555555",
            "organisation_id": "22222222-3333-4444-5555-666666666666",
            "action_type": "financial_transaction",
            "domain": "payment",
            "decision": "allow",
            "execution_action_hash": "a" * 64,
            "policy_snapshot_format": "inntris-payment-authority-policy-v1",
            "policy_snapshot_digest": "b" * 64,
            "grant_id": _CHAIN_GRANT,
            "executor_binding_digest": "f" * 64,
        }
        body.update(overrides)
        return DecisionEvidenceV3(**body).to_body()

    def _consumption_body(self, **overrides):
        body = {
            "consumption_audit_id": "cccccccc-0000-0000-0000-000000000001",
            "grant_id": _CHAIN_GRANT,
            "execution_action_hash": "a" * 64,
            "execution_ref": "exec-1",
            "outcome": "authorised",
            "executor_binding_digest": "f" * 64,
            "agent_id": "11111111-2222-3333-4444-555555555555",
            "organisation_id": "22222222-3333-4444-5555-666666666666",
        }
        body.update(overrides)
        return ConsumptionEvidenceV3(**body).to_body()

    def _chain(self, key, *, consumption_overrides=None, outcome_grant=None):
        decision = self._sign(
            key, EvidenceEventType.DECISION, self._decision_body(), event_id="d-1"
        )
        consumption = self._sign(
            key,
            EvidenceEventType.CONSUMPTION,
            self._consumption_body(**(consumption_overrides or {})),
            parent=decision,
            event_id="c-1",
        )
        outcome = None
        if outcome_grant is not None:
            outcome = self._sign(
                key,
                EvidenceEventType.OUTCOME,
                OutcomeEvidenceV3(
                    grant_id=outcome_grant, outcome_state="succeeded"
                ).to_body(),
                parent=consumption,
                event_id="o-1",
            )
        return AuthorityEvidenceChain(decision, consumption, outcome)

    def test_a_correctly_signed_chain_with_valid_parents_verifies(self, key) -> None:
        assert self._chain(key).verify(public_key_b64=key.public_key_b64)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("grant_id", _UNRELATED_GRANT),
            ("execution_action_hash", "9" * 64),
            ("executor_binding_digest", "0" * 64),
            ("agent_id", "99999999-9999-9999-9999-999999999999"),
            ("organisation_id", "88888888-8888-8888-8888-888888888888"),
        ],
    )
    def test_a_mismatched_consumption_fails_despite_valid_parent_hashes(
        self, key, field, value
    ) -> None:
        """Every hash is correct. The story is not."""
        chain = self._chain(key, consumption_overrides={field: value})
        # The parent link itself is genuinely valid ...
        assert chain.consumption.parent_payload_hash == (
            chain.decision.evidence_payload_hash
        )
        # ... and verification still refuses it.
        result = chain.verify(public_key_b64=key.public_key_b64)
        assert not result
        assert any(f"consumption {field}" in reason for reason in result.failures)

    def test_a_consumption_cannot_follow_a_block(self, key) -> None:
        """Authority that was refused cannot have been spent."""
        decision = self._sign(
            key,
            EvidenceEventType.DECISION,
            self._decision_body(decision="block", grant_id=None),
            event_id="d-block",
        )
        consumption = self._sign(
            key,
            EvidenceEventType.CONSUMPTION,
            self._consumption_body(),
            parent=decision,
            event_id="c-block",
        )
        result = AuthorityEvidenceChain(decision, consumption).verify(
            public_key_b64=key.public_key_b64
        )
        assert not result
        assert any("not an allow" in reason for reason in result.failures)

    def test_a_mismatched_outcome_grant_fails(self, key) -> None:
        chain = self._chain(key, outcome_grant=_UNRELATED_GRANT)
        result = chain.verify(public_key_b64=key.public_key_b64)
        assert not result
        assert any("outcome grant_id" in reason for reason in result.failures)

    def test_a_matching_outcome_grant_verifies(self, key) -> None:
        assert self._chain(key, outcome_grant=_CHAIN_GRANT).verify(
            public_key_b64=key.public_key_b64
        )

    def test_the_verifier_reads_only_signed_payloads(self, key) -> None:
        """Usable by a third party holding events and a public key.

        Handed plain dictionaries rather than the library's own objects,
        the same continuity rules apply — so the checks cannot be said to
        depend on the producer's types.
        """
        chain = self._chain(
            key, consumption_overrides={"grant_id": _UNRELATED_GRANT}
        )
        failures = evidence_chain_continuity_failures(
            decision=chain.decision.as_public_dict(),
            consumption=chain.consumption.as_public_dict(),
        )
        assert any("grant_id" in reason for reason in failures)


class TestAuthorityEvidenceSurvivesAuthorisedErasure:
    """Privacy erasure must not destroy forensic authority evidence.

    ``app.erase_personal_data`` is deliberately authorised to replace
    ``audit_logs.payload`` and ``metadata`` with a tombstone. That is
    correct and is not weakened here. It does mean ``audit_logs.payload``
    is not an immutable source, so the authority commitment lives in
    ``authority_decision_evidence`` — which carries identifiers, digests
    and the decision, and no request content for erasure to remove.
    """

    @staticmethod
    def _key():
        return load_evidence_signing_key(environment="test")

    @staticmethod
    async def _erase(org_id, agent_id):
        """The real mechanism, through an authorised operator connection."""
        from api.erasure import erase_personal_data

        operator_dsn = os.getenv("ALEMBIC_DATABASE_URL")
        if not operator_dsn:
            pytest.skip("authorised erasure needs ALEMBIC_DATABASE_URL")
        conn = await asyncpg.connect(operator_dsn)
        try:
            return await erase_personal_data(
                conn,
                organization_id=org_id,
                agent_id=agent_id,
                requested_by="phase-4-hardening-test",
                legal_basis="gdpr_art17",
                reason="authority evidence survival test",
            )
        finally:
            await conn.close()

    async def test_a_decision_receipt_survives_erasure_byte_for_byte(
        self, db
    ) -> None:
        org_id, agent = await _make_agent(db, sandbox=False)
        key = self._key()
        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(recipient="acct-erase"),
            executor=executor(org_id),
            issuance_ref="erase-1",
        )
        before = build_decision_evidence(
            await get_authority_decision(db, issued.decision_audit_id), key=key
        )
        assert verify_evidence_event(before, public_key_b64=key.public_key_b64)

        result = await self._erase(org_id, agent.id)
        assert result.rows_affected >= 1

        # The request record really was tombstoned — this is not a no-op test.
        audit_row = await get_authority_decision_audit_row(
            db, issued.decision_audit_id
        )
        assert json.loads(audit_row["payload"])["erased"] is True

        after = build_decision_evidence(
            await get_authority_decision(db, issued.decision_audit_id), key=key
        )
        assert after.as_public_dict() == before.as_public_dict()
        assert verify_evidence_event(after, public_key_b64=key.public_key_b64)

    async def test_a_block_receipt_also_survives_erasure(self, db) -> None:
        org_id, agent = await _make_agent(db, sandbox=False)
        key = self._key()
        blocked = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(amount="999999.00", recipient="acct-erase-b"),
            executor=executor(org_id),
            issuance_ref="erase-2",
        )
        assert blocked.decision is Decision.BLOCK
        before = build_decision_evidence(
            await get_authority_decision(db, blocked.decision_audit_id), key=key
        )

        await self._erase(org_id, agent.id)

        after = build_decision_evidence(
            await get_authority_decision(db, blocked.decision_audit_id), key=key
        )
        assert after.as_public_dict() == before.as_public_dict()

    async def test_the_evidence_row_retains_no_request_content(self, db) -> None:
        """Digests and identifiers only — nothing erasure exists to remove."""
        org_id, agent = await _make_agent(db, sandbox=False)
        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(amount="77.00", recipient="secret-payee-xyz"),
            executor=executor(org_id),
            issuance_ref="erase-3",
        )
        record = await get_authority_decision(db, issued.decision_audit_id)
        serialised = json.dumps(json.loads(record["decision_body"]))
        assert "secret-payee-xyz" not in serialised
        assert "77.00" not in serialised
        for leaked in ("recipient", "amount", "currency", "request_ip", "user_agent"):
            assert leaked not in serialised

    async def test_the_evidence_row_is_append_only(self, db) -> None:
        org_id, agent = await _make_agent(db, sandbox=False)
        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(recipient="acct-append"),
            executor=executor(org_id),
            issuance_ref="erase-4",
        )
        for statement in (
            "UPDATE authority_decision_evidence SET decision_body = '{}'::JSONB "
            "WHERE audit_log_id = $1",
            "DELETE FROM authority_decision_evidence WHERE audit_log_id = $1",
        ):
            with pytest.raises(asyncpg.PostgresError):
                async with db.acquire() as conn:
                    await conn.execute(statement, issued.decision_audit_id)

    async def test_erasure_still_does_its_job(self, db) -> None:
        """The guard is not weakened: personal request content still goes."""
        org_id, agent = await _make_agent(db, sandbox=False)
        await AuthorityEvaluationService(db, server_secret=SERVER_SECRET).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(recipient="acct-erase-5"),
            executor=executor(org_id),
            issuance_ref="erase-5",
        )
        await self._erase(org_id, agent.id)
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT payload, request_ip, request_user_agent FROM audit_logs "
                "WHERE agent_id = $1",
                agent.id,
            )
        assert rows
        for row in rows:
            assert json.loads(row["payload"])["erased"] is True
            assert row["request_ip"] is None
            assert row["request_user_agent"] is None


class TestForensicEvidenceIdentityCannotContradict:
    """The database, not the writer, guarantees these facts agree.

    Before 0021 the table had three independent foreign keys plus the same
    three identities repeated inside ``decision_body``, and nothing tied
    them together — a row could name one agent in a column and another in
    the body, and every individual constraint was satisfied. Evidence whose
    identities can disagree is not evidence.
    """

    async def _row(self, db, agent, org_id, ref="fx-1"):
        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(recipient=f"acct-{ref}"),
            executor=executor(org_id),
            issuance_ref=ref,
        )
        return issued, await get_authority_decision(db, issued.decision_audit_id)

    @staticmethod
    async def _insert(db, **columns):
        async with db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO authority_decision_evidence (
                    audit_log_id, agent_id, org_id, recorded_at,
                    decision_body, sandbox, audit_action_type
                ) VALUES ($1, $2, $3, $4, $5::JSONB, FALSE, $6)
                """,
                columns["audit_log_id"],
                columns["agent_id"],
                columns["org_id"],
                columns["recorded_at"],
                json.dumps(columns["decision_body"]),
                columns.get("audit_action_type", "authority_decision"),
            )

    async def test_the_honest_row_is_accepted(self, db) -> None:
        """The constraints must not reject correct evidence."""
        org_id, agent = await _make_agent(db, sandbox=False)
        _issued, record = await self._row(db, agent, org_id, "fx-ok")
        assert record is not None
        body = json.loads(record["decision_body"])
        assert body["agent_id"] == str(agent.id)
        assert body["organisation_id"] == str(org_id)
        assert body["audit_id"] == str(record["audit_log_id"])

    async def test_a_cross_agent_audit_row_is_refused(self, db) -> None:
        """The audit row must belong to the agent the evidence names."""
        org_id, agent = await _make_agent(db, sandbox=False)
        _other_org, other = await _make_agent(db, sandbox=False, org_id=org_id)
        _issued, record = await self._row(db, agent, org_id, "fx-agent")

        body = json.loads(record["decision_body"])
        body["agent_id"] = str(other.id)
        with pytest.raises(asyncpg.PostgresError):
            await self._insert(
                db,
                audit_log_id=record["audit_log_id"],
                agent_id=other.id,
                org_id=org_id,
                recorded_at=record["recorded_at"],
                decision_body=body,
            )

    async def test_a_cross_org_ownership_pair_is_refused(self, db) -> None:
        """(agent, org) must be a pair the agents table actually asserts."""
        org_id, agent = await _make_agent(db, sandbox=False)
        foreign_org, _foreign = await _make_agent(db, sandbox=False)
        _issued, record = await self._row(db, agent, org_id, "fx-org")

        body = json.loads(record["decision_body"])
        body["organisation_id"] = str(foreign_org)
        with pytest.raises(asyncpg.PostgresError):
            await self._insert(
                db,
                audit_log_id=record["audit_log_id"],
                agent_id=agent.id,
                org_id=foreign_org,
                recorded_at=record["recorded_at"],
                decision_body=body,
            )

    async def test_an_unknown_audit_id_is_refused(self, db) -> None:
        org_id, agent = await _make_agent(db, sandbox=False)
        _issued, record = await self._row(db, agent, org_id, "fx-audit")
        stranger = uuid4()
        body = json.loads(record["decision_body"])
        body["audit_id"] = str(stranger)
        with pytest.raises(asyncpg.PostgresError):
            await self._insert(
                db,
                audit_log_id=stranger,
                agent_id=agent.id,
                org_id=org_id,
                recorded_at=record["recorded_at"],
                decision_body=body,
            )

    @pytest.mark.parametrize(
        "field", ["audit_id", "agent_id", "organisation_id"]
    )
    async def test_a_body_identity_that_contradicts_its_columns_is_refused(
        self, db, field
    ) -> None:
        """The receipt follows the body, so the body must match the row."""
        org_id, agent = await _make_agent(db, sandbox=False)
        _issued, record = await self._row(db, agent, org_id, f"fx-body-{field}")

        body = json.loads(record["decision_body"])
        body[field] = str(uuid4())
        with pytest.raises(asyncpg.PostgresError):
            await self._insert(
                db,
                audit_log_id=record["audit_log_id"],
                agent_id=agent.id,
                org_id=org_id,
                recorded_at=record["recorded_at"],
                decision_body=body,
            )

    async def test_a_non_authority_audit_row_is_refused(self, db) -> None:
        """Evidence may only point at a row that IS an authority decision."""
        org_id, agent = await _make_agent(db, sandbox=False)
        async with db.acquire() as conn:
            ordinary = await conn.fetchval(
                """
                INSERT INTO audit_logs (
                    agent_id, action_type, action_hash, payload, verdict,
                    verdict_reason, signature, signature_valid,
                    trust_score_at_time, metadata
                ) VALUES ($1, 'api_call', $2, '{}'::JSONB, 'approved', 'ordinary',
                          'X', FALSE, 50, '{"non_cryptographic": true}'::JSONB)
                RETURNING id
                """,
                agent.id,
                "c" * 64,
            )
        body = {
            "audit_id": str(ordinary),
            "agent_id": str(agent.id),
            "organisation_id": str(org_id),
        }
        with pytest.raises(asyncpg.PostgresError):
            await self._insert(
                db,
                audit_log_id=ordinary,
                agent_id=agent.id,
                org_id=org_id,
                recorded_at=datetime.now(UTC),
                decision_body=body,
            )

    async def test_the_audit_kind_column_cannot_be_repointed(self, db) -> None:
        """The constant the composite key matches on is pinned."""
        org_id, agent = await _make_agent(db, sandbox=False)
        _issued, record = await self._row(db, agent, org_id, "fx-kind")
        with pytest.raises(asyncpg.PostgresError):
            await self._insert(
                db,
                audit_log_id=record["audit_log_id"],
                agent_id=agent.id,
                org_id=org_id,
                recorded_at=record["recorded_at"],
                decision_body=json.loads(record["decision_body"]),
                audit_action_type="api_call",
            )

    async def test_the_tenant_role_cannot_insert_forensic_evidence(
        self, db
    ) -> None:
        """The writer is the trusted runtime role, not the tenant session."""
        async with db.acquire() as conn:
            granted = await conn.fetchval(
                """
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.role_table_grants
                    WHERE table_name = 'authority_decision_evidence'
                      AND grantee = 'inntris_api'
                      AND privilege_type = 'INSERT'
                )
                """
            )
        assert granted is False


class TestForensicIdentityFailsClosedOnNull:
    """A CHECK accepts UNKNOWN, so plain equality does not fail closed.

    ``decision_body ->> 'agent_id' = agent_id::TEXT`` yields SQL NULL when
    the key is absent OR its value is JSON null, and ``NULL = <value>`` is
    UNKNOWN, which a CHECK accepts. The constraint therefore enforced "if
    the body states an identity it must match" and said nothing about a
    body that states none.

    That is the wrong default for a forensic record: the receipt is built
    from ``decision_body``, so a body that cannot say who it is about is
    not a permissive edge case. ``IS NOT DISTINCT FROM`` compares NULL as
    a value, returning FALSE rather than UNKNOWN.
    """

    async def _audit_row(self, db, agent):
        async with db.acquire() as conn:
            return await conn.fetchval(
                """
                INSERT INTO audit_logs (
                    agent_id, action_type, action_hash, payload, verdict,
                    verdict_reason, signature, signature_valid,
                    trust_score_at_time, metadata
                ) VALUES ($1, 'authority_decision', $2, '{}'::JSONB, 'approved',
                          'null-identity test', 'X', FALSE, 0,
                          '{"test_request": true}'::JSONB)
                RETURNING id
                """,
                agent.id,
                "b" * 64,
            )

    @staticmethod
    async def _insert(db, audit_id, agent, org_id, body):
        async with db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO authority_decision_evidence (
                    audit_log_id, agent_id, org_id, recorded_at,
                    decision_body, sandbox, audit_action_type
                ) VALUES ($1, $2, $3, $4, $5::JSONB, TRUE, 'authority_decision')
                """,
                audit_id,
                agent.id,
                org_id,
                datetime.now(UTC),
                json.dumps(body),
            )

    def _body(self, audit_id, agent, org_id, *, omit=None, nullify=None):
        body = {
            "audit_id": str(audit_id),
            "agent_id": str(agent.id),
            "organisation_id": str(org_id),
        }
        if omit:
            body.pop(omit)
        if nullify:
            body[nullify] = None
        return body

    async def test_the_exact_matching_body_is_accepted(self, db) -> None:
        """The constraints must still admit correct evidence."""
        org_id, agent = await _make_agent(db, sandbox=False)
        audit_id = await self._audit_row(db, agent)
        await self._insert(
            db, audit_id, agent, org_id, self._body(audit_id, agent, org_id)
        )
        async with db.acquire() as conn:
            assert (
                await conn.fetchval(
                    "SELECT count(*) FROM authority_decision_evidence "
                    "WHERE audit_log_id = $1",
                    audit_id,
                )
                == 1
            )

    @pytest.mark.parametrize(
        "field", ["audit_id", "agent_id", "organisation_id"]
    )
    async def test_a_missing_identity_is_rejected(self, db, field) -> None:
        org_id, agent = await _make_agent(db, sandbox=False)
        audit_id = await self._audit_row(db, agent)
        with pytest.raises(asyncpg.PostgresError):
            await self._insert(
                db,
                audit_id,
                agent,
                org_id,
                self._body(audit_id, agent, org_id, omit=field),
            )

    @pytest.mark.parametrize(
        "field", ["audit_id", "agent_id", "organisation_id"]
    )
    async def test_a_json_null_identity_is_rejected(self, db, field) -> None:
        org_id, agent = await _make_agent(db, sandbox=False)
        audit_id = await self._audit_row(db, agent)
        with pytest.raises(asyncpg.PostgresError):
            await self._insert(
                db,
                audit_id,
                agent,
                org_id,
                self._body(audit_id, agent, org_id, nullify=field),
            )

    async def test_an_entirely_identityless_body_is_rejected(self, db) -> None:
        """The degenerate case: evidence that says nothing about itself."""
        org_id, agent = await _make_agent(db, sandbox=False)
        audit_id = await self._audit_row(db, agent)
        with pytest.raises(asyncpg.PostgresError):
            await self._insert(db, audit_id, agent, org_id, {})


class TestForensicEvidenceWriteIsAtomic:
    """The decision row and its evidence commit together or not at all."""

    async def test_a_conflicting_evidence_row_rolls_the_decision_back(
        self, db
    ) -> None:
        """No ON CONFLICT DO NOTHING: a conflict must not commit half a write.

        Forced by making the evidence insert fail on a real constraint —
        here, an audit id already carrying evidence. The decision audit row
        written moments earlier in the same transaction must be gone too.
        """
        import api.persistence.authority_decisions as decisions

        org_id, agent = await _make_agent(db, sandbox=False)
        service = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)

        original_body = decisions.evidence_body
        seen: dict[str, object] = {}

        def _steal_then_collide(payload, *, audit_id, agent_id):
            # Record the audit id the transaction is using, then hand back a
            # body that violates the body/column identity constraint.
            seen["audit_id"] = audit_id
            body = dict(original_body(payload, audit_id=audit_id, agent_id=agent_id))
            body["audit_id"] = str(uuid4())
            return body

        decisions.evidence_body = _steal_then_collide
        try:
            with pytest.raises(asyncpg.PostgresError):
                await service.evaluate(
                    agent=agent,
                    action_type="financial_transaction",
                    payload=payment_payload(recipient="acct-atomic"),
                    executor=executor(org_id),
                    issuance_ref="atomic-1",
                )
        finally:
            decisions.evidence_body = original_body

        assert "audit_id" in seen
        async with db.acquire() as conn:
            audit_rows = await conn.fetchval(
                "SELECT count(*) FROM audit_logs WHERE id = $1", seen["audit_id"]
            )
            evidence_rows = await conn.fetchval(
                "SELECT count(*) FROM authority_decision_evidence "
                "WHERE audit_log_id = $1",
                seen["audit_id"],
            )
        # Neither half survived: the decision was never recorded at all.
        assert audit_rows == 0
        assert evidence_rows == 0

    async def test_the_insert_has_no_conflict_swallow(self) -> None:
        """Pinned: a silent DO NOTHING would hide exactly the above."""
        import api.persistence.authority_decisions as decisions

        assert "ON CONFLICT" not in decisions._INSERT_EVIDENCE.upper()


class TestSignedActionHashDurability:
    """The field means "a hash an agent signed and Core verified".

    Only a trusted internal caller that has already done that verification
    may supply one. It then has to survive to the receipt, or the claim is
    made and immediately lost.
    """

    _VERIFIED = "d" * 64

    async def test_a_verified_hash_reaches_the_receipt(self, db) -> None:
        org_id, agent = await _make_agent(db, sandbox=False)
        key = load_evidence_signing_key(environment="test")
        issued = await AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET
        ).evaluate(
            agent=agent,
            action_type="financial_transaction",
            payload=payment_payload(recipient="acct-sah"),
            executor=executor(org_id),
            issuance_ref="sah-1",
            verified_signed_action_hash=self._VERIFIED,
        )
        record = await get_authority_decision(db, issued.decision_audit_id)
        assert json.loads(record["decision_body"])["signed_action_hash"] == (
            self._VERIFIED
        )

        event = build_decision_evidence(record, key=key)
        assert event.payload["body"]["signed_action_hash"] == self._VERIFIED
        assert verify_evidence_event(event, public_key_b64=key.public_key_b64)

    async def test_the_service_authenticated_endpoint_emits_null(
        self, db
    ) -> None:
        """This surface verified no agent signature, so it claims none."""
        from api.routes.authority import EvaluateRequest

        org_id, agent = await _make_agent(db, sandbox=False)
        endpoint = TestTheEndpointItselfEnforcesCorePolicy._route(
            "/authority/evaluate"
        )
        response = await endpoint(
            body=EvaluateRequest(
                agent_id=agent.id,
                action_type="financial_transaction",
                payload=payment_payload(recipient="acct-sah-2"),
                issuance_ref="sah-2",
            ),
            database=db,
            auth={"org_id": org_id, "api_key_id": "k", "scopes": ["write"]},
        )
        assert response["decision"] == "allow"

        async with db.acquire() as conn:
            body = await conn.fetchval(
                """
                SELECT decision_body
                FROM authority_decision_evidence
                WHERE agent_id = $1
                  AND decision_body ->> 'grant_id' = $2
                """,
                agent.id,
                response["grant_id"],
            )
        assert body is not None
        assert json.loads(body)["signed_action_hash"] is None

    def test_no_request_model_accepts_the_field(self) -> None:
        """A caller cannot forge it: there is no field to put it in."""
        from api.routes.authority import ConsumeRequest, EvaluateRequest

        assert "signed_action_hash" not in EvaluateRequest.model_fields
        assert "verified_signed_action_hash" not in EvaluateRequest.model_fields
        assert "signed_action_hash" not in ConsumeRequest.model_fields

    def test_the_route_hardcodes_none(self) -> None:
        """And the one call site pins it, so a future edit is visible."""
        source = pathlib.Path("api/routes/authority.py").read_text()
        assert "verified_signed_action_hash=None," in source
