"""Phase 3 — execution authority against a real PostgreSQL.

Gated the same way as the other database integration tests: they need
``INNTRIS_DB_INTEGRATION=1`` and a ``DATABASE_URL`` pointing at a database
migrated to head. Nothing here is simulated — the concurrency assertions
run genuinely concurrent transactions against the same rows and rely on
the database, not on test ordering, to pick a winner.

The invariant that matters most is the last one: two *different*
transactions competing for the same cumulative capacity must not both
observe the same headroom. That is not the same test as two callers
racing for one grant, and a system can pass the second while failing the
first.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

asyncpg = pytest.importorskip("asyncpg")

from asyncpg.exceptions import InterfaceError  # noqa: E402

from api.core.authority.decision import DecisionReason  # noqa: E402
from api.core.authority.grant import GrantStatus  # noqa: E402
from api.core.authority.lifecycle import ConsumptionOutcome  # noqa: E402
from api.database import Database  # noqa: E402
from api.models import ActionVerdict, AuditLogEntry  # noqa: E402
from api.persistence.authority_store import (  # noqa: E402
    MAX_EXECUTION_AUTHORITY_TTL,
    AuthorityStore,
    GrantLifetimeError,
    IssueOutcome,
    OutcomeState,
    ResolvedAuthorityEvidence,
    authority_scope_digest,
    clamp_grant_expiry,
    issuance_digest,
)

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")
# A DSN whose role holds DELETE, used only to prove the append-only trigger
# fires for a role that privilege alone would not stop.
MIGRATOR_URL = os.getenv("ALEMBIC_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="authority persistence tests require INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)

DIGEST_A = "a" * 64
POLICY_HASH = "b" * 64
BINDING = "c" * 64
FORMAT = "inntris-payment-authority-policy-v1"

#: Set by the fixture so helpers do not have to thread the organisation
#: through every call. Identity still comes from the fixture, never a payload.
ORG_BY_AGENT: dict[UUID, UUID] = {}


def action_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=2, max_size=12)
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
async def org_and_agent(db: Database):
    async for pair in _make_org_and_agent(db):
        yield pair


async def _make_org_and_agent(db: Database):
    """A fresh organisation and its production-approved agent."""
    org_id = uuid4()
    agent_id = uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO organizations (
                id, name, billing_tier, contact_email, api_key_hash
            ) VALUES ($1, $2, 'enterprise', $3, $4)
            """,
            org_id,
            f"authority-test-{org_id}",
            f"authority-{org_id}@example.test",
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
            f"authority-agent-{agent_id}",
            secrets.token_bytes(32),
            hashlib.sha256(str(agent_id).encode()).hexdigest(),
            # Migration 014 requires a production-approved agent to carry its
            # approval metadata. Satisfy it rather than sandboxing the agent:
            # a sandbox agent is excluded from the very paths under test.
            json.dumps(
                {
                    "sandbox": False,
                    "production_approval_reference": "authority-persistence-test",
                    "production_approved_at": "2026-01-01T00:00:00Z",
                    "production_approved_by": "phase-3-test-fixture",
                }
            ),
        )
    ORG_BY_AGENT[agent_id] = org_id
    yield org_id, agent_id


@pytest.fixture
async def second_org_and_agent(db: Database):
    """A second, unrelated tenant for the isolation assertions."""
    async for pair in _make_org_and_agent(db):
        yield pair


def _static_policy(policy_hash: str = POLICY_HASH):
    """A resolver standing in for 'what does policy say right now'."""

    def resolver(_agent, _action_type, _domain):
        return policy_hash, "revision-1"

    return resolver


async def issue(
    store: AuthorityStore,
    agent_id: UUID,
    *,
    issuance_ref: str,
    org_id: UUID | None = None,
    amount: Decimal = Decimal("0"),
    seed: str = "act-1",
    daily_limit: Decimal = Decimal("10000"),
    scope_digest: str | None = None,
    policy_hash: str = POLICY_HASH,
    policy_revision: str = "revision-1",
    binding: str = BINDING,
    authority_expires_at: datetime | None = None,
    expires_at: datetime | None = None,
):
    now = datetime.now(UTC)
    return await store.issue(
        agent_id=agent_id,
        organisation_id=org_id if org_id is not None else ORG_BY_AGENT[agent_id],
        issuance_ref=issuance_ref,
        execution_action_hash=action_hash(seed),
        policy_hash=policy_hash,
        policy_snapshot_format=FORMAT,
        policy_revision=policy_revision,
        executor_binding_digest=binding,
        domain="payment",
        action_type="financial_transaction",
        expires_at=expires_at,
        authority_expires_at=authority_expires_at,
        minute_start=now.replace(second=0, microsecond=0),
        day_start=now.replace(hour=0, minute=0, second=0, microsecond=0),
        rate_limit_per_minute=1000,
        daily_limit_usd=daily_limit,
        amount_usd=amount,
        authority_scope_digest=scope_digest,
    )


class TestIssuanceIdempotency:
    async def test_a_first_issuance_creates_a_grant(self, db, org_and_agent) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        result = await issue(store, agent_id, issuance_ref="ref-1")
        assert result.outcome is IssueOutcome.ISSUED
        assert result.grant_id is not None
        assert result.authorises_execution

    async def test_an_identical_retry_returns_the_same_grant(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        first = await issue(store, agent_id, issuance_ref="ref-2", amount=Decimal("100"))
        second = await issue(store, agent_id, issuance_ref="ref-2", amount=Decimal("100"))
        assert second.outcome is IssueOutcome.IDEMPOTENT
        assert second.grant_id == first.grant_id

    async def test_an_idempotent_retry_reserves_no_further_capacity(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        await issue(store, agent_id, issuance_ref="ref-3", amount=Decimal("100"))
        await issue(store, agent_id, issuance_ref="ref-3", amount=Decimal("100"))
        async with db.acquire() as conn:
            reserved = await conn.fetchval(
                """
                SELECT COALESCE(SUM(amount_usd), 0) FROM spend_reservations
                WHERE agent_id = $1 AND status IN ('reserved', 'consumed')
                """,
                agent_id,
            )
        assert Decimal(reserved) == Decimal("100")

    async def test_changed_material_on_the_same_reference_conflicts(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        first = await issue(
            store, agent_id, issuance_ref="ref-4", amount=Decimal("100"), seed="act-a"
        )
        changed = await issue(
            store, agent_id, issuance_ref="ref-4", amount=Decimal("9999"), seed="act-a"
        )
        assert changed.outcome is IssueOutcome.CONFLICT
        assert changed.grant_id == first.grant_id
        assert not changed.authorises_execution

    async def test_a_changed_act_on_the_same_reference_conflicts(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        await issue(store, agent_id, issuance_ref="ref-5", seed="act-a")
        changed = await issue(store, agent_id, issuance_ref="ref-5", seed="act-b")
        assert changed.outcome is IssueOutcome.CONFLICT

    async def test_concurrent_identical_retries_yield_one_logical_grant(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        results = await asyncio.gather(
            *(
                issue(store, agent_id, issuance_ref="ref-race", amount=Decimal("50"))
                for _ in range(6)
            )
        )
        grant_ids = {r.grant_id for r in results}
        assert len(grant_ids) == 1, grant_ids
        assert sum(r.outcome is IssueOutcome.ISSUED for r in results) == 1
        assert all(r.authorises_execution for r in results)

        async with db.acquire() as conn:
            rows = await conn.fetchval(
                "SELECT COUNT(*) FROM execution_authority_grants WHERE agent_id = $1",
                agent_id,
            )
            reserved = await conn.fetchval(
                """
                SELECT COALESCE(SUM(amount_usd), 0) FROM spend_reservations
                WHERE agent_id = $1 AND status IN ('reserved', 'consumed')
                """,
                agent_id,
            )
        assert rows == 1
        assert Decimal(reserved) == Decimal("50"), "capacity reserved exactly once"


class TestCumulativeSpendCapacity:
    """Two DIFFERENT transactions competing for the same remaining capacity.

    This is a different failure mode from two callers racing for one
    grant: each transaction is legitimately its own act, and each on its
    own fits inside the limit. Only together do they exceed it. If both
    read the same headroom before either writes, both are authorised and
    the organisation is over its limit with no single request at fault.
    """

    async def test_two_transactions_cannot_both_take_the_same_headroom(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())

        # Remaining capacity 10,000. Two independent 7,000 transactions.
        first, second = await asyncio.gather(
            issue(
                store,
                agent_id,
                issuance_ref="tx-A",
                amount=Decimal("7000"),
                seed="tx-A",
                daily_limit=Decimal("10000"),
            ),
            issue(
                store,
                agent_id,
                issuance_ref="tx-B",
                amount=Decimal("7000"),
                seed="tx-B",
                daily_limit=Decimal("10000"),
            ),
        )

        outcomes = [first.outcome, second.outcome]
        assert outcomes.count(IssueOutcome.ISSUED) == 1, outcomes
        assert outcomes.count(IssueOutcome.REFUSED) == 1, outcomes

        refused = first if first.outcome is IssueOutcome.REFUSED else second
        assert refused.reason is DecisionReason.DAILY_LIMIT_EXCEEDED
        assert refused.grant_id is None

        async with db.acquire() as conn:
            reserved = await conn.fetchval(
                """
                SELECT COALESCE(SUM(amount_usd), 0) FROM spend_reservations
                WHERE agent_id = $1 AND status IN ('reserved', 'consumed')
                """,
                agent_id,
            )
            grants = await conn.fetchval(
                "SELECT COUNT(*) FROM execution_authority_grants WHERE agent_id = $1",
                agent_id,
            )
        assert Decimal(reserved) == Decimal("7000"), "the loser reserved nothing"
        assert grants == 1

    async def test_many_transactions_never_exceed_the_limit(
        self, db, org_and_agent
    ) -> None:
        """Eight concurrent 2,000s against 10,000: at most four may pass."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        results = await asyncio.gather(
            *(
                issue(
                    store,
                    agent_id,
                    issuance_ref=f"tx-{index}",
                    amount=Decimal("2000"),
                    seed=f"tx-{index}",
                    daily_limit=Decimal("10000"),
                )
                for index in range(8)
            )
        )
        issued = [r for r in results if r.outcome is IssueOutcome.ISSUED]
        assert len(issued) == 5, [r.outcome for r in results]

        async with db.acquire() as conn:
            reserved = await conn.fetchval(
                """
                SELECT COALESCE(SUM(amount_usd), 0) FROM spend_reservations
                WHERE agent_id = $1 AND status IN ('reserved', 'consumed')
                """,
                agent_id,
            )
        assert Decimal(reserved) <= Decimal("10000")

    async def test_a_refused_issuance_leaves_no_partial_state(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        await issue(
            store, agent_id, issuance_ref="fill", amount=Decimal("10000"), seed="fill"
        )
        refused = await issue(
            store, agent_id, issuance_ref="over", amount=Decimal("1"), seed="over"
        )
        assert refused.outcome is IssueOutcome.REFUSED

        async with db.acquire() as conn:
            leftover = await conn.fetchval(
                """
                SELECT COUNT(*) FROM execution_authority_grants
                WHERE agent_id = $1 AND issuance_ref = 'over'
                """,
                agent_id,
            )
        assert leftover == 0


class TestConsumption:
    async def test_a_grant_is_consumed_once(self, db, org_and_agent) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="c-1", seed="c-1")

        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("c-1"),
            executor_binding_digest=BINDING,
            execution_ref="exec-1",
        )
        assert result.outcome is ConsumptionOutcome.AUTHORISED
        assert result.spent_authority
        assert result.may_execute
        assert result.consumption_audit_id is not None

        row = await store.get(issued.grant_id)
        assert row["status"] == "consumed"
        assert row["consumption_audit_id"] == result.consumption_audit_id

    async def test_the_same_execution_ref_recovers_the_original(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="c-2", seed="c-2")
        first = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("c-2"),
            executor_binding_digest=BINDING,
            execution_ref="exec-2",
        )
        replay = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("c-2"),
            executor_binding_digest=BINDING,
            execution_ref="exec-2",
        )
        assert replay.outcome is ConsumptionOutcome.RECOVERED
        assert replay.consumption_audit_id == first.consumption_audit_id
        assert not replay.spent_authority, "recovery authorises nothing"
        assert not replay.may_execute

    async def test_a_different_execution_ref_is_refused(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="c-3", seed="c-3")
        await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("c-3"),
            executor_binding_digest=BINDING,
            execution_ref="exec-3",
        )
        second = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("c-3"),
            executor_binding_digest=BINDING,
            execution_ref="exec-3-different",
        )
        assert second.outcome is ConsumptionOutcome.REJECTED
        assert second.rejection_reason is DecisionReason.EXECUTION_REF_CONFLICT

    async def test_recovery_survives_the_grants_expiry(
        self, db, org_and_agent
    ) -> None:
        """The authority was spent while valid; this returns its record."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="c-4", seed="c-4")
        first = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("c-4"),
            executor_binding_digest=BINDING,
            execution_ref="exec-4",
        )
        recovered = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("c-4"),
            executor_binding_digest=BINDING,
            execution_ref="exec-4",
            at=datetime.now(UTC) + timedelta(days=30),
        )
        assert recovered.outcome is ConsumptionOutcome.RECOVERED
        assert recovered.consumption_audit_id == first.consumption_audit_id

    async def test_an_unknown_grant_is_refused(self, db, org_and_agent) -> None:
        _org, _agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        result = await store.consume(
            grant_id=uuid4(),
            execution_action_hash=action_hash("nope"),
            executor_binding_digest=BINDING,
            execution_ref="exec-x",
        )
        assert result.rejection_reason is DecisionReason.GRANT_NOT_FOUND

    async def test_a_mismatched_act_is_refused_before_lifecycle(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="c-5", seed="c-5")
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("a-different-act"),
            executor_binding_digest=BINDING,
            execution_ref="exec-5",
        )
        assert result.rejection_reason is DecisionReason.GRANT_ACTION_MISMATCH

    async def test_a_mismatched_executor_is_refused(self, db, org_and_agent) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="c-6", seed="c-6")
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("c-6"),
            executor_binding_digest="d" * 64,
            execution_ref="exec-6",
        )
        assert result.rejection_reason is DecisionReason.GRANT_EXECUTOR_MISMATCH

    async def test_an_expired_grant_is_refused(self, db, org_and_agent) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="c-7", seed="c-7")
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("c-7"),
            executor_binding_digest=BINDING,
            execution_ref="exec-7",
            at=datetime.now(UTC) + timedelta(days=1),
        )
        assert result.rejection_reason is DecisionReason.GRANT_EXPIRED

    async def test_a_revoked_grant_is_refused(self, db, org_and_agent) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="c-8", seed="c-8")
        assert await store.revoke(grant_id=issued.grant_id, reason="operator withdrew")
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("c-8"),
            executor_binding_digest=BINDING,
            execution_ref="exec-8",
        )
        assert result.rejection_reason is DecisionReason.GRANT_REVOKED

    async def test_consumption_marks_the_reservation_consumed(
        self, db, org_and_agent
    ) -> None:
        """The existing reservation lifecycle, reached through the same path."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(
            store, agent_id, issuance_ref="c-9", seed="c-9", amount=Decimal("250")
        )
        await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("c-9"),
            executor_binding_digest=BINDING,
            execution_ref="exec-9",
        )
        async with db.acquire() as conn:
            status = await conn.fetchval(
                "SELECT status FROM spend_reservations WHERE approval_token_id = $1",
                issued.approval_token_id,
            )
        assert status == "consumed"


class TestConcurrentConsumers:
    async def test_exactly_one_consumer_of_one_grant_wins(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="race-1", seed="race-1")

        results = await asyncio.gather(
            *(
                store.consume(
                    grant_id=issued.grant_id,
                    execution_action_hash=action_hash("race-1"),
                    executor_binding_digest=BINDING,
                    execution_ref=f"exec-race-{index}",
                )
                for index in range(6)
            )
        )
        authorised = [r for r in results if r.outcome is ConsumptionOutcome.AUTHORISED]
        assert len(authorised) == 1, [r.outcome for r in results]
        assert all(
            r.rejection_reason
            in (
                DecisionReason.GRANT_ALREADY_CONSUMED,
                DecisionReason.EXECUTION_REF_CONFLICT,
            )
            for r in results
            if r.outcome is ConsumptionOutcome.REJECTED
        )

        async with db.acquire() as conn:
            claims = await conn.fetchval(
                "SELECT COUNT(*) FROM approval_token_consumptions WHERE token_id = $1",
                issued.approval_token_id,
            )
        assert claims == 1

    async def test_concurrent_identical_retries_produce_one_consumption(
        self, db, org_and_agent
    ) -> None:
        """Same grant, same reference: one claim, everyone sees the result."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="race-2", seed="race-2")

        results = await asyncio.gather(
            *(
                store.consume(
                    grant_id=issued.grant_id,
                    execution_action_hash=action_hash("race-2"),
                    executor_binding_digest=BINDING,
                    execution_ref="exec-shared",
                )
                for _ in range(6)
            )
        )
        authorised = [r for r in results if r.outcome is ConsumptionOutcome.AUTHORISED]
        recovered = [r for r in results if r.outcome is ConsumptionOutcome.RECOVERED]
        assert len(authorised) == 1
        assert len(authorised) + len(recovered) == 6, [r.outcome for r in results]
        assert {r.consumption_audit_id for r in authorised + recovered} == {
            authorised[0].consumption_audit_id
        }


class TestCurrentPolicyDecidesNotTheSnapshot:
    async def test_a_policy_change_between_decision_and_consumption_refuses(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="p-1", seed="p-1")

        moved = AuthorityStore(db, current_policy_resolver=_static_policy("e" * 64))
        result = await moved.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("p-1"),
            executor_binding_digest=BINDING,
            execution_ref="exec-p1",
        )
        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.rejection_reason is DecisionReason.POLICY_HASH_MISMATCH

        async with db.acquire() as conn:
            claims = await conn.fetchval(
                "SELECT COUNT(*) FROM approval_token_consumptions WHERE token_id = $1",
                issued.approval_token_id,
            )
        assert claims == 0, "a refused consumption claims nothing"

    async def test_a_suspended_principal_cannot_consume(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="p-2", seed="p-2")
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET status = 'suspended' WHERE id = $1", agent_id
            )
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("p-2"),
            executor_binding_digest=BINDING,
            execution_ref="exec-p2",
        )
        assert result.rejection_reason is DecisionReason.AGENT_NOT_ACTIVE

    async def test_a_changed_delegated_scope_cannot_be_spent(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        at_decision = authority_scope_digest(
            issuer="external-issuer",
            external_reference_id="ref-1",
            artefact_digest=DIGEST_A,
            scope={"max_amount": "500.00", "currency": "USD"},
        )
        issued = await issue(
            store, agent_id, issuance_ref="p-3", seed="p-3", scope_digest=at_decision
        )

        narrowed = authority_scope_digest(
            issuer="external-issuer",
            external_reference_id="ref-1",
            artefact_digest=DIGEST_A,
            scope={"max_amount": "10.00", "currency": "USD"},
        )
        assert narrowed != at_decision
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("p-3"),
            executor_binding_digest=BINDING,
            execution_ref="exec-p3",
            authority_evidence=ResolvedAuthorityEvidence(scope_digest=narrowed),
        )
        assert result.rejection_reason is DecisionReason.AUTHORITY_SCOPE_EXCEEDED

    async def test_a_grant_with_delegation_needs_current_evidence(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        at_decision = authority_scope_digest(
            issuer="external-issuer",
            external_reference_id="ref-1",
            artefact_digest=DIGEST_A,
            scope={"max_amount": "500.00", "currency": "USD"},
        )
        issued = await issue(
            store, agent_id, issuance_ref="p-4", seed="p-4", scope_digest=at_decision
        )
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("p-4"),
            executor_binding_digest=BINDING,
            execution_ref="exec-p4",
            authority_evidence=None,
        )
        assert result.rejection_reason is DecisionReason.AUTHORITY_UNVERIFIED

    async def test_a_policy_change_racing_a_consumption_cannot_slip_through(
        self, db, org_and_agent
    ) -> None:
        """Either the change lands first and refuses, or after and finds it spent.

        There is no ordering in which the consumption is claimed under the
        old policy *and* the change is treated as having applied.
        """
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="p-5", seed="p-5")

        moved = AuthorityStore(db, current_policy_resolver=_static_policy("f" * 64))
        results = await asyncio.gather(
            store.consume(
                grant_id=issued.grant_id,
                execution_action_hash=action_hash("p-5"),
                executor_binding_digest=BINDING,
                execution_ref="exec-p5",
            ),
            moved.consume(
                grant_id=issued.grant_id,
                execution_action_hash=action_hash("p-5"),
                executor_binding_digest=BINDING,
                execution_ref="exec-p5-stale",
            ),
        )
        authorised = [r for r in results if r.outcome is ConsumptionOutcome.AUTHORISED]
        assert len(authorised) <= 1

        async with db.acquire() as conn:
            claims = await conn.fetchval(
                "SELECT COUNT(*) FROM approval_token_consumptions WHERE token_id = $1",
                issued.approval_token_id,
            )
        assert claims == len(authorised)
        stale = [r for r in results if r.rejection_reason is not None]
        assert all(
            r.rejection_reason
            in (
                DecisionReason.POLICY_HASH_MISMATCH,
                DecisionReason.GRANT_ALREADY_CONSUMED,
                DecisionReason.EXECUTION_REF_CONFLICT,
            )
            for r in stale
        )


class TestDatabaseEnforcesTheStateModel:
    async def test_a_consumed_grant_cannot_return_to_active(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="s-1", seed="s-1")
        await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("s-1"),
            executor_binding_digest=BINDING,
            execution_ref="exec-s1",
        )
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.RaiseError, match="cannot transition"):
                await conn.execute(
                    "UPDATE execution_authority_grants SET status = 'active' WHERE id = $1",
                    issued.grant_id,
                )

    async def test_the_act_cannot_be_edited_after_issuance(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="s-2", seed="s-2")
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.RaiseError, match="immutable"):
                await conn.execute(
                    """
                    UPDATE execution_authority_grants
                    SET execution_action_hash = $2 WHERE id = $1
                    """,
                    issued.grant_id,
                    action_hash("something-else"),
                )

    async def test_the_runtime_role_holds_no_delete_privilege(
        self, db, org_and_agent
    ) -> None:
        """First line of defence: the runtime cannot even attempt a delete."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="s-3", seed="s-3")
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.execute(
                    "DELETE FROM execution_authority_grants WHERE id = $1",
                    issued.grant_id,
                )

    @pytest.mark.skipif(
        not MIGRATOR_URL,
        reason="trigger check needs a DSN whose role actually holds DELETE",
    )
    async def test_the_trigger_refuses_a_delete_that_privilege_would_allow(
        self, db, org_and_agent
    ) -> None:
        """Second line: even a role with DELETE cannot remove the evidence."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="s-3b", seed="s-3b")
        privileged = await asyncpg.connect(MIGRATOR_URL)
        try:
            with pytest.raises(asyncpg.RaiseError, match="append only"):
                await privileged.execute(
                    "DELETE FROM execution_authority_grants WHERE id = $1",
                    issued.grant_id,
                )
        finally:
            await privileged.close()

    async def test_multi_use_authority_cannot_be_written(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="s-4", seed="s-4")
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.PostgresError):
                await conn.execute(
                    "UPDATE execution_authority_grants SET single_use = FALSE WHERE id = $1",
                    issued.grant_id,
                )


class TestTenantIsolation:
    async def test_a_tenant_cannot_see_another_tenants_grants(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="t-1", seed="t-1")

        other_org = uuid4()
        async with db.acquire_as_tenant(other_org) as conn:
            visible = await conn.fetchval(
                "SELECT COUNT(*) FROM execution_authority_grants WHERE id = $1",
                issued.grant_id,
            )
        assert visible == 0

    async def test_the_owning_tenant_sees_its_own_grant(
        self, db, org_and_agent
    ) -> None:
        org_id, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="t-2", seed="t-2")
        async with db.acquire_as_tenant(org_id) as conn:
            visible = await conn.fetchval(
                "SELECT COUNT(*) FROM execution_authority_grants WHERE id = $1",
                issued.grant_id,
            )
        assert visible == 1

    async def test_a_tenant_cannot_insert_a_grant_for_another_tenants_agent(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        other_org = uuid4()
        async with db.acquire_as_tenant(other_org) as conn:
            with pytest.raises(asyncpg.PostgresError):
                await conn.execute(
                    """
                    INSERT INTO execution_authority_grants (
                        agent_id, issuance_ref, issuance_digest,
                        execution_action_hash, policy_hash,
                        policy_snapshot_format, policy_revision,
                        executor_binding_digest, domain, action_type,
                        approval_token_id, expires_at
                    ) VALUES (
                        $1, 'cross-tenant', $2, $3, $4, $5, 'r', $6,
                        'payment', 'financial_transaction', $7, NOW() + INTERVAL '5 min'
                    )
                    """,
                    agent_id,
                    DIGEST_A,
                    action_hash("cross"),
                    POLICY_HASH,
                    FORMAT,
                    BINDING,
                    secrets.token_urlsafe(24),
                )


class TestIssuanceDigest:
    def test_it_ignores_timestamps_so_a_late_retry_still_matches(self) -> None:
        common = {
            "organisation_id": UUID(int=2),
            "agent_id": UUID(int=1),
            "issuance_ref": "ref",
            "execution_action_hash": action_hash("x"),
            "signed_action_hash": None,
            "policy_hash": POLICY_HASH,
            "policy_revision": "revision-1",
            "policy_snapshot_format": FORMAT,
            "executor_binding_digest": BINDING,
            "amount_usd": Decimal("10.00"),
            "domain": "payment",
            "action_type": "financial_transaction",
            "consequence_class": None,
            "authority_scope_digest": None,
        }
        assert issuance_digest(**common) == issuance_digest(**common)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("execution_action_hash", action_hash("y")),
            ("policy_hash", "9" * 64),
            ("executor_binding_digest", "8" * 64),
            ("amount_usd", Decimal("11.00")),
            ("action_type", "wallet_transaction"),
            ("authority_scope_digest", DIGEST_A),
            ("organisation_id", UUID(int=99)),
            ("policy_revision", "revision-2"),
            ("policy_snapshot_format", "inntris-payment-authority-policy-v2"),
            ("ttl_profile", "execution-authority-ttl-v2"),
            ("requested_expires_at", datetime(2027, 1, 1, tzinfo=UTC)),
            ("authority_expires_at", datetime(2027, 1, 1, tzinfo=UTC)),
        ],
    )
    def test_changed_material_changes_the_digest(self, field, value) -> None:
        common = {
            "organisation_id": UUID(int=2),
            "agent_id": UUID(int=1),
            "issuance_ref": "ref",
            "execution_action_hash": action_hash("x"),
            "signed_action_hash": None,
            "policy_hash": POLICY_HASH,
            "policy_revision": "revision-1",
            "policy_snapshot_format": FORMAT,
            "executor_binding_digest": BINDING,
            "amount_usd": Decimal("10.00"),
            "domain": "payment",
            "action_type": "financial_transaction",
            "consequence_class": None,
            "authority_scope_digest": None,
        }
        assert issuance_digest(**{**common, field: value}) != issuance_digest(**common)


class TestARefusalDoesNotBurnTheGrant:
    """A mismatch must not spend authority the caller was never granted.

    Otherwise a wrong executor, or a caller presenting the wrong act, could
    destroy a legitimate grant by simply failing at it.
    """

    async def test_a_wrong_executor_leaves_the_grant_consumable(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="b-1", seed="b-1")

        refused = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("b-1"),
            executor_binding_digest="d" * 64,
            execution_ref="exec-b1-wrong",
        )
        assert refused.rejection_reason is DecisionReason.GRANT_EXECUTOR_MISMATCH
        assert (await store.get(issued.grant_id))["status"] == "active"

        correct = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("b-1"),
            executor_binding_digest=BINDING,
            execution_ref="exec-b1-right",
        )
        assert correct.outcome is ConsumptionOutcome.AUTHORISED

    async def test_a_changed_action_leaves_the_grant_consumable(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="b-2", seed="b-2")

        refused = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("a-tampered-act"),
            executor_binding_digest=BINDING,
            execution_ref="exec-b2-wrong",
        )
        assert refused.rejection_reason is DecisionReason.GRANT_ACTION_MISMATCH
        assert (await store.get(issued.grant_id))["status"] == "active"

        original = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("b-2"),
            executor_binding_digest=BINDING,
            execution_ref="exec-b2-right",
        )
        assert original.outcome is ConsumptionOutcome.AUTHORISED

    async def test_a_refused_consumption_claims_no_token(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="b-3", seed="b-3")
        await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("wrong"),
            executor_binding_digest=BINDING,
            execution_ref="exec-b3",
        )
        async with db.acquire() as conn:
            claims = await conn.fetchval(
                "SELECT COUNT(*) FROM approval_token_consumptions WHERE token_id = $1",
                issued.approval_token_id,
            )
        assert claims == 0


class TestDatabaseFailureFailsClosed:
    async def test_a_broken_connection_yields_no_authority(
        self, org_and_agent
    ) -> None:
        """No database, no grant. Never an optimistic success."""
        _org, agent_id = org_and_agent
        broken = await Database.create(DATABASE_URL, min_size=1, max_size=2)
        await broken.close()
        store = AuthorityStore(broken, current_policy_resolver=_static_policy())
        with pytest.raises((asyncpg.PostgresError, InterfaceError, RuntimeError)):
            await issue(store, agent_id, issuance_ref="f-1", seed="f-1")

    async def test_a_broken_connection_yields_no_consumption(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="f-2", seed="f-2")

        broken = await Database.create(DATABASE_URL, min_size=1, max_size=2)
        await broken.close()
        failing = AuthorityStore(broken, current_policy_resolver=_static_policy())
        with pytest.raises((asyncpg.PostgresError, InterfaceError, RuntimeError)):
            await failing.consume(
                grant_id=issued.grant_id,
                execution_action_hash=action_hash("f-2"),
                executor_binding_digest=BINDING,
                execution_ref="exec-f2",
            )
        assert (await store.get(issued.grant_id))["status"] == "active"
        async with db.acquire() as conn:
            claims = await conn.fetchval(
                "SELECT COUNT(*) FROM approval_token_consumptions WHERE token_id = $1",
                issued.approval_token_id,
            )
        assert claims == 0

    async def test_a_resolver_that_cannot_answer_refuses(
        self, db, org_and_agent
    ) -> None:
        """A policy that cannot be re-derived is not a policy that permits."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="f-3", seed="f-3")

        def unavailable(_agent, _action_type, _domain):
            raise ValueError("policy source unavailable")

        blind = AuthorityStore(db, current_policy_resolver=unavailable)
        result = await blind.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("f-3"),
            executor_binding_digest=BINDING,
            execution_ref="exec-f3",
        )
        assert result.rejection_reason is DecisionReason.POLICY_HASH_MISMATCH


class TestGrantLifetimeIsClamped:
    def test_the_configured_ttl_is_the_ceiling(self) -> None:
        issued = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
        assert clamp_grant_expiry(
            issued_at=issued, requested_expires_at=issued + timedelta(days=1)
        ) == issued + MAX_EXECUTION_AUTHORITY_TTL

    def test_a_delegated_expiry_wins_when_it_is_tighter(self) -> None:
        issued = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
        assert clamp_grant_expiry(
            issued_at=issued,
            requested_expires_at=issued + timedelta(minutes=5),
            authority_expires_at=issued + timedelta(minutes=2),
        ) == issued + timedelta(minutes=2)

    def test_any_tighter_trusted_bound_wins(self) -> None:
        issued = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
        assert clamp_grant_expiry(
            issued_at=issued,
            authority_expires_at=issued + timedelta(minutes=4),
            additional_bounds=(issued + timedelta(seconds=30),),
        ) == issued + timedelta(seconds=30)

    async def test_a_grant_never_outlives_its_delegated_authority(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        cap = datetime.now(UTC) + timedelta(minutes=1)
        issued = await issue(
            store, agent_id, issuance_ref="l-1", seed="l-1", authority_expires_at=cap
        )
        row = await store.get(issued.grant_id)
        assert row["expires_at"] <= cap

    async def test_an_already_expired_delegation_issues_nothing(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        with pytest.raises(GrantLifetimeError):
            await issue(
                store,
                agent_id,
                issuance_ref="l-2",
                seed="l-2",
                authority_expires_at=datetime.now(UTC) - timedelta(minutes=1),
            )

    async def test_the_database_refuses_a_grant_beyond_its_delegation(
        self, db, org_and_agent
    ) -> None:
        """Belt and braces: the clamp is application code, this is the schema."""
        org_id, agent_id = org_and_agent
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.CheckViolationError, match="within_delegated"):
                await conn.execute(
                    """
                    INSERT INTO execution_authority_grants (
                        agent_id, org_id, issuance_ref, issuance_digest,
                        execution_action_hash, policy_hash,
                        policy_snapshot_format, policy_revision,
                        executor_binding_digest, domain, action_type,
                        approval_token_id, expires_at, authority_expires_at
                    ) VALUES (
                        $1, $2, 'beyond', $3, $4, $5, $6, 'r', $7,
                        'payment', 'financial_transaction', $8,
                        NOW() + INTERVAL '10 min', NOW() + INTERVAL '1 min'
                    )
                    """,
                    agent_id,
                    org_id,
                    DIGEST_A,
                    action_hash("beyond"),
                    POLICY_HASH,
                    FORMAT,
                    BINDING,
                    secrets.token_urlsafe(24),
                )


class TestDelegationRevocationAndExpiry:
    async def test_a_revoked_delegation_is_refused_distinctly(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="d-1", seed="d-1")
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("d-1"),
            executor_binding_digest=BINDING,
            execution_ref="exec-d1",
            authority_evidence=ResolvedAuthorityEvidence(revoked=True),
        )
        assert result.rejection_reason is DecisionReason.AUTHORITY_REVOKED

    async def test_an_expired_delegation_is_refused_distinctly(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="d-2", seed="d-2")
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("d-2"),
            executor_binding_digest=BINDING,
            execution_ref="exec-d2",
            authority_evidence=ResolvedAuthorityEvidence(
                expires_at=datetime.now(UTC) - timedelta(seconds=1)
            ),
        )
        assert result.rejection_reason is DecisionReason.AUTHORITY_EXPIRED

    async def test_a_delegation_that_no_longer_verifies_is_refused(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="d-3", seed="d-3")
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("d-3"),
            executor_binding_digest=BINDING,
            execution_ref="exec-d3",
            authority_evidence=ResolvedAuthorityEvidence(verified=False),
        )
        assert result.rejection_reason is DecisionReason.AUTHORITY_VERIFICATION_FAILED

    async def test_a_still_valid_delegation_consumes(self, db, org_and_agent) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="d-4", seed="d-4")
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("d-4"),
            executor_binding_digest=BINDING,
            execution_ref="exec-d4",
            authority_evidence=ResolvedAuthorityEvidence(
                expires_at=datetime.now(UTC) + timedelta(minutes=10)
            ),
        )
        assert result.outcome is ConsumptionOutcome.AUTHORISED


class TestOutcomeNeverReleasesReservedSpend:
    """A timeout is not proof that no money moved."""

    async def _consumed_grant(self, db, agent_id, ref):
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(
            store, agent_id, issuance_ref=ref, seed=ref, amount=Decimal("250")
        )
        await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash(ref),
            executor_binding_digest=BINDING,
            execution_ref=f"exec-{ref}",
        )
        return store, issued

    async def _reserved_total(self, db, agent_id) -> Decimal:
        async with db.acquire() as conn:
            return Decimal(
                await conn.fetchval(
                    """
                    SELECT COALESCE(SUM(amount_usd), 0) FROM spend_reservations
                    WHERE agent_id = $1 AND status IN ('reserved', 'consumed')
                    """,
                    agent_id,
                )
            )

    @pytest.mark.parametrize(
        "state",
        [
            OutcomeState.SUCCEEDED,
            OutcomeState.FAILED_FINAL,
            OutcomeState.OUTCOME_UNKNOWN,
        ],
    )
    async def test_no_outcome_releases_the_reservation(
        self, db, org_and_agent, state
    ) -> None:
        _org, agent_id = org_and_agent
        store, issued = await self._consumed_grant(db, agent_id, f"o-{state.value}")
        before = await self._reserved_total(db, agent_id)
        assert await store.record_outcome(grant_id=issued.grant_id, outcome_state=state)
        assert await self._reserved_total(db, agent_id) == before

        async with db.acquire() as conn:
            status = await conn.fetchval(
                "SELECT status FROM spend_reservations WHERE approval_token_id = $1",
                issued.approval_token_id,
            )
        assert status == "consumed", "a recorded outcome never un-charges the spend"

    async def test_an_unknown_outcome_may_later_be_resolved_by_evidence(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store, issued = await self._consumed_grant(db, agent_id, "o-resolve")
        await store.record_outcome(
            grant_id=issued.grant_id, outcome_state=OutcomeState.OUTCOME_UNKNOWN
        )
        assert await store.record_outcome(
            grant_id=issued.grant_id,
            outcome_state=OutcomeState.SUCCEEDED,
            outcome_reference="rail-reference-1",
        )
        row = await store.get(issued.grant_id)
        assert row["outcome_state"] == "succeeded"
        assert row["outcome_reference"] == "rail-reference-1"

    async def test_a_settled_outcome_cannot_be_reopened(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store, issued = await self._consumed_grant(db, agent_id, "o-final")
        await store.record_outcome(
            grant_id=issued.grant_id, outcome_state=OutcomeState.SUCCEEDED
        )
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.RaiseError, match="cannot transition"):
                await conn.execute(
                    """
                    UPDATE execution_authority_grants
                    SET outcome_state = 'outcome_unknown' WHERE id = $1
                    """,
                    issued.grant_id,
                )

    async def test_an_unconsumed_grant_cannot_carry_an_outcome(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="o-unspent", seed="o-unspent")
        assert not await store.record_outcome(
            grant_id=issued.grant_id, outcome_state=OutcomeState.SUCCEEDED
        )
        assert (await store.get(issued.grant_id))["outcome_state"] == "pending"


class TestLegacyApprovalTokenCompatibility:
    """One authoritative consumption state, reached two ways.

    A legacy approval token simply has no grant row. Nothing about its
    behaviour changes, nothing is converted, and both paths claim through
    the same table -- so the two can never disagree about whether authority
    was consumed.
    """

    def _entry(self, agent_id) -> AuditLogEntry:
        return AuditLogEntry(
            agent_id=agent_id,
            action_type="financial_transaction",
            action_hash=action_hash("legacy"),
            payload={"amount": "1.00"},
            verdict=ActionVerdict.APPROVED,
            verdict_reason="legacy path",
            signature=b"LEGACY_TEST_SIGNATURE",
            signature_valid=True,
            request_ip=None,
            request_user_agent=None,
            response_time_ms=None,
            trust_score_at_time=80,
            chain_previous_hash=None,
            policy_hash=POLICY_HASH,
        )

    async def test_a_legacy_token_still_consumes_exactly_once(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        token_id = secrets.token_urlsafe(24)
        digest = hashlib.sha256(token_id.encode()).digest()

        first = await db.insert_token_consumption(
            self._entry(agent_id),
            token_id=token_id,
            token_digest=digest,
            approved_action_hash=action_hash("legacy"),
            execution_ref="legacy-exec-1",
        )
        assert first is not None
        assert first[1] == "consumed"

        second = await db.insert_token_consumption(
            self._entry(agent_id),
            token_id=token_id,
            token_digest=digest,
            approved_action_hash=action_hash("legacy"),
            execution_ref="legacy-exec-1",
        )
        assert second == (first[0], "idempotent"), "same ref replays the original"

        third = await db.insert_token_consumption(
            self._entry(agent_id),
            token_id=token_id,
            token_digest=digest,
            approved_action_hash=action_hash("legacy"),
            execution_ref="legacy-exec-2",
        )
        assert third is None, "a different ref is still refused"

    async def test_a_legacy_token_has_no_grant_and_needs_none(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        token_id = secrets.token_urlsafe(24)
        await db.insert_token_consumption(
            self._entry(agent_id),
            token_id=token_id,
            token_digest=hashlib.sha256(token_id.encode()).digest(),
            approved_action_hash=action_hash("legacy"),
            execution_ref="legacy-exec-3",
        )
        async with db.acquire() as conn:
            grants = await conn.fetchval(
                """
                SELECT COUNT(*) FROM execution_authority_grants
                WHERE approval_token_id = $1
                """,
                token_id,
            )
            claims = await conn.fetchval(
                "SELECT COUNT(*) FROM approval_token_consumptions WHERE token_id = $1",
                token_id,
            )
        assert grants == 0, "no conversion, no backfill, no shadow row"
        assert claims == 1, "the same table is still the authority"

    async def test_both_paths_share_one_consumption_table(
        self, db, org_and_agent
    ) -> None:
        """The property that makes two sources of truth impossible."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="mix-1", seed="mix-1")
        await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("mix-1"),
            executor_binding_digest=BINDING,
            execution_ref="exec-mix-1",
        )
        legacy_token = secrets.token_urlsafe(24)
        await db.insert_token_consumption(
            self._entry(agent_id),
            token_id=legacy_token,
            token_digest=hashlib.sha256(legacy_token.encode()).digest(),
            approved_action_hash=action_hash("legacy"),
            execution_ref="legacy-exec-4",
        )
        async with db.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT token_id FROM approval_token_consumptions
                WHERE token_id = ANY($1::TEXT[])
                """,
                [issued.approval_token_id, legacy_token],
            )
        assert {row["token_id"] for row in rows} == {
            issued.approval_token_id,
            legacy_token,
        }

    async def test_a_grant_backed_token_cannot_be_double_claimed_legacily(
        self, db, org_and_agent
    ) -> None:
        """The legacy path cannot spend a grant behind the store's back."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="mix-2", seed="mix-2")
        await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("mix-2"),
            executor_binding_digest=BINDING,
            execution_ref="exec-mix-2",
        )
        replay = await db.insert_token_consumption(
            self._entry(agent_id),
            token_id=issued.approval_token_id,
            token_digest=hashlib.sha256(issued.approval_token_id.encode()).digest(),
            approved_action_hash=action_hash("mix-2"),
            execution_ref="a-different-ref",
        )
        assert replay is None


class TestCrossTenantIdempotency:
    async def test_two_tenants_may_use_the_same_issuance_reference(
        self, db, org_and_agent, second_org_and_agent
    ) -> None:
        """Idempotency is scoped per principal, not globally."""
        _org_a, agent_a = org_and_agent
        _org_b, agent_b = second_org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())

        first = await issue(store, agent_a, issuance_ref="shared-ref", seed="x-a")
        second = await issue(store, agent_b, issuance_ref="shared-ref", seed="x-b")
        assert first.outcome is IssueOutcome.ISSUED
        assert second.outcome is IssueOutcome.ISSUED
        assert first.grant_id != second.grant_id

    async def test_one_tenants_reference_cannot_return_anothers_grant(
        self, db, org_and_agent, second_org_and_agent
    ) -> None:
        _org_a, agent_a = org_and_agent
        _org_b, agent_b = second_org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        mine = await issue(store, agent_a, issuance_ref="ref-mine", seed="same-act")
        theirs = await issue(store, agent_b, issuance_ref="ref-mine", seed="same-act")
        assert theirs.grant_id != mine.grant_id
        assert theirs.approval_token_id != mine.approval_token_id


class TestCompositeOwnershipIntegrity:
    async def test_a_grant_cannot_name_an_organisation_that_does_not_own_it(
        self, db, org_and_agent, second_org_and_agent
    ) -> None:
        _org_a, agent_a = org_and_agent
        org_b, _agent_b = second_org_and_agent
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.ForeignKeyViolationError):
                await conn.execute(
                    """
                    INSERT INTO execution_authority_grants (
                        agent_id, org_id, issuance_ref, issuance_digest,
                        execution_action_hash, policy_hash,
                        policy_snapshot_format, policy_revision,
                        executor_binding_digest, domain, action_type,
                        approval_token_id, expires_at
                    ) VALUES (
                        $1, $2, 'mismatched-owner', $3, $4, $5, $6, 'r', $7,
                        'payment', 'financial_transaction', $8,
                        NOW() + INTERVAL '5 min'
                    )
                    """,
                    agent_a,
                    org_b,
                    DIGEST_A,
                    action_hash("mismatch"),
                    POLICY_HASH,
                    FORMAT,
                    BINDING,
                    secrets.token_urlsafe(24),
                )

    async def test_a_grant_cannot_be_repointed_to_another_tenant(
        self, db, org_and_agent, second_org_and_agent
    ) -> None:
        _org_a, agent_a = org_and_agent
        org_b, _agent_b = second_org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_a, issuance_ref="own-1", seed="own-1")
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.RaiseError, match="immutable"):
                await conn.execute(
                    "UPDATE execution_authority_grants SET org_id = $2 WHERE id = $1",
                    issued.grant_id,
                    org_b,
                )


class TestRestrictedRoleExecution:
    """The isolation that matters is the one the service actually runs under."""

    async def test_the_restricted_role_sees_only_its_own_tenants_grant(
        self, db, org_and_agent, second_org_and_agent
    ) -> None:
        org_a, agent_a = org_and_agent
        org_b, _agent_b = second_org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        mine = await issue(store, agent_a, issuance_ref="role-1", seed="role-1")

        async with db.acquire_as_tenant(org_a) as conn:
            assert await conn.fetchval("SELECT current_user") == "inntris_api"
            assert (
                await conn.fetchval(
                    "SELECT COUNT(*) FROM execution_authority_grants WHERE id = $1",
                    mine.grant_id,
                )
                == 1
            )
        async with db.acquire_as_tenant(org_b) as conn:
            assert (
                await conn.fetchval(
                    "SELECT COUNT(*) FROM execution_authority_grants WHERE id = $1",
                    mine.grant_id,
                )
                == 0
            )

    async def test_the_restricted_role_cannot_consume_another_tenants_grant(
        self, db, org_and_agent, second_org_and_agent
    ) -> None:
        _org_a, agent_a = org_and_agent
        org_b, _agent_b = second_org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        mine = await issue(store, agent_a, issuance_ref="role-2", seed="role-2")

        async with db.acquire_as_tenant(org_b) as conn:
            updated = await conn.execute(
                """
                UPDATE execution_authority_grants
                SET status = 'consumed', consumed_at = NOW()
                WHERE id = $1
                """,
                mine.grant_id,
            )
        assert updated == "UPDATE 0", "invisible rows cannot be transitioned"
        assert (await store.get(mine.grant_id))["status"] == "active"

    async def test_the_restricted_role_holds_no_delete_privilege(
        self, db, org_and_agent
    ) -> None:
        org_id, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="role-3", seed="role-3")
        async with db.acquire_as_tenant(org_id) as conn:
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.execute(
                    "DELETE FROM execution_authority_grants WHERE id = $1",
                    issued.grant_id,
                )


class TestRealPolicyRaceAgainstConsume:
    """Two real connections, a real UPDATE agents, and the actual lock graph.

    An in-memory resolver cannot prove this. The question is whether a
    concurrent policy change can commit *between* the moment consume
    derives current policy and the moment its claim commits. That window
    exists or does not exist in PostgreSQL's lock graph, so the test has
    to be two connections contending over one row.
    """

    async def _suspend_agent(self, agent_id) -> None:
        conn = await asyncpg.connect(DATABASE_URL)
        try:
            await conn.execute(
                "UPDATE agents SET status = 'suspended' WHERE id = $1", agent_id
            )
        finally:
            await conn.close()

    async def test_a_committed_policy_change_is_seen_and_refuses(
        self, db, org_and_agent
    ) -> None:
        """Update commits first -> consume sees the new state and refuses."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="r-1", seed="r-1")

        await self._suspend_agent(agent_id)

        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("r-1"),
            executor_binding_digest=BINDING,
            execution_ref="exec-r1",
        )
        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.rejection_reason is DecisionReason.AGENT_NOT_ACTIVE
        async with db.acquire() as conn:
            assert (
                await conn.fetchval(
                    "SELECT COUNT(*) FROM approval_token_consumptions WHERE token_id = $1",
                    issued.approval_token_id,
                )
                == 0
            )

    async def test_a_policy_writer_waits_while_consume_holds_the_row(
        self, db, org_and_agent
    ) -> None:
        """Consume holds the required locks first -> the update waits.

        Proven by timing the writer against a consume that is deliberately
        held open: if the row lock were not taken, the UPDATE would commit
        immediately instead of blocking.
        """
        org_id, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="r-2", seed="r-2")

        writer_started = asyncio.Event()
        writer_committed = asyncio.Event()
        release_holder = asyncio.Event()

        async def hold_the_locks() -> None:
            """Take the same locks consume takes, in the same order, and hold."""
            conn = await asyncpg.connect(DATABASE_URL)
            try:
                tx = conn.transaction()
                await tx.start()
                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
                    f"authority-grant:{issued.grant_id}",
                )
                await conn.fetchrow(
                    """
                    SELECT a.* FROM agents a
                    JOIN execution_authority_grants g ON g.agent_id = a.id
                    WHERE g.id = $1
                    FOR SHARE OF a
                    """,
                    issued.grant_id,
                )
                writer_started.set()
                await release_holder.wait()
                await tx.commit()
            finally:
                await conn.close()

        async def write_policy() -> None:
            await writer_started.wait()
            conn = await asyncpg.connect(DATABASE_URL)
            try:
                await conn.execute(
                    "UPDATE agents SET daily_limit_usd = 1 WHERE id = $1", agent_id
                )
                writer_committed.set()
            finally:
                await conn.close()

        holder = asyncio.create_task(hold_the_locks())
        writer = asyncio.create_task(write_policy())

        await writer_started.wait()
        await asyncio.sleep(0.4)
        assert not writer_committed.is_set(), (
            "the policy UPDATE committed while the consume path held the "
            "principal row: the TOCTOU window is open"
        )

        release_holder.set()
        await holder
        await asyncio.wait_for(writer, timeout=10)
        assert writer_committed.is_set(), "the writer must proceed once released"

        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET daily_limit_usd = 10000 WHERE id = $1", agent_id
            )
        assert org_id is not None

    async def test_no_old_policy_claim_commits_after_the_change_commits(
        self, db, org_and_agent
    ) -> None:
        """The invariant, run under real contention.

        A consume racing a suspension either claims before the suspension
        commits, or sees it and refuses. What must never happen is a claim
        that commits *after* the conflicting change committed.
        """
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="r-3", seed="r-3")

        consume_task = asyncio.create_task(
            store.consume(
                grant_id=issued.grant_id,
                execution_action_hash=action_hash("r-3"),
                executor_binding_digest=BINDING,
                execution_ref="exec-r3",
            )
        )
        suspend_task = asyncio.create_task(self._suspend_agent(agent_id))
        result, _ = await asyncio.gather(consume_task, suspend_task)

        async with db.acquire() as conn:
            claims = await conn.fetchval(
                "SELECT COUNT(*) FROM approval_token_consumptions WHERE token_id = $1",
                issued.approval_token_id,
            )
            status = await conn.fetchval(
                "SELECT status FROM agents WHERE id = $1", agent_id
            )
        assert status == "suspended"

        if result.outcome is ConsumptionOutcome.AUTHORISED:
            # It won the race: the claim committed before the suspension did.
            assert claims == 1
        else:
            assert result.rejection_reason is DecisionReason.AGENT_NOT_ACTIVE
            assert claims == 0, "a refused consumption must claim nothing"

    async def test_the_race_holds_under_repetition(self, db, org_and_agent) -> None:
        """Run the contention repeatedly; the invariant must never break."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        for attempt in range(8):
            async with db.acquire() as conn:
                await conn.execute(
                    "UPDATE agents SET status = 'active' WHERE id = $1", agent_id
                )
            issued = await issue(
                store, agent_id, issuance_ref=f"r-loop-{attempt}", seed=f"r-loop-{attempt}"
            )
            result, _ = await asyncio.gather(
                store.consume(
                    grant_id=issued.grant_id,
                    execution_action_hash=action_hash(f"r-loop-{attempt}"),
                    executor_binding_digest=BINDING,
                    execution_ref=f"exec-loop-{attempt}",
                ),
                self._suspend_agent(agent_id),
            )
            async with db.acquire() as conn:
                claims = await conn.fetchval(
                    """
                    SELECT COUNT(*) FROM approval_token_consumptions
                    WHERE token_id = $1
                    """,
                    issued.approval_token_id,
                )
            expected = 1 if result.outcome is ConsumptionOutcome.AUTHORISED else 0
            assert claims == expected, f"attempt {attempt}: {result.outcome}"


class TestTerminalIdempotentIssuanceIsNotUsable:
    """Recovering a spent grant's identity is not recovering its authority."""

    async def test_a_consumed_grant_retry_is_not_usable(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        first = await issue(store, agent_id, issuance_ref="t-consumed", seed="t-c")
        await store.consume(
            grant_id=first.grant_id,
            execution_action_hash=action_hash("t-c"),
            executor_binding_digest=BINDING,
            execution_ref="exec-t-c",
        )
        retry = await issue(store, agent_id, issuance_ref="t-consumed", seed="t-c")
        assert retry.outcome is IssueOutcome.IDEMPOTENT
        assert retry.grant_id == first.grant_id
        assert retry.grant_status is GrantStatus.CONSUMED
        assert not retry.authorises_execution

    async def test_a_revoked_grant_retry_is_not_usable(self, db, org_and_agent) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        first = await issue(store, agent_id, issuance_ref="t-revoked", seed="t-r")
        assert await store.revoke(grant_id=first.grant_id, reason="withdrawn")
        retry = await issue(store, agent_id, issuance_ref="t-revoked", seed="t-r")
        assert retry.outcome is IssueOutcome.IDEMPOTENT
        assert retry.grant_id == first.grant_id
        assert retry.grant_status is GrantStatus.REVOKED
        assert not retry.authorises_execution

    async def test_a_time_expired_grant_retry_is_not_usable(
        self, db, org_and_agent
    ) -> None:
        """Still 'active' in the column, but its window has closed."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        first = await issue(store, agent_id, issuance_ref="t-expired", seed="t-e")
        async with db.acquire() as conn:
            assert (
                await conn.fetchval(
                    "SELECT status FROM execution_authority_grants WHERE id = $1",
                    first.grant_id,
                )
                == "active"
            )
        retry = await store.issue(
            agent_id=agent_id,
            organisation_id=ORG_BY_AGENT[agent_id],
            issuance_ref="t-expired",
            execution_action_hash=action_hash("t-e"),
            policy_hash=POLICY_HASH,
            policy_snapshot_format=FORMAT,
            policy_revision="revision-1",
            executor_binding_digest=BINDING,
            domain="payment",
            action_type="financial_transaction",
            minute_start=datetime.now(UTC).replace(second=0, microsecond=0),
            day_start=datetime.now(UTC).replace(
                hour=0, minute=0, second=0, microsecond=0
            ),
            issued_at=datetime.now(UTC) + timedelta(hours=1),
        )
        assert retry.outcome is IssueOutcome.IDEMPOTENT
        assert retry.grant_status is GrantStatus.EXPIRED
        assert not retry.authorises_execution

    async def test_an_active_grant_retry_remains_usable(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        first = await issue(store, agent_id, issuance_ref="t-active", seed="t-a")
        retry = await issue(store, agent_id, issuance_ref="t-active", seed="t-a")
        assert retry.grant_status is GrantStatus.ACTIVE
        assert retry.authorises_execution
        assert retry.grant_id == first.grant_id


class TestExecutionRefIsRequiredOnTheGenericPath:
    @pytest.mark.parametrize("bad_ref", [None, "", "   "])
    async def test_a_missing_or_blank_reference_is_refused(
        self, db, org_and_agent, bad_ref
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref=f"x-{bad_ref!r}", seed="x-1")
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("x-1"),
            executor_binding_digest=BINDING,
            execution_ref=bad_ref,
        )
        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.rejection_reason is DecisionReason.EXECUTION_REF_CONFLICT
        assert (await store.get(issued.grant_id))["status"] == "active"

    async def test_the_legacy_path_still_permits_omitting_it(
        self, db, org_and_agent
    ) -> None:
        """Legacy /verify-token semantics are unchanged by the new rule."""
        _org, agent_id = org_and_agent
        token_id = secrets.token_urlsafe(24)
        claim = await db.insert_token_consumption(
            AuditLogEntry(
                agent_id=agent_id,
                action_type="financial_transaction",
                action_hash=action_hash("legacy-noref"),
                payload={},
                verdict=ActionVerdict.APPROVED,
                verdict_reason="legacy",
                signature=b"LEGACY_TEST_SIGNATURE",
                signature_valid=True,
                request_ip=None,
                request_user_agent=None,
                response_time_ms=None,
                trust_score_at_time=80,
                chain_previous_hash=None,
            ),
            token_id=token_id,
            token_digest=hashlib.sha256(token_id.encode()).digest(),
            approved_action_hash=action_hash("legacy-noref"),
            execution_ref=None,
        )
        assert claim is not None and claim[1] == "consumed"


class TestCapacityComesFromTrustedState:
    async def test_an_inflated_daily_limit_cannot_be_asserted(
        self, db, org_and_agent
    ) -> None:
        """A caller naming its own ceiling is refused, not obeyed."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        refused = await issue(
            store,
            agent_id,
            issuance_ref="cap-1",
            seed="cap-1",
            amount=Decimal("50000"),
            daily_limit=Decimal("1000000"),
        )
        assert refused.outcome is IssueOutcome.REFUSED
        assert refused.reason is DecisionReason.POLICY_HASH_MISMATCH
        assert refused.grant_id is None

    async def test_an_inflated_rate_limit_cannot_be_asserted(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        now = datetime.now(UTC)
        refused = await store.issue(
            agent_id=agent_id,
            organisation_id=ORG_BY_AGENT[agent_id],
            issuance_ref="cap-2",
            execution_action_hash=action_hash("cap-2"),
            policy_hash=POLICY_HASH,
            policy_snapshot_format=FORMAT,
            policy_revision="revision-1",
            executor_binding_digest=BINDING,
            domain="payment",
            action_type="financial_transaction",
            minute_start=now.replace(second=0, microsecond=0),
            day_start=now.replace(hour=0, minute=0, second=0, microsecond=0),
            rate_limit_per_minute=10_000_000,
        )
        assert refused.outcome is IssueOutcome.REFUSED
        assert refused.reason is DecisionReason.POLICY_HASH_MISMATCH

    async def test_the_agents_own_limit_is_what_binds(
        self, db, org_and_agent
    ) -> None:
        """No limits supplied at all: the trusted ceiling still applies."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        over = await issue(
            store, agent_id, issuance_ref="cap-3", seed="cap-3", amount=Decimal("50000")
        )
        assert over.outcome is IssueOutcome.REFUSED
        assert over.reason is DecisionReason.DAILY_LIMIT_EXCEEDED

        within = await issue(
            store, agent_id, issuance_ref="cap-4", seed="cap-4", amount=Decimal("100")
        )
        assert within.outcome is IssueOutcome.ISSUED

    async def test_a_suspended_principal_cannot_be_issued_authority(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET status = 'suspended' WHERE id = $1", agent_id
            )
        refused = await issue(store, agent_id, issuance_ref="cap-5", seed="cap-5")
        assert refused.outcome is IssueOutcome.REFUSED
        assert refused.reason is DecisionReason.AGENT_NOT_ACTIVE


class TestCrossGrantExecutionRefConflict:
    async def test_a_reference_held_by_another_grant_is_a_reference_conflict(
        self, db, org_and_agent
    ) -> None:
        """Not 'already consumed' — a different grant owns that reference."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        first = await issue(store, agent_id, issuance_ref="xr-1", seed="xr-1")
        second = await issue(store, agent_id, issuance_ref="xr-2", seed="xr-2")

        claimed = await store.consume(
            grant_id=first.grant_id,
            execution_action_hash=action_hash("xr-1"),
            executor_binding_digest=BINDING,
            execution_ref="shared-execution-ref",
        )
        assert claimed.outcome is ConsumptionOutcome.AUTHORISED

        collision = await store.consume(
            grant_id=second.grant_id,
            execution_action_hash=action_hash("xr-2"),
            executor_binding_digest=BINDING,
            execution_ref="shared-execution-ref",
        )
        assert collision.outcome is ConsumptionOutcome.REJECTED
        assert collision.rejection_reason is DecisionReason.EXECUTION_REF_CONFLICT
        assert (await store.get(second.grant_id))["status"] == "active", (
            "a reference conflict must not burn the second grant"
        )

    async def test_the_second_grant_remains_consumable_with_its_own_reference(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        first = await issue(store, agent_id, issuance_ref="xr-3", seed="xr-3")
        second = await issue(store, agent_id, issuance_ref="xr-4", seed="xr-4")
        await store.consume(
            grant_id=first.grant_id,
            execution_action_hash=action_hash("xr-3"),
            executor_binding_digest=BINDING,
            execution_ref="ref-taken",
        )
        await store.consume(
            grant_id=second.grant_id,
            execution_action_hash=action_hash("xr-4"),
            executor_binding_digest=BINDING,
            execution_ref="ref-taken",
        )
        ok = await store.consume(
            grant_id=second.grant_id,
            execution_action_hash=action_hash("xr-4"),
            executor_binding_digest=BINDING,
            execution_ref="ref-of-its-own",
        )
        assert ok.outcome is ConsumptionOutcome.AUTHORISED


class TestConsumptionSignatureSemantics:
    async def test_the_receipt_is_not_marked_as_a_verified_signature(
        self, db, org_and_agent
    ) -> None:
        """AUTHORITY_GRANT:<id> is a marker, not an Ed25519 signature."""
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="sig-1", seed="sig-1")
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("sig-1"),
            executor_binding_digest=BINDING,
            execution_ref="exec-sig-1",
        )
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT signature, signature_valid, metadata FROM audit_logs WHERE id = $1",
                result.consumption_audit_id,
            )
        assert row["signature"].startswith(b"AUTHORITY_GRANT:")
        assert row["signature_valid"] is False, (
            "signature_valid asserts that a real agent signature verified"
        )
        metadata = json.loads(row["metadata"])
        assert metadata["signature_kind"] == "authority_grant"
        assert metadata["evidence_kind"] == "authority_grant"


class TestDelegatedAuthorityRequiresEvidence:
    def _digest(self) -> str:
        return authority_scope_digest(
            issuer="external-issuer",
            external_reference_id="ref-1",
            artefact_digest=DIGEST_A,
            scope={"max_amount": "500.00", "currency": "USD"},
        )

    async def test_absent_evidence_is_not_evidence_of_validity(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(
            store, agent_id, issuance_ref="e-1", seed="e-1", scope_digest=self._digest()
        )
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("e-1"),
            executor_binding_digest=BINDING,
            execution_ref="exec-e1",
        )
        assert result.rejection_reason is DecisionReason.AUTHORITY_UNVERIFIED

    async def test_matching_evidence_permits_the_claim(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        digest = self._digest()
        issued = await issue(
            store, agent_id, issuance_ref="e-2", seed="e-2", scope_digest=digest
        )
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("e-2"),
            executor_binding_digest=BINDING,
            execution_ref="exec-e2",
            authority_evidence=ResolvedAuthorityEvidence(scope_digest=digest),
        )
        assert result.outcome is ConsumptionOutcome.AUTHORISED

    async def test_evidence_about_another_authority_is_refused(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(
            store, agent_id, issuance_ref="e-3", seed="e-3", scope_digest=self._digest()
        )
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("e-3"),
            executor_binding_digest=BINDING,
            execution_ref="exec-e3",
            authority_evidence=ResolvedAuthorityEvidence(scope_digest="f" * 64),
        )
        assert result.rejection_reason is DecisionReason.AUTHORITY_SCOPE_EXCEEDED

    async def test_an_undelegated_grant_needs_no_evidence(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="e-4", seed="e-4")
        result = await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("e-4"),
            executor_binding_digest=BINDING,
            execution_ref="exec-e4",
        )
        assert result.outcome is ConsumptionOutcome.AUTHORISED


class TestWriteOnceLifecycleEvidence:
    @pytest.mark.parametrize(
        ("column", "value"),
        [
            ("policy_snapshot_format", "tampered-format"),
            ("policy_revision", "tampered-revision"),
            ("executor_reference", "tampered-executor"),
            ("consequence_class", "c4"),
        ],
    )
    async def test_issuance_fields_are_immutable(
        self, db, org_and_agent, column, value
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref=f"w-{column}", seed="w-1")
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.RaiseError, match="immutable"):
                await conn.execute(
                    f"UPDATE execution_authority_grants SET {column} = $2 WHERE id = $1",
                    issued.grant_id,
                    value,
                )

    async def test_the_spend_reservation_link_is_immutable(
        self, db, org_and_agent
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref="w-res", seed="w-res")
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.RaiseError, match="immutable"):
                await conn.execute(
                    """
                    UPDATE execution_authority_grants
                    SET spend_reservation_id = NULL WHERE id = $1
                    """,
                    issued.grant_id,
                )

    @pytest.mark.parametrize(
        "column", ["consumed_at", "execution_ref", "consumption_audit_id"]
    )
    async def test_consumption_evidence_is_write_once(
        self, db, org_and_agent, column
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref=f"w1-{column}", seed="w1")
        await store.consume(
            grant_id=issued.grant_id,
            execution_action_hash=action_hash("w1"),
            executor_binding_digest=BINDING,
            execution_ref="exec-w1",
        )
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.RaiseError, match="write-once"):
                await conn.execute(
                    f"UPDATE execution_authority_grants SET {column} = NULL WHERE id = $1",
                    issued.grant_id,
                )

    @pytest.mark.parametrize("column", ["revoked_at", "revocation_reason"])
    async def test_revocation_evidence_is_write_once(
        self, db, org_and_agent, column
    ) -> None:
        _org, agent_id = org_and_agent
        store = AuthorityStore(db, current_policy_resolver=_static_policy())
        issued = await issue(store, agent_id, issuance_ref=f"w2-{column}", seed="w2")
        await store.revoke(grant_id=issued.grant_id, reason="withdrawn")
        async with db.acquire() as conn:
            with pytest.raises(asyncpg.RaiseError, match="write-once"):
                await conn.execute(
                    f"UPDATE execution_authority_grants SET {column} = NULL WHERE id = $1",
                    issued.grant_id,
                )
