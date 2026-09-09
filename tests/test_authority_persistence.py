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

from api.core.authority.decision import DecisionReason  # noqa: E402
from api.core.authority.lifecycle import ConsumptionOutcome  # noqa: E402
from api.database import Database  # noqa: E402
from api.persistence.authority_store import (  # noqa: E402
    AuthorityStore,
    IssueOutcome,
    authority_scope_digest,
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
    """A fresh organisation and agent, cleaned up afterwards."""
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
    yield org_id, agent_id


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
    amount: Decimal = Decimal("0"),
    seed: str = "act-1",
    daily_limit: Decimal = Decimal("10000"),
    scope_digest: str | None = None,
    policy_hash: str = POLICY_HASH,
):
    now = datetime.now(UTC)
    return await store.issue(
        agent_id=agent_id,
        issuance_ref=issuance_ref,
        execution_action_hash=action_hash(seed),
        policy_hash=policy_hash,
        policy_snapshot_format=FORMAT,
        policy_revision="revision-1",
        executor_binding_digest=BINDING,
        domain="payment",
        action_type="financial_transaction",
        expires_at=now + timedelta(minutes=5),
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
            authority_scope_digest=narrowed,
        )
        assert result.rejection_reason is DecisionReason.AUTHORITY_SCOPE_EXCEEDED

    async def test_a_withdrawn_delegation_cannot_be_spent(
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
            authority_scope_digest=None,
        )
        assert result.rejection_reason is DecisionReason.AUTHORITY_SCOPE_EXCEEDED

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
            "agent_id": UUID(int=1),
            "issuance_ref": "ref",
            "execution_action_hash": action_hash("x"),
            "signed_action_hash": None,
            "policy_hash": POLICY_HASH,
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
        ],
    )
    def test_changed_material_changes_the_digest(self, field, value) -> None:
        common = {
            "agent_id": UUID(int=1),
            "issuance_ref": "ref",
            "execution_action_hash": action_hash("x"),
            "signed_action_hash": None,
            "policy_hash": POLICY_HASH,
            "executor_binding_digest": BINDING,
            "amount_usd": Decimal("10.00"),
            "domain": "payment",
            "action_type": "financial_transaction",
            "consequence_class": None,
            "authority_scope_digest": None,
        }
        assert issuance_digest(**{**common, field: value}) != issuance_digest(**common)
