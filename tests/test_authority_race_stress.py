"""Phase 7A, Gate 6 — race safety under sustained concurrency and faults.

``tests/test_authority_persistence.py`` already proves each race has the
right *semantics*, with two or a handful of competing transactions. This
suite exists because a race with two participants and a race with sixty are
different experiments: the second explores interleavings the first never
reaches, and a lock order that is subtly wrong can pass the first every time.

So everything here runs many rounds at real concurrency and asserts the
invariant after each one. Two of the scenarios also inject a genuine
PostgreSQL restart mid-flight, because "what happens when the database goes
away" cannot be answered by a mock that has never gone away.

The headline invariant, stated once
-----------------------------------
**No stale-policy first consumption may succeed after a change that should
deny the action.** Everything else here is in service of that. Whatever the
interleaving, there must be no ordering in which a grant is claimed under
policy that has already been replaced by one which would refuse it.

Running it
----------
Opt-in, because it is slow and needs a real database:

    INNTRIS_DB_INTEGRATION=1 INNTRIS_STRESS=1 \\
      DATABASE_URL=... pytest tests/test_authority_race_stress.py

``INNTRIS_STRESS_CONCURRENCY`` and ``INNTRIS_STRESS_ROUNDS`` scale it.
``INNTRIS_PG_RESTART_COMMAND`` enables the fault-injection cases; without
it they skip rather than pretending to have run.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import shlex
import subprocess
from collections.abc import AsyncIterator
from datetime import UTC, datetime
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
    ResolvedAuthorityEvidence,
    authority_scope_digest,
)

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
STRESS_ENABLED = os.getenv("INNTRIS_STRESS") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")
PG_RESTART_COMMAND = os.getenv("INNTRIS_PG_RESTART_COMMAND", "")

CONCURRENCY = int(os.getenv("INNTRIS_STRESS_CONCURRENCY", "32"))
ROUNDS = int(os.getenv("INNTRIS_STRESS_ROUNDS", "20"))

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and STRESS_ENABLED and DATABASE_URL),
    reason=(
        "race stress tests require INNTRIS_DB_INTEGRATION=1, INNTRIS_STRESS=1 " "and DATABASE_URL"
    ),
)

POLICY_HASH = "b" * 64
DENYING_POLICY_HASH = "e" * 64
BINDING = "c" * 64
FORMAT = "inntris-payment-authority-policy-v1"
DIGEST_A = "a" * 64


def action_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def static_policy(policy_hash: str = POLICY_HASH):
    def resolver(_agent, _action_type, _domain):
        return policy_hash, "revision-1"

    return resolver


class MovingPolicy:
    """A resolver an operator can change mid-flight, as a real one is.

    Reads a mutable attribute on every call rather than closing over a
    value, so a change genuinely lands between one consumer's read and
    another's.
    """

    def __init__(self, policy_hash: str = POLICY_HASH) -> None:
        self.policy_hash = policy_hash

    def __call__(self, _agent, _action_type, _domain):
        return self.policy_hash, "revision-1"


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=4, max_size=max(CONCURRENCY, 16))
    try:
        yield database
    finally:
        # Bounded on purpose. A pool whose server has been restarted under it
        # can stall trying to close connections the server already dropped --
        # a real operational behaviour, and one that must not turn a finished
        # test into a hung suite. Production clients need the same bound.
        try:
            await asyncio.wait_for(database.close(), timeout=15)
        except TimeoutError:
            # Recorded rather than swallowed silently: a pool that will not
            # close after its server restarted is a finding for the release
            # evidence, not a test-harness inconvenience.
            print(
                "NOTE: the connection pool did not close within 15s after the "
                "database restarted; production clients need a bounded close too"
            )


async def make_agent(db: Database) -> tuple[UUID, UUID]:
    org_id, agent_id = uuid4(), uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
            VALUES ($1, $2, 'enterprise', $3, $4)
            """,
            org_id,
            f"stress-{org_id}",
            f"stress-{org_id}@invalid.test",
            hashlib.sha256(str(org_id).encode()).digest(),
        )
        await conn.execute(
            """
            INSERT INTO agents (
                id, org_id, name, public_key, public_key_fingerprint, trust_score,
                status, daily_limit_usd, per_action_limit_usd, allowed_actions,
                blocked_actions, rate_limit_per_minute, metadata
            ) VALUES (
                $1, $2, $3, $4, $5, 95, 'active', 1000000, 1000000,
                ARRAY['financial_transaction']::TEXT[], ARRAY[]::TEXT[], 100000, $6::JSONB
            )
            """,
            agent_id,
            org_id,
            f"stress-agent-{agent_id}",
            secrets.token_bytes(32),
            hashlib.sha256(str(agent_id).encode()).hexdigest(),
            json.dumps(
                {
                    "sandbox": False,
                    "production_approval_reference": "gate-6-stress",
                    "production_approved_at": "2026-01-01T00:00:00Z",
                    "production_approved_by": "gate-6-fixture",
                }
            ),
        )
    return org_id, agent_id


async def issue(
    store: AuthorityStore,
    *,
    org_id: UUID,
    agent_id: UUID,
    issuance_ref: str,
    seed: str,
    amount: Decimal = Decimal("0"),
    scope_digest: str | None = None,
):
    now = datetime.now(UTC)
    return await store.issue(
        agent_id=agent_id,
        organisation_id=org_id,
        issuance_ref=issuance_ref,
        execution_action_hash=action_hash(seed),
        policy_hash=POLICY_HASH,
        policy_snapshot_format=FORMAT,
        policy_revision="revision-1",
        executor_binding_digest=BINDING,
        domain="payment",
        action_type="financial_transaction",
        minute_start=now.replace(second=0, microsecond=0),
        day_start=now.replace(hour=0, minute=0, second=0, microsecond=0),
        rate_limit_per_minute=100000,
        daily_limit_usd=Decimal("1000000"),
        amount_usd=amount,
        authority_scope_digest=scope_digest,
    )


async def claim_count(db: Database, token_id: str) -> int:
    async with db.acquire() as conn:
        return await conn.fetchval(
            "SELECT COUNT(*) FROM approval_token_consumptions WHERE token_id = $1",
            token_id,
        )


# =============================================================================
# Concurrent consumption of one grant
# =============================================================================


class TestOneGrantManyConsumers:
    async def test_different_execution_refs_produce_at_most_one_execution(self, db) -> None:
        """Single-use authority under sustained contention.

        The claim is not "usually one" -- it is exactly one, every round.
        """
        org_id, agent_id = await make_agent(db)
        store = AuthorityStore(db, current_policy_resolver=static_policy())

        for round_index in range(ROUNDS):
            seed = f"many-{round_index}"
            issued = await issue(
                store,
                org_id=org_id,
                agent_id=agent_id,
                issuance_ref=f"many-{round_index}",
                seed=seed,
            )
            results = await asyncio.gather(
                *(
                    store.consume(
                        grant_id=issued.grant_id,
                        execution_action_hash=action_hash(seed),
                        executor_binding_digest=BINDING,
                        execution_ref=f"exec-{round_index}-{index}",
                    )
                    for index in range(CONCURRENCY)
                ),
                return_exceptions=True,
            )
            raised = [r for r in results if isinstance(r, BaseException)]
            assert not raised, f"round {round_index} raised: {raised[:3]}"

            authorised = [r for r in results if r.outcome is ConsumptionOutcome.AUTHORISED]
            assert (
                len(authorised) == 1
            ), f"round {round_index}: {len(authorised)} consumers authorised"
            assert await claim_count(db, issued.approval_token_id) == 1

            # Everybody else must be refused with a reason that is TRUE of
            # what happened, not a generic failure.
            for result in results:
                if result.outcome is ConsumptionOutcome.AUTHORISED:
                    continue
                assert result.rejection_reason in (
                    DecisionReason.GRANT_ALREADY_CONSUMED,
                    DecisionReason.EXECUTION_REF_CONFLICT,
                )

    async def test_the_same_execution_ref_recovers_rather_than_re_executing(self, db) -> None:
        """A retry storm after a lost response: one execution, many answers."""
        org_id, agent_id = await make_agent(db)
        store = AuthorityStore(db, current_policy_resolver=static_policy())

        for round_index in range(ROUNDS):
            seed = f"same-{round_index}"
            issued = await issue(
                store,
                org_id=org_id,
                agent_id=agent_id,
                issuance_ref=f"same-{round_index}",
                seed=seed,
            )
            ref = f"exec-same-{round_index}"
            results = await asyncio.gather(
                *(
                    store.consume(
                        grant_id=issued.grant_id,
                        execution_action_hash=action_hash(seed),
                        executor_binding_digest=BINDING,
                        execution_ref=ref,
                    )
                    for _ in range(CONCURRENCY)
                )
            )
            authorised = [r for r in results if r.outcome is ConsumptionOutcome.AUTHORISED]
            recovered = [r for r in results if r.outcome is ConsumptionOutcome.RECOVERED]
            assert len(authorised) == 1
            # Recovery authorises nothing: it hands back the record.
            assert all(r.may_execute is False for r in recovered)
            assert await claim_count(db, issued.approval_token_id) == 1


# =============================================================================
# The headline invariant
# =============================================================================


class TestNoStalePolicyConsumption:
    """No stale-policy first consumption may succeed after a denying change."""

    async def test_a_policy_change_racing_many_consumers_never_slips_through(self, db) -> None:
        """The change lands while N consumers are already in flight.

        Two outcomes are acceptable per round: the grant was claimed before
        the change (so the change had not yet applied), or it was refused.
        What must never happen is a claim by a consumer that read the OLD
        policy after the change committed.
        """
        org_id, agent_id = await make_agent(db)
        moving = MovingPolicy()
        store = AuthorityStore(db, current_policy_resolver=moving)

        slipped: list[str] = []
        for round_index in range(ROUNDS):
            moving.policy_hash = POLICY_HASH
            seed = f"stale-{round_index}"
            issued = await issue(
                store,
                org_id=org_id,
                agent_id=agent_id,
                issuance_ref=f"stale-{round_index}",
                seed=seed,
            )

            async def flip() -> None:
                # Land the change part-way into the consumer wave rather than
                # before or after it.
                await asyncio.sleep(0)
                moving.policy_hash = DENYING_POLICY_HASH

            results = await asyncio.gather(
                flip(),
                *(
                    store.consume(
                        grant_id=issued.grant_id,
                        execution_action_hash=action_hash(seed),
                        executor_binding_digest=BINDING,
                        execution_ref=f"exec-stale-{round_index}-{index}",
                    )
                    for index in range(CONCURRENCY)
                ),
            )
            consumptions = list(results[1:])
            authorised = [r for r in consumptions if r.outcome is ConsumptionOutcome.AUTHORISED]
            assert len(authorised) <= 1
            assert await claim_count(db, issued.approval_token_id) == len(authorised)

            # Whatever the interleaving, the final policy denies this grant,
            # so no FURTHER consumption may be authorised now.
            after = await store.consume(
                grant_id=issued.grant_id,
                execution_action_hash=action_hash(seed),
                executor_binding_digest=BINDING,
                execution_ref=f"exec-stale-after-{round_index}",
            )
            if after.outcome is ConsumptionOutcome.AUTHORISED:
                slipped.append(
                    f"round {round_index}: a consumption succeeded under a "
                    "policy that should have denied it"
                )
            else:
                assert after.rejection_reason in (
                    DecisionReason.POLICY_HASH_MISMATCH,
                    DecisionReason.GRANT_ALREADY_CONSUMED,
                )

        assert not slipped, slipped

    async def test_a_suspension_racing_many_consumers_never_slips_through(self, db) -> None:
        """Suspending a principal must stop the very next consumption."""
        org_id, agent_id = await make_agent(db)
        store = AuthorityStore(db, current_policy_resolver=static_policy())

        for round_index in range(ROUNDS):
            async with db.acquire() as conn:
                await conn.execute("UPDATE agents SET status = 'active' WHERE id = $1", agent_id)
            seed = f"suspend-{round_index}"
            issued = await issue(
                store,
                org_id=org_id,
                agent_id=agent_id,
                issuance_ref=f"suspend-{round_index}",
                seed=seed,
            )

            async def suspend() -> None:
                await asyncio.sleep(0)
                async with db.acquire() as conn:
                    await conn.execute(
                        "UPDATE agents SET status = 'suspended' WHERE id = $1",
                        agent_id,
                    )

            results = await asyncio.gather(
                suspend(),
                *(
                    store.consume(
                        grant_id=issued.grant_id,
                        execution_action_hash=action_hash(seed),
                        executor_binding_digest=BINDING,
                        execution_ref=f"exec-susp-{round_index}-{index}",
                    )
                    for index in range(CONCURRENCY)
                ),
            )
            authorised = [r for r in results[1:] if r.outcome is ConsumptionOutcome.AUTHORISED]
            assert len(authorised) <= 1
            assert await claim_count(db, issued.approval_token_id) == len(authorised)

            after = await store.consume(
                grant_id=issued.grant_id,
                execution_action_hash=action_hash(seed),
                executor_binding_digest=BINDING,
                execution_ref=f"exec-susp-after-{round_index}",
            )
            assert after.outcome is not ConsumptionOutcome.AUTHORISED
            # EXECUTION_REF_CONFLICT appears when the grant was already
            # claimed in the wave: a NEW reference against spent single-use
            # authority is a second execution attempt, refused as such
            # before the suspension is even reached.
            assert after.rejection_reason in (
                DecisionReason.AGENT_NOT_ACTIVE,
                DecisionReason.GRANT_ALREADY_CONSUMED,
                DecisionReason.EXECUTION_REF_CONFLICT,
            )

    async def test_a_narrowed_delegation_racing_consumers_never_slips_through(self, db) -> None:
        """Revoking or narrowing the delegation stops the next consumption."""
        org_id, agent_id = await make_agent(db)
        store = AuthorityStore(db, current_policy_resolver=static_policy())

        at_decision = authority_scope_digest(
            issuer="stress-issuer",
            external_reference_id="ref-1",
            artefact_digest=DIGEST_A,
            scope={"max_amount": "500.00", "currency": "USD"},
        )
        narrowed = authority_scope_digest(
            issuer="stress-issuer",
            external_reference_id="ref-1",
            artefact_digest=DIGEST_A,
            scope={"max_amount": "1.00", "currency": "USD"},
        )
        assert narrowed != at_decision

        for round_index in range(ROUNDS):
            seed = f"scope-{round_index}"
            issued = await issue(
                store,
                org_id=org_id,
                agent_id=agent_id,
                issuance_ref=f"scope-{round_index}",
                seed=seed,
                scope_digest=at_decision,
            )
            # Half the consumers carry current evidence, half carry the
            # narrowed evidence an operator has just made true.
            results = await asyncio.gather(
                *(
                    store.consume(
                        grant_id=issued.grant_id,
                        execution_action_hash=action_hash(seed),
                        executor_binding_digest=BINDING,
                        execution_ref=f"exec-scope-{round_index}-{index}",
                        authority_evidence=ResolvedAuthorityEvidence(
                            scope_digest=at_decision if index % 2 == 0 else narrowed
                        ),
                    )
                    for index in range(CONCURRENCY)
                )
            )
            authorised = [r for r in results if r.outcome is ConsumptionOutcome.AUTHORISED]
            assert len(authorised) <= 1
            assert await claim_count(db, issued.approval_token_id) == len(authorised)
            # A narrowed-evidence consumer must never be the one that won.
            for index, result in enumerate(results):
                if index % 2 == 1:
                    assert result.outcome is not ConsumptionOutcome.AUTHORISED


# =============================================================================
# Issuance storms
# =============================================================================


class TestIssuanceStorms:
    async def test_identical_issuance_refs_yield_one_logical_grant(self, db) -> None:
        org_id, agent_id = await make_agent(db)
        store = AuthorityStore(db, current_policy_resolver=static_policy())

        for round_index in range(ROUNDS):
            ref = f"storm-{round_index}"
            results = await asyncio.gather(
                *(
                    issue(
                        store,
                        org_id=org_id,
                        agent_id=agent_id,
                        issuance_ref=ref,
                        seed=ref,
                        amount=Decimal("5"),
                    )
                    for _ in range(CONCURRENCY)
                )
            )
            grant_ids = {r.grant_id for r in results if r.grant_id is not None}
            assert len(grant_ids) == 1, f"round {round_index}: {len(grant_ids)} grants"
            issued = [r for r in results if r.outcome is IssueOutcome.ISSUED]
            assert len(issued) == 1

            # Capacity is committed once, not once per racer.
            async with db.acquire() as conn:
                reservations = await conn.fetchval(
                    """
                    SELECT COUNT(*) FROM spend_reservations
                    WHERE agent_id = $1 AND amount_usd = 5
                    """,
                    agent_id,
                )
            assert reservations == round_index + 1

    async def test_distinct_refs_each_reserve_exactly_once(self, db) -> None:
        """Different attempts are different authority and each is charged."""
        org_id, agent_id = await make_agent(db)
        store = AuthorityStore(db, current_policy_resolver=static_policy())

        results = await asyncio.gather(
            *(
                issue(
                    store,
                    org_id=org_id,
                    agent_id=agent_id,
                    issuance_ref=f"distinct-{index}",
                    seed=f"distinct-{index}",
                    amount=Decimal("1"),
                )
                for index in range(CONCURRENCY)
            )
        )
        grant_ids = {r.grant_id for r in results if r.grant_id is not None}
        assert len(grant_ids) == CONCURRENCY

        async with db.acquire() as conn:
            total = await conn.fetchval(
                """
                SELECT COALESCE(SUM(amount_usd), 0) FROM spend_reservations
                WHERE agent_id = $1 AND status IN ('reserved', 'consumed')
                """,
                agent_id,
            )
        assert Decimal(total) == Decimal(CONCURRENCY)

    async def test_a_cumulative_limit_is_not_over_committed_under_contention(self, db) -> None:
        """The race two callers for one grant does NOT cover.

        Different transactions competing for the same cumulative headroom
        must not both observe it. A system can pass every single-grant race
        and still fail this one.
        """
        org_id, agent_id = await make_agent(db)
        store = AuthorityStore(db, current_policy_resolver=static_policy())
        async with db.acquire() as conn:
            await conn.execute("UPDATE agents SET daily_limit_usd = 100 WHERE id = $1", agent_id)

        now = datetime.now(UTC)
        results = await asyncio.gather(
            *(
                store.issue(
                    agent_id=agent_id,
                    organisation_id=org_id,
                    issuance_ref=f"cap-{index}",
                    execution_action_hash=action_hash(f"cap-{index}"),
                    policy_hash=POLICY_HASH,
                    policy_snapshot_format=FORMAT,
                    policy_revision="revision-1",
                    executor_binding_digest=BINDING,
                    domain="payment",
                    action_type="financial_transaction",
                    minute_start=now.replace(second=0, microsecond=0),
                    day_start=now.replace(hour=0, minute=0, second=0, microsecond=0),
                    rate_limit_per_minute=100000,
                    daily_limit_usd=Decimal("100"),
                    amount_usd=Decimal("25"),
                )
                for index in range(CONCURRENCY)
            ),
            return_exceptions=True,
        )
        issued = [
            r
            for r in results
            if not isinstance(r, BaseException) and r.outcome is IssueOutcome.ISSUED
        ]
        assert len(issued) <= 4, f"{len(issued)} grants issued against a limit of 4"

        async with db.acquire() as conn:
            committed = await conn.fetchval(
                """
                SELECT COALESCE(SUM(amount_usd), 0) FROM spend_reservations
                WHERE agent_id = $1 AND status IN ('reserved', 'consumed')
                """,
                agent_id,
            )
        assert Decimal(committed) <= Decimal("100")


# =============================================================================
# Fault injection: the database actually goes away
# =============================================================================


restart_required = pytest.mark.skipif(
    not PG_RESTART_COMMAND,
    reason=(
        "set INNTRIS_PG_RESTART_COMMAND to the command that restarts the test "
        "PostgreSQL, e.g. 'pg_ctlcluster 16 main restart'"
    ),
)


#: Every wait in the fault-injection cases is bounded. A hang is a real
#: finding -- an in-flight consumer holding a connection the server has
#: dropped does not necessarily return on its own -- so it is reported as a
#: timed-out attempt rather than allowed to stall the suite. Production
#: clients need their own bound for the same reason.
FAULT_TIMEOUT_SECONDS: float = 30.0


def restart_postgres() -> None:
    subprocess.run(shlex.split(PG_RESTART_COMMAND), check=True, timeout=120)


async def bounded(awaitable):
    """Await with a bound, turning a hang into a recorded outcome."""
    try:
        return await asyncio.wait_for(awaitable, timeout=FAULT_TIMEOUT_SECONDS)
    except TimeoutError as exc:
        return exc


@restart_required
class TestDatabaseRestart:
    async def test_a_restart_mid_flight_never_double_executes(self, db) -> None:
        """The question a mock cannot answer.

        Consumers are in flight when the server goes away. Some of their
        connections die. What must hold afterwards is not "everything
        succeeded" -- it is that the grant was claimed at most once, and
        that the surviving record says so.
        """
        org_id, agent_id = await make_agent(db)
        store = AuthorityStore(db, current_policy_resolver=static_policy())
        seed = "restart-1"
        issued = await issue(
            store,
            org_id=org_id,
            agent_id=agent_id,
            issuance_ref="restart-1",
            seed=seed,
        )

        async def restart_soon() -> None:
            await asyncio.sleep(0.05)
            await asyncio.get_running_loop().run_in_executor(None, restart_postgres)

        results = await asyncio.gather(
            restart_soon(),
            *(
                bounded(
                    store.consume(
                        grant_id=issued.grant_id,
                        execution_action_hash=action_hash(seed),
                        executor_binding_digest=BINDING,
                        execution_ref=f"exec-restart-{index}",
                    )
                )
                for index in range(CONCURRENCY)
            ),
            return_exceptions=True,
        )
        consumptions = [r for r in results[1:] if not isinstance(r, BaseException)]
        authorised = [r for r in consumptions if r.outcome is ConsumptionOutcome.AUTHORISED]
        assert len(authorised) <= 1

        timed_out = sum(1 for r in results[1:] if isinstance(r, TimeoutError))
        # Reconnect and confirm the durable record agrees. Neither a
        # connection failure nor a consumer that never returned may have
        # produced a second claim -- a client that gave up is exactly the
        # case where a duplicate execution would be invisible.
        fresh = await Database.create(DATABASE_URL, min_size=1, max_size=4)
        try:
            async with fresh.acquire() as conn:
                claims = await conn.fetchval(
                    "SELECT COUNT(*) FROM approval_token_consumptions WHERE token_id = $1",
                    issued.approval_token_id,
                )
            assert claims == len(authorised), (
                f"{claims} claims for {len(authorised)} authorised consumers "
                f"({timed_out} timed out)"
            )
        finally:
            await fresh.close()

    async def test_the_service_recovers_after_the_restart(self, db) -> None:
        """A restart must not leave the store permanently broken."""
        org_id, agent_id = await make_agent(db)
        store = AuthorityStore(db, current_policy_resolver=static_policy())
        await asyncio.get_running_loop().run_in_executor(None, restart_postgres)

        # The pool's dead connections are replaced on demand; the first
        # attempt after a restart may legitimately fail, and the next must
        # not.
        last_error: BaseException | None = None
        for attempt in range(5):
            try:
                issued = await asyncio.wait_for(
                    issue(
                        store,
                        org_id=org_id,
                        agent_id=agent_id,
                        issuance_ref=f"after-restart-{attempt}",
                        seed=f"after-restart-{attempt}",
                    ),
                    timeout=FAULT_TIMEOUT_SECONDS,
                )
                break
            except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError, TimeoutError) as exc:
                last_error = exc
                await asyncio.sleep(0.5)
        else:  # pragma: no cover - only on a genuinely broken recovery
            pytest.fail(f"store never recovered after restart: {last_error}")

        result = await asyncio.wait_for(
            store.consume(
                grant_id=issued.grant_id,
                execution_action_hash=action_hash(f"after-restart-{attempt}"),
                executor_binding_digest=BINDING,
                execution_ref="exec-after-restart",
            ),
            timeout=FAULT_TIMEOUT_SECONDS,
        )
        assert result.outcome is ConsumptionOutcome.AUTHORISED

    async def test_a_failure_during_consumption_never_half_claims(self, db) -> None:
        """Terminate the backend mid-transaction rather than restarting it.

        This is the sharper version: one specific transaction is killed
        while it holds the grant's advisory lock. The claim and the grant
        update are one transaction, so either both happened or neither did.
        """
        org_id, agent_id = await make_agent(db)
        store = AuthorityStore(db, current_policy_resolver=static_policy())
        seed = "kill-1"
        issued = await issue(
            store, org_id=org_id, agent_id=agent_id, issuance_ref="kill-1", seed=seed
        )

        async def kill_backends() -> None:
            await asyncio.sleep(0.02)
            killer = await asyncpg.connect(DATABASE_URL)
            try:
                await killer.execute("""
                    SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                    WHERE datname = current_database()
                      AND pid <> pg_backend_pid()
                      AND state = 'idle in transaction'
                    """)
            finally:
                await killer.close()

        results = await asyncio.gather(
            kill_backends(),
            *(
                bounded(
                    store.consume(
                        grant_id=issued.grant_id,
                        execution_action_hash=action_hash(seed),
                        executor_binding_digest=BINDING,
                        execution_ref=f"exec-kill-{index}",
                    )
                )
                for index in range(CONCURRENCY)
            ),
            return_exceptions=True,
        )
        authorised = [
            r
            for r in results[1:]
            if not isinstance(r, BaseException) and r.outcome is ConsumptionOutcome.AUTHORISED
        ]

        fresh = await Database.create(DATABASE_URL, min_size=1, max_size=4)
        try:
            async with fresh.acquire() as conn:
                claims = await conn.fetchval(
                    "SELECT COUNT(*) FROM approval_token_consumptions WHERE token_id = $1",
                    issued.approval_token_id,
                )
                status = await conn.fetchval(
                    "SELECT status FROM execution_authority_grants WHERE id = $1",
                    issued.grant_id,
                )
            assert claims <= 1
            assert claims == len(authorised)
            # No half state: a claimed token means a consumed grant.
            assert (claims == 1) == (status == "consumed")
        finally:
            await fresh.close()
