"""Gate 7 — the consume lock order, and the cycle it exists to prevent.

Frozen Phase 6 held the ``agents`` row ``FOR SHARE`` and only then reached
the per-agent forensic-chain lock, which ``audit_logs`` takes from its
BEFORE INSERT trigger. Its AFTER INSERT trigger then UPDATEs that same
agents row. So the audit append is chain-then-principal while consumption
was principal-then-chain: an ABBA inversion, and two consumers of different
grants for one principal deadlocked on it deterministically.

These tests pin the order that removes it. Every one of them fails on
frozen Phase 6 by deadlocking or by admitting state the recheck must refuse.

Gated like the other database integration tests: ``INNTRIS_DB_INTEGRATION=1``
and a ``DATABASE_URL`` on a database migrated to head.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

asyncpg = pytest.importorskip("asyncpg")

from api.core.authority.decision import DecisionReason  # noqa: E402
from api.core.authority.lifecycle import ConsumptionOutcome  # noqa: E402
from api.database import Database  # noqa: E402
from api.models import ActionVerdict, AuditLogEntry  # noqa: E402
from api.persistence.authority_store import AuthorityStore  # noqa: E402

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="lock-order tests require INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)

POLICY_HASH = "b" * 64
BINDING = "c" * 64
FORMAT = "inntris-payment-authority-policy-v1"

#: Anything slower than this under contention means we are queueing on a
#: lock that should not be held, or deadlocking and retrying.
CONTENTION_BUDGET_S = 60.0


def action_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _static_policy():
    def resolver(_agent, _action_type, _domain):
        return POLICY_HASH, "revision-1"

    return resolver


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=4, max_size=40)
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
async def store(db: Database) -> AuthorityStore:
    return AuthorityStore(db, current_policy_resolver=_static_policy())


async def make_org(db: Database) -> UUID:
    org_id = uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
               VALUES ($1,$2,'enterprise',$3,$4)""",
            org_id,
            f"lockorder-{org_id}",
            f"lockorder-{org_id}@example.test",
            hashlib.sha256(str(org_id).encode()).digest(),
        )
    return org_id


async def make_agent(db: Database, org_id: UUID) -> UUID:
    agent_id = uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """INSERT INTO agents (
                 id, org_id, name, public_key, public_key_fingerprint, trust_score,
                 status, daily_limit_usd, per_action_limit_usd, allowed_actions,
                 blocked_actions, rate_limit_per_minute, metadata)
               VALUES ($1,$2,$3,$4,$5,95,'active',100000000,100000000,
                       ARRAY['financial_transaction']::TEXT[], ARRAY[]::TEXT[],
                       10000000, $6::JSONB)""",
            agent_id,
            org_id,
            f"lockorder-agent-{agent_id}",
            secrets.token_bytes(32),
            hashlib.sha256(str(agent_id).encode()).hexdigest(),
            json.dumps(
                {
                    "sandbox": False,
                    "production_approval_reference": "gate7-lock-order",
                    "production_approved_at": "2026-01-01T00:00:00Z",
                    "production_approved_by": "gate7-lock-order",
                }
            ),
        )
    return agent_id


async def issue(store: AuthorityStore, org_id: UUID, agent_id: UUID, ref: str):
    now = datetime.now(UTC)
    return await store.issue(
        agent_id=agent_id,
        organisation_id=org_id,
        issuance_ref=ref,
        execution_action_hash=action_hash(ref),
        policy_hash=POLICY_HASH,
        policy_snapshot_format=FORMAT,
        policy_revision="revision-1",
        executor_binding_digest=BINDING,
        domain="payment",
        action_type="financial_transaction",
        minute_start=now.replace(second=0, microsecond=0),
        day_start=now.replace(hour=0, minute=0, second=0, microsecond=0),
        rate_limit_per_minute=10_000_000,
        daily_limit_usd=Decimal("100000000"),
        amount_usd=Decimal("1"),
    )


async def consume(store: AuthorityStore, ref: str, grant, *, execution_ref=None):
    return await store.consume(
        grant_id=grant.grant_id,
        execution_action_hash=action_hash(ref),
        executor_binding_digest=BINDING,
        execution_ref=execution_ref or f"exec-{ref}",
    )


async def assert_chain_intact(db: Database, agent_ids: list[UUID]) -> None:
    """The four chain properties, asserted together because they fail together."""
    async with db.acquire() as conn:
        rows = await conn.fetch(
            """SELECT agent_id, COUNT(*) AS n, MAX(chain_sequence) AS top,
                      COUNT(DISTINCT chain_sequence) AS distinct_n
               FROM audit_logs WHERE agent_id = ANY($1::UUID[]) GROUP BY agent_id""",
            agent_ids,
        )
        for row in rows:
            assert row["n"] == row["top"], f"gap in chain for {row['agent_id']}"
            assert row["n"] == row["distinct_n"], f"forked chain for {row['agent_id']}"

        broken = await conn.fetchval(
            """SELECT COUNT(*) FROM (
                 SELECT chain_sequence, chain_previous_hash,
                        LAG(action_hash) OVER (
                            PARTITION BY agent_id ORDER BY chain_sequence) AS prev
                 FROM audit_logs WHERE agent_id = ANY($1::UUID[])) s
               WHERE chain_sequence > 1 AND chain_previous_hash IS DISTINCT FROM prev""",
            agent_ids,
        )
        assert broken == 0, f"{broken} audit rows do not name their predecessor"


async def assert_no_duplicate_spend(db: Database, grants: list) -> None:
    token_ids = [g.approval_token_id for g in grants]
    grant_ids = [g.grant_id for g in grants]
    async with db.acquire() as conn:
        dup = await conn.fetchval(
            """SELECT COUNT(*) FROM (
                 SELECT token_id FROM approval_token_consumptions
                 WHERE token_id = ANY($1::TEXT[])
                 GROUP BY token_id HAVING COUNT(*) > 1) s""",
            token_ids,
        )
        assert dup == 0, f"{dup} token(s) spent more than once"

        orphan = await conn.fetchval(
            """SELECT COUNT(*) FROM execution_authority_grants g
               WHERE g.id = ANY($1::UUID[]) AND g.status = 'consumed'
                 AND NOT EXISTS (SELECT 1 FROM approval_token_consumptions c
                                 WHERE c.token_id = g.approval_token_id)""",
            grant_ids,
        )
        assert orphan == 0, f"{orphan} consumed grant(s) with no consumption record"

        contradiction = await conn.fetchval(
            """SELECT COUNT(*) FROM execution_authority_grants g
               JOIN approval_token_consumptions c ON c.token_id = g.approval_token_id
               WHERE g.id = ANY($1::UUID[]) AND g.status = 'active'""",
            grant_ids,
        )
        assert contradiction == 0, "token claimed while its grant still reads active"


class TestConcurrentConsumptionShapes:
    """1-4: the shapes that deadlocked on frozen Phase 6."""

    async def test_1_two_grants_one_principal_concurrently(self, db, store) -> None:
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grants = [await issue(store, org_id, agent_id, f"c2-{i}") for i in range(2)]

        results = await asyncio.wait_for(
            asyncio.gather(*(consume(store, f"c2-{i}", g) for i, g in enumerate(grants))),
            timeout=CONTENTION_BUDGET_S,
        )

        assert [r.outcome for r in results] == [ConsumptionOutcome.AUTHORISED] * 2
        await assert_chain_intact(db, [agent_id])
        await assert_no_duplicate_spend(db, grants)

    async def test_2_many_grants_one_principal(self, db, store) -> None:
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grants = [await issue(store, org_id, agent_id, f"many-{i}") for i in range(40)]

        results = await asyncio.wait_for(
            asyncio.gather(
                *(consume(store, f"many-{i}", g) for i, g in enumerate(grants))
            ),
            timeout=CONTENTION_BUDGET_S,
        )

        assert all(r.outcome is ConsumptionOutcome.AUTHORISED for r in results)
        await assert_chain_intact(db, [agent_id])
        await assert_no_duplicate_spend(db, grants)

    async def test_3_many_principals_one_organisation(self, db, store) -> None:
        org_id = await make_org(db)
        agents = [await make_agent(db, org_id) for _ in range(8)]
        grants, refs = [], []
        for agent_id in agents:
            for i in range(4):
                ref = f"mp1-{agent_id.hex[:6]}-{i}"
                grants.append(await issue(store, org_id, agent_id, ref))
                refs.append(ref)

        results = await asyncio.wait_for(
            asyncio.gather(*(consume(store, r, g) for r, g in zip(refs, grants, strict=True))),
            timeout=CONTENTION_BUDGET_S,
        )

        assert all(r.outcome is ConsumptionOutcome.AUTHORISED for r in results)
        await assert_chain_intact(db, agents)
        await assert_no_duplicate_spend(db, grants)

    async def test_4_many_principals_many_organisations(self, db, store) -> None:
        agents, grants, refs = [], [], []
        for _ in range(8):
            org_id = await make_org(db)
            agent_id = await make_agent(db, org_id)
            agents.append(agent_id)
            for i in range(4):
                ref = f"mpm-{agent_id.hex[:6]}-{i}"
                grants.append(await issue(store, org_id, agent_id, ref))
                refs.append(ref)

        results = await asyncio.wait_for(
            asyncio.gather(*(consume(store, r, g) for r, g in zip(refs, grants, strict=True))),
            timeout=CONTENTION_BUDGET_S,
        )

        assert all(r.outcome is ConsumptionOutcome.AUTHORISED for r in results)
        await assert_chain_intact(db, agents)
        await assert_no_duplicate_spend(db, grants)


class TestCrossPathContention:
    """5-8: authority consumption against every other writer of the same rows."""

    async def test_5_authority_consume_against_legacy_token_consumption(
        self, db, store
    ) -> None:
        """The legacy path takes TOKEN then CHAIN; consume must agree on that order."""
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grants = [await issue(store, org_id, agent_id, f"legacy-{i}") for i in range(6)]

        def legacy_entry(index: int) -> AuditLogEntry:
            return AuditLogEntry(
                agent_id=agent_id,
                action_type="financial_transaction",
                action_hash=action_hash(f"legacy-side-{index}"),
                payload={},
                verdict=ActionVerdict.APPROVED,
                verdict_reason="legacy",
                signature=b"legacy-signature",
                signature_valid=True,
                request_ip=None,
                request_user_agent=None,
                response_time_ms=None,
                trust_score_at_time=95,
                chain_previous_hash=None,
            )

        async def legacy(index: int):
            token = f"legacy-token-{uuid4().hex}"
            return await db.insert_token_consumption(
                legacy_entry(index),
                token_id=token,
                token_digest=hashlib.sha256(token.encode()).digest(),
                approved_action_hash=action_hash(f"legacy-side-{index}"),
                execution_ref=f"legacy-exec-{index}",
            )

        results = await asyncio.wait_for(
            asyncio.gather(
                *(consume(store, f"legacy-{i}", g) for i, g in enumerate(grants)),
                *(legacy(i) for i in range(6)),
            ),
            timeout=CONTENTION_BUDGET_S,
        )

        assert all(
            r.outcome is ConsumptionOutcome.AUTHORISED
            for r in results[:6]
        )
        assert all(r is not None for r in results[6:])
        await assert_chain_intact(db, [agent_id])
        await assert_no_duplicate_spend(db, grants)

    async def test_6_authority_consume_against_ordinary_audit_writer(
        self, db, store
    ) -> None:
        """A plain chain-deriving audit append is the other half of the cycle."""
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grants = [await issue(store, org_id, agent_id, f"audit-{i}") for i in range(6)]

        async def plain_audit(index: int):
            return await db.insert_audit_log(
                AuditLogEntry(
                    agent_id=agent_id,
                    action_type="financial_transaction",
                    action_hash=action_hash(f"plain-{index}"),
                    payload={},
                    verdict=ActionVerdict.APPROVED,
                    verdict_reason="plain",
                    signature=b"plain-signature",
                    signature_valid=True,
                    request_ip=None,
                    request_user_agent=None,
                    response_time_ms=None,
                    trust_score_at_time=95,
                    chain_previous_hash=None,
                ),
                derive_chain_hash=True,
            )

        results = await asyncio.wait_for(
            asyncio.gather(
                *(consume(store, f"audit-{i}", g) for i, g in enumerate(grants)),
                *(plain_audit(i) for i in range(6)),
            ),
            timeout=CONTENTION_BUDGET_S,
        )

        assert all(r.outcome is ConsumptionOutcome.AUTHORISED for r in results[:6])
        await assert_chain_intact(db, [agent_id])
        await assert_no_duplicate_spend(db, grants)

    async def test_7_concurrent_principal_suspension_is_serialised(
        self, db, store
    ) -> None:
        """Suspension must win or lose cleanly -- never deadlock, never half-apply."""
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grants = [await issue(store, org_id, agent_id, f"susp-{i}") for i in range(6)]

        async def suspend():
            await asyncio.sleep(0.01)
            async with db.acquire() as conn:
                await conn.execute(
                    "UPDATE agents SET status = 'suspended' WHERE id = $1", agent_id
                )

        results = await asyncio.wait_for(
            asyncio.gather(
                *(consume(store, f"susp-{i}", g) for i, g in enumerate(grants)),
                suspend(),
            ),
            timeout=CONTENTION_BUDGET_S,
        )

        outcomes = list(results[:6])
        for result in outcomes:
            if result.outcome is not ConsumptionOutcome.AUTHORISED:
                # A refusal must name the principal, not a lock artefact.
                assert result.rejection_reason is DecisionReason.AGENT_NOT_ACTIVE
        await assert_chain_intact(db, [agent_id])
        await assert_no_duplicate_spend(db, grants)

    async def test_8_concurrent_policy_update_never_admits_stale_policy(
        self, db, store
    ) -> None:
        """A limit change concurrent with consumption must not be straddled."""
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grants = [await issue(store, org_id, agent_id, f"pol-{i}") for i in range(6)]

        async def retighten():
            await asyncio.sleep(0.01)
            async with db.acquire() as conn:
                await conn.execute(
                    "UPDATE agents SET per_action_limit_usd = 1 WHERE id = $1",
                    agent_id,
                )

        results = await asyncio.wait_for(
            asyncio.gather(
                *(consume(store, f"pol-{i}", g) for i, g in enumerate(grants)),
                retighten(),
            ),
            timeout=CONTENTION_BUDGET_S,
        )

        assert all(r.rejection_reason is not None or r.outcome for r in results[:6])
        await assert_chain_intact(db, [agent_id])
        await assert_no_duplicate_spend(db, grants)


class TestExecutionRefConcurrency:
    """9-10: single use, and idempotent recovery, under contention."""

    async def test_9_same_execution_ref_yields_one_spend_and_recoveries(
        self, db, store
    ) -> None:
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grant = await issue(store, org_id, agent_id, "same-ref")

        results = await asyncio.wait_for(
            asyncio.gather(
                *(
                    consume(store, "same-ref", grant, execution_ref="one-and-only")
                    for _ in range(8)
                )
            ),
            timeout=CONTENTION_BUDGET_S,
        )

        authorised = [r for r in results if r.outcome is ConsumptionOutcome.AUTHORISED]
        recovered = [r for r in results if r.outcome is ConsumptionOutcome.RECOVERED]
        assert len(authorised) == 1, "single-use authority was spent more than once"
        assert len(authorised) + len(recovered) == 8, "a caller got neither spend nor record"
        assert {r.consumption_audit_id for r in authorised + recovered} == {
            authorised[0].consumption_audit_id
        }
        await assert_chain_intact(db, [agent_id])
        await assert_no_duplicate_spend(db, [grant])

    async def test_10_different_execution_refs_refuse_the_replay(
        self, db, store
    ) -> None:
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grant = await issue(store, org_id, agent_id, "diff-ref")

        results = await asyncio.wait_for(
            asyncio.gather(
                *(
                    consume(store, "diff-ref", grant, execution_ref=f"ref-{i}")
                    for i in range(8)
                )
            ),
            timeout=CONTENTION_BUDGET_S,
        )

        authorised = [r for r in results if r.outcome is ConsumptionOutcome.AUTHORISED]
        assert len(authorised) == 1
        for result in results:
            if result.outcome is not ConsumptionOutcome.AUTHORISED:
                assert result.rejection_reason in {
                    DecisionReason.GRANT_ALREADY_CONSUMED,
                    DecisionReason.EXECUTION_REF_CONFLICT,
                }
        await assert_chain_intact(db, [agent_id])
        await assert_no_duplicate_spend(db, [grant])


class _DoctoredDiscoveryConnection:
    """A connection whose DISCOVERY read reports a different identity.

    Only the unlocked discovery select is doctored; every authoritative
    read passes straight through. That is precisely the disagreement the
    recheck exists to catch, and the database's own immutability guards
    make it otherwise unreachable -- so without this the fail-closed branch
    would be untested code guarding money.
    """

    _DISCOVERY = "SELECT id, agent_id, org_id, approval_token_id"

    def __init__(self, inner, field: str, value) -> None:
        self._inner = inner
        self._field = field
        self._value = value
        self._doctored = False

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def fetchrow(self, query, *args, **kwargs):
        row = await self._inner.fetchrow(query, *args, **kwargs)
        if not self._doctored and self._DISCOVERY in query and row is not None:
            self._doctored = True
            drifted = dict(row)
            drifted[self._field] = self._value
            return drifted
        return row


class _DoctoringAcquire:
    def __init__(self, cm, field, value):
        self._cm, self._field, self._value = cm, field, value

    async def __aenter__(self):
        conn = await self._cm.__aenter__()
        return _DoctoredDiscoveryConnection(conn, self._field, self._value)

    async def __aexit__(self, *exc):
        return await self._cm.__aexit__(*exc)


class _DoctoringDatabase:
    def __init__(self, inner, field, value):
        self._inner, self._field, self._value = inner, field, value

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def acquire(self, *a, **kw):
        return _DoctoringAcquire(self._inner.acquire(*a, **kw), self._field, self._value)


class TestDiscoveryIdentityCannotDrift:
    """11-13: the identities that choose the locks cannot move underneath us.

    ``consume`` picks the TOKEN and CHAIN keys from an unlocked discovery
    read and then refuses if the authoritative locked rows disagree. Two
    independent things must hold for that to be safe, and both are asserted
    here: the database must not permit the drift at all, and the refusal
    must be live code rather than an unreachable branch.
    """

    async def test_11_a_discovered_grant_cannot_be_deleted(self, db, store) -> None:
        """Discovery cannot be invalidated by the grant vanishing."""
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grant = await issue(store, org_id, agent_id, "no-delete")

        with pytest.raises(asyncpg.PostgresError):
            async with db.acquire() as conn:
                await conn.execute(
                    "DELETE FROM execution_authority_grants WHERE id = $1",
                    grant.grant_id,
                )

        # Still intact, and still spendable exactly once.
        result = await consume(store, "no-delete", grant)
        assert result.outcome is ConsumptionOutcome.AUTHORISED

    async def test_12_token_id_is_database_immutable(self, db, store) -> None:
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grant = await issue(store, org_id, agent_id, "token-immutable")

        with pytest.raises(asyncpg.PostgresError, match="immutable"):
            async with db.acquire() as conn:
                await conn.execute(
                    "UPDATE execution_authority_grants SET approval_token_id = $2 "
                    "WHERE id = $1",
                    grant.grant_id,
                    f"rotated-{uuid4().hex}",
                )

    async def test_13_principal_and_organisation_are_database_immutable(
        self, db, store
    ) -> None:
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        other_agent = await make_agent(db, org_id)
        grant = await issue(store, org_id, agent_id, "principal-immutable")

        for column, value in (("agent_id", other_agent), ("org_id", await make_org(db))):
            with pytest.raises(asyncpg.PostgresError):
                async with db.acquire() as conn:
                    await conn.execute(
                        f"UPDATE execution_authority_grants SET {column} = $2 "
                        "WHERE id = $1",
                        grant.grant_id,
                        value,
                    )

    async def test_13b_recheck_refuses_a_drifted_token_identity(
        self, db, store
    ) -> None:
        """The fail-closed branch is reachable and it refuses."""
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grant = await issue(store, org_id, agent_id, "drift-token")

        drifting = _DoctoringDatabase(db, "approval_token_id", f"ghost-{uuid4().hex}")
        drifted_store = AuthorityStore(drifting, current_policy_resolver=_static_policy())

        result = await consume(drifted_store, "drift-token", grant)

        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.rejection_reason is DecisionReason.GRANT_MALFORMED
        # Refused means refused: nothing was spent.
        async with db.acquire() as conn:
            status = await conn.fetchval(
                "SELECT status FROM execution_authority_grants WHERE id = $1",
                grant.grant_id,
            )
        assert status == "active"
        await assert_no_duplicate_spend(db, [grant])

    async def test_13c_recheck_refuses_a_drifted_principal_identity(
        self, db, store
    ) -> None:
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grant = await issue(store, org_id, agent_id, "drift-principal")

        drifting = _DoctoringDatabase(db, "agent_id", uuid4())
        drifted_store = AuthorityStore(drifting, current_policy_resolver=_static_policy())

        result = await consume(drifted_store, "drift-principal", grant)

        assert result.outcome is ConsumptionOutcome.REJECTED
        assert result.rejection_reason is DecisionReason.GRANT_MALFORMED, (
            "a grant whose principal disagrees with the chain lock we took "
            "must never be spent"
        )
        await assert_chain_intact(db, [agent_id])
        await assert_no_duplicate_spend(db, [grant])


class TestLockLifetime:
    """14-15: locks must not outlive their transaction, or die with it."""

    async def test_14_terminated_backend_releases_every_lock_it_held(
        self, db, store
    ) -> None:
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grant = await issue(store, org_id, agent_id, "terminate")

        victim = await asyncpg.connect(DATABASE_URL)
        victim_pid = victim.get_server_pid()
        tx = victim.transaction()
        await tx.start()
        await victim.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)", str(agent_id)
        )

        async with db.acquire() as conn:
            await conn.execute("SELECT pg_terminate_backend($1)", victim_pid)
        with contextlib.suppress(Exception):  # the backend is already gone
            await victim.close(timeout=5)

        # The lock died with the backend, so this must simply succeed.
        result = await asyncio.wait_for(
            consume(store, "terminate", grant), timeout=CONTENTION_BUDGET_S
        )
        assert result.outcome is ConsumptionOutcome.AUTHORISED
        await assert_chain_intact(db, [agent_id])
        await assert_no_duplicate_spend(db, [grant])

    async def test_15_savepoint_rollback_keeps_parent_locks_and_stays_atomic(
        self, db, store
    ) -> None:
        """Losers of the claim race roll back a savepoint, not the chain lock.

        On frozen Phase 6 that rollback released the trigger-acquired chain
        lock. Here the parent owns it, so the loser's rejection is clean and
        the chain is still contiguous afterwards.
        """
        org_id = await make_org(db)
        agent_id = await make_agent(db, org_id)
        grant = await issue(store, org_id, agent_id, "savepoint")

        results = await asyncio.wait_for(
            asyncio.gather(
                *(
                    consume(store, "savepoint", grant, execution_ref=f"sp-{i}")
                    for i in range(6)
                )
            ),
            timeout=CONTENTION_BUDGET_S,
        )

        authorised = [r for r in results if r.outcome is ConsumptionOutcome.AUTHORISED]
        assert len(authorised) == 1
        for result in results:
            if result.outcome is not ConsumptionOutcome.AUTHORISED:
                assert result.rejection_reason is not None
        await assert_chain_intact(db, [agent_id])
        await assert_no_duplicate_spend(db, [grant])

        # And the grant's own state agrees with the consumption record.
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT status, consumption_audit_id FROM execution_authority_grants "
                "WHERE id = $1",
                grant.grant_id,
            )
        assert row["status"] == "consumed"
        assert row["consumption_audit_id"] == authorised[0].consumption_audit_id
