"""Latent Core defects the Phase-6 adversarial proof discovered.

Each test here failed on the frozen Phase-5 commit
``7354981366b57831c83b7e9161d819ea268edc4c`` before the accompanying fix,
and each was reproduced with the production services alone — no proof
harness, no mock executor, no Verifiable Intent fixture for the first two.
That matters: a regression test that needs the proof to fail is testing
the proof.

Gated like the rest of the database integration suite.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

pytest.importorskip("asyncpg")

from api.core.authority.decision import Decision, DecisionReason  # noqa: E402
from api.core.authority.lifecycle import ConsumptionOutcome  # noqa: E402
from api.database import Database  # noqa: E402
from api.domains.payment.snapshot import (  # noqa: E402
    PAYMENT_AUTHORITY_POLICY_FORMAT,
)
from api.services.authority_service import (  # noqa: E402
    AuthorityConsumptionService,
    AuthorityEvaluationService,
)
from api.services.executor_context import executor_context_from_auth  # noqa: E402

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="core regression tests require INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)

SERVER_SECRET = b"phase6-core-regression-secret-not-production"
CHAIN = "eip155:8453"
ALLOWED_ACCOUNT = "0x1111111111111111111111111111111111111111"


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=2, max_size=8)
    try:
        yield database
    finally:
        await database.close()


async def make_principal(
    database: Database, *, wallet_policy: bool, per_action_limit: Decimal = Decimal("10000")
) -> tuple[UUID, object]:
    """A production-approved agent, optionally carrying a wallet policy."""
    org_id = uuid4()
    agent_id = uuid4()
    metadata: dict = {
        "sandbox": False,
        "production_approval_reference": "phase-6-core-regression",
        "production_approved_at": "2026-01-01T00:00:00Z",
        "production_approved_by": "phase-6-regression-fixture",
    }
    if wallet_policy:
        metadata["wallet_policy"] = {
            "allowed_chains": [CHAIN],
            "allowed_recipients": {CHAIN: [ALLOWED_ACCOUNT]},
        }
    async with database.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
            VALUES ($1, $2, 'enterprise', $3, $4)
            """,
            org_id,
            f"regression-{org_id}",
            f"regression-{org_id}@example.test",
            hashlib.sha256(str(org_id).encode()).digest(),
        )
        await conn.execute(
            """
            INSERT INTO agents (
                id, org_id, name, public_key, public_key_fingerprint, trust_score,
                status, daily_limit_usd, per_action_limit_usd, allowed_actions,
                blocked_actions, rate_limit_per_minute, metadata
            ) VALUES (
                $1, $2, $3, $4, $5, 80, 'active', 100000, $6,
                ARRAY['wallet_transaction']::TEXT[], ARRAY[]::TEXT[], 1000, $7::JSONB
            )
            """,
            agent_id,
            org_id,
            f"regression-agent-{agent_id}",
            secrets.token_bytes(32),
            hashlib.sha256(str(agent_id).encode()).hexdigest(),
            per_action_limit,
            json.dumps(metadata),
        )
    return org_id, await database.get_agent_by_id(agent_id)


def executor(org_id: UUID, key_id: str = "regression-key"):
    return executor_context_from_auth(
        {"org_id": org_id, "api_key_id": key_id, "scopes": ["write"]}
    )


def payload(amount: str, account: str = ALLOWED_ACCOUNT) -> dict:
    return {"amount": amount, "currency": "USD", "chain": CHAIN, "recipient": account}


class TestWalletPolicyPrincipalCanSpendItsGrant:
    """A principal with a wallet_policy could never consume its own authority.

    ``_AgentView`` adapts an ``agents`` row for the policy snapshot
    builder, and the driver returns a JSONB column as text unless a codec
    is registered. The builder reads ``metadata`` only when it is a
    mapping, so the consumption-time re-derivation silently produced a
    digest computed as though **no wallet policy were configured** —
    while issuance had computed one that included the chain and recipient
    allowlists.

    The two digests could therefore never agree, and every consumption
    failed ``policy_hash_mismatch``. The effect is total: no principal
    with a wallet policy could spend a grant at all, which is precisely
    the population this connector exists for.
    """

    async def test_a_wallet_policy_principal_consumes_successfully(
        self, db: Database
    ) -> None:
        org_id, agent = await make_principal(db, wallet_policy=True)
        evaluation = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        consumption = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        caller = executor(org_id)

        issued = await evaluation.evaluate(
            agent=agent,
            action_type="wallet_transaction",
            payload=payload("100.00"),
            executor=caller,
            issuance_ref="regression-wallet-policy",
        )
        assert issued.decision is Decision.ALLOW

        result = await consumption.consume(
            authority_token=issued.authority_token,
            executor=caller,
            agent=agent,
            action_type="wallet_transaction",
            payload=payload("100.00"),
            execution_ref="regression-wallet-policy-exec",
        )
        assert result.rejection_reason is not DecisionReason.POLICY_HASH_MISMATCH, (
            "the consumption-time policy re-derivation disagreed with issuance "
            "for a principal whose only distinguishing feature is a wallet_policy"
        )
        assert result.outcome is ConsumptionOutcome.AUTHORISED

    async def test_a_principal_without_one_was_never_affected(
        self, db: Database
    ) -> None:
        """The control. It passed before the fix and must keep passing."""
        org_id, agent = await make_principal(db, wallet_policy=False)
        evaluation = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        consumption = AuthorityConsumptionService(db, server_secret=SERVER_SECRET)
        caller = executor(org_id)

        issued = await evaluation.evaluate(
            agent=agent,
            action_type="wallet_transaction",
            payload=payload("100.00"),
            executor=caller,
            issuance_ref="regression-no-wallet-policy",
        )
        result = await consumption.consume(
            authority_token=issued.authority_token,
            executor=caller,
            agent=agent,
            action_type="wallet_transaction",
            payload=payload("100.00"),
            execution_ref="regression-no-wallet-policy-exec",
        )
        assert result.outcome is ConsumptionOutcome.AUTHORISED


class TestEveryPaymentDecisionRecordsItsPolicy:
    """A refusal must be as provable as a permission.

    The policy snapshot was built only on the path that reaches the
    domain policy. Every refusal before that — a core-stage spend or
    allowlist violation, an unresolvable delegation, a required-but-
    missing one — persisted a decision row with a null policy digest, so
    nobody could later establish which policy had refused the act.

    Nothing about the *decision* changes here; only what is recorded.
    """

    async def test_a_core_stage_block_records_the_policy_it_was_refused_under(
        self, db: Database
    ) -> None:
        org_id, agent = await make_principal(
            db, wallet_policy=True, per_action_limit=Decimal("1000")
        )
        evaluation = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)

        blocked = await evaluation.evaluate(
            agent=agent,
            action_type="wallet_transaction",
            # Above the per-action cap: refused by the core engine, before
            # the payment domain policy runs.
            payload=payload("50000.00"),
            executor=executor(org_id),
            issuance_ref="regression-early-block",
        )
        assert blocked.decision is Decision.BLOCK
        assert DecisionReason.PER_ACTION_LIMIT_EXCEEDED in blocked.reasons
        assert blocked.policy_snapshot_digest is not None, (
            "a BLOCK that cannot name the policy which refused it is not auditable"
        )
        assert len(blocked.policy_snapshot_digest) == 64
        assert blocked.policy_snapshot_format == PAYMENT_AUTHORITY_POLICY_FORMAT

    async def test_the_recorded_digest_matches_what_an_allow_would_bind(
        self, db: Database
    ) -> None:
        """Same policy, same digest, whichever way the decision went.

        Capturing the snapshot on two different code paths would let the
        digest a BLOCK records drift from the digest a grant is issued
        under. One capture, one value.
        """
        org_id, agent = await make_principal(db, wallet_policy=True)
        evaluation = AuthorityEvaluationService(db, server_secret=SERVER_SECRET)
        caller = executor(org_id)

        allowed = await evaluation.evaluate(
            agent=agent,
            action_type="wallet_transaction",
            payload=payload("100.00"),
            executor=caller,
            issuance_ref="regression-digest-allow",
        )
        blocked = await evaluation.evaluate(
            agent=agent,
            action_type="wallet_transaction",
            # Refused by the wallet allowlist, in the core engine.
            payload=payload("100.00", account="0x9999999999999999999999999999999999999999"),
            executor=caller,
            issuance_ref="regression-digest-block",
        )
        assert allowed.decision is Decision.ALLOW
        assert blocked.decision is Decision.BLOCK
        assert DecisionReason.WALLET_RECIPIENT_NOT_ALLOWED in blocked.reasons
        assert blocked.policy_snapshot_digest == allowed.policy_snapshot_digest


class TestDelegatedPayeesAreEnforceableThroughTheService:
    """A scope restricting payees was unenforceable on the evaluation path.

    ``PaymentDomainPolicy`` binds an approved payee identity to a concrete
    execution destination through a ``PayeeBindingResolver``, and fails
    closed with ``AUTHORITY_SCOPE_UNSUPPORTED`` when it has none — which
    is correct. What was missing is any way to give it one:
    ``AuthorityEvaluationService`` constructed the policy without that
    argument and exposed no parameter for it.

    So every delegation carrying ``allowed_payees`` — which the Verifiable
    Intent connector emits for any mandate with a payee allowlist — was
    refused through the service, however valid. The port existed, the
    mapper produced input for it, and nothing connected the two.

    Deliberately stubbed rather than driven through the connector: the gap
    is in Core's wiring, and a test that needed a signed credential to
    show it would be testing the wrong layer.
    """

    @staticmethod
    def _authority_with_payees(payee: str):
        from api.core.authority.authority import (
            DelegateBindingStatus,
            DelegatedAuthorityReference,
            ResolvedAuthority,
            VerificationStatus,
            trusted_authority_construction,
        )

        construction = trusted_authority_construction()
        reference = DelegatedAuthorityReference(
            construction,
            issuer="regression-issuer",
            external_reference_id="regression-delegation",
            artefact_digest="d" * 64,
            verification_status=VerificationStatus.VERIFIED,
            verified_at=datetime.now(UTC),
        )
        return ResolvedAuthority(
            construction,
            reference=reference,
            delegate_binding_status=DelegateBindingStatus.BOUND,
            delegate_binding_reference="regression-delegate",
            scope={
                "currency": "USD",
                "max_amount": "20000.00",
                "allowed_payees": [payee],
            },
        )

    @staticmethod
    def _provider(resolved):
        class _StubProvider:
            def resolve(self, raw_authority, expected_principal_context):  # noqa: ARG002
                return resolved

        return _StubProvider()

    @staticmethod
    def _payee_bindings(payee: str, account: str):
        from api.domains.payment.binding import ExecutionDestination, PayeeBinding

        binding = PayeeBinding(
            payee_reference=payee,
            destination=ExecutionDestination(network=CHAIN, account=account, asset="USD"),
            source="regression-supplier-register",
        )

        class _Registry:
            def binding_for(self, organisation_id, payee_reference):  # noqa: ARG002
                return binding if payee_reference == payee else None

        return _Registry()

    async def test_a_bound_payee_is_allowed_through_the_service(
        self, db: Database
    ) -> None:
        from api.core.authority.authority import DelegatedAuthorityClaim

        payee = "payee:id:supplier-a"
        org_id, agent = await make_principal(db, wallet_policy=True)
        resolved = self._authority_with_payees(payee)
        service = AuthorityEvaluationService(
            db,
            server_secret=SERVER_SECRET,
            authority_provider=self._provider(resolved),
            payee_binding_resolver=self._payee_bindings(payee, ALLOWED_ACCOUNT),
        )
        result = await service.evaluate(
            agent=agent,
            action_type="wallet_transaction",
            payload=payload("500.00"),
            executor=executor(org_id),
            issuance_ref="regression-payee-bound",
            authority_claim=DelegatedAuthorityClaim(
                issuer="regression-issuer", external_reference_id="regression-delegation"
            ),
        )
        assert result.decision is Decision.ALLOW, (
            f"a delegation whose payee is bound to this destination was refused: "
            f"{[reason.value for reason in result.reasons]}"
        )
        assert result.grant_id is not None

    async def test_an_unbound_payee_still_fails_closed(self, db: Database) -> None:
        """The resolver narrows; it never waves anything through."""
        from api.core.authority.authority import DelegatedAuthorityClaim

        payee = "payee:id:supplier-a"
        org_id, agent = await make_principal(db, wallet_policy=True)
        service = AuthorityEvaluationService(
            db,
            server_secret=SERVER_SECRET,
            authority_provider=self._provider(self._authority_with_payees(payee)),
            # Bound to a different account than the act pays.
            payee_binding_resolver=self._payee_bindings(
                payee, "0x9999999999999999999999999999999999999999"
            ),
        )
        result = await service.evaluate(
            agent=agent,
            action_type="wallet_transaction",
            payload=payload("500.00"),
            executor=executor(org_id),
            issuance_ref="regression-payee-unbound",
            authority_claim=DelegatedAuthorityClaim(
                issuer="regression-issuer", external_reference_id="regression-delegation"
            ),
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_SCOPE_EXCEEDED in result.reasons
        assert result.grant_id is None

    async def test_without_a_resolver_the_scope_is_still_unenforceable(
        self, db: Database
    ) -> None:
        """Unchanged behaviour for a deployment that configures none.

        The fix adds a way to supply a resolver. It does not make a
        payee-restricted delegation enforceable without one.
        """
        from api.core.authority.authority import DelegatedAuthorityClaim

        org_id, agent = await make_principal(db, wallet_policy=True)
        service = AuthorityEvaluationService(
            db,
            server_secret=SERVER_SECRET,
            authority_provider=self._provider(
                self._authority_with_payees("payee:id:supplier-a")
            ),
        )
        result = await service.evaluate(
            agent=agent,
            action_type="wallet_transaction",
            payload=payload("500.00"),
            executor=executor(org_id),
            issuance_ref="regression-payee-none",
            authority_claim=DelegatedAuthorityClaim(
                issuer="regression-issuer", external_reference_id="regression-delegation"
            ),
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_SCOPE_UNSUPPORTED in result.reasons
