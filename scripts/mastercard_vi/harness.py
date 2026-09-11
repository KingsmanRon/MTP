"""Wiring the proof: a real organisation, a real database, the real services.

Nothing here reimplements a decision. The harness creates an organisation
with a deliberately narrow policy, registers the Verifiable Intent
identity that organisation has bound to its agent, and then calls the
*production* ``AuthorityEvaluationService`` and
``AuthorityConsumptionService``. Every verdict the proof prints came out
of the same code path a deployed ``/authority/*`` request takes.

The organisation policy is narrower than the delegation on purpose
------------------------------------------------------------------
The VI mandate permits Supplier A and Supplier B, USD up to 20,000.00.
This organisation allowlists only Supplier A's execution recipient and
caps a single action at 10,000.00. That gap is what cases 2 and 3
exercise: a delegation that is entirely valid, refused by the
organisation's own current policy.

Reset between headline scenarios
--------------------------------
Each headline case gets its own organisation and agent. Spend windows,
rate windows and consumed grants are per-principal, so a fresh principal
is a complete reset — no case can inherit another's daily spend or a
grant it already consumed.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Final
from uuid import UUID, uuid4

from api.authority_providers.verifiable_intent import (
    StaticIssuerTrustStore,
    TrustedIssuer,
    VerifiableIntentAuthorityProvider,
    jwk_thumbprint,
)
from api.core.authority.authority import (
    DelegatedAuthorityClaim,
    ExecutionContext,
    trusted_authority_construction,
)
from api.domains.payment.binding import ExecutionDestination, PayeeBinding
from api.persistence.authority_store import (
    ResolvedAuthorityEvidence,
    authority_scope_digest,
)
from api.services.authority_service import (
    AuthorityConsumptionService,
    AuthorityEvaluationService,
    authority_binding_for,
)
from api.services.executor_context import executor_context_from_auth
from scripts.mastercard_vi import fixture as fx
from scripts.mastercard_vi.executor import MockExecutor, MockSideEffect
from scripts.mastercard_vi.journal import ExecutionJournal

#: A fixed, non-secret HMAC secret. The proof mints and verifies its own
#: authority tokens; nothing here reaches a deployed system.
PROOF_SERVER_SECRET: Final[bytes] = b"mastercard-vi-proof-server-secret-not-production"

#: The execution rail the proof organisation allows.
PROOF_CHAIN: Final[str] = "eip155:8453"
PROOF_ASSET: Final[str] = "USD"

#: Supplier A's execution recipient — allowlisted by the organisation.
SUPPLIER_A_ACCOUNT: Final[str] = "0xA11CE00000000000000000000000000000000A11"
#: Supplier B's execution recipient — permitted by VI, NOT allowlisted here.
SUPPLIER_B_ACCOUNT: Final[str] = "0xB0B0000000000000000000000000000000000B0B"
#: A recipient no payee is bound to, for the substitution case.
UNBOUND_ACCOUNT: Final[str] = "0xDEAD000000000000000000000000000000000DEAD"[:42]

#: Inntris organisation policy, deliberately below the VI ceiling.
PER_ACTION_LIMIT: Final[Decimal] = Decimal("10000")
DAILY_LIMIT: Final[Decimal] = Decimal("100000")

#: The action type the proof exercises. Chosen because it is the existing
#: payment action whose evaluation runs BOTH the recipient allowlist and
#: the spend caps; no policy behaviour is changed to make that true.
PROOF_ACTION_TYPE: Final[str] = "wallet_transaction"


@dataclass(frozen=True, slots=True)
class ProofPrincipal:
    """One organisation and the agent it acts through."""

    org_id: UUID
    agent_id: UUID
    agent: Any


@dataclass
class PayeeBindingRegistry:
    """Trusted server-side payee-to-destination bindings.

    A delegated payee identity is not proof that a particular account
    belongs to that payee. This registry is where the organisation has
    recorded that it does. It reads no request data, by construction: its
    only input is the organisation id and the payee reference.
    """

    bindings: dict[tuple[str, str], PayeeBinding] = field(default_factory=dict)

    def register(
        self, organisation_id: Any, payee_reference: str, account: str
    ) -> None:
        self.bindings[(str(organisation_id), payee_reference)] = PayeeBinding(
            payee_reference=payee_reference,
            destination=ExecutionDestination(
                network=PROOF_CHAIN, account=account, asset=PROOF_ASSET
            ),
            source="mastercard-vi-proof-registry",
            bound_at=datetime.now(UTC),
        )

    def binding_for(
        self, organisation_id: str, payee_reference: str
    ) -> PayeeBinding | None:
        return self.bindings.get((str(organisation_id), payee_reference))


def proof_trust_store() -> StaticIssuerTrustStore:
    """The issuers this proof accepts, on keys it holds out of band."""
    return StaticIssuerTrustStore(
        [
            TrustedIssuer(
                issuer_id=fx.ISSUER_ID,
                public_key=fx.issuer_keys().public_key,
                l2_audience=fx.AGENT_AUDIENCE,
                l3_payment_audience=fx.NETWORK_AUDIENCE,
            )
        ]
    )


def payment_payload(
    *, amount: str, account: str, chain: str = PROOF_CHAIN, currency: str = PROOF_ASSET
) -> dict[str, Any]:
    """The act, in the shape the existing wallet path already accepts."""
    return {
        "amount": amount,
        "currency": currency,
        "chain": chain,
        "recipient": account,
    }


class ProofHarness:
    """Everything one proof run needs, over a real database."""

    def __init__(
        self,
        database: Any,
        *,
        journal_path: str,
        side_effect: MockSideEffect | None = None,
        provider: Any | None = None,
    ) -> None:
        self.db = database
        self.payees = PayeeBindingRegistry()
        self.provider = provider or VerifiableIntentAuthorityProvider(
            proof_trust_store()
        )
        self.evaluation = AuthorityEvaluationService(
            database,
            server_secret=PROOF_SERVER_SECRET,
            authority_provider=self.provider,
            payee_binding_resolver=self.payees,
        )
        self.consumption = AuthorityConsumptionService(
            database, server_secret=PROOF_SERVER_SECRET
        )
        self.journal = ExecutionJournal(journal_path)
        self.side_effect = side_effect or MockSideEffect()
        self.executor_service = MockExecutor(
            self.consumption, self.journal, self.side_effect
        )

    # -- the organisation --------------------------------------------------

    async def create_principal(
        self,
        *,
        label: str,
        delegate_thumbprint: str | None = None,
        vi_subject: str = fx.VI_SUBJECT,
        per_action_limit: Decimal = PER_ACTION_LIMIT,
        daily_limit: Decimal = DAILY_LIMIT,
        allowed_recipients: list[str] | None = None,
        status: str = "active",
        register_payees: bool = True,
    ) -> ProofPrincipal:
        """A fresh organisation whose policy is narrower than the delegation."""
        org_id = uuid4()
        agent_id = uuid4()
        recipients = (
            [SUPPLIER_A_ACCOUNT] if allowed_recipients is None else allowed_recipients
        )
        metadata = {
            "sandbox": False,
            "production_approval_reference": f"mastercard-vi-proof-{label}",
            "production_approved_at": "2026-01-01T00:00:00Z",
            "production_approved_by": "mastercard-vi-proof",
            # Only Supplier A's execution recipient is allowlisted. Supplier
            # B is permitted by VI and refused here; that is the point.
            "wallet_policy": {
                "allowed_chains": [PROOF_CHAIN],
                "allowed_recipients": {PROOF_CHAIN: recipients},
            },
            # The trusted binding between this principal and its external
            # delegated identity. Read server-side; never from a request.
            "authority_binding": {
                "vi_subject": vi_subject,
                "vi_delegate_jwk_thumbprint": delegate_thumbprint
                or jwk_thumbprint(fx.agent_keys().public_jwk),
            },
        }
        async with self.db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO organizations (
                    id, name, billing_tier, contact_email, api_key_hash
                ) VALUES ($1, $2, 'enterprise', $3, $4)
                """,
                org_id,
                f"mastercard-vi-proof-{label}-{org_id}",
                f"proof-{org_id}@example.test",
                hashlib.sha256(str(org_id).encode()).digest(),
            )
            await conn.execute(
                """
                INSERT INTO agents (
                    id, org_id, name, public_key, public_key_fingerprint,
                    trust_score, status, daily_limit_usd, per_action_limit_usd,
                    allowed_actions, blocked_actions, rate_limit_per_minute, metadata
                ) VALUES (
                    $1, $2, $3, $4, $5, 80, $6, $7, $8,
                    ARRAY[$9]::TEXT[], ARRAY[]::TEXT[], 1000, $10::JSONB
                )
                """,
                agent_id,
                org_id,
                f"mastercard-vi-proof-agent-{agent_id}",
                secrets.token_bytes(32),
                hashlib.sha256(str(agent_id).encode()).hexdigest(),
                status,
                daily_limit,
                per_action_limit,
                PROOF_ACTION_TYPE,
                json.dumps(metadata),
            )
            agent = await self.db.get_agent_by_id(agent_id)

        if register_payees:
            self.payees.register(org_id, fx.SUPPLIER_A["id"], SUPPLIER_A_ACCOUNT)
            self.payees.register(org_id, fx.SUPPLIER_B["id"], SUPPLIER_B_ACCOUNT)
        return ProofPrincipal(org_id=org_id, agent_id=agent_id, agent=agent)

    async def reload(self, principal: ProofPrincipal) -> ProofPrincipal:
        """Re-read the agent record after mutating it mid-scenario."""
        agent = await self.db.get_agent_by_id(principal.agent_id)
        return ProofPrincipal(
            org_id=principal.org_id, agent_id=principal.agent_id, agent=agent
        )

    async def suspend(self, principal: ProofPrincipal) -> ProofPrincipal:
        async with self.db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET status = 'suspended' WHERE id = $1",
                principal.agent_id,
            )
        return await self.reload(principal)

    async def tighten_per_action_limit(
        self, principal: ProofPrincipal, limit: Decimal
    ) -> ProofPrincipal:
        """Change the organisation's policy after a grant was issued."""
        async with self.db.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET per_action_limit_usd = $2 WHERE id = $1",
                principal.agent_id,
                limit,
            )
        return await self.reload(principal)

    # -- executors ---------------------------------------------------------

    @staticmethod
    def executor(
        org_id: UUID,
        *,
        key_id: str,
        scopes: tuple[str, ...] = ("write",),
        reference: str | None = None,
    ) -> Any:
        """An executor identity derived from an authenticated API key.

        ``key_id`` is the part that binds. Two executors in one
        organisation differ only in their key, which is exactly the
        distinction the grant's executor binding rests on.
        """
        return executor_context_from_auth(
            {"org_id": org_id, "api_key_id": key_id, "scopes": list(scopes)},
            executor_reference=reference,
        )

    # -- the delegation ----------------------------------------------------

    def claim_for(
        self,
        delegation: fx.Delegation,
        *,
        payee: dict[str, str],
        amount: Decimal | str,
        reference_id: str,
        signer: fx.KeyPair | None = None,
    ) -> DelegatedAuthorityClaim:
        """Sign an L3a fulfilment for this act and wrap it as a claim."""
        minor_units = int((Decimal(str(amount)) * 100).to_integral_value())
        l3 = fx.build_payment_fulfilment(
            delegation,
            payee=payee,
            minor_units=minor_units,
            transaction_id=hashlib.sha256(
                f"{reference_id}:{payee['id']}:{minor_units}".encode()
            ).hexdigest(),
            signer=signer,
        )
        return DelegatedAuthorityClaim(
            issuer=fx.ISSUER_ID,
            external_reference_id=reference_id,
            evidence=fx.presented_evidence(delegation, l3, payee_id=payee["id"]),
        )

    def resolve(self, claim: DelegatedAuthorityClaim, principal: ProofPrincipal) -> Any:
        """Resolve a claim exactly as the evaluation service would.

        Used by the proof to report the VI verdict on its own, and to build
        the consumption-time authority evidence. It is the same provider
        object and the same trusted context, so it cannot disagree with
        what the decision path saw.
        """
        context = ExecutionContext(
            trusted_authority_construction(),
            organisation_id=str(principal.org_id),
            principal_id=str(principal.agent_id),
            principal_binding=authority_binding_for(principal.agent),
        )
        return self.provider.resolve(claim, context)

    @staticmethod
    def evidence_for(resolved: Any, *, revoked: bool = False) -> ResolvedAuthorityEvidence:
        """Current evidence about the delegation, for the consume path.

        The store validates this against the digest the grant was issued
        under. Handing over evidence for a different authority, or none at
        all when the grant rested on one, fails closed.
        """
        return ResolvedAuthorityEvidence(
            scope_digest=authority_scope_digest(
                issuer=resolved.reference.issuer,
                external_reference_id=resolved.reference.external_reference_id,
                artefact_digest=resolved.reference.artefact_digest,
                scope=dict(resolved.scope),
            ),
            verified=resolved.is_verified,
            revoked=revoked,
            expires_at=resolved.not_after,
        )

    # -- the two service calls --------------------------------------------

    async def evaluate(
        self,
        principal: ProofPrincipal,
        *,
        claim: DelegatedAuthorityClaim | None,
        amount: str,
        account: str,
        executor: Any,
        issuance_ref: str,
        chain: str = PROOF_CHAIN,
        currency: str = PROOF_ASSET,
        at: datetime | None = None,
        daily_spend: Decimal = Decimal("0"),
    ) -> Any:
        return await self.evaluation.evaluate(
            agent=principal.agent,
            action_type=PROOF_ACTION_TYPE,
            payload=payment_payload(
                amount=amount, account=account, chain=chain, currency=currency
            ),
            executor=executor,
            issuance_ref=issuance_ref,
            authority_claim=claim,
            daily_spend=daily_spend,
            at=at,
        )

    async def execute(
        self,
        principal: ProofPrincipal,
        *,
        authority_token: str,
        grant_id: Any,
        execution_action_hash: str,
        amount: str,
        account: str,
        executor: Any,
        execution_ref: str,
        authority_evidence: ResolvedAuthorityEvidence | None,
        chain: str = PROOF_CHAIN,
        currency: str = PROOF_ASSET,
        at: datetime | None = None,
        crash_before_consume: bool = False,
        crash_before_claim: bool = False,
        crash_after_claim: bool = False,
    ) -> Any:
        return await self.executor_service.execute(
            authority_token=authority_token,
            executor=executor,
            agent=principal.agent,
            action_type=PROOF_ACTION_TYPE,
            payload=payment_payload(
                amount=amount, account=account, chain=chain, currency=currency
            ),
            execution_ref=execution_ref,
            grant_id=str(grant_id),
            execution_action_hash=execution_action_hash,
            authority_evidence=authority_evidence,
            at=at,
            crash_before_consume=crash_before_consume,
            crash_before_claim=crash_before_claim,
            crash_after_claim=crash_after_claim,
        )

    async def grant(self, grant_id: Any) -> Any:
        return await self.consumption.grant_for(grant_id)
