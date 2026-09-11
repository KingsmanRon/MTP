"""Wiring the proof: a real organisation, a real database, the real services.

Nothing here reimplements a decision. The harness provisions an
organisation whose policy is deliberately narrower than the delegation,
registers the Verifiable Intent identity that organisation has bound to
its agent, and then calls the production
``AuthorityEvaluationService``, ``AuthorityConsumptionService`` and the
Phase-5 connector at ``api/connectors/mastercard_vi``. Every verdict the
proof prints came out of the code path a deployed ``/authority/*``
request takes.

Re-resolution is the default, not an option
-------------------------------------------
Issuance-time verification is not enough to consume. Before every
consumption :meth:`ProofHarness.execute` re-resolves the delegation
through the connector *again*, from the credential material as it stands
now, and hands the result to the store as
``ResolvedAuthorityEvidence``. A grant whose delegation has since been
revoked, expired or altered is refused on current evidence rather than on
what was true when the decision was made. The store enforces this from
its side too: a grant issued under a delegated scope cannot be consumed
with no evidence at all.

Reset between headline scenarios
--------------------------------
Each headline case provisions its own organisation and agent. Spend
windows, rate windows and consumed grants are per-principal, so a fresh
principal is a complete reset: no case can inherit another's daily spend
or a grant it already consumed.
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

from api.connectors.mastercard_vi import (
    PRINCIPAL_BINDING_CONTEXT_KEY,
    StaticIssuerKeyResolver,
    StaticPrincipalDelegateBindingResolver,
    TrustedIssuerKeyset,
    VerifiableIntentAuthorityProvider,
    VerifiableIntentPrincipalBinding,
)
from api.core.authority.authority import (
    ExecutionContext,
    trusted_authority_construction,
)
from api.domains.payment.binding import ExecutionDestination, PayeeBinding
from api.persistence.authority_store import (
    ResolvedAuthorityEvidence,
    authority_scope_digest,
)
from api.services.authority_service import (
    PRINCIPAL_BINDING_METADATA_KEY,
    AuthorityConsumptionService,
    AuthorityEvaluationService,
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
#: Supplier B's execution recipient — permitted by Verifiable Intent,
#: deliberately NOT allowlisted here.
SUPPLIER_B_ACCOUNT: Final[str] = "0xB0B0000000000000000000000000000000000B0B"

#: Inntris organisation policy, deliberately below the delegation's ceiling.
PER_ACTION_LIMIT: Final[Decimal] = Decimal("10000")
DAILY_LIMIT: Final[Decimal] = Decimal("100000")

#: The action type the proof exercises. Chosen because it is the existing
#: payment action whose evaluation already runs BOTH the recipient
#: allowlist and the spend caps. No policy behaviour is changed for it.
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
    belongs to that payee. This is where the organisation has recorded
    that it does. It reads no request data by construction: its only
    inputs are the organisation id and the payee reference the connector
    mapped.
    """

    bindings: dict[tuple[str, str], PayeeBinding] = field(default_factory=dict)

    def register(self, organisation_id: Any, payee_reference: str, account: str) -> None:
        self.bindings[(str(organisation_id), payee_reference)] = PayeeBinding(
            payee_reference=payee_reference,
            destination=ExecutionDestination(
                network=PROOF_CHAIN, account=account, asset=PROOF_ASSET
            ),
            source="mastercard-vi-proof-supplier-register",
            bound_at=datetime.now(UTC),
        )

    def binding_for(
        self, organisation_id: str, payee_reference: str
    ) -> PayeeBinding | None:
        return self.bindings.get((str(organisation_id), payee_reference))


def proof_issuer_keys() -> StaticIssuerKeyResolver:
    """The credential providers this proof trusts, on keys held out of band."""
    return StaticIssuerKeyResolver(
        [TrustedIssuerKeyset(issuer=fx.ISSUER, keys={fx.ISSUER_KID: fx.issuer_jwk()})]
    )


def principal_binding_metadata(
    *,
    audience: str = fx.AGENT_AUDIENCE,
    thumbprints: tuple[str, ...] | None = None,
    revoked: tuple[str, ...] = (),
) -> dict[str, Any]:
    """The trusted binding, in the shape agent metadata carries it."""
    return {
        PRINCIPAL_BINDING_CONTEXT_KEY: {
            "expected_audience": audience,
            "agent_key_thumbprints": list(
                thumbprints if thumbprints is not None else (fx.agent_thumbprint(),)
            ),
            "revoked_agent_key_thumbprints": list(revoked),
            "source": "mastercard-vi-proof-provisioning",
        }
    }


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
        # The Phase-5 connector, unmodified. The binding resolver is left
        # unset: every binding in this proof travels on the trusted
        # ExecutionContext, from agent metadata, which is the path a
        # deployment provisioning per-principal bindings actually uses.
        self.provider = provider or VerifiableIntentAuthorityProvider(
            issuer_key_resolver=proof_issuer_keys()
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
        #: Counts every re-resolution the proof performed before a consume,
        #: so a case can assert the re-resolution actually happened.
        self.reresolutions: list[str] = []

    # -- the organisation --------------------------------------------------

    async def create_principal(
        self,
        *,
        label: str,
        binding: dict[str, Any] | None = None,
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
            # B is permitted by Verifiable Intent and refused here.
            "wallet_policy": {
                "allowed_chains": [PROOF_CHAIN],
                "allowed_recipients": {PROOF_CHAIN: recipients},
            },
            # The trusted binding between this principal and the delegate a
            # mandate names. Server-side state; never from a request.
            PRINCIPAL_BINDING_METADATA_KEY: (
                principal_binding_metadata() if binding is None else binding
            ),
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
            self.payees.register(org_id, fx.SUPPLIER_A_REFERENCE, SUPPLIER_A_ACCOUNT)
            self.payees.register(org_id, fx.SUPPLIER_B_REFERENCE, SUPPLIER_B_ACCOUNT)
        return ProofPrincipal(org_id=org_id, agent_id=agent_id, agent=agent)

    async def reload(self, principal: ProofPrincipal) -> ProofPrincipal:
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

    async def revoke_delegate_key(self, principal: ProofPrincipal) -> ProofPrincipal:
        """Move the delegate thumbprint into the revoked set, as an operator would."""
        async with self.db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT metadata FROM agents WHERE id = $1", principal.agent_id
            )
            metadata = row["metadata"]
            metadata = json.loads(metadata) if isinstance(metadata, str) else dict(metadata)
            metadata[PRINCIPAL_BINDING_METADATA_KEY] = principal_binding_metadata(
                revoked=(fx.agent_thumbprint(),)
            )
            await conn.execute(
                "UPDATE agents SET metadata = $2::JSONB WHERE id = $1",
                principal.agent_id,
                json.dumps(metadata),
            )
        return await self.reload(principal)

    async def tighten_per_action_limit(
        self, principal: ProofPrincipal, limit: Decimal
    ) -> ProofPrincipal:
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
        distinction a grant's executor binding rests on.
        """
        return executor_context_from_auth(
            {"org_id": org_id, "api_key_id": key_id, "scopes": list(scopes)},
            executor_reference=reference,
        )

    # -- the delegation ----------------------------------------------------

    def context_for(self, principal: ProofPrincipal) -> ExecutionContext:
        """The trusted context the evaluation service builds internally."""
        from api.services.authority_service import _principal_binding_for

        return ExecutionContext(
            trusted_authority_construction(),
            organisation_id=str(principal.org_id),
            principal_id=str(principal.agent_id),
            principal_binding=_principal_binding_for(principal.agent),
        )

    def resolve(self, claim: Any, principal: ProofPrincipal) -> Any:
        """Resolve a claim exactly as the evaluation service would.

        Same provider object, same trusted context, so it cannot disagree
        with what the decision path saw.
        """
        return self.provider.resolve(claim, self.context_for(principal))

    def resolve_detailed(self, claim: Any, principal: ProofPrincipal) -> Any:
        return self.provider.resolve_detailed(claim, self.context_for(principal))

    @staticmethod
    def evidence_for(resolved: Any, *, revoked: bool = False) -> ResolvedAuthorityEvidence:
        """Current evidence about the delegation, for the consume path.

        The store compares ``scope_digest`` against the digest the grant
        was issued under, so evidence about a different or re-issued
        authority cannot be passed off as evidence for this one.
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

    def reresolve_evidence(
        self, claim: Any, principal: ProofPrincipal, *, revoked: bool = False
    ) -> ResolvedAuthorityEvidence:
        """Re-resolve the delegation NOW and report what is true now.

        This is the step that makes issuance-time verification
        insufficient. It runs the connector again, against the credential
        as it stands, under the principal's current binding — so a
        revoked delegate key, a lapsed mandate or an altered credential
        produces unverified evidence and the consumption fails closed.
        """
        self.reresolutions.append(str(claim.external_reference_id))
        return self.evidence_for(self.resolve(claim, principal), revoked=revoked)

    # -- the two service calls --------------------------------------------

    async def evaluate(
        self,
        principal: ProofPrincipal,
        *,
        claim: Any | None,
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
        claim: Any | None = None,
        authority_evidence: ResolvedAuthorityEvidence | None = None,
        reresolve: bool = True,
        chain: str = PROOF_CHAIN,
        currency: str = PROOF_ASSET,
        at: datetime | None = None,
        crash_before_consume: bool = False,
        crash_before_claim: bool = False,
        crash_after_claim: bool = False,
    ) -> Any:
        """Re-resolve the delegation, then consume, then act at most once.

        ``authority_evidence`` overrides the re-resolution, and
        ``reresolve=False`` suppresses it entirely — both only so an
        acceptance case can present deliberately stale or absent evidence
        and show the store refusing it.
        """
        if authority_evidence is None and reresolve and claim is not None:
            authority_evidence = self.reresolve_evidence(claim, principal)
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


def binding_resolver_for(
    principal: ProofPrincipal, *, thumbprints: tuple[str, ...] | None = None
) -> StaticPrincipalDelegateBindingResolver:
    """An injected binding resolver, for cases that bypass agent metadata."""
    return StaticPrincipalDelegateBindingResolver.from_bindings(
        [
            VerifiableIntentPrincipalBinding(
                organisation_id=str(principal.org_id),
                principal_id=str(principal.agent_id),
                expected_audience=fx.AGENT_AUDIENCE,
                agent_key_thumbprints=frozenset(
                    thumbprints if thumbprints is not None else (fx.agent_thumbprint(),)
                ),
                source="mastercard-vi-proof-injected",
            )
        ]
    )
