"""The payment domain's policy semantics.

Two surfaces, one body of rules.

The **legacy hooks** — :func:`check_wallet_policy` and
:func:`check_spending_limits` — are the checks the general engine used to
implement inline. They were moved here unchanged, and the engine still
calls them at exactly the same points in exactly the same order, so
``/verify`` behaviour is byte-identical to before the split.

The **domain policy** — :class:`PaymentDomainPolicy` — implements the
``DomainPolicy`` port from ``api.core.authority`` for the delegated
path. It applies the same organisation rules first and only then
intersects them with the delegated scope.

The ordering is the security property: organisation policy decides first,
and a delegated scope is consulted only to narrow an act the organisation
already permits. There is no path through this module in which external
authority produces an ALLOW that organisation policy would have blocked.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Final

from api.core.authority.authority import (
    AuthorityVerificationFailure,
    ResolvedAuthority,
)
from api.core.authority.decision import (
    ConsequenceClass,
    Decision,
    DecisionReason,
    PolicyDecision,
)
from api.core.authority.envelope import ActionEnvelope
from api.core.authority.errors import UnknownDomainError
from api.domains.payment.binding import (
    ExecutionDestination,
    PayeeBindingResolver,
)
from api.domains.payment.delegation import (
    DelegationScopeError,
    parse_delegation_constraints,
)
from api.domains.payment.money import Money, MoneyError, normalise_payment_money
from api.domains.payment.snapshot import (
    PaymentAuthorityPolicySnapshot,
    build_payment_authority_policy_snapshot,
)
from api.domains.payment.wallet import (
    WALLET_ACTION_TYPES,
    WALLET_ALLOWLIST_ACTION_TYPES,
    WalletPolicyError,
    chain_allowlist_for,
    recipient_in_allowlist,
    validate_wallet_policy,
)
from api.models import ActionVerdict
from api.policy_contracts import PolicyResult, PolicyViolation

logger = logging.getLogger(__name__)

#: The domain identifier this module owns, as it appears on an envelope.
PAYMENT_DOMAIN: Final[str] = "payment"

#: Action types this domain governs.
PAYMENT_ACTION_TYPES: Final[frozenset[str]] = frozenset(
    {"financial_transaction", "wallet_transaction", "wallet_signature"}
)

def _allow() -> PolicyResult:
    return PolicyResult(allowed=True, verdict=ActionVerdict.APPROVED)


def _block(violation: PolicyViolation, reason: str) -> PolicyResult:
    return PolicyResult(
        allowed=False,
        verdict=ActionVerdict.BLOCKED,
        violation=violation,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# Legacy hooks — called by the general engine, behaviour frozen
# ---------------------------------------------------------------------------


def evaluate_wallet_allowlists(
    raw_policy: Any,
    action_type: str,
    chain: str | None,
    recipient: str | None,
    *,
    agent_id: Any = None,
) -> PolicyResult:
    """The wallet chain/recipient decision, independent of where it read from.

    Three layers, each fail-closed:

    1. No ``wallet_policy`` configured => no chain or recipient restriction.
       Every other Core policy check still applies.
    2. A ``wallet_policy`` that cannot be interpreted blocks every wallet
       action, including signatures. The operator expressed an intent the
       server cannot evaluate, and proceeding would mean ignoring it.
    3. Chain and recipient allowlists gate ``wallet_transaction`` only.
       A signature carries no recipient and is not chain-scoped.

    Amounts are deliberately not considered here; see the module notes on
    ``WALLET_ACTION_TYPES``.
    """
    if action_type not in WALLET_ACTION_TYPES:
        return _allow()

    if raw_policy is None:
        return _allow()

    try:
        allowed_chains, allowed_recipients = validate_wallet_policy(raw_policy)
    except WalletPolicyError as exc:
        logger.error(
            "Agent %s has an invalid wallet_policy; blocking wallet actions: %s",
            agent_id,
            exc,
        )
        return _block(
            PolicyViolation.WALLET_POLICY_INVALID,
            f"The configured wallet policy is invalid: {exc}",
        )

    if action_type not in WALLET_ALLOWLIST_ACTION_TYPES:
        return _allow()

    if allowed_chains is not None:
        if chain is None:
            return _block(
                PolicyViolation.WALLET_CHAIN_NOT_ALLOWED,
                (
                    "payload.chain is required because this agent has a wallet "
                    "chain allowlist configured."
                ),
            )
        if chain not in allowed_chains:
            return _block(
                PolicyViolation.WALLET_CHAIN_NOT_ALLOWED,
                (
                    f"Chain '{chain}' is not in the agent's allowed chains: "
                    f"{', '.join(allowed_chains)}."
                ),
            )

    if allowed_recipients is None:
        return _allow()

    if chain is None:
        # A recipient allowlist is keyed by chain, so without a chain the
        # applicable list cannot be selected. Guessing would mean either
        # skipping the allowlist or applying an unrelated one.
        return _block(
            PolicyViolation.WALLET_CHAIN_NOT_ALLOWED,
            (
                "payload.chain is required to select the recipient allowlist "
                "configured for this agent."
            ),
        )

    allowlist = chain_allowlist_for(allowed_recipients, chain)
    if allowlist is None:
        # No allowlist for this chain: the chain check above already decided
        # whether the chain itself is permitted. See the provisioning trap
        # documented on chain_allowlist_for.
        return _allow()

    if not isinstance(recipient, str) or not recipient.strip():
        return _block(
            PolicyViolation.WALLET_RECIPIENT_REQUIRED,
            (
                f"payload.recipient is required because a recipient allowlist is "
                f"configured for chain '{chain}'."
            ),
        )

    if not recipient_in_allowlist(chain, recipient, allowlist):
        return _block(
            PolicyViolation.WALLET_RECIPIENT_NOT_ALLOWED,
            (
                f"Recipient '{recipient}' is not in the allowlist configured for "
                f"chain '{chain}'."
            ),
        )

    return _allow()


def check_wallet_policy(
    agent: Any,
    action_type: str,
    payload: dict[str, Any],
) -> PolicyResult:
    """Legacy hook: read chain and recipient from the wire payload.

    The extraction is exactly what the general engine did inline — a
    non-string or blank ``chain`` reads as absent, and ``recipient`` is
    validated only where an allowlist actually applies.
    """
    metadata = agent.metadata if isinstance(agent.metadata, dict) else {}
    raw_policy = metadata.get("wallet_policy")

    chain = payload.get("chain") if isinstance(payload, dict) else None
    chain = chain if isinstance(chain, str) and chain.strip() else None
    recipient = payload.get("recipient") if isinstance(payload, dict) else None

    return evaluate_wallet_allowlists(
        raw_policy, action_type, chain, recipient, agent_id=getattr(agent, "id", None)
    )


def check_spending_limits(
    agent: Any,
    amount: Decimal,
    daily_spend: Decimal,
) -> PolicyResult:
    """Check spending limits for financial transactions.

    Applies to every action type that carries an amount, not only payment
    action types. The general engine calls this for any amount-bearing
    request, exactly as it did before this code moved: narrowing it to the
    payment domain would silently exempt every other action type from the
    organisation's global caps.
    """
    # Check per-action limit
    if amount > agent.per_action_limit_usd:
        return _block(
            PolicyViolation.PER_ACTION_LIMIT_EXCEEDED,
            f"Amount ${amount} exceeds per-action limit of ${agent.per_action_limit_usd}.",
        )

    # Check daily limit
    projected_daily = daily_spend + amount
    if projected_daily > agent.daily_limit_usd:
        remaining = agent.daily_limit_usd - daily_spend
        return _block(
            PolicyViolation.DAILY_LIMIT_EXCEEDED,
            f"Amount ${amount} would exceed daily limit. Remaining: ${remaining}.",
        )

    return _allow()


# ---------------------------------------------------------------------------
# Delegated path — the DomainPolicy port
# ---------------------------------------------------------------------------

_AUTHORITY_FAILURE_REASONS: Final[dict[AuthorityVerificationFailure, DecisionReason]] = {
    AuthorityVerificationFailure.AUTHORITY_NOT_FOUND: (
        DecisionReason.AUTHORITY_VERIFICATION_FAILED
    ),
    AuthorityVerificationFailure.AUTHORITY_ARTEFACT_INVALID: (
        DecisionReason.AUTHORITY_VERIFICATION_FAILED
    ),
    AuthorityVerificationFailure.AUTHORITY_DIGEST_MISMATCH: (
        DecisionReason.AUTHORITY_VERIFICATION_FAILED
    ),
    AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID: (
        DecisionReason.AUTHORITY_VERIFICATION_FAILED
    ),
    AuthorityVerificationFailure.AUTHORITY_NOT_YET_VALID: (
        DecisionReason.AUTHORITY_NOT_YET_VALID
    ),
    AuthorityVerificationFailure.AUTHORITY_EXPIRED: DecisionReason.AUTHORITY_EXPIRED,
    AuthorityVerificationFailure.AUTHORITY_REVOKED: DecisionReason.AUTHORITY_REVOKED,
    AuthorityVerificationFailure.AUTHORITY_PRINCIPAL_MISMATCH: (
        DecisionReason.AUTHORITY_PRINCIPAL_MISMATCH
    ),
    AuthorityVerificationFailure.AUTHORITY_DELEGATE_NOT_BOUND: (
        DecisionReason.AUTHORITY_DELEGATE_NOT_BOUND
    ),
    AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE: (
        DecisionReason.AUTHORITY_SCOPE_UNSUPPORTED
    ),
    AuthorityVerificationFailure.AUTHORITY_PROVIDER_UNAVAILABLE: (
        DecisionReason.AUTHORITY_PROVIDER_UNAVAILABLE
    ),
}


def payment_destination(
    envelope: ActionEnvelope,
    money: Money | None,
) -> ExecutionDestination | None:
    """The concrete destination this act would send value to, if determinable.

    ``None`` when any binding dimension is missing. That is not a pass:
    callers that need to bind a payee treat an undeterminable destination
    as a fail-closed condition.
    """
    target = envelope.action.target
    if target is None:
        return None
    payload = envelope.action.payload

    network = payload.get("chain") or payload.get("network") or target.resource_type
    asset = payload.get("asset") or (money.currency if money is not None else None)
    if not isinstance(network, str) or not isinstance(asset, str):
        return None
    try:
        return ExecutionDestination(
            network=network, account=target.resource_id, asset=asset
        )
    except ValueError:
        return None


@dataclass
class PaymentDomainPolicy:
    """Payment policy for one request, over trusted server-side state.

    Constructed per request, like the general engine, from the agent
    record and the current spend window. Nothing here is read from the
    request body: the envelope supplies the *act*, this object supplies
    the *rules*.
    """

    agent: Any
    daily_spend: Decimal = Decimal("0")
    trust_threshold: int | None = None
    registered_policy_hash: str | None = None
    payee_binding_resolver: PayeeBindingResolver | None = None
    #: Trusted answer to "is delegated authority required here". ``None``
    #: means the organisation is not enrolled, which is today's behaviour.
    authority_requirement_resolver: Any = None
    consequence_class: ConsequenceClass | None = None

    def snapshot(self, action_type: str) -> PaymentAuthorityPolicySnapshot:
        """The versioned policy digest this decision is made under."""
        return build_payment_authority_policy_snapshot(
            self.agent,
            action_type,
            trust_threshold=self.trust_threshold,
            registered_policy_hash=self.registered_policy_hash,
        )

    def evaluate(
        self,
        envelope: ActionEnvelope,
        resolved_authority: ResolvedAuthority | None = None,
        context: Any = None,
        *,
        at: datetime | None = None,
    ) -> PolicyDecision:
        """Decide, then narrow. Never the other way round."""
        action = envelope.action
        if envelope.domain != PAYMENT_DOMAIN or action.action_type not in PAYMENT_ACTION_TYPES:
            raise UnknownDomainError(
                f"the payment domain does not govern domain={envelope.domain!r} "
                f"action_type={action.action_type!r}"
            )

        now = (at or datetime.now(UTC)).astimezone(UTC)
        snapshot = self.snapshot(action.action_type).as_policy_snapshot()

        def block(*reasons: DecisionReason) -> PolicyDecision:
            return PolicyDecision(
                decision=Decision.BLOCK,
                policy_snapshot=snapshot,
                reasons=reasons,
                consequence_class=self.consequence_class,
            )

        # --- 0. The act must be about the principal the trusted context names. ---
        # The envelope's identity comes from the adapter, which derives it from
        # authenticated server-side state; the context comes from a trusted
        # ContextProvider. If those two ever disagree, something upstream is
        # attributing an act to the wrong principal and nothing below is safe.
        if context is not None and (
            str(getattr(context, "organisation_id", "")) != action.organisation_id
            or str(getattr(context, "principal_id", "")) != action.principal_id
        ):
            return block(DecisionReason.AUTHORITY_PRINCIPAL_MISMATCH)

        # --- 1. Organisation policy. It decides first and it decides alone. ---
        money: Money | None
        try:
            money = normalise_payment_money(dict(action.payload))
        except MoneyError:
            return block(DecisionReason.AMOUNT_INVALID)

        if money is None and action.action_type in {"financial_transaction"}:
            return block(DecisionReason.AMOUNT_INVALID)

        destination = payment_destination(envelope, money)

        wallet_result = evaluate_wallet_allowlists(
            (self.agent.metadata or {}).get("wallet_policy")
            if isinstance(getattr(self.agent, "metadata", None), dict)
            else None,
            action.action_type,
            destination.network if destination is not None else None,
            destination.account if destination is not None else None,
            agent_id=getattr(self.agent, "id", None),
        )
        if not wallet_result.allowed and wallet_result.violation is not None:
            return block(DecisionReason(wallet_result.violation.value))

        if money is not None:
            spend_result = check_spending_limits(self.agent, money.as_decimal(), self.daily_spend)
            if not spend_result.allowed and spend_result.violation is not None:
                return block(DecisionReason(spend_result.violation.value))

        # --- 2. Is delegated authority required at all? ---
        requirement_required = False
        if self.authority_requirement_resolver is not None:
            requirement = self.authority_requirement_resolver.requirement(
                str(self.agent.org_id), str(self.agent.id), action.action_type
            )
            requirement_required = bool(requirement.required)

        has_verified_authority = (
            resolved_authority is not None and resolved_authority.is_verified
        )

        if requirement_required and not has_verified_authority:
            # Fail closed. The non-delegated path is not a fallback for an
            # organisation that requires delegation: silently taking it is
            # exactly the hole this check exists to close.
            if resolved_authority is None:
                return block(DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING)
            return block(*self._authority_failure_reasons(resolved_authority))

        if resolved_authority is None:
            # No delegated authority presented and none required: behaviour is
            # exactly the organisation-policy outcome computed above.
            return PolicyDecision(
                decision=Decision.ALLOW,
                policy_snapshot=snapshot,
                consequence_class=self.consequence_class,
            )

        # --- 3. Narrow by the delegated scope. It can only subtract. ---
        if not resolved_authority.is_verified:
            return block(*self._authority_failure_reasons(resolved_authority))

        try:
            constraints = parse_delegation_constraints(resolved_authority.scope)
        except DelegationScopeError:
            return block(DecisionReason.AUTHORITY_SCOPE_UNSUPPORTED)

        if not constraints.is_fully_enforceable:
            # The issuer granted authority carrying a machine-enforceable
            # constraint this build cannot interpret. Proceeding would mean
            # enforcing a subset of what was granted, which is broader than
            # what was granted.
            return block(DecisionReason.AUTHORITY_SCOPE_UNSUPPORTED)

        if not resolved_authority.is_within_validity(now):
            if resolved_authority.not_before is not None and now < resolved_authority.not_before:
                return block(DecisionReason.AUTHORITY_NOT_YET_VALID)
            return block(DecisionReason.AUTHORITY_EXPIRED)

        if not constraints.is_within_validity(now):
            if constraints.not_before is not None and now < constraints.not_before:
                return block(DecisionReason.AUTHORITY_NOT_YET_VALID)
            return block(DecisionReason.AUTHORITY_EXPIRED)

        if constraints.max_amount is not None:
            if money is None:
                return block(DecisionReason.AMOUNT_INVALID)
            if money.currency != constraints.max_amount.currency:
                return block(DecisionReason.AUTHORITY_SCOPE_EXCEEDED)
            if not money <= constraints.max_amount:
                return block(DecisionReason.AUTHORITY_SCOPE_EXCEEDED)

        if constraints.allowed_payees is not None:
            payee_reason = self._check_payee_binding(constraints.allowed_payees, destination)
            if payee_reason is not None:
                return block(payee_reason)

        return PolicyDecision(
            decision=Decision.ALLOW,
            policy_snapshot=snapshot,
            consequence_class=self.consequence_class,
        )

    def _authority_failure_reasons(
        self, resolved_authority: ResolvedAuthority
    ) -> tuple[DecisionReason, ...]:
        reasons = tuple(
            dict.fromkeys(
                _AUTHORITY_FAILURE_REASONS.get(
                    code, DecisionReason.AUTHORITY_VERIFICATION_FAILED
                )
                for code in resolved_authority.failure_codes
            )
        )
        return reasons or (DecisionReason.AUTHORITY_UNVERIFIED,)

    def _check_payee_binding(
        self,
        allowed_payees: frozenset[str],
        destination: ExecutionDestination | None,
    ) -> DecisionReason | None:
        """Bind an approved payee to the destination the executor will use.

        A payee identity is not a destination. Unless one of the payees the
        authority approved is bound — by trusted server-side state — to
        exactly this network, account and asset, the request fails closed.
        """
        if self.payee_binding_resolver is None:
            # The scope restricts payees and nothing here can resolve a
            # binding, so the constraint cannot be enforced.
            return DecisionReason.AUTHORITY_SCOPE_UNSUPPORTED
        if destination is None:
            return DecisionReason.AUTHORITY_SCOPE_EXCEEDED

        organisation_id = str(self.agent.org_id)
        for payee in sorted(allowed_payees):
            binding = self.payee_binding_resolver.binding_for(organisation_id, payee)
            if binding is None:
                continue
            if binding.mismatch_against(destination) is None:
                return None
        return DecisionReason.AUTHORITY_SCOPE_EXCEEDED
