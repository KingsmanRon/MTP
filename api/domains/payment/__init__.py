"""The payment domain.

Owns the payment-specific policy that used to live inline in the general
engine: amount and currency handling, per-action and daily spend limits,
and the wallet chain/recipient allowlists. The general engine keeps
action-type registration, trust thresholds and lifecycle checks, and
calls into this module at the same points and in the same order as
before, so legacy ``/verify`` behaviour is unchanged.

On top of that it adds the delegated-payment extension point:
:class:`~api.domains.payment.policy.PaymentDomainPolicy` implements the
``DomainPolicy`` port and intersects organisation policy with an external
delegated scope. The intersection only ever narrows.
"""

from __future__ import annotations

from api.domains.payment.amounts import (
    AMOUNT_FIELDS,
    AMOUNT_REQUIRED_ACTIONS,
    AmountError,
    extract_amount,
)
from api.domains.payment.binding import (
    DestinationMismatch,
    ExecutionDestination,
    PayeeBinding,
    PayeeBindingError,
    PayeeBindingResolver,
)
from api.domains.payment.delegation import (
    KNOWN_SCOPE_KEYS,
    DelegationScopeError,
    PaymentDelegationConstraints,
    parse_delegation_constraints,
)
from api.domains.payment.money import (
    CURRENCY_FIELDS,
    SUPPORTED_CURRENCIES,
    AmountPrecisionError,
    ConflictingAmountError,
    Money,
    MoneyError,
    UnsupportedCurrencyError,
    normalise_payment_money,
)
from api.domains.payment.policy import (
    PAYMENT_ACTION_TYPES,
    PAYMENT_DOMAIN,
    PaymentDomainPolicy,
    check_spending_limits,
    check_wallet_policy,
    evaluate_wallet_allowlists,
    payment_destination,
)
from api.domains.payment.snapshot import (
    PAYMENT_AUTHORITY_POLICY_FORMAT,
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

__all__ = [
    "AMOUNT_FIELDS",
    "AMOUNT_REQUIRED_ACTIONS",
    "CURRENCY_FIELDS",
    "KNOWN_SCOPE_KEYS",
    "PAYMENT_ACTION_TYPES",
    "PAYMENT_AUTHORITY_POLICY_FORMAT",
    "PAYMENT_DOMAIN",
    "SUPPORTED_CURRENCIES",
    "WALLET_ACTION_TYPES",
    "WALLET_ALLOWLIST_ACTION_TYPES",
    "AmountError",
    "AmountPrecisionError",
    "ConflictingAmountError",
    "DelegationScopeError",
    "DestinationMismatch",
    "ExecutionDestination",
    "Money",
    "MoneyError",
    "PayeeBinding",
    "PayeeBindingError",
    "PayeeBindingResolver",
    "PaymentAuthorityPolicySnapshot",
    "PaymentDelegationConstraints",
    "PaymentDomainPolicy",
    "UnsupportedCurrencyError",
    "WalletPolicyError",
    "build_payment_authority_policy_snapshot",
    "chain_allowlist_for",
    "check_spending_limits",
    "check_wallet_policy",
    "evaluate_wallet_allowlists",
    "extract_amount",
    "normalise_payment_money",
    "parse_delegation_constraints",
    "payment_destination",
    "recipient_in_allowlist",
    "validate_wallet_policy",
]
