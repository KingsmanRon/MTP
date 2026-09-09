"""Wallet chain and recipient allowlists.

Moved verbatim from ``api/policy.py`` when the payment domain was split
out. The semantics are unchanged; see the provisioning trap documented on
:func:`chain_allowlist_for` before touching anything here.

An opt-in, per-agent chain and recipient allowlist stored at
``agent.metadata["wallet_policy"]``. It governs only the wallet_* action
types the connected-wallet adapter submits; every other action type is
untouched, and an agent with no wallet_policy behaves exactly as before.

Deliberately no amount or budget semantics: a connected-wallet transaction
may express native-token or atomic-unit value, which cannot be interpreted
as USD without an authoritative asset-normalisation layer. Adding a
fabricated conversion here would corrupt the existing USD-denominated
spend controls.

This module deliberately imports nothing from the rest of the API. It is
pure validation, so ``api.models`` can call it from a field validator
without an import cycle.
"""

from __future__ import annotations

from typing import Any

WALLET_ACTION_TYPES = frozenset({"wallet_transaction", "wallet_signature"})

# The action types whose chain and recipient are enforced. Signature actions
# carry no recipient and are not chain-scoped, so only transactions are gated
# on the allowlists.
WALLET_ALLOWLIST_ACTION_TYPES = frozenset({"wallet_transaction"})


class WalletPolicyError(ValueError):
    """Raised when a configured ``wallet_policy`` is structurally invalid.

    A policy the server cannot interpret is a fail-closed signal: the operator
    expressed an intent that cannot be evaluated, and guessing at it would be
    worse than refusing. Distinct from "no policy configured", which simply
    means no chain or recipient restriction applies.
    """


def validate_wallet_policy(raw: Any) -> tuple[list[str] | None, dict[str, list[str]] | None]:
    """Validate a ``wallet_policy`` document and return its two allowlists.

    Unknown top-level keys are tolerated so a future field does not brick a
    deployed policy, but every recognised key is type-checked strictly.

    Raises ``WalletPolicyError`` when the document cannot be interpreted.
    """
    if not isinstance(raw, dict):
        raise WalletPolicyError("wallet_policy must be an object")

    allowed_chains = raw.get("allowed_chains")
    if allowed_chains is not None:
        if not isinstance(allowed_chains, list) or not allowed_chains:
            raise WalletPolicyError("wallet_policy.allowed_chains must be a non-empty list")
        for chain in allowed_chains:
            if not isinstance(chain, str) or not chain.strip():
                raise WalletPolicyError(
                    "wallet_policy.allowed_chains entries must be non-empty CAIP-2 strings"
                )

    allowed_recipients = raw.get("allowed_recipients")
    if allowed_recipients is not None:
        if not isinstance(allowed_recipients, dict):
            raise WalletPolicyError(
                "wallet_policy.allowed_recipients must be an object keyed by CAIP-2 chain"
            )
        for chain, entries in allowed_recipients.items():
            if not isinstance(chain, str) or not chain.strip():
                raise WalletPolicyError(
                    "wallet_policy.allowed_recipients keys must be non-empty CAIP-2 strings"
                )
            if not isinstance(entries, list):
                raise WalletPolicyError(
                    f"wallet_policy.allowed_recipients['{chain}'] must be a list"
                )
            for entry in entries:
                if not isinstance(entry, str) or not entry.strip():
                    raise WalletPolicyError(
                        f"wallet_policy.allowed_recipients['{chain}'] entries must be "
                        "non-empty address strings"
                    )

    return allowed_chains, allowed_recipients


def recipient_in_allowlist(chain: str, recipient: str, allowlist: list[str]) -> bool:
    """Whether ``recipient`` appears in ``allowlist`` for ``chain``.

    EVM addresses are compared case-insensitively because EIP-55 checksum
    casing is presentational and two spellings of the same address must not
    produce different decisions. The address is otherwise never rewritten — no
    checksumming, no trimming — so what the policy authorises is exactly what
    was submitted.
    """
    if chain.split(":", 1)[0].lower() == "eip155":
        target = recipient.lower()
        return any(entry.lower() == target for entry in allowlist)
    return recipient in allowlist


def chain_allowlist_for(
    allowed_recipients: dict[str, list[str]] | None,
    chain: str,
) -> list[str] | None:
    """The recipient allowlist configured for ``chain``, or ``None``.

    PROVISIONING TRAP — preserved deliberately. ``allowed_recipients`` is
    keyed by CAIP-2 chain, and a key that does not match the submitted
    chain imposes no restriction on that other chain. An operator who
    configures recipients for ``eip155:1`` and nothing for ``eip155:137``
    has NOT restricted recipients on ``eip155:137``; only the
    ``allowed_chains`` list decides whether that chain may be used at all.

    This is existing deployed behaviour and it stays. It is documented and
    regression-tested rather than "fixed", because tightening it would
    silently start denying traffic that operators configured to allow.

    It must NOT be generalised to delegated-authority allowlists: external
    delegation constraints have their own semantics and may be stricter.
    See ``api.domains.payment.delegation``.
    """
    if allowed_recipients is None:
        return None
    return allowed_recipients.get(chain)
