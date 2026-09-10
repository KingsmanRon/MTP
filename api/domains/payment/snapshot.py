"""The versioned policy snapshot a payment grant is issued under.

This does **not** redefine ``_effective_policy_hash`` or v1/v2 receipt
semantics. Those stay exactly as they are: they describe the legacy
``/verify`` decision and appear in deployed receipts. This is a separate,
explicitly versioned digest for delegated-payment execution authority,
under the format identifier ``inntris-payment-authority-policy-v1``.

Why a second digest exists
--------------------------
The legacy effective-policy hash covers the agent's status, allowed and
blocked actions, limits and trust score. It does **not** cover the wallet
chain and recipient allowlists, which live in agent metadata and which
absolutely do decide whether a payment is permitted. A grant that claimed
the legacy hash as its policy binding would be claiming to bind rules it
never covered. So this snapshot covers every rule actually applied to the
canonical payment action, the wallet allowlists included.

Determinism and secrecy
-----------------------
The preimage is canonicalized with the repository's RFC 8785
implementation, so the digest is stable across processes and languages.
It carries policy content only — limits, allowlists, statuses, versions.
No key material, no API keys, no agent metadata beyond the wallet policy
allowlists, nothing that would turn a published snapshot into a
disclosure.

Change detection, and why the revision is semantic
--------------------------------------------------
``digest`` is the authoritative comparison key: a JCS hash over every
policy input. ``revision`` is a readable label derived FROM that digest,
plus the principal and key version.

It once derived from the agent's ``updated_at``. That is a row mtime, not
a policy input — an AFTER INSERT trigger on ``audit_logs`` bumps the
agent's action counters, which bumps ``updated_at`` — and because
``AuthorityStore.issuance_digest`` binds ``policy_revision`` into the
issuance identity, an ordinary audit write made an identical retry look
like a different request. Deriving the revision from the digest makes
"same policy" and "same revision" one statement by construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Final

from api import jcs
from api.core.authority.decision import PolicySnapshot
from api.domains.payment.amounts import AMOUNT_REQUIRED_ACTIONS
from api.domains.payment.delegation import KNOWN_SCOPE_KEYS
from api.domains.payment.wallet import validate_wallet_policy

#: The versioned preimage identifier for this snapshot.
PAYMENT_AUTHORITY_POLICY_FORMAT: Final[str] = "inntris-payment-authority-policy-v1"


def _instant(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, datetime):
        return str(value)
    normalised = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    iso = normalised.astimezone(UTC).isoformat()
    return iso[:-6] + "Z" if iso.endswith("+00:00") else iso


def _amount(value: Any) -> str:
    return str(value if isinstance(value, Decimal) else Decimal(str(value)))


@dataclass(frozen=True, slots=True)
class PaymentAuthorityPolicySnapshot:
    """A deterministic digest of every rule applied to one payment act."""

    digest: str
    revision: str
    captured_at: datetime
    preimage: dict[str, Any]

    def as_policy_snapshot(self) -> PolicySnapshot:
        """The core-layer snapshot a grant or decision carries."""
        return PolicySnapshot(
            policy_hash=self.digest,
            captured_at=self.captured_at,
            source=PAYMENT_AUTHORITY_POLICY_FORMAT,
        )


def build_payment_authority_policy_snapshot(
    agent: Any,
    action_type: str,
    *,
    trust_threshold: int | None,
    registered_policy_hash: str | None = None,
    captured_at: datetime | None = None,
) -> PaymentAuthorityPolicySnapshot:
    """Snapshot the organisation policy governing ``action_type`` for ``agent``.

    ``agent`` is the trusted server-side record, never anything derived
    from the request. An unreadable ``wallet_policy`` is recorded as
    ``"invalid"`` rather than omitted: a snapshot that quietly dropped a
    policy it could not parse would claim to cover a rule it did not.
    """
    metadata = agent.metadata if isinstance(getattr(agent, "metadata", None), dict) else {}
    raw_wallet_policy = metadata.get("wallet_policy")

    wallet_section: dict[str, Any]
    if raw_wallet_policy is None:
        wallet_section = {"configured": False}
    else:
        try:
            allowed_chains, allowed_recipients = validate_wallet_policy(raw_wallet_policy)
        except Exception:
            wallet_section = {"configured": True, "state": "invalid"}
        else:
            wallet_section = {
                "configured": True,
                "state": "valid",
                "allowed_chains": sorted(allowed_chains) if allowed_chains else None,
                "allowed_recipients": (
                    {
                        chain: sorted(entries)
                        for chain, entries in sorted(allowed_recipients.items())
                    }
                    if allowed_recipients
                    else None
                ),
            }

    captured = (captured_at or datetime.now(UTC)).astimezone(UTC)

    preimage: dict[str, Any] = {
        "format": PAYMENT_AUTHORITY_POLICY_FORMAT,
        "action_type": action_type,
        "principal": {
            "agent_id": str(agent.id),
            "organisation_id": str(agent.org_id),
            "status": (
                agent.status.value if hasattr(agent.status, "value") else str(agent.status)
            ),
            "trust_score": int(agent.trust_score),
            "key_version": int(getattr(agent, "key_version", 1)),
            # ``updated_at`` is deliberately NOT here. It is a row mtime, not
            # a policy input: an AFTER INSERT trigger on audit_logs bumps the
            # agent's action counters, which bumps updated_at, which would
            # change this digest and make every outstanding grant fail
            # revalidation as a POLICY_HASH_MISMATCH -- for a statistic, not
            # a policy change. Every actual policy input is committed to
            # explicitly above and below, so nothing is lost by its absence
            # and a false mismatch is gained by its presence. It is absent
            # from ``revision`` below for the same reason, and a sharper one:
            # that revision is bound into the issuance identity, so a row
            # mtime there breaks retry idempotency rather than merely
            # mislabelling a snapshot.
        },
        "action_permissions": {
            "allowed_actions": sorted(agent.allowed_actions or []),
            "blocked_actions": sorted(agent.blocked_actions or []),
        },
        "limits": {
            "daily_limit_usd": _amount(agent.daily_limit_usd),
            "per_action_limit_usd": _amount(agent.per_action_limit_usd),
            "rate_limit_per_minute": int(agent.rate_limit_per_minute),
        },
        "trust": {"threshold": trust_threshold},
        "amount": {"required": action_type in AMOUNT_REQUIRED_ACTIONS},
        "wallet_policy": wallet_section,
        "registered_policy_hash": registered_policy_hash,
        # Which delegated constraints this build is able to enforce. A later
        # build that understands more keys produces a different digest, which
        # is correct: it is a different rule set.
        "enforceable_delegation_scope_keys": sorted(KNOWN_SCOPE_KEYS),
    }

    digest = jcs.sha256_hex(preimage)
    # --- The revision is SEMANTIC, and it is load-bearing -----------------
    # ``AuthorityStore.issuance_digest`` binds policy_revision into the
    # issuance identity, so this string decides whether a retry of one
    # request is the same request. It must therefore change when the policy
    # changes and at no other time.
    #
    # It used to carry ``agents.updated_at``. That is a row mtime: an AFTER
    # INSERT trigger on audit_logs bumps the agent's action counters, which
    # bumps updated_at -- so writing the first decision's own audit row
    # changed the revision, and an identical retry that reloaded the agent
    # computed a different issuance digest and was refused as a conflicting
    # request. Deriving it from the policy digest instead makes "same policy"
    # and "same revision" the same statement, by construction.
    revision = "|".join(
        (
            PAYMENT_AUTHORITY_POLICY_FORMAT,
            str(getattr(agent, "id", "")),
            str(int(getattr(agent, "key_version", 1) or 1)),
            digest,
        )
    )
    return PaymentAuthorityPolicySnapshot(
        digest=digest,
        revision=revision,
        captured_at=captured,
        preimage=preimage,
    )
