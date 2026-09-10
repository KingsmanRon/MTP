"""What Inntris pinned itself to, recorded as code rather than prose.

Verifiable Intent is a public draft, so "the spec" is not a stable thing
to verify against — it is a moving repository. Every constant here names
the exact revision this connector was written and tested against, and the
test suite asserts the pinned values against a fixture file so a silent
upstream drift shows up as a failing test instead of a subtly different
verification result.

The VCT and constraint-type strings below are Verifiable Intent's own
vocabulary. They live here, inside the connector, and nothing exports
them inward.
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# The pinned upstream normative source
# ---------------------------------------------------------------------------

#: The project's published site.
UPSTREAM_SITE: Final[str] = "https://verifiableintent.dev/"

#: The normative repository: specification documents and reference code.
UPSTREAM_REPOSITORY: Final[str] = "https://github.com/agent-intent/verifiable-intent"

#: The exact commit this connector was implemented and tested against.
UPSTREAM_COMMIT: Final[str] = "356c29635f1c44df7de02edb58699ca9f29bece6"

#: ``verifiable_intent.__version__`` at that commit. The runtime refuses to
#: verify against a different version rather than assume compatibility.
UPSTREAM_PACKAGE_VERSION: Final[str] = "0.1.0"

#: The revision the specification documents declare at that commit.
SPEC_REVISION: Final[str] = "0.1-draft"

#: The date those documents carry.
SPEC_DATE: Final[str] = "2026-02-18"

#: The issuer namespace this connector answers for, as it appears on a
#: :class:`~api.core.authority.authority.DelegatedAuthorityClaim`.
AUTHORITY_ISSUER_SCHEME: Final[str] = "verifiable-intent"


# ---------------------------------------------------------------------------
# Credential types (credential-format.md §10, VCT Registry)
# ---------------------------------------------------------------------------

#: The L1 credential type of the Mastercard reference profile.
L1_VCT_MASTERCARD_CARD: Final[str] = "https://credentials.mastercard.com/card"

#: Autonomous-mode ("open") mandate types. These are the only L2 mandate
#: types that express delegation to an agent, and therefore the only ones
#: that can be a source of delegated authority here.
L2_CHECKOUT_VCT_OPEN: Final[str] = "mandate.checkout.open.1"
L2_PAYMENT_VCT_OPEN: Final[str] = "mandate.payment.open.1"

#: Immediate-mode ("final") mandate types. A user confirming final values
#: in person delegates nothing to an agent, so these are rejected.
L2_CHECKOUT_VCT_FINAL: Final[str] = "mandate.checkout.1"
L2_PAYMENT_VCT_FINAL: Final[str] = "mandate.payment.1"

#: L2 header ``typ`` for autonomous mode (a KB-SD-JWT that further
#: delegates to the agent key carried in the mandates' ``cnf``).
L2_TYP_AUTONOMOUS: Final[str] = "kb-sd-jwt+kb"


# ---------------------------------------------------------------------------
# Constraint types (constraints.md §6.2, Constraint Type Registry)
# ---------------------------------------------------------------------------

CONSTRAINT_ALLOWED_MERCHANTS: Final[str] = "mandate.checkout.allowed_merchants"
CONSTRAINT_LINE_ITEMS: Final[str] = "mandate.checkout.line_items"
CONSTRAINT_ALLOWED_PAYEES: Final[str] = "mandate.payment.allowed_payees"
CONSTRAINT_AMOUNT_RANGE: Final[str] = "mandate.payment.amount_range"
CONSTRAINT_BUDGET: Final[str] = "mandate.payment.budget"
CONSTRAINT_RECURRENCE: Final[str] = "mandate.payment.recurrence"
CONSTRAINT_AGENT_RECURRENCE: Final[str] = "mandate.payment.agent_recurrence"
CONSTRAINT_REFERENCE: Final[str] = "mandate.payment.reference"

#: Every type the pinned draft registers. A constraint outside this set is
#: unknown, and Verifiable Intent itself requires open mandates to reject
#: unknown constraint types (constraints.md §5.4) — an unevaluable
#: constraint leaves agent authority unbounded.
REGISTERED_CONSTRAINT_TYPES: Final[frozenset[str]] = frozenset(
    {
        CONSTRAINT_ALLOWED_MERCHANTS,
        CONSTRAINT_LINE_ITEMS,
        CONSTRAINT_ALLOWED_PAYEES,
        CONSTRAINT_AMOUNT_RANGE,
        CONSTRAINT_BUDGET,
        CONSTRAINT_RECURRENCE,
        CONSTRAINT_AGENT_RECURRENCE,
        CONSTRAINT_REFERENCE,
    }
)

#: Payment-mandate constraint types this release maps into enforceable
#: Inntris scope. Anything else in a payment mandate fails closed.
MAPPED_PAYMENT_CONSTRAINT_TYPES: Final[frozenset[str]] = frozenset(
    {
        CONSTRAINT_ALLOWED_PAYEES,
        CONSTRAINT_AMOUNT_RANGE,
    }
)

#: Payment-mandate constraint types that bound nothing about the act and
#: are verified structurally instead. ``mandate.payment.reference`` is the
#: checkout/payment pairing binding; the pinned reference implementation
#: verifies it in ``verify_l2_reference_binding`` and explicitly excludes
#: it from constraint checking (constraints.md §4.8).
STRUCTURAL_PAYMENT_CONSTRAINT_TYPES: Final[frozenset[str]] = frozenset(
    {CONSTRAINT_REFERENCE}
)

#: Payment-mandate constraint types that express cumulative or recurring
#: usage accounting. Inntris v0.5 keeps no per-mandate spend or occurrence
#: ledger, so it cannot enforce them and refuses to pretend otherwise.
USAGE_ACCOUNTING_CONSTRAINT_TYPES: Final[frozenset[str]] = frozenset(
    {
        CONSTRAINT_BUDGET,
        CONSTRAINT_RECURRENCE,
        CONSTRAINT_AGENT_RECURRENCE,
    }
)

#: Checkout-mandate constraint types the draft registers. These bound the
#: agent's *merchant checkout*, which Inntris neither performs nor issues
#: execution authority for; see the module notes in ``scope.py``.
CHECKOUT_CONSTRAINT_TYPES: Final[frozenset[str]] = frozenset(
    {
        CONSTRAINT_ALLOWED_MERCHANTS,
        CONSTRAINT_LINE_ITEMS,
    }
)
