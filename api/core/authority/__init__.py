"""Core authority boundary — vendor-neutral types and ports.

Inntris is becoming an execution-authority layer for consequential agent
actions. Something outside this system may establish what was delegated;
this boundary independently decides whether the *exact* proposed act is
permitted by the organisation's current policy immediately before
execution, and, if it is, issues bounded execution authority for that one
act.

Payments are the first domain, not the ontology. Nothing in this package
names a rail, an issuer, a connector or a vendor field, and nothing may
be added that does.

What is here
------------
``envelope``   the one validated executable representation of an act, and
               the versioned ``inntris-execution-action-v1`` hash over it
``authority``  untrusted claims, trusted resolved authority, and the
               capability that separates them
``decision``   ALLOW / BLOCK / REQUIRE_APPROVAL, typed reasons,
               consequence classes, policy snapshots
``grant``      bounded single-use execution authority and its state model
``lifecycle``  reservation and consumption, including recovery semantics
``outcome``    opaque references to what happened downstream
``ports``      the protocols the boundary is defined against
``errors``     typed faults, and the rule that expected denial is data

This phase adds types and ports only. There is no policy behaviour
change, no route change, no persistence and no executor.
"""

from __future__ import annotations

from api.core.authority.authority import (
    AuthorityRequirement,
    AuthorityVerificationFailure,
    AuthorityVerificationIssue,
    DelegateBindingStatus,
    DelegatedAuthorityClaim,
    DelegatedAuthorityReference,
    ExecutionContext,
    ResolvedAuthority,
    TrustedAuthorityConstruction,
    VerificationStatus,
    trusted_authority_construction,
)
from api.core.authority.decision import (
    ApprovalRequirement,
    ConsequenceClass,
    Decision,
    DecisionReason,
    PolicyDecision,
    PolicySnapshot,
)
from api.core.authority.envelope import (
    EXECUTION_ACTION_HASH_FORMAT,
    MAX_PAYLOAD_DEPTH,
    RESERVED_TARGET_PAYLOAD_KEYS,
    ActionEnvelope,
    ExecutableAction,
    ResourceReference,
)
from api.core.authority.errors import (
    CoreAuthorityError,
    InvalidAuthorityConstructionError,
    InvalidEnvelopeError,
    InvalidGrantError,
    UnknownDomainError,
)
from api.core.authority.grant import (
    ALLOWED_GRANT_TRANSITIONS,
    CONSUMPTION_REJECTION_PRECEDENCE,
    TERMINAL_GRANT_STATUSES,
    ExecutionAuthorityGrant,
    ExecutorBinding,
    GrantStatus,
    first_rejection,
    is_allowed_transition,
)
from api.core.authority.lifecycle import (
    AuthorityConsumption,
    AuthorityReservation,
    ConsumptionOutcome,
    ReservationStatus,
)
from api.core.authority.outcome import EvidenceLink, OutcomeReference, OutcomeStatus
from api.core.authority.ports import (
    AuthorityProvider,
    AuthorityRequirementResolver,
    ContextProvider,
    DomainPolicy,
    Executor,
    OutcomeProvider,
)

__all__ = [
    "ALLOWED_GRANT_TRANSITIONS",
    "CONSUMPTION_REJECTION_PRECEDENCE",
    "EXECUTION_ACTION_HASH_FORMAT",
    "MAX_PAYLOAD_DEPTH",
    "RESERVED_TARGET_PAYLOAD_KEYS",
    "TERMINAL_GRANT_STATUSES",
    "ActionEnvelope",
    "ApprovalRequirement",
    "AuthorityConsumption",
    "AuthorityProvider",
    "AuthorityRequirement",
    "AuthorityRequirementResolver",
    "AuthorityReservation",
    "AuthorityVerificationFailure",
    "AuthorityVerificationIssue",
    "ConsequenceClass",
    "ConsumptionOutcome",
    "ContextProvider",
    "CoreAuthorityError",
    "Decision",
    "DecisionReason",
    "DelegateBindingStatus",
    "DelegatedAuthorityClaim",
    "DelegatedAuthorityReference",
    "DomainPolicy",
    "EvidenceLink",
    "ExecutableAction",
    "ExecutionAuthorityGrant",
    "ExecutionContext",
    "Executor",
    "ExecutorBinding",
    "GrantStatus",
    "InvalidAuthorityConstructionError",
    "InvalidEnvelopeError",
    "InvalidGrantError",
    "OutcomeProvider",
    "OutcomeReference",
    "OutcomeStatus",
    "PolicyDecision",
    "PolicySnapshot",
    "ReservationStatus",
    "ResolvedAuthority",
    "ResourceReference",
    "TrustedAuthorityConstruction",
    "UnknownDomainError",
    "VerificationStatus",
    "first_rejection",
    "is_allowed_transition",
    "trusted_authority_construction",
]
