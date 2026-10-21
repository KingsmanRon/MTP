"""The ports the authority boundary is defined against.

Protocols only. There is no implementation in this module and there must
not be one: an implementation would have to know something about a
particular issuer, rail or store, and that knowledge does not belong in
Core.

Trust direction
---------------
:class:`AuthorityProvider`, :class:`ContextProvider` and
:class:`AuthorityRequirementResolver` are the trusted side of the
boundary. They are the only components allowed to mint a
``TrustedAuthorityConstruction`` and therefore the only source of
verified authority, organisation identity, delegate binding and
requirement answers. Everything else in the system consumes their output
and cannot fabricate it.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from api.core.authority.authority import (
    AuthorityRequirement,
    DelegatedAuthorityClaim,
    ExecutionContext,
    ResolvedAuthority,
)
from api.core.authority.decision import PolicyDecision
from api.core.authority.envelope import ActionEnvelope
from api.core.authority.grant import ExecutionAuthorityGrant
from api.core.authority.outcome import OutcomeReference


@runtime_checkable
class AuthorityProvider(Protocol):
    """Turns an untrusted claim into trusted, typed evidence."""

    def resolve(
        self,
        raw_authority: DelegatedAuthorityClaim | None,
        expected_principal_context: ExecutionContext,
    ) -> ResolvedAuthority:
        """Resolve ``raw_authority`` against the principal it must belong to.

        Returns a ``ResolvedAuthority`` in every ordinary case, including
        every kind of failure: not found, digest mismatch, expired,
        revoked, delegate not bound, provider unreachable. Each is
        reported as a non-verified status with typed issues so the
        decision path can ``BLOCK`` with a truthful reason.

        Raising is reserved for genuine faults — a bug, or a caller that
        handed over something structurally impossible. "The artefact did
        not verify" is not a fault.

        A ``None`` claim means the caller presented no authority at all;
        the provider returns an unverified resolution rather than
        inventing one.
        """
        ...


@runtime_checkable
class ContextProvider(Protocol):
    """Supplies trusted current context for an organisation and principal."""

    def context(self, organisation_id: str, principal_id: str) -> ExecutionContext:
        """Return the current trusted context.

        The returned ``principal_binding`` carries whatever external
        principal-binding data an ``AuthorityProvider`` needs in order to
        check that an authority artefact really belongs to this
        principal. It is trusted because it was assembled server-side,
        never because a caller sent it.
        """
        ...


@runtime_checkable
class AuthorityRequirementResolver(Protocol):
    """Answers whether delegated authority is required, from trusted config."""

    def requirement(
        self,
        organisation_id: str,
        principal_id: str,
        action_class: str,
    ) -> AuthorityRequirement:
        """Return the requirement for this organisation/principal/action class.

        Answered from trusted server-side configuration and context, never
        from the request. A resolver that cannot determine the answer
        returns ``required=True``: not knowing is not permission. Later
        phases fail closed when authority is required and absent.
        """
        ...


@runtime_checkable
class DomainPolicy(Protocol):
    """Decides whether the organisation's current policy permits an act."""

    def evaluate(
        self,
        envelope: ActionEnvelope,
        resolved_authority: ResolvedAuthority | None,
        context: ExecutionContext,
    ) -> PolicyDecision:
        """Evaluate the envelope and return the decision with its reasons.

        Returns a ``PolicyDecision`` rather than a bare ``Decision`` so
        that the typed reasons and the policy snapshot the decision was
        made under travel with it; a bare verdict would drop both.

        The implementation reads the act from
        ``envelope.action`` and nowhere else. It may read
        ``resolved_authority.scope`` as domain data. It never treats an
        unverified authority as verified.
        """
        ...


@runtime_checkable
class Executor(Protocol):
    """Performs the act a grant authorises."""

    def execute(
        self,
        grant: ExecutionAuthorityGrant,
        envelope: ActionEnvelope,
    ) -> OutcomeReference:
        """Perform the act and return a reference to what happened.

        The executor must verify that ``grant.execution_action_hash``
        matches the act it is about to perform, and that its own
        authenticated identity matches ``grant.executor_binding``, before
        doing anything with an effect.
        """
        ...


@runtime_checkable
class OutcomeProvider(Protocol):
    """Reads back the current state of a downstream execution."""

    def outcome(self, reference: OutcomeReference) -> OutcomeReference:
        """Return the current known state for ``reference``.

        A provider that cannot reach the downstream system returns
        ``UNKNOWN``. It never reports ``FAILED`` for an unreachable
        system: "we could not ask" and "it did not happen" are different
        facts, and conflating them invites a duplicate execution.
        """
        ...
