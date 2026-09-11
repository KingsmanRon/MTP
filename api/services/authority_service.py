"""The one evaluation path and the one consumption path.

Both HTTP surfaces — the new ``/authority/*`` endpoints and the legacy
``/verify`` / ``/verify-token`` routes — call into these. Neither
reimplements a decision, so there is no second place where policy could
drift or a second authoritative record of what was consumed.

What the caller is never allowed to supply
------------------------------------------
Organisation, principal, consequence class and any verification status
are derived from trusted server-side state. A request body may carry an
*opaque reference* to external authority for a configured provider to
resolve; it may not carry the conclusion.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Final
from uuid import UUID

from api.adapters.verify_envelope import build_action_envelope
from api.core.authority.authority import (
    AuthorityRequirement,
    DelegatedAuthorityClaim,
    ResolvedAuthority,
)
from api.core.authority.decision import ConsequenceClass, Decision, DecisionReason
from api.core.authority.lifecycle import ConsumptionOutcome
from api.crypto import CryptoService
from api.database import Database
from api.domains.payment.policy import PAYMENT_ACTION_TYPES, PaymentDomainPolicy
from api.domains.payment.snapshot import build_payment_authority_policy_snapshot
from api.persistence.authority_decisions import (
    build_decision_payload,
    record_authority_decision,
)
from api.persistence.authority_store import (
    AuthorityStore,
    ConsumeResult,
    IssueOutcome,
    IssueResult,
    ResolvedAuthorityEvidence,
    authority_scope_digest,
)
from api.policy import PolicyEngine
from api.services.core_evaluation import (
    CorePolicyInputs,
    core_violation_to_reason,
    evaluate_core_policy,
)
from api.services.executor_context import AuthenticatedExecutorContext, binding_matches

logger = logging.getLogger(__name__)

#: Version tag on the authority bearer token. The token is produced by the
#: EXISTING approval-token primitive (HMAC over a claim set, verified with
#: the server secret) rather than a second bearer scheme; this claim marks
#: which claim set it carries.
AUTHORITY_TOKEN_VERSION: Final[str] = "inntris-authority-token-v1"


def principal_is_sandbox(agent: Any) -> bool:
    """Whether this principal's activity is test activity.

    Read from server-side agent metadata, exactly as the legacy path reads
    it, so both surfaces answer this question the same way. ``test_request``
    is honoured alongside ``sandbox`` because that is the key the anchor
    worker already excludes on.
    """
    metadata = getattr(agent, "metadata", None)
    if not isinstance(metadata, dict):
        return False
    return bool(metadata.get("sandbox") or metadata.get("test_request"))


def _scope_digest_for(resolved: ResolvedAuthority | None) -> str | None:
    """Digest of the delegated scope this decision was bound by.

    Deliberately a SCOPE digest and nothing else. It commits to what the
    delegation permits — issuer, reference and the scope mapping — and it
    is not a digest of the issuer's artefact, which this phase never sees.
    """
    if resolved is None:
        return None
    return authority_scope_digest(
        issuer=resolved.reference.issuer,
        external_reference_id=resolved.reference.external_reference_id,
        artefact_digest=resolved.reference.artefact_digest,
        scope=dict(resolved.scope),
    )


#: Server-side agent metadata key carrying the external principal-binding
#: data an ``AuthorityProvider`` needs — an expected audience, a registered
#: delegate key thumbprint, whatever a given issuer's binding requires.
#: Provisioned out of band and read only from the agent record, never from
#: a request: a principal binding a caller could assert about itself would
#: bind nothing.
PRINCIPAL_BINDING_METADATA_KEY: Final[str] = "authority_principal_binding"


def _principal_binding_for(agent: Any) -> dict[str, Any]:
    """The trusted principal-binding data for this agent, or nothing."""
    metadata = getattr(agent, "metadata", None)
    if not isinstance(metadata, dict):
        return {}
    binding = metadata.get(PRINCIPAL_BINDING_METADATA_KEY)
    if not isinstance(binding, dict):
        return {}
    return dict(binding)


class AuthorityTimestampError(Exception):
    """The caller-supplied act timestamp cannot be used as a decision instant."""


def authority_decision_instant(timestamp: Any) -> datetime | None:
    """Strictly parse the instant the caller says this act occurred.

    Returns ``None`` when no timestamp was supplied, in which case server
    time is authoritative. Anything supplied is parsed strictly:

    * ISO-8601 only — a value that is not a timestamp is refused, not
      quietly replaced by "now";
    * an explicit UTC offset is REQUIRED. A naive value silently
      reinterpreted as UTC would let a caller shift the freshness window
      by a whole timezone just by omitting the offset.

    The legacy ``/verify`` adapter deliberately tolerates naive values for
    wire compatibility with clients that predate the rule. This surface is
    new, so it does not inherit that tolerance.
    """
    if timestamp is None:
        return None
    if isinstance(timestamp, datetime):
        parsed = timestamp
    elif isinstance(timestamp, str):
        try:
            parsed = datetime.fromisoformat(timestamp.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuthorityTimestampError(
                f"timestamp {timestamp!r} is not an ISO-8601 instant"
            ) from exc
    else:
        raise AuthorityTimestampError(
            "timestamp must be an ISO-8601 string, got "
            f"{type(timestamp).__name__}"
        )
    if parsed.tzinfo is None:
        raise AuthorityTimestampError(
            "timestamp must carry an explicit UTC offset; a naive instant is "
            "ambiguous and cannot be checked for freshness"
        )
    return parsed.astimezone(UTC)


class AuthorityUnresolvable(Exception):
    """A presented delegated-authority claim could not be resolved.

    Carries the typed decision reason so the caller BLOCKs with a truthful
    explanation rather than converting an unresolvable claim into the
    absence of one. Raised, not returned, because every call site must
    make a decision about it — a value could be dropped on the floor.
    """

    def __init__(self, reason: DecisionReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


#: How long an issued grant may live unless something tighter applies.
DEFAULT_GRANT_TTL: Final[timedelta] = timedelta(minutes=5)


class AuthorityServiceError(RuntimeError):
    """The service could not reach a decision. Never an implicit allow."""


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Typed internal result of one evaluation."""

    decision: Decision
    reasons: tuple[DecisionReason, ...] = ()
    grant_id: UUID | None = None
    authority_token: str | None = None
    expires_at: datetime | None = None
    execution_action_hash: str | None = None
    policy_snapshot_digest: str | None = None
    policy_snapshot_format: str | None = None
    policy_revision: str | None = None
    issue_outcome: IssueOutcome | None = None
    detail: str | None = None
    #: Material the durable decision record needs, set by whichever branch
    #: knows it. Absent on paths that refused before the fact was reached.
    domain: str | None = None
    executor_binding_digest: str | None = None
    executor_reference: str | None = None
    consequence_class: str | None = None
    authority_scope_digest: str | None = None
    #: Durable identity of this decision in ``audit_logs``. Present for
    #: BLOCK as well as ALLOW -- a refusal is as provable as a permission.
    decision_audit_id: UUID | None = None
    decision_recorded_at: datetime | None = None

    @property
    def authorises_execution(self) -> bool:
        """Only an ALLOW that actually produced usable authority."""
        return self.decision is Decision.ALLOW and self.authority_token is not None


class StaticAuthorityRequirementResolver:
    """Trusted configuration answer, defaulting to today's behaviour.

    An organisation not explicitly enrolled gets ``required=False``, which
    is exactly how Core behaves now. Enrolment is a deliberate act, so
    nothing changes for existing organisations until someone changes it.

    A resolver that cannot answer must return ``required=True``; this one
    always can, because absence from the enrolled set *is* the answer.
    """

    def __init__(self, required_organisations: frozenset[str] = frozenset()) -> None:
        self._required = frozenset(str(o) for o in required_organisations)

    def requirement(
        self, organisation_id: str, principal_id: str, action_class: str
    ) -> AuthorityRequirement:
        from api.core.authority.authority import trusted_authority_construction

        return AuthorityRequirement(
            trusted_authority_construction(),
            organisation_id=str(organisation_id),
            principal_id=str(principal_id),
            action_class=action_class,
            required=str(organisation_id) in self._required,
            source="static-organisation-enrolment",
        )


#: Environment variable naming the organisations that REQUIRE delegated
#: authority, comma-separated. Absent means no organisation is enrolled,
#: which is exactly today's behaviour.
AUTHORITY_REQUIRED_ORGS_ENV: Final[str] = "INNTRIS_AUTHORITY_REQUIRED_ORGS"


def default_requirement_resolver() -> StaticAuthorityRequirementResolver:
    """The single resolver both HTTP surfaces consult.

    Built fresh from the environment on each call so a deployment can
    enrol an organisation without a code change, and so tests can enrol
    one without leaking that state into other tests.
    """
    raw = os.getenv(AUTHORITY_REQUIRED_ORGS_ENV, "")
    enrolled = frozenset(part.strip() for part in raw.split(",") if part.strip())
    return StaticAuthorityRequirementResolver(enrolled)


def legacy_authority_gate(
    *,
    organisation_id: Any,
    principal_id: Any,
    action_type: str,
    has_verified_authority: bool = False,
) -> DecisionReason | None:
    """The requirement gate, for a caller that cannot carry authority.

    ``/verify`` has no field in which to present delegated authority, so
    for an enrolled organisation the answer is always "required and
    absent". Returning a reason here is what stops the legacy route
    quietly issuing a token that bypasses a rule the organisation
    deliberately turned on.

    ``None`` means the organisation is not enrolled and behaviour is
    unchanged -- which is every organisation until someone enrols one.
    """
    requirement = default_requirement_resolver().requirement(
        str(organisation_id), str(principal_id), action_type
    )
    if requirement.required and not has_verified_authority:
        return DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING
    return None


class AuthorityEvaluationService:
    """Builds the envelope, evaluates policy, issues bounded authority."""

    def __init__(
        self,
        database: Database,
        *,
        server_secret: bytes | list[bytes] | tuple[bytes, ...],
        requirement_resolver: Any | None = None,
        authority_provider: Any | None = None,
        payee_binding_resolver: Any | None = None,
        store: AuthorityStore | None = None,
    ) -> None:
        self._db = database
        # First entry signs; every entry verifies. See the note on the
        # consumption service for why this preserves secret rotation.
        self._server_secret = (
            [server_secret] if isinstance(server_secret, (bytes, bytearray)) else list(server_secret)
        )
        self._requirements = requirement_resolver or default_requirement_resolver()
        self._authority_provider = authority_provider
        # Binds an approved payee identity to the destination an executor
        # will actually pay. A delegated payee identity is not proof that a
        # particular account belongs to that payee, so the payment domain
        # refuses a payee-restricted scope it cannot bind — and without this
        # it could never be given the means to bind one.
        self._payee_binding_resolver = payee_binding_resolver
        self._store = store or AuthorityStore(database)

    # -- the requirement gate, usable on its own by the legacy path -------

    def requirement_for(
        self, *, organisation_id: Any, principal_id: Any, action_type: str
    ) -> AuthorityRequirement:
        """Ask trusted configuration whether delegated authority is required."""
        return self._requirements.requirement(
            str(organisation_id), str(principal_id), action_type
        )

    def resolve_authority(
        self,
        claim: DelegatedAuthorityClaim | None,
        *,
        agent: Any,
    ) -> ResolvedAuthority | None:
        """Resolve an external claim through the configured provider.

        ``None`` means only "no claim was presented", which is a fact
        rather than an error. A claim that cannot be resolved is NOT
        reported as absence — see :meth:`_resolve_presented_authority`,
        which is what the decision path calls.
        """
        if claim is None:
            return None
        if self._authority_provider is None:
            raise AuthorityUnresolvable(
                DecisionReason.AUTHORITY_PROVIDER_UNAVAILABLE,
                "delegated authority was presented but no provider is "
                "configured to resolve it",
            )
        from api.core.authority.authority import trusted_authority_construction

        context = self._build_context(agent, trusted_authority_construction())
        try:
            resolved = self._authority_provider.resolve(claim, context)
        except AuthorityUnresolvable:
            raise
        except Exception as exc:
            # A provider that throws has told us nothing. Treating that as
            # "no delegation" would hand the caller the non-delegated path
            # they did not ask for.
            logger.warning(
                "delegated authority provider failed for issuer %r: %s",
                claim.issuer,
                exc,
            )
            raise AuthorityUnresolvable(
                DecisionReason.AUTHORITY_PROVIDER_UNAVAILABLE,
                "the delegated authority provider could not resolve this claim",
            ) from exc

        if resolved is None:
            raise AuthorityUnresolvable(
                DecisionReason.AUTHORITY_VERIFICATION_FAILED,
                "the delegated authority provider returned no resolution",
            )
        if not resolved.is_verified:
            raise AuthorityUnresolvable(
                DecisionReason.AUTHORITY_VERIFICATION_FAILED,
                "the presented delegated authority did not verify",
            )
        return resolved

    @staticmethod
    def _build_context(agent: Any, construction: Any) -> Any:
        from api.core.authority.authority import ExecutionContext

        return ExecutionContext(
            construction,
            organisation_id=str(agent.org_id),
            principal_id=str(agent.id),
            principal_binding=_principal_binding_for(agent),
        )

    # -- the whole evaluation --------------------------------------------

    async def evaluate(
        self,
        *,
        agent: Any,
        action_type: str,
        payload: dict[str, Any],
        executor: AuthenticatedExecutorContext,
        issuance_ref: str,
        verified_signed_action_hash: str | None = None,
        nonce: str | None = None,
        timestamp: Any = None,
        minute_request_count: int = 0,
        registered_policy: Any = None,
        client_policy_hash: str | None = None,
        authority_claim: DelegatedAuthorityClaim | None = None,
        consequence_class: ConsequenceClass | None = None,
        daily_spend: Decimal = Decimal("0"),
        registered_policy_hash: str | None = None,
        at: datetime | None = None,
    ) -> EvaluationResult:
        """Decide, then record the decision durably — ALLOW or BLOCK.

        The decision itself is :meth:`_decide`. This wrapper exists so the
        durable record cannot be attached on some return paths and
        forgotten on others: every outcome leaves through here.
        """
        result = await self._decide(
            agent=agent,
            action_type=action_type,
            payload=payload,
            executor=executor,
            issuance_ref=issuance_ref,
            verified_signed_action_hash=verified_signed_action_hash,
            nonce=nonce,
            timestamp=timestamp,
            minute_request_count=minute_request_count,
            registered_policy=registered_policy,
            client_policy_hash=client_policy_hash,
            authority_claim=authority_claim,
            consequence_class=consequence_class,
            daily_spend=daily_spend,
            registered_policy_hash=registered_policy_hash,
            at=at,
        )
        return await self._record_decision(
            result,
            agent=agent,
            action_type=action_type,
            # Passed straight from the trusted call, never from a request
            # body: only an internal caller that already verified the
            # agent's signature may supply one.
            verified_signed_action_hash=verified_signed_action_hash,
        )

    async def _record_decision(
        self,
        result: EvaluationResult,
        *,
        agent: Any,
        action_type: str,
        verified_signed_action_hash: str | None = None,
    ) -> EvaluationResult:
        """Append the durable decision row and stamp its identity on the result.

        Skipped only when there is no act to record: a caller whose
        organisation does not own the principal, or whose timestamp could
        not be parsed, was refused BEFORE any act existed, so there is no
        ``execution_action_hash`` and inventing one would be a lie. Those
        refusals are input validation, not a decision about an act.
        """
        if result.execution_action_hash is None:
            return result

        audit_id, recorded_at = await record_authority_decision(
            self._db,
            agent_id=agent.id,
            organisation_id=agent.org_id,
            trust_score=int(getattr(agent, "trust_score", 0) or 0),
            execution_action_hash=result.execution_action_hash,
            policy_snapshot_digest=result.policy_snapshot_digest,
            allowed=result.decision is Decision.ALLOW,
            sandbox=principal_is_sandbox(agent),
            verdict_reason=(
                result.detail
                or (
                    "Execution authority granted"
                    if result.decision is Decision.ALLOW
                    else "Execution authority refused"
                )
            ),
            payload=build_decision_payload(
                organisation_id=agent.org_id,
                action_type=action_type,
                domain=result.domain,
                decision=result.decision.value,
                reasons=tuple(reason.value for reason in result.reasons),
                execution_action_hash=result.execution_action_hash,
                policy_snapshot_format=result.policy_snapshot_format,
                policy_snapshot_digest=result.policy_snapshot_digest,
                policy_revision=result.policy_revision,
                executor_binding_digest=result.executor_binding_digest or "",
                executor_reference=result.executor_reference,
                consequence_class=result.consequence_class,
                authority_scope_digest=result.authority_scope_digest,
                grant_id=result.grant_id,
                grant_expires_at=result.expires_at,
                detail=result.detail,
                signed_action_hash=verified_signed_action_hash,
            ),
        )
        return replace(
            result, decision_audit_id=audit_id, decision_recorded_at=recorded_at
        )

    async def _decide(
        self,
        *,
        agent: Any,
        action_type: str,
        payload: dict[str, Any],
        executor: AuthenticatedExecutorContext,
        issuance_ref: str,
        verified_signed_action_hash: str | None = None,
        nonce: str | None = None,
        timestamp: Any = None,
        minute_request_count: int = 0,
        registered_policy: Any = None,
        client_policy_hash: str | None = None,
        authority_claim: DelegatedAuthorityClaim | None = None,
        consequence_class: ConsequenceClass | None = None,
        daily_spend: Decimal = Decimal("0"),
        registered_policy_hash: str | None = None,
        at: datetime | None = None,
    ) -> EvaluationResult:
        """Decide, and on ALLOW issue bounded authority bound to this executor.

        ``verified_signed_action_hash`` may only be supplied by a caller
        that has ALREADY verified the corresponding agent Ed25519
        signature through the existing request-verification path. The
        service-authenticated HTTP endpoint does not accept one from the
        request body, because a hash a caller typed is not a hash an agent
        signed, and publishing it as ``signed_action_hash`` would give the
        field two meanings.
        """
        now = (at or datetime.now(UTC)).astimezone(UTC)

        if not executor.owns_organisation(agent.org_id):
            # The authenticated caller is not in the principal's organisation.
            return EvaluationResult(
                decision=Decision.BLOCK,
                reasons=(DecisionReason.AUTHORITY_PRINCIPAL_MISMATCH,),
                detail="authenticated organisation does not own this principal",
            )

        # --- The caller's timestamp is a security input, not a label -------
        # It reaches Core's freshness check as the decision instant. A
        # timestamp accepted on the wire but excluded from that check would
        # be a field with no meaning, which is worse than no field.
        try:
            occurred_at = authority_decision_instant(timestamp)
        except AuthorityTimestampError as exc:
            return EvaluationResult(
                decision=Decision.BLOCK,
                reasons=(DecisionReason.TIMESTAMP_INVALID,),
                detail=str(exc),
            )
        #: Server time governs only when the caller asserted no instant.
        decision_instant = occurred_at or now

        envelope = build_action_envelope(
            agent=agent,
            action_type=action_type,
            payload=payload,
            signed_action_hash=verified_signed_action_hash,
            nonce=nonce,
            timestamp=occurred_at,
            delegated_authority_reference=authority_claim,
            consequence_class=consequence_class,
        )

        # The policy this decision is made under, captured as soon as there
        # is an act to attach it to. Every refusal below carries it, not only
        # the ones that reach the domain policy: a BLOCK whose durable record
        # cannot name the policy that refused it is a decision nobody can
        # audit afterwards.
        snapshot = (
            build_payment_authority_policy_snapshot(
                agent,
                action_type,
                trust_threshold=PolicyEngine.TRUST_THRESHOLDS.get(action_type),
                registered_policy_hash=registered_policy_hash,
                captured_at=now,
            )
            if action_type in PAYMENT_ACTION_TYPES
            else None
        )
        #: Spread onto every refusal below. Empty for an action type the
        #: payment domain does not govern, where no payment policy snapshot
        #: exists and inventing one would be a fabrication.
        snapshot_fields: dict[str, Any] = (
            {
                "policy_snapshot_digest": snapshot.digest,
                "policy_snapshot_format": snapshot.preimage["format"],
                "policy_revision": snapshot.revision,
            }
            if snapshot is not None
            else {}
        )

        # --- Is delegated authority required here? Trusted config decides. ---
        requirement = self.requirement_for(
            organisation_id=agent.org_id, principal_id=agent.id, action_type=action_type
        )

        # --- A presented delegation is never silently discarded -------------
        # The contract has two shapes, and only two:
        #
        #   no delegation presented -> the organisation's existing path
        #   delegation presented    -> organisation policy AND delegated scope
        #
        # There is no third shape where a caller presents authority and the
        # server decides to ignore it. Falling back to the non-delegated path
        # would grant MORE than the caller asked to be bound by, which is the
        # one direction a fallback must never go.
        try:
            resolved = self.resolve_authority(authority_claim, agent=agent)
        except AuthorityUnresolvable as unresolvable:
            return EvaluationResult(
                decision=Decision.BLOCK,
                reasons=(unresolvable.reason,),
                execution_action_hash=envelope.execution_action_hash,
                detail=unresolvable.detail,
                domain=envelope.domain,
                executor_binding_digest=executor.binding_digest,
                executor_reference=executor.executor_reference,
                **snapshot_fields,
            )

        if requirement.required and resolved is None:
            # Fail closed. No grant, no token, and the legacy path calls this
            # same gate so it cannot silently take the non-delegated route.
            return EvaluationResult(
                decision=Decision.BLOCK,
                reasons=(DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING,),
                execution_action_hash=envelope.execution_action_hash,
                domain=envelope.domain,
                executor_binding_digest=executor.binding_digest,
                executor_reference=executor.executor_reference,
                **snapshot_fields,
            )

        # --- Shared Core organisation policy. This is the SAME evaluation
        # /verify runs: agent status, allowed/blocked actions, action-type
        # registration, policy binding, trust thresholds, timestamp validity,
        # rate limits and spend. The domain policy runs after it, never
        # instead of it, so this endpoint cannot be the weaker path.
        core = evaluate_core_policy(
            CorePolicyInputs(
                agent=agent,
                action_type=action_type,
                payload=payload,
                timestamp=decision_instant,
                daily_spend=daily_spend,
                minute_request_count=minute_request_count,
                registered_policy=registered_policy,
                client_policy_hash=client_policy_hash,
            )
        )
        if not core.allowed:
            reason = core_violation_to_reason(core)
            return EvaluationResult(
                decision=Decision.BLOCK,
                reasons=(reason,) if reason else (),
                execution_action_hash=envelope.execution_action_hash,
                detail=core.reason,
                domain=envelope.domain,
                executor_binding_digest=executor.binding_digest,
                executor_reference=executor.executor_reference,
                **snapshot_fields,
            )

        # --- Domain policy. Organisation policy decides; scope only narrows. ---
        if action_type not in PAYMENT_ACTION_TYPES:
            return EvaluationResult(
                decision=Decision.BLOCK,
                reasons=(DecisionReason.ACTION_TYPE_UNKNOWN,),
                detail=f"no domain policy governs {action_type!r}",
                execution_action_hash=envelope.execution_action_hash,
                domain=envelope.domain,
                executor_binding_digest=executor.binding_digest,
                executor_reference=executor.executor_reference,
                **snapshot_fields,
            )

        domain_policy = PaymentDomainPolicy(
            agent=agent,
            daily_spend=daily_spend,
            trust_threshold=PolicyEngine.TRUST_THRESHOLDS.get(action_type),
            registered_policy_hash=registered_policy_hash,
            authority_requirement_resolver=self._requirements,
            payee_binding_resolver=self._payee_binding_resolver,
            consequence_class=consequence_class,
        )
        # Deliberately SERVER time, not the caller's instant: the question
        # here is whether the delegation is valid at the moment authority is
        # issued. Core has already refused any caller instant outside the
        # clock-skew window, so the two can differ only within it.
        decision = domain_policy.evaluate(envelope, resolved, at=now)

        # Captured above, before the first refusal could return, so the digest
        # a BLOCK records and the digest a grant is issued under are one value
        # rather than two derivations that could drift. The action type was
        # established as a payment one before this point; the guard refuses
        # rather than trusting that to stay true.
        if snapshot is None:  # pragma: no cover - unreachable via the checks above
            raise AuthorityServiceError(
                "no payment policy snapshot was captured for an action the "
                "payment domain governs"
            )

        if decision.decision is not Decision.ALLOW:
            # REQUIRE_APPROVAL yields no grant either: the core contract is
            # explicit that it produces no executable authority.
            return EvaluationResult(
                decision=decision.decision,
                reasons=decision.reasons,
                execution_action_hash=envelope.execution_action_hash,
                policy_snapshot_digest=snapshot.digest,
                policy_snapshot_format=snapshot.preimage["format"],
                policy_revision=snapshot.revision,
                domain=envelope.domain,
                executor_binding_digest=executor.binding_digest,
                executor_reference=executor.executor_reference,
                consequence_class=(
                    consequence_class.value if consequence_class else None
                ),
                authority_scope_digest=_scope_digest_for(resolved),
            )

        scope_digest = _scope_digest_for(resolved)

        issued = await self._issue(
            agent=agent,
            envelope=envelope,
            executor=executor,
            issuance_ref=issuance_ref,
            snapshot=snapshot,
            signed_action_hash=verified_signed_action_hash,
            consequence_class=consequence_class,
            authority_scope_digest=scope_digest,
            authority_expires_at=(
                resolved.not_after if resolved is not None else None
            ),
            now=now,
        )
        if not issued.authorises_execution:
            return EvaluationResult(
                decision=Decision.BLOCK,
                reasons=(issued.reason,) if issued.reason else (),
                execution_action_hash=envelope.execution_action_hash,
                policy_snapshot_digest=snapshot.digest,
                policy_snapshot_format=snapshot.preimage["format"],
                policy_revision=snapshot.revision,
                issue_outcome=issued.outcome,
                detail=issued.detail,
                domain=envelope.domain,
                executor_binding_digest=executor.binding_digest,
                executor_reference=executor.executor_reference,
                consequence_class=(
                    consequence_class.value if consequence_class else None
                ),
                authority_scope_digest=scope_digest,
            )

        grant = await self._store.get(issued.grant_id)
        token = self.mint_authority_token(
            grant_id=issued.grant_id,
            execution_action_hash=envelope.execution_action_hash,
            agent_id=agent.id,
            approval_token_id=issued.approval_token_id,
            expires_at=grant["expires_at"],
            sandbox=principal_is_sandbox(agent),
        )
        return EvaluationResult(
            decision=Decision.ALLOW,
            grant_id=issued.grant_id,
            authority_token=token,
            expires_at=grant["expires_at"],
            execution_action_hash=envelope.execution_action_hash,
            policy_snapshot_digest=snapshot.digest,
            policy_snapshot_format=snapshot.preimage["format"],
            policy_revision=snapshot.revision,
            issue_outcome=issued.outcome,
            domain=envelope.domain,
            executor_binding_digest=executor.binding_digest,
            executor_reference=executor.executor_reference,
            consequence_class=(
                consequence_class.value if consequence_class else None
            ),
            authority_scope_digest=scope_digest,
        )

    async def _issue(
        self,
        *,
        agent: Any,
        envelope: Any,
        executor: AuthenticatedExecutorContext,
        issuance_ref: str,
        snapshot: Any,
        signed_action_hash: str | None,
        consequence_class: ConsequenceClass | None,
        authority_scope_digest: str | None,
        authority_expires_at: datetime | None,
        now: datetime,
    ) -> IssueResult:
        from api.domains.payment.amounts import extract_amount

        amount = extract_amount(dict(envelope.action.payload)) or Decimal("0")
        return await self._store.issue(
            agent_id=agent.id,
            organisation_id=agent.org_id,
            issuance_ref=issuance_ref,
            execution_action_hash=envelope.execution_action_hash,
            signed_action_hash=signed_action_hash,
            policy_hash=snapshot.digest,
            policy_snapshot_format=snapshot.preimage["format"],
            policy_revision=snapshot.revision,
            # The binding comes from the authenticated credential, never
            # from anything the request body said about itself.
            executor_binding_digest=executor.binding_digest,
            executor_reference=executor.executor_reference,
            domain=envelope.domain,
            action_type=envelope.action_type,
            consequence_class=consequence_class.value if consequence_class else None,
            authority_scope_digest=authority_scope_digest,
            authority_expires_at=authority_expires_at,
            issued_at=now,
            minute_start=now.replace(second=0, microsecond=0),
            day_start=now.replace(hour=0, minute=0, second=0, microsecond=0),
            amount_usd=amount,
        )

    # -- the bearer token, over the existing primitive --------------------

    def mint_authority_token(
        self,
        *,
        grant_id: UUID,
        execution_action_hash: str,
        agent_id: UUID,
        approval_token_id: str | None,
        expires_at: datetime,
        sandbox: bool = False,
    ) -> str:
        """An unforgeable token bound to grant, act and expiry.

        Produced by the existing approval-token primitive — the same HMAC
        over a claim set, verified with the same server secret — rather
        than a second bearer scheme with its own failure modes. The extra
        claims name what this token authorises.
        """
        return CryptoService.generate_approval_token(
            agent_id=str(agent_id),
            action_hash=execution_action_hash,
            verdict="approved",
            server_secret=self._server_secret[0],
            token_id=approval_token_id,
            expires_at=expires_at,
            # Signed into the token, so it travels with the authority and
            # cannot be edited off it later. Promoting the agent afterwards
            # does not launder test authority into production authority:
            # the claim was signed when the authority was minted.
            sandbox=sandbox,
            extra_claims={
                "token_version": AUTHORITY_TOKEN_VERSION,
                "grant_id": str(grant_id),
                "execution_action_hash": execution_action_hash,
            },
        )

    def read_authority_token(self, token: str) -> dict[str, Any] | None:
        """Decode and verify a token. ``None`` means do not proceed."""
        claims = CryptoService.verify_approval_token(token, self._server_secret)
        if not claims or claims.get("token_version") != AUTHORITY_TOKEN_VERSION:
            return None
        return claims


class AuthorityConsumptionService:
    """The one path that spends authority, for both HTTP surfaces."""

    def __init__(
        self,
        database: Database,
        *,
        server_secret: bytes | list[bytes] | tuple[bytes, ...],
        store: AuthorityStore | None = None,
    ) -> None:
        self._db = database
        # A list preserves the existing zero-downtime rotation property:
        # new tokens are signed with the current secret, and verification
        # accepts the previous one while it is still configured. Removing
        # the previous secret makes old tokens fail normally.
        self._server_secret = (
            [server_secret] if isinstance(server_secret, (bytes, bytearray)) else list(server_secret)
        )
        self._store = store or AuthorityStore(database)

    async def consume(
        self,
        *,
        authority_token: str,
        executor: AuthenticatedExecutorContext,
        agent: Any,
        action_type: str,
        payload: dict[str, Any],
        execution_ref: str,
        authority_evidence: ResolvedAuthorityEvidence | None = None,
        at: datetime | None = None,
    ) -> ConsumeResult:
        """Spend authority once, for the exact act, by the bound executor.

        The act's hash is recomputed here from the presented action, never
        taken from the request. Possession of a grant id is not authority:
        the caller must present the unforgeable token AND authenticate as
        the executor the grant was bound to.
        """
        executor.require_consume()

        # Authenticity and expiry are separate questions. A forged token is
        # refused outright. An AUTHENTIC but expired token may still recover
        # an already committed consumption -- that is reading history, not
        # authorising execution -- so expiry downgrades the request to
        # recovery-only rather than rejecting it here.
        claims, expired = CryptoService.authenticate_approval_token(
            authority_token, self._server_secret
        )
        if not claims or claims.get("token_version") != AUTHORITY_TOKEN_VERSION:
            return ConsumeResult(
                outcome=ConsumptionOutcome.REJECTED,
                rejection_reason=DecisionReason.GRANT_NOT_FOUND,
            )

        # --- Sandbox authority never authorises a production execution -----
        # Checked in BOTH directions and before any state is touched:
        #
        #   the signed claim  -- authority minted for a sandbox principal
        #                        stays sandbox even after promotion, because
        #                        the claim was signed at issuance;
        #   the current agent -- a principal sandboxed since issuance cannot
        #                        spend authority minted while it was live.
        #
        # This mirrors the legacy route's refusal rather than inventing a
        # second, weaker rule for the same question.
        if claims.get("sandbox") or principal_is_sandbox(agent):
            return ConsumeResult(
                outcome=ConsumptionOutcome.REJECTED,
                rejection_reason=DecisionReason.GRANT_SANDBOX_EXECUTION_DENIED,
            )

        try:
            grant_id = UUID(str(claims.get("grant_id")))
        except (TypeError, ValueError):
            return ConsumeResult(
                outcome=ConsumptionOutcome.REJECTED,
                rejection_reason=DecisionReason.GRANT_MALFORMED,
            )

        # Recompute the act server-side from what was actually presented.
        envelope = build_action_envelope(
            agent=agent,
            action_type=action_type,
            payload=payload,
        )
        if claims.get("execution_action_hash") != envelope.execution_action_hash:
            # The token authorises a different act than the one presented.
            return ConsumeResult(
                outcome=ConsumptionOutcome.REJECTED,
                grant_id=grant_id,
                rejection_reason=DecisionReason.GRANT_ACTION_MISMATCH,
            )

        return await self._store.consume(
            grant_id=grant_id,
            execution_action_hash=envelope.execution_action_hash,
            executor_binding_digest=executor.binding_digest,
            execution_ref=execution_ref,
            authority_evidence=authority_evidence,
            recovery_only=expired,
            at=at,
        )

    async def grant_for(self, grant_id: UUID) -> Any:
        return await self._store.get(grant_id)

    @staticmethod
    def executor_matches(executor: AuthenticatedExecutorContext, grant: Any) -> bool:
        return binding_matches(executor, grant["executor_binding_digest"])


class LegacyTokenDowngradeError(PermissionError):
    """A v0.5 executor-bound authority token was presented to a legacy route.

    The legacy route authenticates the *agent*, not the executor, so it
    cannot establish the identity a v0.5 grant is bound to. Allowing the
    downgrade would let anyone holding the token spend authority that was
    issued to one specific authenticated executor.
    """


def is_executor_bound_authority_token(claims: dict[str, Any] | None) -> bool:
    """Whether these claims belong to the v0.5 executor-bound surface."""
    return bool(claims) and claims.get("token_version") == AUTHORITY_TOKEN_VERSION


async def consume_legacy_approval_token(
    database: Database,
    audit_entry: Any,
    *,
    token_id: str,
    token_digest: bytes,
    approved_action_hash: str,
    execution_ref: str | None,
    token_claims: dict[str, Any] | None = None,
) -> Any:
    """The single consumption primitive, entered from the legacy route.

    Both routes end at ``approval_token_consumptions`` -- there is no
    second consumption state that could disagree about whether authority
    was spent. This wrapper exists so that fact is enforced in one place
    rather than by two call sites that happen to agree today, and so the
    downgrade guard below cannot be forgotten by one of them.

    Legacy wire behaviour is unchanged: the same insert, the same
    ``execution_ref`` retry semantics, the same return shape.
    """
    if is_executor_bound_authority_token(token_claims):
        raise LegacyTokenDowngradeError(
            "this authority token is bound to an authenticated executor and "
            "must be consumed through POST /authority/consume"
        )
    return await database.insert_token_consumption(
        audit_entry,
        token_id=token_id,
        token_digest=token_digest,
        approved_action_hash=approved_action_hash,
        execution_ref=execution_ref,
    )
