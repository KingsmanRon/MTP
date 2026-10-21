"""Phase 1 — the core authority boundary's types, ports and contracts.

These pin the security contracts the rest of the phases build on:

* trusted authority objects cannot be built from caller-supplied data;
* the grant state model has exactly the transitions v0.5 defines, and
  rejection has a single deterministic precedence;
* recovery of a committed consumption is not authorisation;
* the decision vocabulary stays compatible with the deployed one;
* the boundary stays vendor-neutral.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import api.core.authority as core_authority
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
from api.core.authority.envelope import ActionEnvelope, ExecutableAction, ResourceReference
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
from api.policy import PolicyViolation

CORE_PACKAGE_ROOT = Path(core_authority.__file__).parent

ISSUED_AT = datetime(2026, 4, 17, 12, 0, 0, tzinfo=UTC)
EXPIRES_AT = ISSUED_AT + timedelta(minutes=5)
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def trusted() -> TrustedAuthorityConstruction:
    return trusted_authority_construction()


def verified_reference() -> DelegatedAuthorityReference:
    return DelegatedAuthorityReference(
        trusted(),
        issuer="external-issuer",
        external_reference_id="ref-1",
        artefact_digest=DIGEST_A,
        verification_status=VerificationStatus.VERIFIED,
        verified_at=ISSUED_AT,
    )


def snapshot() -> PolicySnapshot:
    return PolicySnapshot(policy_hash=DIGEST_B, captured_at=ISSUED_AT)


def action() -> ExecutableAction:
    return ExecutableAction(
        principal_id="agent-1",
        organisation_id="org-1",
        domain="payments",
        action_type="financial_transaction",
        payload={"amount": "10.00"},
        target=ResourceReference(resource_type="account", resource_id="acct_123"),
    )


def grant(**overrides: object) -> ExecutionAuthorityGrant:
    kwargs: dict = {
        "grant_id": "grant-1",
        "execution_action_hash": action().execution_action_hash,
        "policy_snapshot": snapshot(),
        "executor_binding": ExecutorBinding(DIGEST_C, "settlement-worker"),
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
    }
    kwargs.update(overrides)
    return ExecutionAuthorityGrant(**kwargs)  # type: ignore[arg-type]


class TestTrustedConstruction:
    """A client must never be able to assert its own authority."""

    def test_the_capability_cannot_be_constructed_directly(self) -> None:
        with pytest.raises(InvalidAuthorityConstructionError):
            TrustedAuthorityConstruction()

    def test_the_capability_cannot_be_forged_from_data(self) -> None:
        for forged in ("trusted", True, 1, {"trusted": True}, object()):
            with pytest.raises(InvalidAuthorityConstructionError):
                TrustedAuthorityConstruction(forged)

    @pytest.mark.parametrize(
        "factory",
        [
            lambda: DelegatedAuthorityReference(
                None,
                issuer="i",
                external_reference_id="r",
                artefact_digest=DIGEST_A,
                verification_status=VerificationStatus.VERIFIED,
                verified_at=ISSUED_AT,
            ),
            lambda: ResolvedAuthority(None, reference=verified_reference()),
            lambda: ExecutionContext(None, organisation_id="org-1", principal_id="agent-1"),
            lambda: AuthorityRequirement(
                None,
                organisation_id="org-1",
                principal_id="agent-1",
                action_class="financial_transaction",
            ),
        ],
    )
    def test_trusted_outputs_require_the_capability(self, factory) -> None:
        with pytest.raises(InvalidAuthorityConstructionError):
            factory()

    def test_an_unverified_reference_still_requires_the_capability(self) -> None:
        """Even the default status is a provider statement, not a client one."""
        with pytest.raises(InvalidAuthorityConstructionError):
            DelegatedAuthorityReference(
                None, issuer="i", external_reference_id="r", artefact_digest=DIGEST_A
            )

    def test_a_client_shaped_mapping_cannot_be_splatted_into_a_reference(self) -> None:
        client_supplied = {
            "issuer": "external-issuer",
            "external_reference_id": "ref-1",
            "artefact_digest": DIGEST_A,
            "verification_status": VerificationStatus.VERIFIED,
            "verified_at": ISSUED_AT,
        }
        with pytest.raises(TypeError):
            DelegatedAuthorityReference(**client_supplied)  # type: ignore[call-arg]

    def test_the_trusted_path_produces_a_verified_reference(self) -> None:
        reference = verified_reference()
        assert reference.is_verified
        assert reference.verification_status is VerificationStatus.VERIFIED

    def test_a_verified_reference_must_record_when_it_was_verified(self) -> None:
        with pytest.raises(InvalidAuthorityConstructionError, match="verified_at"):
            DelegatedAuthorityReference(
                trusted(),
                issuer="i",
                external_reference_id="r",
                artefact_digest=DIGEST_A,
                verification_status=VerificationStatus.VERIFIED,
            )

    def test_a_claim_is_untrusted_and_needs_no_capability(self) -> None:
        claim = DelegatedAuthorityClaim(issuer="external-issuer", external_reference_id="ref-1")
        assert not isinstance(claim, DelegatedAuthorityReference)
        assert not hasattr(claim, "verification_status")

    def test_a_claim_cannot_carry_a_verification_status(self) -> None:
        with pytest.raises(TypeError):
            DelegatedAuthorityClaim(  # type: ignore[call-arg]
                issuer="i", external_reference_id="r", verification_status="verified"
            )


class TestResolvedAuthority:
    def test_a_failed_resolution_is_data_not_an_exception(self) -> None:
        reference = DelegatedAuthorityReference(
            trusted(),
            issuer="external-issuer",
            external_reference_id="ref-1",
            artefact_digest=DIGEST_A,
            verification_status=VerificationStatus.FAILED,
        )
        resolved = ResolvedAuthority(
            trusted(),
            reference=reference,
            issues=(
                AuthorityVerificationIssue(
                    AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID
                ),
            ),
        )
        assert not resolved.is_verified
        assert resolved.failure_codes == (
            AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID,
        )

    def test_an_unavailable_provider_is_never_verified(self) -> None:
        reference = DelegatedAuthorityReference(
            trusted(),
            issuer="external-issuer",
            external_reference_id="ref-1",
            artefact_digest=DIGEST_A,
            verification_status=VerificationStatus.UNAVAILABLE,
        )
        assert not ResolvedAuthority(trusted(), reference=reference).is_verified

    def test_a_verified_reference_cannot_carry_verification_issues(self) -> None:
        with pytest.raises(InvalidAuthorityConstructionError, match="cannot be resolved"):
            ResolvedAuthority(
                trusted(),
                reference=verified_reference(),
                issues=(
                    AuthorityVerificationIssue(
                        AuthorityVerificationFailure.AUTHORITY_EXPIRED
                    ),
                ),
            )

    def test_scope_is_opaque_and_frozen(self) -> None:
        resolved = ResolvedAuthority(
            trusted(), reference=verified_reference(), scope={"limit": "100", "nested": {"a": 1}}
        )
        assert resolved.scope["limit"] == "100"
        with pytest.raises(TypeError):
            resolved.scope["limit"] = "1000"  # type: ignore[index]

    def test_validity_bounds_are_honoured(self) -> None:
        resolved = ResolvedAuthority(
            trusted(),
            reference=verified_reference(),
            not_before=ISSUED_AT,
            not_after=ISSUED_AT + timedelta(hours=1),
        )
        assert not resolved.is_within_validity(ISSUED_AT - timedelta(seconds=1))
        assert resolved.is_within_validity(ISSUED_AT)
        assert not resolved.is_within_validity(ISSUED_AT + timedelta(hours=1))

    def test_an_empty_validity_window_is_rejected(self) -> None:
        with pytest.raises(InvalidAuthorityConstructionError, match="not_after"):
            ResolvedAuthority(
                trusted(),
                reference=verified_reference(),
                not_before=ISSUED_AT,
                not_after=ISSUED_AT,
            )

    def test_delegate_binding_defaults_to_unknown(self) -> None:
        resolved = ResolvedAuthority(trusted(), reference=verified_reference())
        assert resolved.delegate_binding_status is DelegateBindingStatus.UNKNOWN


class TestAuthorityRequirement:
    def test_it_defaults_to_required(self) -> None:
        """Not knowing is not permission."""
        requirement = AuthorityRequirement(
            trusted(),
            organisation_id="org-1",
            principal_id="agent-1",
            action_class="financial_transaction",
        )
        assert requirement.required is True

    def test_it_can_be_answered_negatively_by_trusted_configuration(self) -> None:
        requirement = AuthorityRequirement(
            trusted(),
            organisation_id="org-1",
            principal_id="agent-1",
            action_class="api_call",
            required=False,
            source="organisation-configuration",
        )
        assert requirement.required is False
        assert requirement.source == "organisation-configuration"

    def test_a_truthy_non_bool_is_rejected(self) -> None:
        with pytest.raises(InvalidAuthorityConstructionError, match="must be a bool"):
            AuthorityRequirement(
                trusted(),
                organisation_id="org-1",
                principal_id="agent-1",
                action_class="api_call",
                required="yes",  # type: ignore[arg-type]
            )


class TestExecutionContext:
    def test_principal_binding_is_frozen(self) -> None:
        context = ExecutionContext(
            trusted(),
            organisation_id="org-1",
            principal_id="agent-1",
            principal_binding={"external_reference": "sub-1"},
        )
        with pytest.raises(TypeError):
            context.principal_binding["external_reference"] = "sub-2"  # type: ignore[index]


class TestDecisionVocabulary:
    def test_every_existing_policy_violation_has_an_identical_reason(self) -> None:
        reason_values = {reason.value for reason in DecisionReason}
        missing = {
            violation.value
            for violation in PolicyViolation
            if violation.value not in reason_values
        }
        assert not missing, f"existing policy vocabulary not represented: {sorted(missing)}"

    def test_the_shared_codes_keep_their_member_names(self) -> None:
        for violation in PolicyViolation:
            assert DecisionReason[violation.name].value == violation.value

    def test_decision_has_exactly_the_three_verdicts(self) -> None:
        assert {member.value for member in Decision} == {
            "allow",
            "block",
            "require_approval",
        }

    def test_consequence_classes_are_c1_to_c4(self) -> None:
        assert [member.value for member in ConsequenceClass] == ["c1", "c2", "c3", "c4"]

    def test_new_reason_codes_are_authority_lifecycle_only(self) -> None:
        existing = {violation.value for violation in PolicyViolation}
        new_codes = {reason.value for reason in DecisionReason} - existing
        assert new_codes
        assert all(
            code.startswith(("authority_", "grant_", "execution_ref_", "approval_"))
            for code in new_codes
        ), sorted(new_codes)


class TestPolicyDecision:
    def test_only_allow_authorises_execution(self) -> None:
        allow = PolicyDecision(decision=Decision.ALLOW, policy_snapshot=snapshot())
        assert allow.authorises_execution

    def test_require_approval_never_authorises_execution(self) -> None:
        pending = PolicyDecision(
            decision=Decision.REQUIRE_APPROVAL,
            policy_snapshot=snapshot(),
            approval_requirement=ApprovalRequirement(
                consequence_class=ConsequenceClass.C4, approver_scope="organisation-admin"
            ),
        )
        assert not pending.authorises_execution

    def test_require_approval_must_say_what_it_is_waiting_for(self) -> None:
        with pytest.raises(CoreAuthorityError, match="ApprovalRequirement"):
            PolicyDecision(decision=Decision.REQUIRE_APPROVAL, policy_snapshot=snapshot())

    def test_an_approval_requirement_on_an_allow_is_rejected(self) -> None:
        with pytest.raises(CoreAuthorityError, match="only meaningful"):
            PolicyDecision(
                decision=Decision.ALLOW,
                policy_snapshot=snapshot(),
                approval_requirement=ApprovalRequirement(),
            )

    def test_a_block_must_carry_a_reason(self) -> None:
        with pytest.raises(CoreAuthorityError, match="at least one reason"):
            PolicyDecision(decision=Decision.BLOCK, policy_snapshot=snapshot())

    def test_a_block_carries_typed_reasons(self) -> None:
        blocked = PolicyDecision(
            decision=Decision.BLOCK,
            policy_snapshot=snapshot(),
            reasons=(DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING,),
        )
        assert blocked.reasons == (DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING,)

    def test_free_text_reasons_are_rejected(self) -> None:
        with pytest.raises(CoreAuthorityError, match="DecisionReason"):
            PolicyDecision(
                decision=Decision.BLOCK,
                policy_snapshot=snapshot(),
                reasons=("something went wrong",),  # type: ignore[arg-type]
            )

    def test_the_decision_records_the_policy_it_was_made_under(self) -> None:
        decided = PolicyDecision(decision=Decision.ALLOW, policy_snapshot=snapshot())
        assert decided.policy_snapshot.policy_hash == DIGEST_B
        assert decided.policy_snapshot.captured_at == ISSUED_AT

    def test_a_snapshot_needs_a_real_digest(self) -> None:
        with pytest.raises(CoreAuthorityError, match="policy_hash"):
            PolicySnapshot(policy_hash="v1", captured_at=ISSUED_AT)


class TestGrantStateModel:
    def test_the_terminal_states_are_the_three_defined_ones(self) -> None:
        terminal_statuses = TERMINAL_GRANT_STATUSES
        assert terminal_statuses == frozenset(
            (GrantStatus.CONSUMED, GrantStatus.REVOKED, GrantStatus.EXPIRED)
        )

    @pytest.mark.parametrize(
        "target", [GrantStatus.CONSUMED, GrantStatus.REVOKED, GrantStatus.EXPIRED]
    )
    def test_active_transitions_to_each_terminal_state(self, target: GrantStatus) -> None:
        assert is_allowed_transition(GrantStatus.ACTIVE, target)

    @pytest.mark.parametrize("terminal", sorted(TERMINAL_GRANT_STATUSES))
    def test_terminal_states_have_no_outgoing_transitions(
        self, terminal: GrantStatus
    ) -> None:
        assert ALLOWED_GRANT_TRANSITIONS[terminal] == frozenset()
        for target in GrantStatus:
            assert not is_allowed_transition(terminal, target)

    def test_a_grant_cannot_return_to_active(self) -> None:
        for terminal in TERMINAL_GRANT_STATUSES:
            assert not is_allowed_transition(terminal, GrantStatus.ACTIVE)

    def test_every_status_appears_in_the_transition_table(self) -> None:
        assert set(ALLOWED_GRANT_TRANSITIONS) == set(GrantStatus)

    def test_expiry_is_time_derived(self) -> None:
        active = grant()
        assert active.effective_status(ISSUED_AT) is GrantStatus.ACTIVE
        assert active.effective_status(EXPIRES_AT) is GrantStatus.EXPIRED
        assert not active.authorises_new_execution_at(EXPIRES_AT)

    def test_expiry_does_not_overwrite_a_terminal_record(self) -> None:
        consumed = grant(status=GrantStatus.CONSUMED)
        assert consumed.effective_status(EXPIRES_AT) is GrantStatus.CONSUMED
        revoked = grant(status=GrantStatus.REVOKED)
        assert revoked.effective_status(EXPIRES_AT) is GrantStatus.REVOKED

    @pytest.mark.parametrize("status", sorted(TERMINAL_GRANT_STATUSES))
    def test_no_terminal_grant_authorises_new_execution(self, status: GrantStatus) -> None:
        assert not grant(status=status).authorises_new_execution_at(ISSUED_AT)


class TestRejectionPrecedence:
    def test_the_precedence_covers_every_rejection_reason_once(self) -> None:
        assert len(set(CONSUMPTION_REJECTION_PRECEDENCE)) == len(
            CONSUMPTION_REJECTION_PRECEDENCE
        )

    def test_identity_and_integrity_outrank_lifecycle(self) -> None:
        order = list(CONSUMPTION_REJECTION_PRECEDENCE)
        assert order.index(DecisionReason.GRANT_ACTION_MISMATCH) < order.index(
            DecisionReason.GRANT_EXPIRED
        )
        assert order.index(DecisionReason.GRANT_EXECUTOR_MISMATCH) < order.index(
            DecisionReason.GRANT_ALREADY_CONSUMED
        )

    def test_revocation_outranks_expiry_which_outranks_consumption(self) -> None:
        order = list(CONSUMPTION_REJECTION_PRECEDENCE)
        assert (
            order.index(DecisionReason.GRANT_REVOKED)
            < order.index(DecisionReason.GRANT_EXPIRED)
            < order.index(DecisionReason.GRANT_ALREADY_CONSUMED)
        )

    def test_the_result_does_not_depend_on_the_order_checks_ran_in(self) -> None:
        candidates = [
            DecisionReason.GRANT_ALREADY_CONSUMED,
            DecisionReason.GRANT_EXPIRED,
            DecisionReason.GRANT_ACTION_MISMATCH,
        ]
        assert first_rejection(candidates) is DecisionReason.GRANT_ACTION_MISMATCH
        assert first_rejection(reversed(candidates)) is DecisionReason.GRANT_ACTION_MISMATCH

    def test_no_candidates_means_no_rejection(self) -> None:
        assert first_rejection([]) is None

    def test_a_reason_without_defined_precedence_is_rejected(self) -> None:
        with pytest.raises(InvalidGrantError, match="precedence"):
            first_rejection([DecisionReason.TRUST_SCORE_TOO_LOW])

    def test_a_bare_string_is_not_an_iterable_of_reasons(self) -> None:
        with pytest.raises(InvalidGrantError, match="iterable"):
            first_rejection("grant_expired")


class TestExecutionAuthorityGrant:
    def test_it_carries_the_execution_hash_and_the_signed_hash_separately(self) -> None:
        issued = grant(signed_action_hash=DIGEST_A)
        assert issued.execution_action_hash == action().execution_action_hash
        assert issued.signed_action_hash == DIGEST_A
        assert issued.execution_action_hash != issued.signed_action_hash

    def test_it_exposes_the_policy_hash_it_was_issued_under(self) -> None:
        assert grant().policy_hash == DIGEST_B

    def test_multi_use_is_not_defined_in_this_version(self) -> None:
        with pytest.raises(InvalidGrantError, match="single-use"):
            grant(single_use=False)

    def test_there_is_no_consumption_counter(self) -> None:
        assert not hasattr(grant(), "max_consumptions")

    def test_an_empty_validity_window_is_rejected(self) -> None:
        with pytest.raises(InvalidGrantError, match="strictly after"):
            grant(expires_at=ISSUED_AT)

    def test_a_malformed_execution_hash_is_rejected(self) -> None:
        with pytest.raises(InvalidGrantError, match="execution_action_hash"):
            grant(execution_action_hash="not-a-digest")

    def test_naive_timestamps_are_rejected(self) -> None:
        with pytest.raises(InvalidGrantError, match="timezone-aware"):
            grant(issued_at=datetime(2026, 4, 17, 12, 0, 0))

    def test_an_untrusted_authority_reference_cannot_be_attached(self) -> None:
        with pytest.raises(InvalidGrantError, match="DelegatedAuthorityReference"):
            grant(
                authority_reference=DelegatedAuthorityClaim(
                    issuer="external-issuer", external_reference_id="ref-1"
                )
            )

    def test_a_verified_authority_reference_can_be_attached(self) -> None:
        assert grant(authority_reference=verified_reference()).authority_reference is not None


class TestExecutorBinding:
    def test_the_binding_is_the_digest_not_the_label(self) -> None:
        binding = ExecutorBinding(DIGEST_C, "settlement-worker")
        assert binding.matches(DIGEST_C)
        assert not binding.matches(DIGEST_A)

    def test_a_readable_reference_is_optional(self) -> None:
        assert ExecutorBinding(DIGEST_C).executor_reference is None

    def test_a_readable_reference_is_not_the_binding(self) -> None:
        binding = ExecutorBinding(DIGEST_C, "settlement-worker")
        with pytest.raises(InvalidGrantError):
            binding.matches("settlement-worker")

    def test_the_binding_is_separate_from_the_execution_hash(self) -> None:
        issued = grant()
        assert issued.executor_binding.binding_digest != issued.execution_action_hash


class TestConsumptionAndRecovery:
    def test_a_reservation_binds_one_executor_and_one_execution_reference(self) -> None:
        reservation = AuthorityReservation(
            reservation_id="res-1",
            grant_id="grant-1",
            executor_binding=ExecutorBinding(DIGEST_C),
            reserved_at=ISSUED_AT,
            expires_at=EXPIRES_AT,
            execution_ref="payment-attempt-1",
        )
        assert reservation.status is ReservationStatus.HELD
        assert reservation.is_recoverable

    def test_without_an_execution_reference_a_retry_cannot_be_recovered(self) -> None:
        reservation = AuthorityReservation(
            reservation_id="res-1",
            grant_id="grant-1",
            executor_binding=ExecutorBinding(DIGEST_C),
            reserved_at=ISSUED_AT,
            expires_at=EXPIRES_AT,
        )
        assert not reservation.is_recoverable

    def test_only_an_authorised_consumption_spends_the_grant(self) -> None:
        authorised = AuthorityConsumption(
            consumption_id="con-1",
            grant_id="grant-1",
            outcome=ConsumptionOutcome.AUTHORISED,
            consumed_at=ISSUED_AT,
            execution_ref="payment-attempt-1",
        )
        assert authorised.spent_authority

    def test_a_recovered_consumption_authorises_nothing(self) -> None:
        recovered = AuthorityConsumption(
            consumption_id="con-1",
            grant_id="grant-1",
            outcome=ConsumptionOutcome.RECOVERED,
            consumed_at=ISSUED_AT + timedelta(hours=1),
            execution_ref="payment-attempt-1",
            outcome_reference=OutcomeReference(
                domain="payments",
                outcome_reference="settlement-1",
                status=OutcomeStatus.SUCCEEDED,
            ),
        )
        assert not recovered.spent_authority

    def test_recovery_survives_the_grants_own_expiry(self) -> None:
        """The authority was spent while valid; this only returns the record."""
        expired = grant()
        assert expired.effective_status(EXPIRES_AT + timedelta(hours=1)) is GrantStatus.EXPIRED
        recovered = AuthorityConsumption(
            consumption_id="con-1",
            grant_id=expired.grant_id,
            outcome=ConsumptionOutcome.RECOVERED,
            consumed_at=EXPIRES_AT + timedelta(hours=1),
            execution_ref="payment-attempt-1",
        )
        assert not recovered.spent_authority
        assert not expired.authorises_new_execution_at(recovered.consumed_at)

    def test_recovery_is_unreachable_without_an_execution_reference(self) -> None:
        with pytest.raises(CoreAuthorityError, match="execution_ref"):
            AuthorityConsumption(
                consumption_id="con-1",
                grant_id="grant-1",
                outcome=ConsumptionOutcome.RECOVERED,
                consumed_at=ISSUED_AT,
            )

    def test_a_rejected_consumption_must_carry_a_typed_reason(self) -> None:
        with pytest.raises(CoreAuthorityError, match="rejection_reason"):
            AuthorityConsumption(
                consumption_id="con-1",
                grant_id="grant-1",
                outcome=ConsumptionOutcome.REJECTED,
                consumed_at=ISSUED_AT,
            )

    def test_a_successful_consumption_cannot_carry_a_rejection_reason(self) -> None:
        with pytest.raises(CoreAuthorityError, match="only meaningful"):
            AuthorityConsumption(
                consumption_id="con-1",
                grant_id="grant-1",
                outcome=ConsumptionOutcome.AUTHORISED,
                consumed_at=ISSUED_AT,
                rejection_reason=DecisionReason.GRANT_EXPIRED,
            )

    def test_a_rejected_consumption_uses_the_precedence_vocabulary(self) -> None:
        rejected = AuthorityConsumption(
            consumption_id="con-1",
            grant_id="grant-1",
            outcome=ConsumptionOutcome.REJECTED,
            consumed_at=ISSUED_AT,
            rejection_reason=DecisionReason.GRANT_ALREADY_CONSUMED,
        )
        assert rejected.rejection_reason in CONSUMPTION_REJECTION_PRECEDENCE


class TestOutcome:
    def test_pending_is_the_default_and_is_not_settled(self) -> None:
        reference = OutcomeReference(domain="payments", outcome_reference="settlement-1")
        assert reference.status is OutcomeStatus.PENDING
        assert not reference.is_settled

    def test_unknown_is_not_a_failure(self) -> None:
        unreachable = OutcomeReference(
            domain="payments", outcome_reference="settlement-1", status=OutcomeStatus.UNKNOWN
        )
        assert not unreachable.is_settled
        assert unreachable.status is not OutcomeStatus.FAILED

    def test_an_evidence_link_pins_its_artefact(self) -> None:
        link = EvidenceLink(
            evidence_type="audit-record", locator="record-1", digest=DIGEST_A
        )
        assert link.digest == DIGEST_A

    def test_a_malformed_evidence_digest_is_rejected(self) -> None:
        with pytest.raises(CoreAuthorityError, match="digest"):
            EvidenceLink(evidence_type="audit-record", locator="record-1", digest="short")


class TestPorts:
    PORTS = (
        AuthorityProvider,
        AuthorityRequirementResolver,
        ContextProvider,
        DomainPolicy,
        Executor,
        OutcomeProvider,
    )

    @pytest.mark.parametrize("port", PORTS, ids=[port.__name__ for port in PORTS])
    def test_every_port_is_a_protocol(self, port: type) -> None:
        assert getattr(port, "_is_protocol", False)

    @pytest.mark.parametrize("port", PORTS, ids=[port.__name__ for port in PORTS])
    def test_no_port_carries_an_implementation(self, port: type) -> None:
        for name, member in vars(port).items():
            if name.startswith("_") or not inspect.isfunction(member):
                continue
            body = ast.parse(textwrap.dedent(inspect.getsource(member))).body[0]
            assert isinstance(body, ast.FunctionDef)
            statements = [
                node
                for node in body.body
                if not (
                    isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                )
            ]
            assert len(statements) == 1
            assert isinstance(statements[0], ast.Expr)
            assert isinstance(statements[0].value, ast.Constant)
            assert statements[0].value.value is Ellipsis

    def test_a_conforming_implementation_satisfies_the_protocol(self) -> None:
        class StubPolicy:
            def evaluate(self, envelope, resolved_authority, context):  # noqa: ARG002
                return PolicyDecision(decision=Decision.ALLOW, policy_snapshot=snapshot())

        assert isinstance(StubPolicy(), DomainPolicy)

    def test_a_policy_reads_the_act_only_from_the_envelopes_action(self) -> None:
        captured: dict = {}

        class StubPolicy:
            def evaluate(self, envelope, resolved_authority, context):  # noqa: ARG002
                captured["hash"] = envelope.action.execution_action_hash
                return PolicyDecision(decision=Decision.ALLOW, policy_snapshot=snapshot())

        subject = action()
        StubPolicy().evaluate(
            ActionEnvelope(action=subject),
            None,
            ExecutionContext(trusted(), organisation_id="org-1", principal_id="agent-1"),
        )
        assert captured["hash"] == subject.execution_action_hash


class TestErrors:
    @pytest.mark.parametrize(
        "error",
        [
            InvalidEnvelopeError,
            UnknownDomainError,
            InvalidAuthorityConstructionError,
            InvalidGrantError,
        ],
    )
    def test_every_error_shares_one_base(self, error: type[Exception]) -> None:
        assert issubclass(error, CoreAuthorityError)

    def test_expected_denial_is_representable_without_raising(self) -> None:
        """A failed external verification must not become a 500."""
        reference = DelegatedAuthorityReference(
            trusted(),
            issuer="external-issuer",
            external_reference_id="ref-1",
            artefact_digest=DIGEST_A,
            verification_status=VerificationStatus.FAILED,
        )
        resolved = ResolvedAuthority(
            trusted(),
            reference=reference,
            issues=(
                AuthorityVerificationIssue(
                    AuthorityVerificationFailure.AUTHORITY_EXPIRED, detail="past not_after"
                ),
            ),
        )
        blocked = PolicyDecision(
            decision=Decision.BLOCK,
            policy_snapshot=snapshot(),
            reasons=(DecisionReason.AUTHORITY_EXPIRED,),
        )
        assert not resolved.is_verified
        assert blocked.decision is Decision.BLOCK


class TestCorePlacementRule:
    """No vendor nouns anywhere in the boundary, including comments and tests."""

    # Split so the scan does not trip over its own term list. The whole
    # token never appears anywhere in this file.
    FORBIDDEN = tuple(
        head + tail
        for head, tail in (
            ("master", "card"),
            ("wallet", "connect"),
            ("x4", "02"),
            ("vi", "sa"),
            ("stri", "pe"),
            ("high", "note"),
            ("moon", "pay"),
            ("coin", "base"),
            ("pay", "pal"),
        )
    )

    def _sources(self) -> list[Path]:
        return sorted(CORE_PACKAGE_ROOT.glob("*.py")) + [
            Path(__file__),
            Path(__file__).with_name("test_core_authority_execution_hash.py"),
        ]

    def test_no_vendor_nouns_appear_anywhere(self) -> None:
        offences: list[str] = []
        for source in self._sources():
            text = source.read_text(encoding="utf-8").lower()
            offences.extend(
                f"{source.name}: {term}" for term in self.FORBIDDEN if term in text
            )
        assert not offences, offences

    def test_the_boundary_uses_the_neutral_nouns(self) -> None:
        exported = set(core_authority.__all__)
        assert {
            "DelegatedAuthorityReference",
            "ExecutorBinding",
            "OutcomeReference",
            "ResolvedAuthority",
        } <= exported

    def test_core_does_not_import_the_outer_layers(self) -> None:
        forbidden_modules = ("api.policy", "api.database", "api.models", "api.main")
        for source in sorted(CORE_PACKAGE_ROOT.glob("*.py")):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert node.module not in forbidden_modules, source.name
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name not in forbidden_modules, source.name
