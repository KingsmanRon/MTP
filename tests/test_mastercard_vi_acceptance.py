"""Phase 6 — the acceptance suite around the seven headline cases.

Separate from ``test_mastercard_vi_proof.py`` on purpose: those seven
cases are the evidence pack, and these are the attacks and failure modes
that have to hold for the evidence pack to mean anything. A headline case
that passed while a cross-tenant caller could read the grant back would
be a demonstration, not a proof.

Everything here drives the Phase-5 connector at
``api/connectors/mastercard_vi``. Same gating as the rest of the database
integration suite, and the same refusal to skip past the cryptography.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip(
    "verifiable_intent",
    reason=(
        "the VI acceptance suite needs the pinned reference implementation: "
        "pip install -e '.[mastercard-vi]'"
    ),
)

from api.core.authority.authority import AuthorityVerificationFailure  # noqa: E402
from api.core.authority.decision import Decision, DecisionReason  # noqa: E402
from api.core.authority.lifecycle import ConsumptionOutcome  # noqa: E402
from api.database import Database  # noqa: E402
from api.persistence.authority_store import IssueOutcome  # noqa: E402
from api.services.authority_service import (  # noqa: E402
    AUTHORITY_REQUIRED_ORGS_ENV,
    AuthorityEvaluationService,
    legacy_authority_gate,
)
from scripts.mastercard_vi import fixture as fx  # noqa: E402
from scripts.mastercard_vi.executor import ExecutionVerdict  # noqa: E402
from scripts.mastercard_vi.harness import (  # noqa: E402
    PROOF_SERVER_SECRET,
    SUPPLIER_A_ACCOUNT,
    SUPPLIER_B_ACCOUNT,
    ProofHarness,
    payment_payload,
    principal_binding_metadata,
)
from scripts.mastercard_vi.journal import ExecutionState  # noqa: E402

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="the VI acceptance suite requires INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)

AMOUNT = "8500.00"


@pytest.fixture
async def database() -> AsyncIterator[Database]:
    db = await Database.create(DATABASE_URL, min_size=2, max_size=12)
    try:
        yield db
    finally:
        await db.close()


@pytest.fixture
def harness(database: Database, tmp_path: Path) -> ProofHarness:
    return ProofHarness(database, journal_path=str(tmp_path / "journal.sqlite"))


@pytest.fixture
def delegation() -> fx.Delegation:
    return fx.build_delegation()


async def granted(
    harness: ProofHarness,
    delegation: fx.Delegation,
    *,
    label: str,
    amount: str = AMOUNT,
    account: str = SUPPLIER_A_ACCOUNT,
    key_id: str = "executor-a",
    reference: str = "op",
):
    """A fresh principal holding one live grant, and everything to spend it."""
    principal = await harness.create_principal(label=label)
    executor = harness.executor(principal.org_id, key_id=key_id, reference=reference)
    claim = delegation.claim()
    result = await harness.evaluate(
        principal,
        claim=claim,
        amount=amount,
        account=account,
        executor=executor,
        issuance_ref=f"iss-{label}",
    )
    assert result.decision is Decision.ALLOW, [r.value for r in result.reasons]
    return principal, executor, claim, result


def spend_kwargs(result, claim, executor, *, amount=AMOUNT, account=SUPPLIER_A_ACCOUNT):
    return {
        "authority_token": result.authority_token,
        "grant_id": result.grant_id,
        "execution_action_hash": result.execution_action_hash,
        "amount": amount,
        "account": account,
        "executor": executor,
        "claim": claim,
    }


# ---------------------------------------------------------------------------
# 8. required delegation omitted
# ---------------------------------------------------------------------------


class TestRequiredDelegationOmitted:
    """An organisation that opted in cannot be served by the path that skips it."""

    async def test_authority_evaluate_fails_closed_without_the_delegation(
        self, harness: ProofHarness, database: Database, monkeypatch
    ) -> None:
        principal = await harness.create_principal(label="case8-new")
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(principal.org_id))
        # Built after the enrolment, exactly as a deployment would be.
        service = AuthorityEvaluationService(
            database,
            server_secret=PROOF_SERVER_SECRET,
            authority_provider=harness.provider,
            payee_binding_resolver=harness.payees,
        )
        result = await service.evaluate(
            agent=principal.agent,
            action_type="wallet_transaction",
            payload=payment_payload(amount=AMOUNT, account=SUPPLIER_A_ACCOUNT),
            executor=harness.executor(principal.org_id, key_id="executor-a"),
            issuance_ref="case8-new",
            authority_claim=None,
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING in result.reasons
        assert result.grant_id is None
        assert result.authority_token is None

    async def test_the_legacy_verify_gate_refuses_the_same_organisation(
        self, harness: ProofHarness, monkeypatch
    ) -> None:
        """/verify has no field to carry a delegation, so it cannot bypass.

        The legacy route consults the same requirement resolver. For an
        enrolled organisation the answer is always "required and absent",
        which is what stops it quietly issuing a token under a rule the
        organisation deliberately turned on.
        """
        principal = await harness.create_principal(label="case8-legacy")
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(principal.org_id))
        assert (
            legacy_authority_gate(
                organisation_id=principal.org_id,
                principal_id=principal.agent_id,
                action_type="wallet_transaction",
            )
            is DecisionReason.AUTHORITY_REQUIRED_BUT_MISSING
        )

    async def test_a_non_enrolled_organisation_is_unaffected(
        self, harness: ProofHarness, monkeypatch
    ) -> None:
        """Enrolment is a deliberate act; nothing changes until someone does it."""
        principal = await harness.create_principal(label="case8-other")
        monkeypatch.setenv(AUTHORITY_REQUIRED_ORGS_ENV, str(uuid4()))
        assert (
            legacy_authority_gate(
                organisation_id=principal.org_id,
                principal_id=principal.agent_id,
                action_type="wallet_transaction",
            )
            is None
        )


# ---------------------------------------------------------------------------
# 9. cross-tenant authority
# ---------------------------------------------------------------------------


class TestCrossTenantAuthority:
    async def test_another_organisation_cannot_evaluate_for_this_principal(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        principal = await harness.create_principal(label="case9")
        stranger = harness.executor(uuid4(), key_id="stranger-key")
        result = await harness.evaluate(
            principal,
            claim=delegation.claim(),
            amount=AMOUNT,
            account=SUPPLIER_A_ACCOUNT,
            executor=stranger,
            issuance_ref="iss-case9",
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_PRINCIPAL_MISMATCH in result.reasons
        assert result.grant_id is None

    async def test_another_organisation_can_neither_consume_nor_read_the_grant(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """Even after a committed consumption, and even holding the token.

        The executor binding is checked BEFORE recovery, so a foreign
        caller cannot read back somebody else's execution either.
        Inspection and consumption fail on the same check.
        """
        principal, executor, claim, result = await granted(
            harness, delegation, label="case9b"
        )
        common = spend_kwargs(result, claim, executor)
        first = await harness.execute(principal, execution_ref="case9b-own", **common)
        assert first.verdict is ExecutionVerdict.EXECUTED

        stranger = harness.executor(uuid4(), key_id="stranger-key")
        intrusion = await harness.execute(
            principal,
            execution_ref="case9b-intrusion",
            **{**common, "executor": stranger},
        )
        assert intrusion.rejection_reason is DecisionReason.GRANT_EXECUTOR_MISMATCH
        assert intrusion.outcome_reference is None
        assert intrusion.side_effect_invocations == 0

    async def test_a_delegation_bound_elsewhere_does_not_resolve_here(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """One organisation's provisioning does not bind another's principal."""
        other = await harness.create_principal(
            label="case9c",
            binding=principal_binding_metadata(
                thumbprints=(fx.agent_thumbprint(fx.OTHER_AGENT_KEY),)
            ),
        )
        resolved = harness.resolve(delegation.claim(), other)
        assert not resolved.is_verified
        assert AuthorityVerificationFailure.AUTHORITY_DELEGATE_NOT_BOUND in (
            resolved.failure_codes
        )


# ---------------------------------------------------------------------------
# 10. spoofed executor
# ---------------------------------------------------------------------------


class TestSpoofedExecutor:
    async def test_a_copied_executor_reference_gains_nothing(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """executor_reference is a label. The binding is the credential."""
        principal, executor_a, claim, result = await granted(
            harness, delegation, label="case10", reference="operation-7731"
        )
        spoofed = harness.executor(
            principal.org_id,
            key_id="attacker-key",
            # Byte-identical to the real one. Anyone who saw a log has it.
            reference="operation-7731",
        )
        assert spoofed.executor_reference == executor_a.executor_reference
        assert spoofed.binding_digest != executor_a.binding_digest

        common = spend_kwargs(result, claim, executor_a)
        attempt = await harness.execute(
            principal, execution_ref="case10-spoof", **{**common, "executor": spoofed}
        )
        assert attempt.rejection_reason is DecisionReason.GRANT_EXECUTOR_MISMATCH
        assert attempt.side_effect_invocations == 0

        grant = await harness.grant(result.grant_id)
        assert grant["status"] == "active", "a spoofed attempt must not burn the grant"

        honest = await harness.execute(principal, execution_ref="case10-real", **common)
        assert honest.verdict is ExecutionVerdict.EXECUTED


# ---------------------------------------------------------------------------
# 11. policy change before first consume
# ---------------------------------------------------------------------------


class TestPolicyChangedBeforeConsume:
    async def test_a_stale_grant_does_not_execute_under_the_old_policy(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        principal, executor, claim, result = await granted(
            harness, delegation, label="case11"
        )
        # Permitted at evaluation. The organisation then tightens the cap.
        principal = await harness.tighten_per_action_limit(principal, Decimal("5000"))

        attempt = await harness.execute(
            principal, execution_ref="case11-exec", **spend_kwargs(result, claim, executor)
        )
        assert attempt.rejection_reason is DecisionReason.POLICY_HASH_MISMATCH
        assert attempt.side_effect_invocations == 0
        grant = await harness.grant(result.grant_id)
        assert grant["status"] == "active"


# ---------------------------------------------------------------------------
# 12. principal suspended before consume
# ---------------------------------------------------------------------------


class TestPrincipalSuspendedBeforeConsume:
    async def test_a_suspended_principal_fails_closed(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        principal, executor, claim, result = await granted(
            harness, delegation, label="case12"
        )
        principal = await harness.suspend(principal)

        attempt = await harness.execute(
            principal, execution_ref="case12-exec", **spend_kwargs(result, claim, executor)
        )
        assert attempt.rejection_reason is DecisionReason.AGENT_NOT_ACTIVE
        assert attempt.side_effect_invocations == 0


# ---------------------------------------------------------------------------
# 13. delegation expiry / revocation before first consume
# ---------------------------------------------------------------------------


class TestDelegationWithdrawnBeforeConsume:
    """Issuance-time verification is never enough to consume."""

    async def test_a_revoked_delegate_key_fails_the_re_resolution(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """A real revocation, through the connector, not a synthetic flag.

        The operator moves the delegate thumbprint into the revoked set
        after the grant is issued. The re-resolution before consumption
        then genuinely fails inside the connector, and the store refuses
        the unverified evidence.
        """
        principal, executor, claim, result = await granted(
            harness, delegation, label="case13a"
        )
        principal = await harness.revoke_delegate_key(principal)

        # The connector itself now refuses the same credential, and says
        # *revoked* rather than merely unbound: a key withdrawn is a
        # different fact from a key that was never this principal's, and
        # the connector keeps them apart.
        reresolved = harness.resolve(claim, principal)
        assert not reresolved.is_verified
        assert AuthorityVerificationFailure.AUTHORITY_REVOKED in (
            reresolved.failure_codes
        )

        attempt = await harness.execute(
            principal, execution_ref="case13a-exec", **spend_kwargs(result, claim, executor)
        )
        assert attempt.consumption_outcome is ConsumptionOutcome.REJECTED
        assert attempt.rejection_reason in {
            DecisionReason.AUTHORITY_VERIFICATION_FAILED,
            DecisionReason.AUTHORITY_SCOPE_EXCEEDED,
            DecisionReason.AUTHORITY_UNVERIFIED,
        }
        assert attempt.side_effect_invocations == 0

    async def test_an_expired_delegation_fails_closed(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        from dataclasses import replace

        principal, executor, claim, result = await granted(
            harness, delegation, label="case13b"
        )
        expired = replace(
            harness.reresolve_evidence(claim, principal),
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        attempt = await harness.execute(
            principal,
            execution_ref="case13b-exec",
            authority_evidence=expired,
            **spend_kwargs(result, claim, executor),
        )
        assert attempt.rejection_reason is DecisionReason.AUTHORITY_EXPIRED
        assert attempt.side_effect_invocations == 0

    async def test_consuming_with_no_current_evidence_fails_closed(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """Absent evidence is not evidence of validity.

        The grant rested on a delegation. Spending it with no current
        statement about that delegation would spend authority whose basis
        may have been withdrawn minutes ago. This is the store's
        AUTHORITY_UNVERIFIED protection, and the proof never bypasses it.
        """
        principal, executor, claim, result = await granted(
            harness, delegation, label="case13c"
        )
        attempt = await harness.execute(
            principal,
            execution_ref="case13c-exec",
            reresolve=False,
            **spend_kwargs(result, claim, executor),
        )
        assert attempt.rejection_reason is DecisionReason.AUTHORITY_UNVERIFIED
        assert attempt.side_effect_invocations == 0


# ---------------------------------------------------------------------------
# 14. concurrent evaluation retries
# ---------------------------------------------------------------------------


class TestConcurrentEvaluationRetries:
    async def test_the_same_issuance_identity_yields_one_grant(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        principal = await harness.create_principal(label="case14a")
        executor = harness.executor(principal.org_id, key_id="executor-a")
        call = {
            "claim": delegation.claim(),
            "amount": AMOUNT,
            "account": SUPPLIER_A_ACCOUNT,
            "executor": executor,
            "issuance_ref": "case14a",
        }
        first, second = await asyncio.gather(
            harness.evaluate(principal, **call), harness.evaluate(principal, **call)
        )
        assert first.decision is Decision.ALLOW
        assert second.decision is Decision.ALLOW
        assert first.grant_id == second.grant_id, "one request must yield one grant"
        assert {first.issue_outcome, second.issue_outcome} == {
            IssueOutcome.ISSUED,
            IssueOutcome.IDEMPOTENT,
        }

    async def test_a_changed_binding_under_the_same_identity_conflicts(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """Same issuance_ref, different act. That is not a retry."""
        principal = await harness.create_principal(label="case14b")
        executor = harness.executor(principal.org_id, key_id="executor-a")
        claim = delegation.claim()
        first = await harness.evaluate(
            principal,
            claim=claim,
            amount=AMOUNT,
            account=SUPPLIER_A_ACCOUNT,
            executor=executor,
            issuance_ref="case14b",
        )
        assert first.decision is Decision.ALLOW

        second = await harness.evaluate(
            principal,
            claim=claim,
            amount="9500.00",
            account=SUPPLIER_A_ACCOUNT,
            executor=executor,
            issuance_ref="case14b",
        )
        assert second.decision is Decision.BLOCK
        assert second.issue_outcome is IssueOutcome.CONFLICT
        assert second.grant_id is None
        assert second.authority_token is None


# ---------------------------------------------------------------------------
# 15. concurrent consumers
# ---------------------------------------------------------------------------


class TestConcurrentConsumers:
    async def test_one_committed_consumption_and_idempotent_recovery(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        principal, executor, claim, result = await granted(
            harness, delegation, label="case15a"
        )
        evidence = harness.reresolve_evidence(claim, principal)
        common = {
            "authority_token": result.authority_token,
            "executor": executor,
            "agent": principal.agent,
            "action_type": "wallet_transaction",
            "payload": payment_payload(amount=AMOUNT, account=SUPPLIER_A_ACCOUNT),
            "execution_ref": "case15a-shared",
            "authority_evidence": evidence,
        }
        left, right = await asyncio.gather(
            harness.consumption.consume(**common), harness.consumption.consume(**common)
        )
        assert sorted(
            (left.outcome, right.outcome), key=lambda outcome: outcome.value
        ) == [ConsumptionOutcome.AUTHORISED, ConsumptionOutcome.RECOVERED], (
            "exactly one attempt may spend the authority; the other recovers it"
        )
        assert sum(r.spent_authority for r in (left, right)) == 1

    async def test_different_references_cannot_both_win(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        principal, executor, claim, result = await granted(
            harness, delegation, label="case15b"
        )
        evidence = harness.reresolve_evidence(claim, principal)
        common = {
            "authority_token": result.authority_token,
            "executor": executor,
            "agent": principal.agent,
            "action_type": "wallet_transaction",
            "payload": payment_payload(amount=AMOUNT, account=SUPPLIER_A_ACCOUNT),
            "authority_evidence": evidence,
        }
        left, right = await asyncio.gather(
            harness.consumption.consume(execution_ref="case15b-X", **common),
            harness.consumption.consume(execution_ref="case15b-Y", **common),
        )
        spent = [r for r in (left, right) if r.spent_authority]
        refused = [r for r in (left, right) if r.outcome is ConsumptionOutcome.REJECTED]
        assert len(spent) == 1, "single-use authority cannot be spent twice"
        assert len(refused) == 1
        assert refused[0].rejection_reason in {
            DecisionReason.EXECUTION_REF_CONFLICT,
            DecisionReason.GRANT_ALREADY_CONSUMED,
        }


# ---------------------------------------------------------------------------
# 17 & 18. crash recovery around the consumption commit
# ---------------------------------------------------------------------------


class TestCrashRecovery:
    async def test_a_crash_before_the_consumption_commit_executes_nothing(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        principal, executor, claim, result = await granted(
            harness, delegation, label="case17"
        )
        common = spend_kwargs(result, claim, executor) | {"execution_ref": "case17-exec"}
        crashed = await harness.execute(principal, crash_before_consume=True, **common)
        assert crashed.side_effect_invocations == 0
        assert harness.side_effect.count == 0
        assert harness.journal.get("case17-exec").state is ExecutionState.PREPARED

        grant = await harness.grant(result.grant_id)
        assert grant["status"] == "active", "no authority was spent"

        recovered = await harness.execute(principal, **common)
        assert recovered.verdict is ExecutionVerdict.EXECUTED
        assert harness.journal.side_effect_count("case17-exec") == 1

    async def test_a_crash_after_the_commit_continues_the_one_prepared_operation(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """Authority spent, side effect provably not started.

        The journal still says `prepared`, the only state in which a
        recovered consumption may go on to act — and it may do so exactly
        once.
        """
        principal, executor, claim, result = await granted(
            harness, delegation, label="case18"
        )
        common = spend_kwargs(result, claim, executor) | {"execution_ref": "case18-exec"}
        crashed = await harness.execute(principal, crash_before_claim=True, **common)
        assert crashed.consumption_outcome is ConsumptionOutcome.AUTHORISED
        assert crashed.side_effect_invocations == 0
        assert harness.journal.get("case18-exec").state is ExecutionState.PREPARED

        grant = await harness.grant(result.grant_id)
        assert grant["status"] == "consumed", "the authority WAS spent"

        recovered = await harness.execute(principal, **common)
        assert recovered.consumption_outcome is ConsumptionOutcome.RECOVERED
        assert recovered.verdict is ExecutionVerdict.EXECUTED
        assert harness.journal.side_effect_count("case18-exec") == 1

        # And only once: a further recovery finds the operation terminal.
        again = await harness.execute(principal, **common)
        assert again.verdict is ExecutionVerdict.RECONCILED
        assert harness.journal.side_effect_count("case18-exec") == 1
        assert harness.side_effect.count == 1


# ---------------------------------------------------------------------------
# 19. the side effect succeeded but its outcome could not be recorded
# ---------------------------------------------------------------------------


class TestOutcomeWriteFailure:
    async def test_an_unrecorded_success_blocks_retry_until_a_resolver_decides(
        self, harness: ProofHarness, delegation: fx.Delegation, monkeypatch
    ) -> None:
        """The worst shape: money moved, and we could not write it down.

        Reporting success would be a claim we cannot support; rolling the
        operation back to `prepared` would invite a second payment. It
        stays `in_progress` — unresolved, un-retryable, and finalised only
        by the authoritative resolver.
        """
        principal, executor, claim, result = await granted(
            harness, delegation, label="case19"
        )
        real_record = harness.journal.record_outcome

        def failing_record(*args, **kwargs):
            if kwargs.get("state") is ExecutionState.SUCCEEDED:
                raise OSError("simulated journal write failure")
            return real_record(*args, **kwargs)

        monkeypatch.setattr(harness.journal, "record_outcome", failing_record)

        common = spend_kwargs(result, claim, executor) | {"execution_ref": "case19-exec"}
        attempt = await harness.execute(principal, **common)
        assert attempt.verdict is ExecutionVerdict.OUTCOME_UNRECORDED
        assert harness.side_effect.count == 1
        assert harness.journal.get("case19-exec").state is ExecutionState.IN_PROGRESS

        monkeypatch.undo()

        # An automatic retry must not call the executor a second time.
        retry = await harness.execute(principal, **common)
        assert retry.verdict is not ExecutionVerdict.EXECUTED
        assert harness.side_effect.count == 1

        # Only the authoritative resolver finalises it.
        finalised = harness.journal.resolve_authoritatively(
            execution_ref="case19-exec",
            state=ExecutionState.SUCCEEDED,
            outcome_reference="reconciled:case19",
            detail="downstream evidence confirmed the transfer",
            side_effect_invoked=True,
        )
        assert finalised.state is ExecutionState.SUCCEEDED
        assert finalised.side_effects == 1

    async def test_a_thrown_side_effect_becomes_outcome_unknown_not_failed(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """A timeout is not proof that nothing happened."""
        from scripts.mastercard_vi.executor import SideEffectUnknown

        principal, executor, claim, result = await granted(
            harness, delegation, label="case19b"
        )

        def times_out(_operation):
            raise SideEffectUnknown("the executor timed out")

        harness.side_effect.behaviour = times_out
        common = spend_kwargs(result, claim, executor) | {"execution_ref": "case19b-exec"}
        attempt = await harness.execute(principal, **common)
        assert attempt.verdict is ExecutionVerdict.OUTCOME_UNKNOWN
        assert harness.journal.get("case19b-exec").state is ExecutionState.OUTCOME_UNKNOWN

        harness.side_effect.behaviour = None
        retry = await harness.execute(principal, **common)
        assert retry.verdict is not ExecutionVerdict.EXECUTED
        assert harness.side_effect.count == 1, "automatic retry must stay blocked"

        grant = await harness.grant(result.grant_id)
        assert grant["outcome_state"] == "outcome_unknown"

        resolved_operation = harness.journal.resolve_authoritatively(
            execution_ref="case19b-exec",
            state=ExecutionState.FAILED_FINAL,
            detail="the rail confirmed no transfer was created",
        )
        assert resolved_operation.state is ExecutionState.FAILED_FINAL


# ---------------------------------------------------------------------------
# 20. substitution
# ---------------------------------------------------------------------------


class TestSubstitution:
    """Changing where value goes changes the act, in every dimension."""

    @pytest.mark.parametrize(
        ("label", "overrides", "expected"),
        [
            (
                "recipient",
                {"account": SUPPLIER_B_ACCOUNT},
                DecisionReason.WALLET_RECIPIENT_NOT_ALLOWED,
            ),
            ("chain", {"chain": "eip155:1"}, DecisionReason.WALLET_CHAIN_NOT_ALLOWED),
        ],
    )
    async def test_a_substituted_destination_is_refused_at_evaluation(
        self,
        harness: ProofHarness,
        delegation: fx.Delegation,
        label: str,
        overrides: dict,
        expected: DecisionReason,
    ) -> None:
        principal = await harness.create_principal(label=f"case20-{label}")
        call = {
            "claim": delegation.claim(),
            "amount": AMOUNT,
            "account": SUPPLIER_A_ACCOUNT,
            "executor": harness.executor(principal.org_id, key_id="executor-a"),
            "issuance_ref": f"iss-20{label}",
        }
        call.update(overrides)
        result = await harness.evaluate(principal, **call)
        assert result.decision is Decision.BLOCK
        assert expected in result.reasons
        assert result.grant_id is None

    async def test_an_unsupported_currency_is_refused(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """The delegation is denominated in USD and only USD."""
        principal = await harness.create_principal(label="case20-currency")
        result = await harness.evaluate(
            principal,
            claim=delegation.claim(),
            amount=AMOUNT,
            account=SUPPLIER_A_ACCOUNT,
            currency="EUR",
            executor=harness.executor(principal.org_id, key_id="executor-a"),
            issuance_ref="iss-20cur",
        )
        assert result.decision is Decision.BLOCK
        assert result.grant_id is None

    async def test_substituting_the_destination_after_the_grant_is_a_mismatch(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """Even to a destination policy would independently permit.

        The grant authorises one exact act. A different recipient is a
        different act, and the binding refuses it before any policy
        question is reached.
        """
        # Both recipients allowlisted, so policy alone would permit either
        # and the refusal below can only be the binding.
        principal = await harness.create_principal(
            label="case20-swap",
            allowed_recipients=[SUPPLIER_A_ACCOUNT, SUPPLIER_B_ACCOUNT],
        )
        executor = harness.executor(principal.org_id, key_id="executor-a")
        claim = delegation.claim()
        result = await harness.evaluate(
            principal,
            claim=claim,
            amount=AMOUNT,
            account=SUPPLIER_A_ACCOUNT,
            executor=executor,
            issuance_ref="iss-20swap",
        )
        assert result.decision is Decision.ALLOW

        substituted = await harness.execute(
            principal,
            execution_ref="case20-swap",
            **{**spend_kwargs(result, claim, executor), "account": SUPPLIER_B_ACCOUNT},
        )
        assert substituted.rejection_reason is DecisionReason.GRANT_ACTION_MISMATCH
        assert substituted.side_effect_invocations == 0


# ---------------------------------------------------------------------------
# 16. delegation usage semantics
# ---------------------------------------------------------------------------


class TestDelegationUsageSemantics:
    async def test_amount_range_is_per_transaction_not_a_cumulative_budget(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """Two transactions whose sum exceeds the ceiling both pass the scope.

        ``mandate.payment.amount_range`` bounds one transaction. 12,000 +
        11,000 is 23,000, over the mandate's 20,000 ceiling, and neither
        is refused by the delegated scope — because the scope never asked
        about the total. Reading it as a budget would refuse the second
        and enforce a constraint the issuer did not express.

        Cumulative control is the organisation's daily limit: a different
        rule with a different reason code.
        """
        principal = await harness.create_principal(
            label="case16a",
            per_action_limit=Decimal("20000"),
            daily_limit=Decimal("100000"),
        )
        executor = harness.executor(principal.org_id, key_id="executor-a")
        # Two different acts: an agent may not hold two active spend
        # reservations for one identical action hash, so a genuine second
        # transaction is a genuinely different one.
        amounts = ("12000.00", "11000.00")
        assert sum(Decimal(a) for a in amounts) > fx.VI_MAX_AMOUNT
        assert all(Decimal(a) <= fx.VI_MAX_AMOUNT for a in amounts)

        results = []
        already_spent = Decimal("0")
        for index, amount in enumerate(amounts):
            results.append(
                await harness.evaluate(
                    principal,
                    claim=delegation.claim(),
                    amount=amount,
                    account=SUPPLIER_A_ACCOUNT,
                    executor=executor,
                    issuance_ref=f"iss-case16a-{index}",
                    daily_spend=already_spent,
                )
            )
            already_spent += Decimal(amount)
        assert [r.decision for r in results] == [Decision.ALLOW, Decision.ALLOW]
        assert len({r.grant_id for r in results}) == 2, "two distinct grants"

    @pytest.mark.parametrize("constraint_name", ["budget", "recurrence"])
    async def test_an_unsupported_mandate_is_rejected_not_reinterpreted(
        self, harness: ProofHarness, constraint_name: str
    ) -> None:
        """Enforcing the part we understand is broader than what was granted."""
        from verifiable_intent.models.constraints import (
            PaymentBudgetConstraint,
            PaymentRecurrenceConstraint,
        )

        constraint = (
            PaymentBudgetConstraint(currency="USD", max=5_000_000)
            if constraint_name == "budget"
            else PaymentRecurrenceConstraint(
                frequency="MNTH",
                start_date="2026-01-01",
                end_date="2027-01-01",
                number=6,
            )
        )
        delegation = fx.build_delegation(extra_payment_constraints=[constraint])
        principal = await harness.create_principal(label=f"case16-{constraint_name}")

        resolved = harness.resolve(delegation.claim(), principal)
        assert not resolved.is_verified, (
            "a mandate carrying a constraint this build cannot enforce must not "
            "resolve as usable authority"
        )
        assert AuthorityVerificationFailure.AUTHORITY_SCOPE_UNREADABLE in (
            resolved.failure_codes
        )

        result = await harness.evaluate(
            principal,
            claim=delegation.claim(),
            amount=AMOUNT,
            account=SUPPLIER_A_ACCOUNT,
            executor=harness.executor(principal.org_id, key_id="executor-a"),
            issuance_ref=f"iss-case16-{constraint_name}",
        )
        assert result.decision is Decision.BLOCK
        assert result.grant_id is None

    async def test_one_delegation_supports_more_than_one_grant(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """There is no single-use VI mandate rule, and none is invented here.

        Single use is a property of an Inntris execution-authority grant.
        The delegation it rested on is not consumed by being used.
        """
        principal = await harness.create_principal(label="case16c")
        executor = harness.executor(principal.org_id, key_id="executor-a")
        grants = []
        for index, amount in enumerate(("8500.00", "7500.00")):
            result = await harness.evaluate(
                principal,
                claim=delegation.claim(),
                amount=amount,
                account=SUPPLIER_A_ACCOUNT,
                executor=executor,
                issuance_ref=f"iss-case16c-{index}",
            )
            assert result.decision is Decision.ALLOW
            grants.append(result.grant_id)
        assert len(set(grants)) == 2


# ---------------------------------------------------------------------------
# 21. receipt forgery attempt
# ---------------------------------------------------------------------------


class TestReceiptForgery:
    async def test_editing_a_v3_authority_field_is_rejected_despite_a_fresh_hash(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """Recomputing the fingerprint is exactly what an attacker would do.

        A payload hash proves the payload has not changed *since the hash
        was taken*. Anyone editing the payload can take a new one. What
        they cannot do is produce the Ed25519 signature over it, so the
        verifier refuses the edited event even though its fingerprint is
        internally consistent.
        """
        from api.persistence.authority_decisions import get_authority_decision
        from api.receipts.evidence_builder import build_decision_evidence
        from api.receipts.v3 import (
            evidence_payload_hash,
            load_evidence_signing_key,
            verify_evidence_event,
        )

        _principal, _executor, _claim, result = await granted(
            harness, delegation, label="case21"
        )
        key = load_evidence_signing_key(environment="test")
        record = await get_authority_decision(harness.db, result.decision_audit_id)
        event = build_decision_evidence(record, key=key).as_public_dict()
        assert verify_evidence_event(event, public_key_b64=key.public_key_b64).valid

        forged = {**event, "payload": {**event["payload"]}}
        body = {**forged["payload"]["body"]}
        body["decision"] = "allow" if body["decision"] != "allow" else "block"
        body["authority_scope_digest"] = "f" * 64
        forged["payload"]["body"] = body
        # A fresh, internally consistent fingerprint over the edited body.
        forged["evidence_payload_hash"] = evidence_payload_hash(forged["payload"])

        verification = verify_evidence_event(forged, public_key_b64=key.public_key_b64)
        assert not verification.valid
        assert any("signature" in failure.lower() for failure in verification.failures), (
            f"the refusal must rest on the signature, not the hash: "
            f"{verification.failures}"
        )

    async def test_a_receipt_does_not_verify_against_another_key(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        from api.persistence.authority_decisions import get_authority_decision
        from api.receipts.evidence_builder import build_decision_evidence
        from api.receipts.v3 import load_evidence_signing_key, verify_evidence_event

        _principal, _executor, _claim, result = await granted(
            harness, delegation, label="case21b"
        )
        key = load_evidence_signing_key(environment="test")
        other = load_evidence_signing_key(environment="test")
        event = build_decision_evidence(
            await get_authority_decision(harness.db, result.decision_audit_id), key=key
        ).as_public_dict()
        assert not verify_evidence_event(
            event, public_key_b64=other.public_key_b64
        ).valid


# ---------------------------------------------------------------------------
# 22. legacy / new race
# ---------------------------------------------------------------------------


class TestLegacyAndNewCannotBothIssue:
    async def test_one_idempotent_evaluation_yields_one_consumable_authority(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """Two surfaces, one logical request, one grant — and one spend.

        Both HTTP surfaces enter the same evaluation and the same
        consumption service, so there is no second place an authority
        could be minted. Reaching the shared path twice with the same
        issuance identity recovers the first grant rather than creating a
        sibling, and spending it once leaves nothing for the second caller.
        """
        principal = await harness.create_principal(label="case22")
        executor = harness.executor(principal.org_id, key_id="executor-a")
        claim = delegation.claim()
        call = {
            "claim": claim,
            "amount": AMOUNT,
            "account": SUPPLIER_A_ACCOUNT,
            "executor": executor,
            "issuance_ref": "case22-shared",
        }
        first = await harness.evaluate(principal, **call)
        second = await harness.evaluate(principal, **call)
        assert first.grant_id == second.grant_id
        assert second.issue_outcome is IssueOutcome.IDEMPOTENT

        spent = await harness.execute(
            principal,
            execution_ref="case22-first",
            **spend_kwargs(first, claim, executor),
        )
        assert spent.verdict is ExecutionVerdict.EXECUTED

        # The second caller's token names the same grant, now spent.
        blocked = await harness.execute(
            principal,
            execution_ref="case22-second",
            **spend_kwargs(second, claim, executor),
        )
        assert blocked.consumption_outcome is ConsumptionOutcome.REJECTED
        assert blocked.rejection_reason in {
            DecisionReason.EXECUTION_REF_CONFLICT,
            DecisionReason.GRANT_ALREADY_CONSUMED,
        }
        assert harness.journal.side_effect_count("case22-second") == 0

    async def test_the_legacy_route_refuses_to_consume_an_executor_bound_token(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        """A downgrade to the legacy path would drop the executor binding."""
        from api.services.authority_service import (
            LegacyTokenDowngradeError,
            consume_legacy_approval_token,
            is_executor_bound_authority_token,
        )

        _principal, _executor, _claim, result = await granted(
            harness, delegation, label="case22b"
        )
        claims = harness.evaluation.read_authority_token(result.authority_token)
        assert is_executor_bound_authority_token(claims)

        with pytest.raises(LegacyTokenDowngradeError):
            await consume_legacy_approval_token(
                harness.db,
                None,
                token_id="unused",
                token_digest=b"\x00" * 32,
                approved_action_hash=result.execution_action_hash,
                execution_ref="case22b",
                token_claims=claims,
            )


# ---------------------------------------------------------------------------
# Phase-5 boundaries the proof must not quietly cross
# ---------------------------------------------------------------------------


class TestLayer3IsNeverAccepted:
    """Inntris decides before the act; Layer 3 records one already committed."""

    async def test_presenting_layer_3_is_refused_rather_than_ignored(
        self, harness: ProofHarness, delegation: fx.Delegation
    ) -> None:
        from api.core.authority.authority import DelegatedAuthorityClaim

        principal = await harness.create_principal(label="l3")
        claim = DelegatedAuthorityClaim(
            issuer=fx.ISSUER,
            external_reference_id=delegation.mandate_pair_reference,
            evidence={**delegation.evidence(), "layer3": "some.l3~"},
        )
        resolved = harness.resolve(claim, principal)
        assert not resolved.is_verified
        assert AuthorityVerificationFailure.AUTHORITY_ARTEFACT_INVALID in (
            resolved.failure_codes
        )

    def test_the_proof_fixture_never_builds_a_layer_3(
        self, delegation: fx.Delegation
    ) -> None:
        assert set(delegation.evidence()) == {"layer1", "layer2"}


class TestIssuerTrustIsNotTakenFromTheArtefact:
    async def test_an_unprovisioned_issuer_key_does_not_verify(
        self, harness: ProofHarness
    ) -> None:
        """The chain is signed by a key this deployment never provisioned."""
        forged = fx.build_delegation(issuer_key=fx.IMPOSTOR_ISSUER_KEY)
        principal = await harness.create_principal(label="impostor")
        resolved = harness.resolve(forged.claim(), principal)
        assert not resolved.is_verified
        assert resolved.failure_codes
