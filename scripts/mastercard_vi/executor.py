"""The mock executor: the only thing in the proof with a "side effect".

There is no network here and no settlement. The "side effect" is a
callable that appends to an in-memory ledger, and the point of the whole
module is *when* it is allowed to run.

The refusal contract
--------------------
The executor performs nothing until the authority consumption service has
confirmed, in one atomic call:

* the authority token is authentic and names a grant;
* the ``execution_action_hash`` recomputed from the act it is about to
  perform is the one the grant authorises;
* the executor's own authenticated binding is the one the grant is bound to;
* the grant is active and unexpired;
* the consumption committed on this attempt.

Only the last of those is a judgement call, and it is the one that
matters most. ``ConsumptionOutcome.RECOVERED`` — an idempotent retry
under the same ``execution_ref`` — is **not** permission to act. It is
the record of an execution that was already authorised. An executor that
treats it as a fresh instruction pays twice, which is precisely the bug
the journal and this contract exist to make impossible.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from uuid import UUID

from api.core.authority.decision import DecisionReason
from api.core.authority.lifecycle import ConsumptionOutcome
from api.persistence.authority_store import ResolvedAuthorityEvidence
from api.services.executor_context import AuthenticatedExecutorContext
from scripts.mastercard_vi.journal import (
    ClaimOutcome,
    ExecutionJournal,
    ExecutionState,
)

logger = logging.getLogger(__name__)


class ExecutionVerdict(StrEnum):
    """What one execution attempt did, end to end."""

    #: Authority was spent on this attempt and the side effect ran once.
    EXECUTED = "executed"
    #: The side effect ran and reported a final failure. Authority is spent.
    FAILED_FINAL = "failed_final"
    #: The side effect may or may not have happened. Retry is blocked.
    OUTCOME_UNKNOWN = "outcome_unknown"
    #: An idempotent retry. The original result is returned; nothing ran.
    RECONCILED = "reconciled"
    #: The side effect ran, but its outcome could not be written down. The
    #: operation stays unresolved: retry is blocked, and only the
    #: authoritative resolver may finalise it.
    OUTCOME_UNRECORDED = "outcome_unrecorded"
    #: Inntris refused the consumption. Nothing ran.
    REFUSED = "refused"
    #: Authority was spent but the journal would not hand over the claim,
    #: so no side effect ran on this attempt.
    BLOCKED = "blocked"


class SideEffectUnknown(RuntimeError):
    """The side effect threw or timed out without proving it did not happen.

    Distinct from an ordinary failure. Raising this is how the proof's
    side effect says "I cannot tell you whether money moved", and it is
    what sends the operation to ``outcome_unknown`` rather than
    ``failed_final``.
    """


class SideEffectFailed(RuntimeError):
    """The side effect proved it did not happen."""


@dataclass
class MockSideEffect:
    """A recorded, non-networked stand-in for a settlement call.

    ``behaviour`` lets an acceptance case make one specific invocation
    throw. Everything else about the executor stays identical, so a case
    changes one variable rather than taking a different code path.
    """

    invocations: list[dict[str, Any]] = field(default_factory=list)
    behaviour: Callable[[dict[str, Any]], str] | None = None

    def __call__(self, operation: dict[str, Any]) -> str:
        self.invocations.append(dict(operation))
        if self.behaviour is not None:
            return self.behaviour(operation)
        return f"mock-settlement:{operation['execution_ref']}"

    @property
    def count(self) -> int:
        return len(self.invocations)


@dataclass(frozen=True, slots=True)
class ExecutionAttempt:
    """The full, inspectable result of one attempt."""

    verdict: ExecutionVerdict
    execution_ref: str
    grant_id: UUID | None = None
    consumption_outcome: ConsumptionOutcome | None = None
    rejection_reason: DecisionReason | None = None
    journal_state: ExecutionState | None = None
    claim_outcome: ClaimOutcome | None = None
    outcome_reference: str | None = None
    side_effect_invocations: int = 0
    detail: str | None = None

    @property
    def performed_side_effect(self) -> bool:
        return self.verdict in {
            ExecutionVerdict.EXECUTED,
            ExecutionVerdict.FAILED_FINAL,
            ExecutionVerdict.OUTCOME_UNKNOWN,
            ExecutionVerdict.OUTCOME_UNRECORDED,
        }


class MockExecutor:
    """Implements the ``Executor`` contract over the real consume service."""

    def __init__(
        self,
        consumption_service: Any,
        journal: ExecutionJournal,
        side_effect: MockSideEffect | None = None,
    ) -> None:
        self._consume = consumption_service
        self._journal = journal
        self.side_effect = side_effect or MockSideEffect()

    async def execute(
        self,
        *,
        authority_token: str,
        executor: AuthenticatedExecutorContext,
        agent: Any,
        action_type: str,
        payload: dict[str, Any],
        execution_ref: str,
        grant_id: str,
        execution_action_hash: str,
        authority_evidence: ResolvedAuthorityEvidence | None = None,
        at: Any = None,
        crash_before_consume: bool = False,
        crash_before_claim: bool = False,
        crash_after_claim: bool = False,
    ) -> ExecutionAttempt:
        """Prepare, consume, claim, act once, record. In that order.

        The three ``crash_*`` switches simulate a process death at the
        points that matter, by returning instead of continuing. Nothing is
        rolled back — that is the point: the next attempt has to cope with
        whatever the journal and the authority store actually contain.
        """
        # --- 1. persist the intent BEFORE authority is spent -------------
        # A crash between here and the consume leaves a prepared row and no
        # consumption, which is recoverable. Consuming first and crashing
        # before the journal write would leave spent authority with no
        # record of what it was spent on.
        self._journal.prepare(
            execution_ref=execution_ref,
            grant_id=grant_id,
            execution_action_hash=execution_action_hash,
            executor_binding_digest=executor.binding_digest,
        )

        if crash_before_consume:
            # Died between persisting the intent and spending the
            # authority. The grant is untouched and the journal says
            # `prepared`, which is exactly the recoverable shape.
            return ExecutionAttempt(
                verdict=ExecutionVerdict.BLOCKED,
                execution_ref=execution_ref,
                journal_state=ExecutionState.PREPARED,
                side_effect_invocations=self._journal.side_effect_count(execution_ref),
                detail="simulated crash after prepare, before the consumption commit",
            )

        # --- 2. consume Inntris authority --------------------------------
        result = await self._consume.consume(
            authority_token=authority_token,
            executor=executor,
            agent=agent,
            action_type=action_type,
            payload=payload,
            execution_ref=execution_ref,
            authority_evidence=authority_evidence,
            at=at,
        )

        if result.outcome is ConsumptionOutcome.REJECTED:
            operation = self._journal.get(execution_ref)
            return ExecutionAttempt(
                verdict=ExecutionVerdict.REFUSED,
                execution_ref=execution_ref,
                grant_id=result.grant_id,
                consumption_outcome=result.outcome,
                rejection_reason=result.rejection_reason,
                journal_state=operation.state if operation else None,
                side_effect_invocations=self._journal.side_effect_count(execution_ref),
                detail="Inntris refused the consumption; nothing was executed",
            )

        if result.outcome is ConsumptionOutcome.RECOVERED:
            # The decisive rule, with one narrow exception.
            #
            # An idempotent consumption response is NOT an instruction to
            # act again — unless the journal says the operation is still
            # `prepared`, which means it was never claimed and the side
            # effect provably never ran. That is the crash-between-commit-
            # and-call shape, and finishing the single prepared operation
            # once is recovery, not a second execution. Any other state
            # (in_progress, unknown, terminal) reconciles and stops.
            operation = self._journal.get(execution_ref)
            if operation is None or operation.state is not ExecutionState.PREPARED:
                return self._reconcile(execution_ref, result)

        if crash_before_claim:
            operation = self._journal.get(execution_ref)
            return ExecutionAttempt(
                verdict=ExecutionVerdict.BLOCKED,
                execution_ref=execution_ref,
                grant_id=result.grant_id,
                consumption_outcome=result.outcome,
                journal_state=operation.state if operation else None,
                side_effect_invocations=self._journal.side_effect_count(execution_ref),
                detail="simulated crash after consumption commit, before claim",
            )

        # --- 3. atomically claim the prepared operation ------------------
        claim = self._journal.claim(
            execution_ref=execution_ref,
            grant_id=grant_id,
            execution_action_hash=execution_action_hash,
            executor_binding_digest=executor.binding_digest,
        )
        if not claim.may_invoke_side_effect:
            operation = claim.operation
            return ExecutionAttempt(
                verdict=(
                    ExecutionVerdict.RECONCILED
                    if claim.outcome is ClaimOutcome.ALREADY_FINAL
                    else ExecutionVerdict.BLOCKED
                ),
                execution_ref=execution_ref,
                grant_id=result.grant_id,
                consumption_outcome=result.outcome,
                journal_state=operation.state if operation else None,
                claim_outcome=claim.outcome,
                outcome_reference=operation.outcome_reference if operation else None,
                side_effect_invocations=self._journal.side_effect_count(execution_ref),
                detail="the journal did not hand over the claim; no side effect ran",
            )

        if crash_after_claim:
            return ExecutionAttempt(
                verdict=ExecutionVerdict.BLOCKED,
                execution_ref=execution_ref,
                grant_id=result.grant_id,
                consumption_outcome=result.outcome,
                journal_state=ExecutionState.IN_PROGRESS,
                claim_outcome=claim.outcome,
                side_effect_invocations=self._journal.side_effect_count(execution_ref),
                detail="simulated crash after claim, before the side effect",
            )

        # --- 4. invoke the side effect ONCE ------------------------------
        operation_view = {
            "execution_ref": execution_ref,
            "grant_id": grant_id,
            "execution_action_hash": execution_action_hash,
            "action_type": action_type,
            "payload": dict(payload),
        }
        try:
            reference = self.side_effect(operation_view)
        except SideEffectUnknown as unknown:
            # A thrown or timed-out effect whose absence cannot be proven.
            # Never failed_final: that would invite a duplicate payment.
            self._journal.record_outcome(
                execution_ref=execution_ref,
                state=ExecutionState.OUTCOME_UNKNOWN,
                detail=str(unknown),
                side_effect_invoked=True,
            )
            await self._record_store_outcome(result.grant_id, "outcome_unknown", str(unknown))
            return self._attempt(
                ExecutionVerdict.OUTCOME_UNKNOWN, execution_ref, result, claim, str(unknown)
            )
        except SideEffectFailed as failed:
            self._journal.record_outcome(
                execution_ref=execution_ref,
                state=ExecutionState.FAILED_FINAL,
                detail=str(failed),
                side_effect_invoked=True,
            )
            await self._record_store_outcome(result.grant_id, "failed_final", str(failed))
            return self._attempt(
                ExecutionVerdict.FAILED_FINAL, execution_ref, result, claim, str(failed)
            )

        # --- 5. record success -------------------------------------------
        # The side effect has already happened. If writing that down fails,
        # the operation must NOT be reported as executed and must not be
        # retried: it stays `in_progress`, where the claim left it, so the
        # next attempt is blocked and only the authoritative resolver can
        # finalise it. Reporting success we could not record, or rolling
        # back to `prepared`, would both invite a second payment.
        try:
            self._journal.record_outcome(
                execution_ref=execution_ref,
                state=ExecutionState.SUCCEEDED,
                outcome_reference=reference,
                side_effect_invoked=True,
            )
        except Exception as exc:
            logger.warning(
                "side effect for %s succeeded but its outcome could not be "
                "recorded: %s",
                execution_ref,
                exc,
            )
            await self._record_store_outcome(
                result.grant_id, "outcome_unknown", f"outcome write failed: {exc}"
            )
            return self._attempt(
                ExecutionVerdict.OUTCOME_UNRECORDED,
                execution_ref,
                result,
                claim,
                f"the side effect ran; its outcome could not be recorded: {exc}",
                reference,
            )
        await self._record_store_outcome(result.grant_id, "succeeded", None, reference)
        return self._attempt(
            ExecutionVerdict.EXECUTED, execution_ref, result, claim, None, reference
        )

    # -- helpers -----------------------------------------------------------

    def _reconcile(self, execution_ref: str, result: Any) -> ExecutionAttempt:
        operation = self._journal.get(execution_ref)
        return ExecutionAttempt(
            verdict=ExecutionVerdict.RECONCILED,
            execution_ref=execution_ref,
            grant_id=result.grant_id,
            consumption_outcome=result.outcome,
            journal_state=operation.state if operation else None,
            outcome_reference=operation.outcome_reference if operation else None,
            side_effect_invocations=self._journal.side_effect_count(execution_ref),
            detail="idempotent retry: the original consumption was returned, "
            "and the side effect was NOT invoked again",
        )

    def _attempt(
        self,
        verdict: ExecutionVerdict,
        execution_ref: str,
        result: Any,
        claim: Any,
        detail: str | None,
        reference: str | None = None,
    ) -> ExecutionAttempt:
        operation = self._journal.get(execution_ref)
        return ExecutionAttempt(
            verdict=verdict,
            execution_ref=execution_ref,
            grant_id=result.grant_id,
            consumption_outcome=result.outcome,
            journal_state=operation.state if operation else None,
            claim_outcome=claim.outcome,
            outcome_reference=reference
            or (operation.outcome_reference if operation else None),
            side_effect_invocations=self._journal.side_effect_count(execution_ref),
            detail=detail,
        )

    async def _record_store_outcome(
        self,
        grant_id: UUID | None,
        state: str,
        detail: str | None,
        reference: str | None = None,
    ) -> None:
        """Mirror the outcome into the authority store's own outcome field.

        Best effort and deliberately non-fatal: the store's outcome column
        is evidence about the grant, and a proof harness failing to write
        it must not change what the proof observed about the execution.
        """
        if grant_id is None:
            return
        from api.persistence.authority_store import OutcomeState

        try:
            await self._consume._store.record_outcome(  # noqa: SLF001
                grant_id=grant_id,
                outcome_state=OutcomeState(state),
                outcome_reference=reference,
                detail=detail,
            )
        except Exception as exc:  # pragma: no cover - proof harness only
            logger.warning("could not mirror outcome for grant %s: %s", grant_id, exc)
