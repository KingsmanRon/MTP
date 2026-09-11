"""The seven headline cases.

Each case is self-contained: its own organisation, its own agent, its own
grants. Nothing carries over, so a successful spend in one case cannot
relax a limit or pre-consume a grant in another.

Read together they demonstrate three separate claims:

1  Inntris verifies and consumes a real VI delegation as an authority
   input (cases 1, 4-7 all rest on a chain that actually verified);
2  a VI-valid action is still BLOCKED by stricter current Inntris
   organisation policy (cases 2 and 3, where VI passes first and the
   refusal is the organisation's own);
3  an ALLOW becomes bounded execution authority tied to the exact action
   and executor, with safe retry and replay semantics (cases 4-7).

Every expectation below is asserted. A case that behaved differently
fails the run rather than being written up as a pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from api.adapters.verify_envelope import build_action_envelope
from api.core.authority.decision import Decision, DecisionReason
from api.core.authority.lifecycle import ConsumptionOutcome
from api.persistence.authority_decisions import get_authority_decision
from api.receipts.evidence_builder import build_evidence_chain
from scripts.mastercard_vi import fixture as fx
from scripts.mastercard_vi.evidence import (
    EVIDENCE_FORMAT,
    attempt_view,
    credential_material,
    decision_view,
    envelope_view,
    grant_view,
    resolved_authority_view,
    upstream_provenance,
    vi_verification_report,
    write_evidence,
)
from scripts.mastercard_vi.executor import ExecutionVerdict
from scripts.mastercard_vi.harness import (
    PROOF_ACTION_TYPE,
    SUPPLIER_A_ACCOUNT,
    SUPPLIER_B_ACCOUNT,
    ProofHarness,
    payment_payload,
)


@dataclass
class CaseOutcome:
    """One case's result, as the table and the evidence file see it."""

    case_id: str
    title: str
    vi: str
    policy: str
    grant: str
    consume: str
    evidence_path: Path | None = None
    checks: list[tuple[str, bool]] = field(default_factory=list)

    def expect(self, description: str, condition: bool) -> None:
        self.checks.append((description, bool(condition)))

    @property
    def passed(self) -> bool:
        return all(passed for _, passed in self.checks)

    @property
    def failures(self) -> list[str]:
        return [text for text, passed in self.checks if not passed]


def _envelope(principal: Any, *, amount: str, account: str) -> Any:
    """The canonical act, built by the same adapter the service uses."""
    return build_action_envelope(
        agent=principal.agent,
        action_type=PROOF_ACTION_TYPE,
        payload=payment_payload(amount=amount, account=account),
    )


async def _receipts(harness: ProofHarness, result: Any, grant: Any, key: Any) -> dict[str, Any]:
    """The signed v3 evidence chain for this decision, and its verification.

    Built with ``build_evidence_chain``, which refuses to sign events that
    describe different histories, and then verified with the public half
    only — exactly as an outside auditor would, and publishing the key so
    a reader can repeat the check without asking anyone for anything.

    A BLOCK still gets a receipt. It simply has no consumption link,
    because nothing was consumed.
    """
    if result.decision_audit_id is None:
        return {}
    record = await get_authority_decision(harness.db, result.decision_audit_id)
    if record is None:
        return {}

    chain = build_evidence_chain(record, key=key, grant=grant)
    verification = chain.verify(public_key_b64=key.public_key_b64)
    return {
        "verifying_public_key_b64": key.public_key_b64,
        "chain_verified": bool(verification.valid),
        "failures": list(verification.failures),
        "decision": chain.decision.as_public_dict(),
        "consumption": (
            chain.consumption.as_public_dict() if chain.consumption else None
        ),
        "outcome": chain.outcome.as_public_dict() if chain.outcome else None,
        "decision_fingerprint": chain.decision.evidence_payload_hash,
    }


async def _write(
    harness: ProofHarness,
    directory: Path,
    outcome: CaseOutcome,
    *,
    description: str,
    delegation: fx.Delegation,
    claim: Any,
    resolved: Any,
    envelope: Any,
    result: Any,
    grant: Any = None,
    attempts: list[Any] | None = None,
    key: Any,
    notes: dict[str, Any] | None = None,
) -> None:
    document: dict[str, Any] = {
        "format": EVIDENCE_FORMAT,
        "case": {
            "id": outcome.case_id,
            "title": outcome.title,
            "description": description,
        },
        "vi_upstream": upstream_provenance(),
        "vi_credential_material": credential_material(delegation),
        "vi_verification": vi_verification_report(claim, resolved=resolved),
        "resolved_authority": resolved_authority_view(resolved),
        "action_envelope": envelope_view(envelope),
        "inntris_decision": decision_view(result),
        "grant": grant_view(grant),
        "execution_attempts": [attempt_view(a) for a in (attempts or [])],
        "receipt_v3": await _receipts(harness, result, grant, key),
        "assertions": [
            {"expectation": text, "held": passed} for text, passed in outcome.checks
        ],
    }
    if notes:
        document["notes"] = notes
    outcome.evidence_path = write_evidence(directory, outcome.case_id, document)


# ---------------------------------------------------------------------------
# 1. permitted + executed
# ---------------------------------------------------------------------------


async def case_1(harness: ProofHarness, directory: Path, key: Any) -> CaseOutcome:
    outcome = CaseOutcome(
        case_id="case-1-permitted-executed",
        title="permitted + executed",
        vi="PASS",
        policy="ALLOW",
        grant="issued",
        consume="authorised",
    )
    amount = "8500.00"
    principal = await harness.create_principal(label="case1")
    executor = harness.executor(principal.org_id, key_id="executor-a", reference="op-1")
    delegation = fx.build_delegation()
    claim = harness.claim_for(
        delegation, payee=fx.SUPPLIER_A, amount=amount, reference_id="case-1"
    )
    resolved = harness.resolve(claim, principal)
    outcome.expect("the VI delegation verifies", resolved.is_verified)

    result = await harness.evaluate(
        principal,
        claim=claim,
        amount=amount,
        account=SUPPLIER_A_ACCOUNT,
        executor=executor,
        issuance_ref="case-1",
    )
    outcome.expect("Inntris ALLOWs", result.decision is Decision.ALLOW)
    outcome.expect("a grant is issued", result.grant_id is not None)
    outcome.expect("an authority token is minted", result.authority_token is not None)

    attempt = await harness.execute(
        principal,
        authority_token=result.authority_token,
        grant_id=result.grant_id,
        execution_action_hash=result.execution_action_hash,
        amount=amount,
        account=SUPPLIER_A_ACCOUNT,
        executor=executor,
        execution_ref="case-1-exec",
        authority_evidence=harness.evidence_for(resolved),
    )
    outcome.expect(
        "the bound executor consumes successfully",
        attempt.verdict is ExecutionVerdict.EXECUTED,
    )
    outcome.expect(
        "authority was spent exactly once",
        attempt.consumption_outcome is ConsumptionOutcome.AUTHORISED,
    )
    outcome.expect("the side effect ran once", attempt.side_effect_invocations == 1)

    grant = await harness.grant(result.grant_id)
    outcome.expect("the grant is now consumed", grant["status"] == "consumed")
    outcome.consume = f"authorised ({attempt.outcome_reference})"

    await _write(
        harness,
        directory,
        outcome,
        description=(
            "8,500.00 USD to Supplier A, whose execution recipient this "
            "organisation allowlists. VI permits it and so does current "
            "Inntris policy, so a grant is issued and the exact executor "
            "spends it once."
        ),
        delegation=delegation,
        claim=claim,
        resolved=resolved,
        envelope=_envelope(principal, amount=amount, account=SUPPLIER_A_ACCOUNT),
        result=result,
        grant=grant,
        attempts=[attempt],
        key=key,
    )
    return outcome


# ---------------------------------------------------------------------------
# 2. VI-valid, organisation recipient block
# ---------------------------------------------------------------------------


async def case_2(harness: ProofHarness, directory: Path, key: Any) -> CaseOutcome:
    outcome = CaseOutcome(
        case_id="case-2-organisation-recipient-block",
        title="VI-valid, organisation recipient block",
        vi="PASS",
        policy="BLOCK",
        grant="none",
        consume="n/a",
    )
    amount = "8500.00"
    principal = await harness.create_principal(label="case2")
    executor = harness.executor(principal.org_id, key_id="executor-a", reference="op-2")
    delegation = fx.build_delegation()
    claim = harness.claim_for(
        delegation, payee=fx.SUPPLIER_B, amount=amount, reference_id="case-2"
    )
    resolved = harness.resolve(claim, principal)

    # The distinction the case exists to make: the credential is fine.
    outcome.expect("the VI delegation verifies", resolved.is_verified)
    outcome.expect(
        "VI permits Supplier B",
        fx.SUPPLIER_B["id"] in set(resolved.scope.get("allowed_payees", ())),
    )
    outcome.expect(
        "the amount is inside the VI per-transaction range",
        Decimal(amount) <= fx.VI_MAX_AMOUNT,
    )

    result = await harness.evaluate(
        principal,
        claim=claim,
        amount=amount,
        account=SUPPLIER_B_ACCOUNT,
        executor=executor,
        issuance_ref="case-2",
    )
    outcome.expect("Inntris BLOCKs", result.decision is Decision.BLOCK)
    outcome.expect(
        "the reason is the live recipient violation code",
        DecisionReason.WALLET_RECIPIENT_NOT_ALLOWED in result.reasons,
    )
    outcome.expect("no grant is issued", result.grant_id is None)
    outcome.expect("no authority token is minted", result.authority_token is None)
    outcome.consume = "no grant to consume"

    await _write(
        harness,
        directory,
        outcome,
        description=(
            "8,500.00 USD to Supplier B. VI permits Supplier B and the amount "
            "is inside the mandate's range, so the delegation is valid and "
            "satisfied. Supplier B's execution recipient is not allowlisted by "
            "this organisation, and the refusal is Inntris's own policy "
            "decision — not a broken credential."
        ),
        delegation=delegation,
        claim=claim,
        resolved=resolved,
        envelope=_envelope(principal, amount=amount, account=SUPPLIER_B_ACCOUNT),
        result=result,
        key=key,
        notes={
            "vi_verdict_precedes_inntris_verdict": (
                "The provider resolved and verified the delegation before any "
                "policy check ran. VI=PASS is therefore established first, and "
                "the BLOCK that follows is the organisation's."
            ),
            "reason_code_provenance": (
                "wallet_recipient_not_allowed is the existing deployed "
                "PolicyViolation code, not a name invented for this proof."
            ),
        },
    )
    return outcome


# ---------------------------------------------------------------------------
# 3. VI-valid, organisation spend block
# ---------------------------------------------------------------------------


async def case_3(harness: ProofHarness, directory: Path, key: Any) -> CaseOutcome:
    outcome = CaseOutcome(
        case_id="case-3-organisation-spend-block",
        title="VI-valid, organisation spend block",
        vi="PASS",
        policy="BLOCK",
        grant="none",
        consume="n/a",
    )
    amount = "18000.00"
    principal = await harness.create_principal(label="case3")
    executor = harness.executor(principal.org_id, key_id="executor-a", reference="op-3")
    delegation = fx.build_delegation()
    claim = harness.claim_for(
        delegation, payee=fx.SUPPLIER_A, amount=amount, reference_id="case-3"
    )
    resolved = harness.resolve(claim, principal)

    outcome.expect("the VI delegation verifies", resolved.is_verified)
    outcome.expect(
        "18,000.00 is inside the VI 20,000.00 per-transaction ceiling",
        Decimal(amount) <= fx.VI_MAX_AMOUNT,
    )
    outcome.expect(
        "18,000.00 is above the Inntris per-action cap",
        Decimal(amount) > Decimal(str(principal.agent.per_action_limit_usd)),
    )

    result = await harness.evaluate(
        principal,
        claim=claim,
        amount=amount,
        account=SUPPLIER_A_ACCOUNT,
        executor=executor,
        issuance_ref="case-3",
    )
    outcome.expect("Inntris BLOCKs", result.decision is Decision.BLOCK)
    outcome.expect(
        "the reason is the live spend-limit violation code",
        DecisionReason.PER_ACTION_LIMIT_EXCEEDED in result.reasons,
    )
    outcome.expect("no grant is issued", result.grant_id is None)
    outcome.consume = "no grant to consume"

    await _write(
        harness,
        directory,
        outcome,
        description=(
            "18,000.00 USD to Supplier A — an allowlisted recipient, and well "
            "inside VI's 20,000.00 per-transaction ceiling. Inntris caps a "
            "single action at 10,000.00, so the organisation refuses what the "
            "delegation permits."
        ),
        delegation=delegation,
        claim=claim,
        resolved=resolved,
        envelope=_envelope(principal, amount=amount, account=SUPPLIER_A_ACCOUNT),
        result=result,
        key=key,
        notes={
            "amount_range_is_per_transaction": (
                "mandate.payment.amount_range bounds one transaction. It is "
                "not a cumulative budget, and nothing here accumulates."
            ),
            "reason_code_provenance": (
                "per_action_limit_exceeded is the existing deployed "
                "PolicyViolation code."
            ),
        },
    )
    return outcome


# ---------------------------------------------------------------------------
# 4. tampered action after ALLOW
# ---------------------------------------------------------------------------


async def case_4(harness: ProofHarness, directory: Path, key: Any) -> CaseOutcome:
    outcome = CaseOutcome(
        case_id="case-4-tampered-action",
        title="tampered action after ALLOW",
        vi="PASS",
        policy="ALLOW",
        grant="issued",
        consume="grant_action_mismatch, then authorised",
    )
    approved, tampered = "8500.00", "9500.00"
    principal = await harness.create_principal(label="case4")
    executor = harness.executor(principal.org_id, key_id="executor-a", reference="op-4")
    delegation = fx.build_delegation()
    claim = harness.claim_for(
        delegation, payee=fx.SUPPLIER_A, amount=approved, reference_id="case-4"
    )
    resolved = harness.resolve(claim, principal)
    evidence = harness.evidence_for(resolved)

    result = await harness.evaluate(
        principal,
        claim=claim,
        amount=approved,
        account=SUPPLIER_A_ACCOUNT,
        executor=executor,
        issuance_ref="case-4",
    )
    outcome.expect("a grant is issued for 8,500.00", result.decision is Decision.ALLOW)

    # 9,500.00 would be policy-valid on its own — under the 10,000.00 cap and
    # inside VI's range. So a refusal here can only be the binding, which is
    # the whole point: the grant authorises one exact act, not a price band.
    outcome.expect(
        "9,500.00 would itself be policy-valid",
        Decimal(tampered) <= Decimal(str(principal.agent.per_action_limit_usd))
        and Decimal(tampered) <= fx.VI_MAX_AMOUNT,
    )

    tampered_envelope = _envelope(principal, amount=tampered, account=SUPPLIER_A_ACCOUNT)
    bad = await harness.execute(
        principal,
        authority_token=result.authority_token,
        grant_id=result.grant_id,
        execution_action_hash=tampered_envelope.execution_action_hash,
        amount=tampered,
        account=SUPPLIER_A_ACCOUNT,
        executor=executor,
        execution_ref="case-4-tampered",
        authority_evidence=evidence,
    )
    outcome.expect(
        "the tampered action is refused with grant_action_mismatch",
        bad.rejection_reason is DecisionReason.GRANT_ACTION_MISMATCH,
    )
    outcome.expect("nothing was executed", bad.side_effect_invocations == 0)

    after_mismatch = await harness.grant(result.grant_id)
    outcome.expect(
        "the failed mismatch did NOT burn the grant",
        after_mismatch["status"] == "active",
    )

    good = await harness.execute(
        principal,
        authority_token=result.authority_token,
        grant_id=result.grant_id,
        execution_action_hash=result.execution_action_hash,
        amount=approved,
        account=SUPPLIER_A_ACCOUNT,
        executor=executor,
        execution_ref="case-4-original",
        authority_evidence=evidence,
    )
    outcome.expect(
        "the original exact action then consumes successfully",
        good.verdict is ExecutionVerdict.EXECUTED,
    )
    grant = await harness.grant(result.grant_id)

    await _write(
        harness,
        directory,
        outcome,
        description=(
            "A grant is issued for 8,500.00 to Supplier A. The executor then "
            "presents an otherwise identical action for 9,500.00. That amount "
            "is itself within both the Inntris cap and the VI range, so the "
            "refusal is the binding to the exact approved act, not a fresh "
            "policy denial. The failed attempt does not burn the grant, and "
            "the original action still consumes."
        ),
        delegation=delegation,
        claim=claim,
        resolved=resolved,
        envelope=_envelope(principal, amount=approved, account=SUPPLIER_A_ACCOUNT),
        result=result,
        grant=grant,
        attempts=[bad, good],
        key=key,
        notes={
            "tampered_execution_action_hash": tampered_envelope.execution_action_hash,
            "approved_execution_action_hash": result.execution_action_hash,
        },
    )
    return outcome


# ---------------------------------------------------------------------------
# 5. replay vs idempotent retry
# ---------------------------------------------------------------------------


async def case_5(harness: ProofHarness, directory: Path, key: Any) -> CaseOutcome:
    outcome = CaseOutcome(
        case_id="case-5-replay-vs-idempotent-retry",
        title="replay vs idempotent retry",
        vi="PASS",
        policy="ALLOW",
        grant="issued",
        consume="authorised, recovered, refused",
    )
    amount = "8500.00"
    principal = await harness.create_principal(label="case5")
    executor = harness.executor(principal.org_id, key_id="executor-a", reference="op-5")
    delegation = fx.build_delegation()
    claim = harness.claim_for(
        delegation, payee=fx.SUPPLIER_A, amount=amount, reference_id="case-5"
    )
    resolved = harness.resolve(claim, principal)
    result = await harness.evaluate(
        principal,
        claim=claim,
        amount=amount,
        account=SUPPLIER_A_ACCOUNT,
        executor=executor,
        issuance_ref="case-5",
    )
    outcome.expect("a grant is issued", result.decision is Decision.ALLOW)

    common = {
        "authority_token": result.authority_token,
        "grant_id": result.grant_id,
        "execution_action_hash": result.execution_action_hash,
        "amount": amount,
        "account": SUPPLIER_A_ACCOUNT,
        "executor": executor,
        "authority_evidence": harness.evidence_for(resolved),
    }
    first = await harness.execute(principal, execution_ref="case-5-X", **common)
    retry = await harness.execute(principal, execution_ref="case-5-X", **common)
    replay = await harness.execute(principal, execution_ref="case-5-Y", **common)

    outcome.expect("the first attempt spends the authority", first.verdict is ExecutionVerdict.EXECUTED)
    outcome.expect(
        "the same execution_ref recovers the original success",
        retry.consumption_outcome is ConsumptionOutcome.RECOVERED,
    )
    outcome.expect(
        "the retry returns the same consumption evidence",
        retry.outcome_reference == first.outcome_reference,
    )
    outcome.expect(
        "the retry did NOT invoke the side effect again",
        retry.side_effect_invocations == 1,
    )
    outcome.expect(
        "a different execution_ref is refused",
        replay.consumption_outcome is ConsumptionOutcome.REJECTED,
    )
    outcome.expect(
        "the replay is refused as an execution_ref conflict",
        replay.rejection_reason is DecisionReason.EXECUTION_REF_CONFLICT,
    )
    outcome.expect(
        "the replay executed nothing",
        harness.journal.side_effect_count("case-5-Y") == 0,
    )
    grant = await harness.grant(result.grant_id)

    await _write(
        harness,
        directory,
        outcome,
        description=(
            "One grant, three attempts. Execution_ref X spends the authority "
            "and runs the side effect once. X again is an idempotent retry: "
            "the original consumption evidence comes back and nothing runs. "
            "Execution_ref Y is a replay attempt on already-spent authority "
            "and is refused."
        ),
        delegation=delegation,
        claim=claim,
        resolved=resolved,
        envelope=_envelope(principal, amount=amount, account=SUPPLIER_A_ACCOUNT),
        result=result,
        grant=grant,
        attempts=[first, retry, replay],
        key=key,
        notes={
            "retry_is_not_replay": (
                "Same execution_ref is idempotent success, not replay failure. "
                "Replay is a DIFFERENT execution_ref reusing consumed "
                "authority, and it is refused."
            ),
            "replay_reason_code": (
                "execution_ref_conflict is the more specific of the two codes "
                "the refusal qualifies for; it outranks grant_already_consumed "
                "in CONSUMPTION_REJECTION_PRECEDENCE because the caller's "
                "reference, not the grant, is what does not match."
            ),
        },
    )
    return outcome


# ---------------------------------------------------------------------------
# 6. expiry
# ---------------------------------------------------------------------------


async def case_6(harness: ProofHarness, directory: Path, key: Any) -> CaseOutcome:
    outcome = CaseOutcome(
        case_id="case-6-expiry",
        title="expiry",
        vi="PASS",
        policy="ALLOW",
        grant="issued",
        consume="grant_expired",
    )
    amount = "8500.00"
    principal = await harness.create_principal(label="case6")
    executor = harness.executor(principal.org_id, key_id="executor-a", reference="op-6")
    delegation = fx.build_delegation()
    claim = harness.claim_for(
        delegation, payee=fx.SUPPLIER_A, amount=amount, reference_id="case-6"
    )
    resolved = harness.resolve(claim, principal)
    result = await harness.evaluate(
        principal,
        claim=claim,
        amount=amount,
        account=SUPPLIER_A_ACCOUNT,
        executor=executor,
        issuance_ref="case-6",
    )
    outcome.expect("a grant is issued", result.decision is Decision.ALLOW)

    # The test clock, not a sleep. The grant's own window is what closes.
    after_expiry = result.expires_at + timedelta(seconds=1)
    attempt = await harness.execute(
        principal,
        authority_token=result.authority_token,
        grant_id=result.grant_id,
        execution_action_hash=result.execution_action_hash,
        amount=amount,
        account=SUPPLIER_A_ACCOUNT,
        executor=executor,
        execution_ref="case-6-exec",
        authority_evidence=harness.evidence_for(resolved),
        at=after_expiry,
    )
    outcome.expect(
        "the exact action and executor are refused with grant_expired",
        attempt.rejection_reason is DecisionReason.GRANT_EXPIRED,
    )
    outcome.expect("nothing was executed", attempt.side_effect_invocations == 0)
    grant = await harness.grant(result.grant_id)

    await _write(
        harness,
        directory,
        outcome,
        description=(
            "A grant is issued, then the test clock is advanced past its "
            "validity window. The exact action, presented by the exact bound "
            "executor, is refused: authority is bounded in time, and holding "
            "a valid token for the right act is not enough once the window "
            "has closed."
        ),
        delegation=delegation,
        claim=claim,
        resolved=resolved,
        envelope=_envelope(principal, amount=amount, account=SUPPLIER_A_ACCOUNT),
        result=result,
        grant=grant,
        attempts=[attempt],
        key=key,
        notes={
            "clock": "injected consumption instant; no sleep runs in CI",
            "grant_expires_at": result.expires_at.isoformat(),
            "consumption_attempted_at": after_expiry.isoformat(),
        },
    )
    return outcome


# ---------------------------------------------------------------------------
# 7. wrong executor
# ---------------------------------------------------------------------------


async def case_7(harness: ProofHarness, directory: Path, key: Any) -> CaseOutcome:
    outcome = CaseOutcome(
        case_id="case-7-wrong-executor",
        title="wrong executor",
        vi="PASS",
        policy="ALLOW",
        grant="issued",
        consume="grant_executor_mismatch, then authorised",
    )
    amount = "8500.00"
    principal = await harness.create_principal(label="case7")
    executor_a = harness.executor(
        principal.org_id, key_id="executor-a", reference="op-7a"
    )
    # Same organisation, same scopes, different authenticated key. The
    # binding is derived from the key, so copying the reference gains
    # Executor B nothing.
    executor_b = harness.executor(
        principal.org_id, key_id="executor-b", reference="op-7a"
    )
    outcome.expect(
        "the two executors have different bindings",
        executor_a.binding_digest != executor_b.binding_digest,
    )

    delegation = fx.build_delegation()
    claim = harness.claim_for(
        delegation, payee=fx.SUPPLIER_A, amount=amount, reference_id="case-7"
    )
    resolved = harness.resolve(claim, principal)
    evidence = harness.evidence_for(resolved)
    result = await harness.evaluate(
        principal,
        claim=claim,
        amount=amount,
        account=SUPPLIER_A_ACCOUNT,
        executor=executor_a,
        issuance_ref="case-7",
    )
    outcome.expect("a grant is issued to Executor A", result.decision is Decision.ALLOW)

    wrong = await harness.execute(
        principal,
        authority_token=result.authority_token,
        grant_id=result.grant_id,
        execution_action_hash=result.execution_action_hash,
        amount=amount,
        account=SUPPLIER_A_ACCOUNT,
        executor=executor_b,
        execution_ref="case-7-executor-b",
        authority_evidence=evidence,
    )
    outcome.expect(
        "Executor B is refused with grant_executor_mismatch",
        wrong.rejection_reason is DecisionReason.GRANT_EXECUTOR_MISMATCH,
    )
    outcome.expect("Executor B executed nothing", wrong.side_effect_invocations == 0)

    after_mismatch = await harness.grant(result.grant_id)
    outcome.expect(
        "the failed mismatch did NOT burn the grant",
        after_mismatch["status"] == "active",
    )

    right = await harness.execute(
        principal,
        authority_token=result.authority_token,
        grant_id=result.grant_id,
        execution_action_hash=result.execution_action_hash,
        amount=amount,
        account=SUPPLIER_A_ACCOUNT,
        executor=executor_a,
        execution_ref="case-7-executor-a",
        authority_evidence=evidence,
    )
    outcome.expect(
        "Executor A can still consume it",
        right.verdict is ExecutionVerdict.EXECUTED,
    )
    grant = await harness.grant(result.grant_id)

    await _write(
        harness,
        directory,
        outcome,
        description=(
            "A grant bound to Executor A. Executor B — same organisation, same "
            "scopes, different authenticated API key — presents the exact "
            "approved action and is refused. The refusal does not burn the "
            "grant, and Executor A still consumes it."
        ),
        delegation=delegation,
        claim=claim,
        resolved=resolved,
        envelope=_envelope(principal, amount=amount, account=SUPPLIER_A_ACCOUNT),
        result=result,
        grant=grant,
        attempts=[wrong, right],
        key=key,
        notes={
            "executor_a_binding_digest": executor_a.binding_digest,
            "executor_b_binding_digest": executor_b.binding_digest,
            "executor_reference_is_not_identity": (
                "Both executors presented the same caller-supplied "
                "executor_reference. The binding is derived from the "
                "authenticated API key, so copying a reference proves nothing."
            ),
        },
    )
    return outcome


HEADLINE_CASES = (case_1, case_2, case_3, case_4, case_5, case_6, case_7)
