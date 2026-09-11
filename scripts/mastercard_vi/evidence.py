"""Building the per-case evidence files.

An evidence file is meant to be read by somebody who does not trust the
proof script. So it carries the material an independent reader needs to
follow the chain — the pinned upstream commit, the issuer's public key,
the mapped scope, both action hashes, the exact reason code, the policy
digest and the signed v3 receipt — and it carries no private key
material at all.

The upstream pin is read, not asserted
--------------------------------------
``VI_UPSTREAM_COMMIT`` is what this repository pins. The commit actually
installed is read back from the distribution's own ``direct_url.json``,
and :func:`upstream_provenance` reports both plus whether they agree. An
evidence file that merely restated the pin would prove nothing about
which code ran.
"""

from __future__ import annotations

import importlib.metadata
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from scripts.mastercard_vi import fixture as fx

#: The official Verifiable Intent reference implementation this proof is
#: pinned to. Repository: https://github.com/agent-intent/verifiable-intent
VI_UPSTREAM_REPOSITORY: Final[str] = "https://github.com/agent-intent/verifiable-intent"
VI_UPSTREAM_COMMIT: Final[str] = "356c29635f1c44df7de02edb58699ca9f29bece6"

#: Identifies the evidence layout, so a later change is visible.
EVIDENCE_FORMAT: Final[str] = "inntris-mastercard-vi-proof-evidence-v1"


def upstream_provenance() -> dict[str, Any]:
    """Which VI implementation this run actually verified against."""
    installed: str | None = None
    try:
        distribution = importlib.metadata.distribution("verifiable-intent")
        raw = distribution.read_text("direct_url.json")
        if raw:
            installed = json.loads(raw).get("vcs_info", {}).get("commit_id")
        version = distribution.version
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover
        version = None
    return {
        "repository": VI_UPSTREAM_REPOSITORY,
        "pinned_commit": VI_UPSTREAM_COMMIT,
        "installed_commit": installed,
        "installed_version": version,
        "matches_pin": installed == VI_UPSTREAM_COMMIT,
    }


def vi_verification_report(claim: Any, *, resolved: Any) -> dict[str, Any]:
    """Re-run the reference implementation's chain check, for the record.

    The provider has already run exactly this check; what it does not
    surface is the reference implementation's own list of which checks
    ran and which were skipped, and a reader of the evidence wants that.
    Running it again here is a report, not a second decision: the decision
    on the table is ``resolved``, and if the two ever disagreed the
    evidence would show it.
    """
    from verifiable_intent.crypto.sd_jwt import decode_sd_jwt
    from verifiable_intent.verification.chain import verify_chain

    from api.authority_providers.verifiable_intent import read_presented_delegation

    presented = read_presented_delegation(claim.evidence)
    issuer = fx.issuer_keys()
    result = verify_chain(
        decode_sd_jwt(presented.l1),
        decode_sd_jwt(presented.l2),
        l3_payment=decode_sd_jwt(presented.l3_payment),
        issuer_public_key=issuer.public_key,
        l1_serialized=presented.l1,
        l2_serialized=presented.l2,
        l2_payment_serialized=presented.l2_payment or presented.l2,
        expected_l2_aud=fx.AGENT_AUDIENCE,
        expected_l3_payment_aud=fx.NETWORK_AUDIENCE,
    )
    return {
        "chain_valid": bool(result.valid),
        "errors": list(result.errors),
        "checks_performed": list(result.checks_performed),
        "checks_skipped": list(result.checks_skipped),
        "l2_payment_disclosed": bool(result.l2_payment_disclosed),
        "l2_checkout_disclosed": bool(result.l2_checkout_disclosed),
        "mandate_pair_count": int(result.mandate_pair_count),
        "provider_agrees": bool(result.valid) == bool(resolved.is_verified),
    }


def credential_material(delegation: fx.Delegation) -> dict[str, Any]:
    """Public material only: keys anyone may hold, no private scalars.

    The full serialised SD-JWTs are deliberately NOT written out. They are
    a bearer presentation: anything holding one can replay it at any
    verifier that trusts this issuer, and a proof artefact is the wrong
    place to publish one. Their digests are here instead, which is what an
    independent reader needs to confirm the chain was not swapped.
    """
    import hashlib

    def digest(serialized: str) -> str:
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    return {
        "issuer_id": fx.ISSUER_ID,
        "issuer_public_key_pem": fx.issuer_keys().public_pem,
        "user_public_jwk": fx.user_keys().public_jwk,
        "delegate_public_jwk": delegation.agent_public_jwk,
        "l2_audience": fx.AGENT_AUDIENCE,
        "l3_payment_audience": fx.NETWORK_AUDIENCE,
        "credential_subject": fx.VI_SUBJECT,
        "permitted_payees": [fx.SUPPLIER_A, fx.SUPPLIER_B],
        "permitted_amount": {
            "currency": fx.VI_CURRENCY,
            "max": str(fx.VI_MAX_AMOUNT),
            "semantics": "per transaction (mandate.payment.amount_range)",
        },
        "l1_sha256": digest(delegation.l1_serialized),
        "l2_sha256": digest(delegation.l2_serialized),
        "mandate_not_before": datetime.fromtimestamp(
            delegation.issued_at, tz=UTC
        ).isoformat(),
        "mandate_not_after": datetime.fromtimestamp(
            delegation.expires_at, tz=UTC
        ).isoformat(),
    }


def resolved_authority_view(resolved: Any) -> dict[str, Any]:
    """What the provider concluded, in a form a reader can check."""
    return {
        "issuer": resolved.reference.issuer,
        "external_reference_id": resolved.reference.external_reference_id,
        "artefact_digest": resolved.reference.artefact_digest,
        "verification_status": resolved.verification_status.value,
        "is_verified": bool(resolved.is_verified),
        "delegate_binding_status": resolved.delegate_binding_status.value,
        "delegate_binding_reference": resolved.delegate_binding_reference,
        "issues": [
            {"code": issue.code.value, "detail": issue.detail}
            for issue in resolved.issues
        ],
        "mapped_scope": dict(resolved.scope),
        "not_before": resolved.not_before.isoformat() if resolved.not_before else None,
        "not_after": resolved.not_after.isoformat() if resolved.not_after else None,
    }


def envelope_view(envelope: Any) -> dict[str, Any]:
    """The ActionEnvelope's public fields — the act, as Core canonicalised it."""
    action = envelope.action
    target = action.target
    return {
        "domain": envelope.domain,
        "action_type": action.action_type,
        "organisation_id": action.organisation_id,
        "principal_id": action.principal_id,
        "payload": dict(action.payload),
        "target": (
            {"resource_type": target.resource_type, "resource_id": target.resource_id}
            if target is not None
            else None
        ),
        "execution_action_hash": envelope.execution_action_hash,
        "signed_action_hash": envelope.signed_action_hash,
    }


def decision_view(result: Any) -> dict[str, Any]:
    """The Inntris verdict, with the exact live reason codes."""
    return {
        "decision": result.decision.value,
        "reason_codes": [reason.value for reason in result.reasons],
        "detail": result.detail,
        "policy_hash": result.policy_snapshot_digest,
        "policy_snapshot_format": result.policy_snapshot_format,
        "policy_revision": result.policy_revision,
        "authority_scope_digest": result.authority_scope_digest,
        "executor_binding_digest": result.executor_binding_digest,
        "executor_reference": result.executor_reference,
        "grant_id": str(result.grant_id) if result.grant_id else None,
        "grant_expires_at": (
            result.expires_at.isoformat() if result.expires_at else None
        ),
        "issue_outcome": result.issue_outcome.value if result.issue_outcome else None,
        "decision_audit_id": (
            str(result.decision_audit_id) if result.decision_audit_id else None
        ),
    }


def grant_view(grant: Any) -> dict[str, Any] | None:
    """A grant's public fields. No token, no secret."""
    if grant is None:
        return None
    return {
        "grant_id": str(grant["id"]),
        "status": grant["status"],
        "domain": grant["domain"],
        "action_type": grant["action_type"],
        "execution_action_hash": grant["execution_action_hash"],
        "signed_action_hash": grant["signed_action_hash"],
        "policy_hash": grant["policy_hash"],
        "policy_snapshot_format": grant["policy_snapshot_format"],
        "policy_revision": grant["policy_revision"],
        "executor_binding_digest": grant["executor_binding_digest"],
        "executor_reference": grant["executor_reference"],
        "authority_scope_digest": grant["authority_scope_digest"],
        "authority_expires_at": _iso(grant["authority_expires_at"]),
        "issued_at": _iso(grant["issued_at"]),
        "expires_at": _iso(grant["expires_at"]),
        "consumed_at": _iso(grant["consumed_at"]),
        "outcome_state": grant["outcome_state"],
        "outcome_reference": grant["outcome_reference"],
    }


def attempt_view(attempt: Any) -> dict[str, Any] | None:
    """One execution attempt, including what the journal recorded."""
    if attempt is None:
        return None
    return {
        "verdict": attempt.verdict.value,
        "execution_ref": attempt.execution_ref,
        "consumption_outcome": (
            attempt.consumption_outcome.value if attempt.consumption_outcome else None
        ),
        "rejection_reason": (
            attempt.rejection_reason.value if attempt.rejection_reason else None
        ),
        "journal_state": attempt.journal_state.value if attempt.journal_state else None,
        "claim_outcome": attempt.claim_outcome.value if attempt.claim_outcome else None,
        "outcome_reference": attempt.outcome_reference,
        "side_effect_invocations_for_reference": attempt.side_effect_invocations,
        "detail": attempt.detail,
    }


def write_evidence(directory: Path, case_id: str, document: dict[str, Any]) -> Path:
    """Write one case's evidence file, sorted and newline-terminated."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{case_id}.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", "utf-8")
    return path


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    return str(value)
