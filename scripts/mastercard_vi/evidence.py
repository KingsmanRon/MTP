"""Building the per-case evidence files.

An evidence file is meant to be read by somebody who does not trust the
proof script. So it carries what an independent reader needs to follow
the chain — the pinned upstream commit, the issuer's public key, the
mapped scope, both action hashes, the exact reason code, the policy
digest, the re-resolution performed before consumption and the signed v3
receipt — and no private key material at all.

The pin is read, not asserted
-----------------------------
The connector records the commit it was written against in
``api.connectors.mastercard_vi.profile``. The commit actually installed
is read back from the distribution's own ``direct_url.json``, and
:func:`upstream_provenance` reports both plus whether they agree. An
evidence file that merely restated the pin would prove nothing about
which code ran.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from api.connectors.mastercard_vi import profile as vi_profile
from scripts.mastercard_vi import fixture as fx

#: Identifies the evidence layout, so a later change is visible.
EVIDENCE_FORMAT: Final[str] = "inntris-mastercard-vi-proof-evidence-v1"


def upstream_provenance() -> dict[str, Any]:
    """Which Verifiable Intent implementation this run actually verified against."""
    installed_commit: str | None = None
    installed_version: str | None = None
    try:
        distribution = importlib.metadata.distribution("verifiable-intent")
        installed_version = distribution.version
        raw = distribution.read_text("direct_url.json")
        if raw:
            installed_commit = json.loads(raw).get("vcs_info", {}).get("commit_id")
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover
        pass
    return {
        "site": vi_profile.UPSTREAM_SITE,
        "repository": vi_profile.UPSTREAM_REPOSITORY,
        "pinned_commit": vi_profile.UPSTREAM_COMMIT,
        "pinned_package_version": vi_profile.UPSTREAM_PACKAGE_VERSION,
        "spec_revision": vi_profile.SPEC_REVISION,
        "spec_date": vi_profile.SPEC_DATE,
        "installed_commit": installed_commit,
        "installed_version": installed_version,
        "matches_pin": (
            installed_commit == vi_profile.UPSTREAM_COMMIT
            and installed_version == vi_profile.UPSTREAM_PACKAGE_VERSION
        ),
    }


def credential_material(delegation: fx.Delegation) -> dict[str, Any]:
    """Public material only: no private scalars, no bearer serialisations.

    The full serialised SD-JWTs are deliberately NOT written out. They are
    a bearer presentation: anything holding one can replay it at any
    verifier trusting this issuer, and a proof artefact is the wrong place
    to publish one. Their digests are recorded instead, which is what an
    independent reader needs to confirm the chain was not swapped.
    """

    def digest(serialized: str) -> str:
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    return {
        "issuer": fx.ISSUER,
        "issuer_kid": fx.ISSUER_KID,
        "issuer_public_jwk": fx.issuer_jwk(),
        "credential_subject": fx.CREDENTIAL_SUBJECT,
        "wallet_issuer": fx.WALLET,
        "mandate_audience": fx.AGENT_AUDIENCE,
        "delegate_key_thumbprint": fx.agent_thumbprint(),
        "delegate_kid": fx.AGENT_KID,
        "layers_presented": ["layer1", "layer2"],
        "layer3_presented": False,
        "layer1_sha256": digest(delegation.layer1_serialized),
        "layer2_sha256": digest(delegation.layer2_serialized),
        "mandate_pair_reference": delegation.mandate_pair_reference,
        "permitted_payees": [fx.SUPPLIER_A, fx.SUPPLIER_B],
        "permitted_amount": {
            "currency": fx.VI_CURRENCY,
            "max": str(fx.VI_MAX_AMOUNT),
            "max_minor_units": fx.VI_MAX_MINOR_UNITS,
            "semantics": "per transaction (mandate.payment.amount_range)",
        },
    }


def vi_verification_view(detailed: Any) -> dict[str, Any]:
    """What the connector concluded, and which upstream checks ran.

    Taken from the connector's own ``resolve_detailed`` rather than from a
    second verification run, so nothing here can disagree with the
    resolution the decision path actually used.
    """
    resolved = detailed.resolved
    mapped = detailed.mapped_scope
    return {
        "is_verified": bool(resolved.is_verified),
        "verification_status": resolved.verification_status.value,
        "issues": [
            {"code": issue.code.value, "detail": issue.detail}
            for issue in resolved.issues
        ],
        "reference_checks_performed": list(detailed.reference_checks_performed),
        "reference_checks_skipped": list(detailed.reference_checks_skipped),
        "agent_key_thumbprint": detailed.agent_key_thumbprint,
        "mandate_pair_reference": detailed.mandate_pair_reference,
        "checkout_constraint_types": (
            list(mapped.checkout_constraint_types) if mapped else []
        ),
        "structural_constraint_types": (
            list(mapped.structural_constraint_types) if mapped else []
        ),
        "undisclosed_payee_count": mapped.undisclosed_payee_count if mapped else None,
        "amount_range_minor_units": dict(mapped.amount_range_minor_units) if mapped else {},
    }


def resolved_authority_view(resolved: Any) -> dict[str, Any]:
    """The neutral boundary object the payment domain was handed."""
    return {
        "issuer": resolved.reference.issuer,
        "external_reference_id": resolved.reference.external_reference_id,
        "artefact_digest": resolved.reference.artefact_digest,
        "verification_status": resolved.verification_status.value,
        "delegate_binding_status": resolved.delegate_binding_status.value,
        "delegate_binding_reference": resolved.delegate_binding_reference,
        "mapped_scope": dict(resolved.scope),
        "effective_not_before": (
            resolved.not_before.isoformat() if resolved.not_before else None
        ),
        "effective_not_after": (
            resolved.not_after.isoformat() if resolved.not_after else None
        ),
        "validity_rule": (
            "max(L1.iat, L2.iat) .. min(L1.exp, L2.exp) — the whole chain's "
            "intersection, never Layer 2 alone"
        ),
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
        "grant_expires_at": result.expires_at.isoformat() if result.expires_at else None,
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
        "execution_ref": grant["execution_ref"],
        "outcome_state": grant["outcome_state"],
        "outcome_reference": grant["outcome_reference"],
    }


def reresolution_view(evidence: Any, resolved: Any) -> dict[str, Any] | None:
    """The delegated-authority re-resolution performed before consumption.

    Issuance-time verification is not enough to consume. This records the
    connector being run again, against the credential as it stands, and
    the evidence handed to the store.
    """
    if evidence is None:
        return None
    return {
        "performed": True,
        "scope_digest": evidence.scope_digest,
        "verified": bool(evidence.verified),
        "revoked": bool(evidence.revoked),
        "expires_at": _iso(evidence.expires_at),
        "resolution_status": (
            resolved.verification_status.value if resolved is not None else None
        ),
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
