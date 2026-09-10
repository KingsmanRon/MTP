"""Receipt v3 — authenticated, linked authority evidence.

Why v3 exists
-------------
v1 and v2 are decision receipts whose integrity rests on a *fingerprint*:
a SHA-256 over seven canonical fields. A fingerprint alone proves only
that the fields hash to the value stored beside them — anyone who can
alter a field can recompute it. That was acceptable while the receipt's
real assurance came from the agent's Ed25519 signature over the action
hash and from on-chain anchoring.

The authority lifecycle needs more. Its fields (which policy snapshot,
which delegated authority, which executor, which grant) have no agent
signature over them, so a fingerprint over them would be self-certifying
and worthless against tampering. v3 therefore signs.

**v1 and v2 are untouched.** Their schema version, field set,
canonicalisation and fingerprint algorithm are frozen; nothing in this
module is reachable from their path. ``schema_version`` selects the
branch, and a stored v1/v2 receipt verifies exactly as it always did.

Linked evidence, never mutation
-------------------------------
A decision receipt is never rewritten once consumption happens. The
lifecycle is a chain of immutable events, each committing to its own
facts and to its parent:

    DecisionEvidenceV3  ──►  ConsumptionEvidenceV3  ──►  OutcomeEvidenceV3
        (evaluation)            (authority spent)          (what happened)

Each event carries its own id, type, version and timestamp, the
``evidence_payload_hash`` = SHA-256 over the RFC 8785 canonical form of
its versioned payload, and an Ed25519 signature over that payload hash.
A child event commits to its parent's id *and* its parent's payload hash,
so re-parenting an event or editing an ancestor breaks the chain.

Key separation
--------------
Signing uses a dedicated authority-evidence key. It is deliberately not
the agent request-signing key, not the offline evidence-pack seed, and
not the anchor-worker wallet: each of those asserts a different thing,
and a key that can assert two things can be misread as asserting the
wrong one. Key publication and rotation are a separate release action.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

from nacl.encoding import RawEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from api import jcs

#: Receipt schema version this module owns. v1 and v2 are elsewhere and frozen.
RECEIPT_SCHEMA_V3: Final[str] = "v3"

#: Versioned preimage identifier for every v3 evidence payload.
EVIDENCE_PAYLOAD_FORMAT: Final[str] = "inntris-authority-evidence-v3"

#: Environment variable holding the dedicated Ed25519 signing seed, base64.
EVIDENCE_SIGNING_KEY_ENV: Final[str] = "AUTHORITY_EVIDENCE_SIGNING_KEY"

#: Environment names in which an ephemeral development key may be minted.
_NON_PRODUCTION: Final[frozenset[str]] = frozenset({"development", "test", "ci"})


class EvidenceError(ValueError):
    """The evidence payload or its signing material is unusable."""


class EvidenceEventType(StrEnum):
    """The three links in the authority evidence chain."""

    DECISION = "decision"
    CONSUMPTION = "consumption"
    OUTCOME = "outcome"


def _require_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{field_name} must be a non-empty string")
    return value


def _instant(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise EvidenceError("evidence timestamps must be timezone-aware")
    iso = value.astimezone(UTC).isoformat()
    return iso[:-6] + "Z" if iso.endswith("+00:00") else iso


@dataclass(frozen=True, slots=True)
class EvidenceSigningKey:
    """A dedicated Ed25519 key for authority evidence, and nothing else."""

    signing_key: SigningKey
    key_id: str

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(
            bytes(self.signing_key.verify_key.encode(encoder=RawEncoder))
        ).decode("ascii")

    @property
    def fingerprint(self) -> str:
        """SHA-256 of the raw public key, as the rest of Core identifies keys."""
        return hashlib.sha256(
            bytes(self.signing_key.verify_key.encode(encoder=RawEncoder))
        ).hexdigest()

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self.signing_key.sign(message).signature).decode("ascii")


def load_evidence_signing_key(
    *,
    environment: str | None = None,
    seed_b64: str | None = None,
) -> EvidenceSigningKey:
    """Load the authority-evidence key from configuration.

    In production the seed must be configured explicitly: silently
    inventing a key would produce evidence that verifies against nothing
    anybody can check. Outside production an ephemeral key is minted so
    tests and local runs work without secret handling.
    """
    raw = seed_b64 if seed_b64 is not None else os.getenv(EVIDENCE_SIGNING_KEY_ENV)
    env = (environment or os.getenv("ENVIRONMENT", "development")).strip().lower()

    if raw:
        try:
            seed = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise EvidenceError(
                f"{EVIDENCE_SIGNING_KEY_ENV} must be base64-encoded"
            ) from exc
        if len(seed) != 32:
            raise EvidenceError(
                f"{EVIDENCE_SIGNING_KEY_ENV} must decode to a 32-byte Ed25519 seed"
            )
        key = SigningKey(seed)
    else:
        if env not in _NON_PRODUCTION:
            raise EvidenceError(
                f"{EVIDENCE_SIGNING_KEY_ENV} is required outside development; "
                "authority evidence signed by an unpublished ephemeral key "
                "cannot be verified by anyone"
            )
        key = SigningKey.generate()

    fingerprint = hashlib.sha256(
        bytes(key.verify_key.encode(encoder=RawEncoder))
    ).hexdigest()
    return EvidenceSigningKey(signing_key=key, key_id=f"authority-evidence-{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class SignedEvidenceEvent:
    """One immutable, authenticated link in the evidence chain."""

    event_id: str
    event_type: EvidenceEventType
    schema_version: str
    recorded_at: datetime
    payload: dict[str, Any]
    evidence_payload_hash: str
    signature_b64: str
    signing_key_id: str
    signing_key_fingerprint: str
    parent_event_id: str | None = None
    parent_payload_hash: str | None = None

    def as_public_dict(self) -> dict[str, Any]:
        """The wire form of this event, including its verification material."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "schema_version": self.schema_version,
            "recorded_at": _instant(self.recorded_at),
            "parent_event_id": self.parent_event_id,
            "parent_payload_hash": self.parent_payload_hash,
            "payload": self.payload,
            "evidence_payload_hash": self.evidence_payload_hash,
            "signature_b64": self.signature_b64,
            "signing_key_id": self.signing_key_id,
            "signing_key_fingerprint": self.signing_key_fingerprint,
        }


def build_evidence_payload(
    *,
    event_id: str,
    event_type: EvidenceEventType,
    recorded_at: datetime,
    body: dict[str, Any],
    signing_key_id: str,
    signing_key_fingerprint: str,
    parent_event_id: str | None = None,
    parent_payload_hash: str | None = None,
) -> dict[str, Any]:
    """The exact object that gets canonicalized, hashed and signed.

    ``format`` is a module constant rather than an input, so no caller can
    steer one event's preimage into another version's hash space. The
    parent link is *inside* the signed payload: re-parenting an event
    changes the hash and invalidates its signature.

    So is the **signer's identity**. If the key id and fingerprint sat only
    in the outer envelope, an attacker could swap in their own key and
    rewrite the metadata to name it, and the event would verify against
    the key they chose. Committing the fingerprint inside the signature
    closes that: the verifier recomputes the fingerprint of whatever key
    it was handed and compares it to the one the signature covers.
    """
    return {
        "format": EVIDENCE_PAYLOAD_FORMAT,
        "schema_version": RECEIPT_SCHEMA_V3,
        "event_id": _require_text(event_id, "event_id"),
        "event_type": event_type.value,
        "recorded_at": _instant(recorded_at),
        "parent_event_id": parent_event_id,
        "parent_payload_hash": parent_payload_hash,
        "signing_key_id": _require_text(signing_key_id, "signing_key_id"),
        "signing_key_fingerprint": _require_text(
            signing_key_fingerprint, "signing_key_fingerprint"
        ),
        "body": body,
    }


def evidence_payload_hash(payload: dict[str, Any]) -> str:
    """SHA-256 over the RFC 8785 canonical form of a versioned payload."""
    try:
        return jcs.sha256_hex(payload)
    except jcs.JCSError as exc:
        raise EvidenceError(f"evidence payload cannot be canonicalized: {exc}") from exc


def sign_evidence_event(
    *,
    event_id: str,
    event_type: EvidenceEventType,
    body: dict[str, Any],
    key: EvidenceSigningKey,
    recorded_at: datetime | None = None,
    parent: SignedEvidenceEvent | None = None,
) -> SignedEvidenceEvent:
    """Build, hash and sign one evidence event, linked to its parent."""
    # Validate BEFORE converting. A naive datetime's .astimezone(UTC)
    # silently reinterprets it as local time, which would sign evidence
    # carrying an instant nobody meant.
    if recorded_at is not None and recorded_at.tzinfo is None:
        raise EvidenceError("evidence timestamps must be timezone-aware")
    recorded = (recorded_at or datetime.now(UTC)).astimezone(UTC)
    payload = build_evidence_payload(
        event_id=event_id,
        event_type=event_type,
        recorded_at=recorded,
        body=body,
        signing_key_id=key.key_id,
        signing_key_fingerprint=key.fingerprint,
        parent_event_id=parent.event_id if parent is not None else None,
        parent_payload_hash=parent.evidence_payload_hash if parent is not None else None,
    )
    digest = evidence_payload_hash(payload)
    return SignedEvidenceEvent(
        event_id=event_id,
        event_type=event_type,
        schema_version=RECEIPT_SCHEMA_V3,
        recorded_at=recorded,
        payload=payload,
        evidence_payload_hash=digest,
        # Sign the digest bytes, matching how CryptoService verifies agent
        # signatures over an action hash.
        signature_b64=key.sign(bytes.fromhex(digest)),
        signing_key_id=key.key_id,
        signing_key_fingerprint=key.fingerprint,
        parent_event_id=parent.event_id if parent is not None else None,
        parent_payload_hash=parent.evidence_payload_hash if parent is not None else None,
    )


@dataclass(frozen=True, slots=True)
class EvidenceVerification:
    """Why an evidence event did or did not verify."""

    valid: bool
    failures: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.valid


def verify_evidence_event(
    event: dict[str, Any] | SignedEvidenceEvent,
    *,
    public_key_b64: str,
    parent: dict[str, Any] | SignedEvidenceEvent | None = None,
) -> EvidenceVerification:
    """Verify one event: payload hash, signature, and parent linkage.

    Recomputing the hash is not enough on its own — an attacker who edits
    a field can recompute it. The signature is what makes the recomputed
    hash mean something, so a mismatch in *either* fails.
    """
    record = event.as_public_dict() if isinstance(event, SignedEvidenceEvent) else dict(event)
    failures: list[str] = []

    payload = record.get("payload")
    if not isinstance(payload, dict):
        return EvidenceVerification(False, ("payload is missing or not an object",))

    if payload.get("format") != EVIDENCE_PAYLOAD_FORMAT:
        failures.append("payload format is not inntris-authority-evidence-v3")

    try:
        recomputed = evidence_payload_hash(payload)
    except EvidenceError as exc:
        return EvidenceVerification(False, (str(exc),))
    if recomputed != record.get("evidence_payload_hash"):
        failures.append("evidence_payload_hash does not match the payload")

    try:
        raw_public_key = base64.b64decode(public_key_b64, validate=True)
        verify_key = VerifyKey(raw_public_key, encoder=RawEncoder)
        verify_key.verify(
            bytes.fromhex(recomputed),
            base64.b64decode(record.get("signature_b64") or "", validate=True),
        )
    except (BadSignatureError, ValueError, TypeError):
        failures.append("signature does not verify over the recomputed payload hash")
        raw_public_key = b""

    # The signer's identity is part of what was signed. Recompute the
    # fingerprint of the key we were actually handed and require the
    # signature to cover exactly that key, so substituting a key and
    # rewriting the metadata to match it cannot pass.
    if raw_public_key:
        supplied_fingerprint = hashlib.sha256(raw_public_key).hexdigest()
        if payload.get("signing_key_fingerprint") != supplied_fingerprint:
            failures.append(
                "signing_key_fingerprint does not identify the verifying key"
            )
    if record.get("signing_key_fingerprint") != payload.get("signing_key_fingerprint"):
        failures.append("outer signing_key_fingerprint contradicts the signed payload")
    if record.get("signing_key_id") != payload.get("signing_key_id"):
        failures.append("outer signing_key_id contradicts the signed payload")

    if parent is not None:
        parent_record = (
            parent.as_public_dict() if isinstance(parent, SignedEvidenceEvent) else dict(parent)
        )
        if payload.get("parent_event_id") != parent_record.get("event_id"):
            failures.append("parent_event_id does not match the supplied parent")
        if payload.get("parent_payload_hash") != parent_record.get("evidence_payload_hash"):
            failures.append("parent_payload_hash does not match the supplied parent")
    elif payload.get("parent_event_id") is not None:
        failures.append("event claims a parent but none was supplied")

    return EvidenceVerification(not failures, tuple(failures))


@dataclass(frozen=True, slots=True)
class AuthorityEvidenceChain:
    """A decision and everything that followed from it."""

    decision: SignedEvidenceEvent
    consumption: SignedEvidenceEvent | None = None
    outcome: SignedEvidenceEvent | None = None

    def events(self) -> tuple[SignedEvidenceEvent, ...]:
        return tuple(e for e in (self.decision, self.consumption, self.outcome) if e is not None)

    def verify(self, *, public_key_b64: str) -> EvidenceVerification:
        """Verify every link, in order, including each parent relationship."""
        failures: list[str] = []
        previous: SignedEvidenceEvent | None = None
        for event in self.events():
            result = verify_evidence_event(
                event, public_key_b64=public_key_b64, parent=previous
            )
            failures.extend(f"{event.event_type.value}: {reason}" for reason in result.failures)
            previous = event
        return EvidenceVerification(not failures, tuple(failures))


# ---------------------------------------------------------------------------
# The three event bodies
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DecisionEvidenceV3:
    """What was decided, and under which policy and authority.

    ``signed_action_hash`` keeps its established meaning: the client-signed
    request hash, exactly as v1/v2 publish it under the name
    ``action_hash``. ``execution_action_hash`` is the separate semantic act
    digest and is never substituted for it.

    **On delegated authority.** The only delegation fact this phase stores
    durably is ``authority_scope_digest`` — a commitment to what the
    delegation permitted. It is published under that name and no other. It
    is emphatically NOT an artefact digest: nothing in this phase has seen
    the issuer's artefact, so a receipt that called it one would be
    asserting a verification that never happened. Issuer, external
    reference and artefact digest are absent until a provider phase
    persists them; absent is the truthful answer, and a null nobody can
    misread beats a plausible-looking value nobody checked.
    """

    audit_id: str
    agent_id: str
    organisation_id: str
    action_type: str
    domain: str
    decision: str
    execution_action_hash: str
    policy_snapshot_format: str
    policy_snapshot_digest: str
    signed_action_hash: str | None = None
    consequence_class: str | None = None
    grant_id: str | None = None
    grant_expires_at: datetime | None = None
    #: Digest of the delegated SCOPE this decision was bound by. A digest
    #: of what was permitted, never of the issuer's credential.
    authority_scope_digest: str | None = None
    executor_binding_digest: str | None = None
    reasons: tuple[str, ...] = ()

    def to_body(self) -> dict[str, Any]:
        return {
            "audit_id": _require_text(self.audit_id, "audit_id"),
            "agent_id": _require_text(self.agent_id, "agent_id"),
            "organisation_id": _require_text(self.organisation_id, "organisation_id"),
            "action_type": _require_text(self.action_type, "action_type"),
            "domain": _require_text(self.domain, "domain"),
            "decision": _require_text(self.decision, "decision"),
            "execution_action_hash": _require_text(
                self.execution_action_hash, "execution_action_hash"
            ),
            "signed_action_hash": self.signed_action_hash,
            "policy_snapshot_format": self.policy_snapshot_format,
            "policy_snapshot_digest": self.policy_snapshot_digest,
            "consequence_class": self.consequence_class,
            "grant_id": self.grant_id,
            "grant_expires_at": (
                _instant(self.grant_expires_at) if self.grant_expires_at else None
            ),
            "authority_scope_digest": self.authority_scope_digest,
            "executor_binding_digest": self.executor_binding_digest,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class ConsumptionEvidenceV3:
    """That the authority was spent, once, by this executor, for this act."""

    consumption_audit_id: str
    grant_id: str
    execution_action_hash: str
    execution_ref: str
    outcome: str
    executor_binding_digest: str
    executor_reference: str | None = None
    consumed_at: datetime | None = None

    def to_body(self) -> dict[str, Any]:
        return {
            "consumption_audit_id": _require_text(
                self.consumption_audit_id, "consumption_audit_id"
            ),
            "grant_id": _require_text(self.grant_id, "grant_id"),
            "execution_action_hash": _require_text(
                self.execution_action_hash, "execution_action_hash"
            ),
            "execution_ref": _require_text(self.execution_ref, "execution_ref"),
            "outcome": _require_text(self.outcome, "outcome"),
            # The binding is the proof; the reference is a label.
            "executor_binding_digest": _require_text(
                self.executor_binding_digest, "executor_binding_digest"
            ),
            "executor_reference": self.executor_reference,
            "consumed_at": _instant(self.consumed_at) if self.consumed_at else None,
        }


@dataclass(frozen=True, slots=True)
class OutcomeEvidenceV3:
    """What became of the execution, when that is trustworthily known."""

    grant_id: str
    outcome_state: str
    outcome_reference: str | None = None
    evidence_links: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    recorded_at: datetime | None = None

    def to_body(self) -> dict[str, Any]:
        return {
            "grant_id": _require_text(self.grant_id, "grant_id"),
            "outcome_state": _require_text(self.outcome_state, "outcome_state"),
            "outcome_reference": self.outcome_reference,
            "evidence_links": [dict(link) for link in self.evidence_links],
            "recorded_at": _instant(self.recorded_at) if self.recorded_at else None,
        }
