"""Phase 7A, Gate 3 — production issuer and delegate trust.

These tests exist because every step in resolving a delegation is a place
somebody could accidentally make Core accept something it should not. Each
step therefore has a test that a real attacker's move fails: an artefact
signed by an unconfigured issuer, by a retired key, by the right key over a
different payload, for a different principal, past its expiry, after
revocation, or simply too large to parse.

The end-to-end tests run against a real PostgreSQL, because revocation and
principal binding are database state and a fake would only prove the fake
agrees with itself.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from nacl.signing import SigningKey

from api import jcs
from api.core.authority.authority import (
    AuthorityVerificationFailure,
    DelegateBindingStatus,
    DelegatedAuthorityClaim,
    ExecutionContext,
    trusted_authority_construction,
)
from api.core.authority.decision import Decision, DecisionReason
from api.database import Database
from api.services.authority_provider import (
    ARTEFACT_EVIDENCE_KEY,
    AuthorityProviderFault,
    TrustedIssuerAuthorityProvider,
    build_authority_provider,
)
from api.services.authority_service import (
    AuthorityEvaluationService,
    AuthorityUnresolvable,
)
from api.services.executor_context import (
    AuthenticatedExecutorContext,
    executor_binding_digest,
)
from api.trust.artefact import (
    ARTEFACT_FORMAT,
    ArtefactBounds,
    ArtefactParseError,
    parse_authority_artefact,
)
from api.trust.issuer_registry import (
    TRUST_FILE_ENV,
    TRUST_INLINE_ENV,
    IssuerTrustConfigError,
    TrustedIssuerRegistry,
    load_registry_from_environment,
    public_key_fingerprint,
)
from api.trust.principal_bindings import (
    PrincipalBindingUnavailable,
    clear_principal_binding,
    load_principal_binding,
    set_principal_binding,
)
from api.trust.revocations import (
    RevocationSnapshot,
    RevocationSubject,
    load_revocations,
    set_revocation,
)

INTEGRATION_ENABLED = os.getenv("INNTRIS_DB_INTEGRATION") == "1"
DATABASE_URL = os.getenv("DATABASE_URL", "")

SERVER_SECRET = b"phase-7a-gate-3-test-secret-not-a-production-value"
ISSUER_ID = "test-issuer"
ACTION = "financial_transaction"

#: Deterministic so a failure is reproducible. Test-only material: it signs
#: nothing outside this file and verifies nothing in production.
ISSUER_SEED = hashlib.sha256(b"gate-3-issuer-seed").digest()
ROTATED_SEED = hashlib.sha256(b"gate-3-rotated-seed").digest()
ATTACKER_SEED = hashlib.sha256(b"gate-3-attacker-seed").digest()

ISSUER_KEY = SigningKey(ISSUER_SEED)
ROTATED_KEY = SigningKey(ROTATED_SEED)
ATTACKER_KEY = SigningKey(ATTACKER_SEED)


def _public(key: SigningKey) -> bytes:
    return bytes(key.verify_key)


def trust_document(
    *,
    issuer_status: str = "active",
    key_status: str = "active",
    expresses_delegate_binding: bool = False,
    include_rotated: bool = False,
    key_not_after: str | None = None,
) -> dict:
    keys = [
        {
            "key_id": "isk-2026-01",
            "public_key": _public(ISSUER_KEY).hex(),
            "fingerprint": public_key_fingerprint(_public(ISSUER_KEY)),
            "status": key_status,
        }
    ]
    if key_not_after is not None:
        keys[0]["not_after"] = key_not_after
    if include_rotated:
        keys.append(
            {
                "key_id": "isk-2026-02",
                "public_key": _public(ROTATED_KEY).hex(),
                "fingerprint": public_key_fingerprint(_public(ROTATED_KEY)),
                "status": "active",
            }
        )
    issuer: dict = {
        "issuer_id": ISSUER_ID,
        "display_name": "Gate 3 Test Issuer",
        "status": issuer_status,
        "keys": keys,
        "principal_claim_bindings": {"account_reference": "issuer_account_reference"},
        "scope_field_mapping": {
            "spend_ceiling": "max_amount",
            "denomination": "currency",
            "payees": "allowed_payees",
        },
    }
    if expresses_delegate_binding:
        issuer["expresses_delegate_binding"] = True
        issuer["delegate_binding_key"] = "issuer_delegate_key_fingerprint"
    return {"version": 1, "issuers": [issuer]}


def registry(**kwargs) -> TrustedIssuerRegistry:
    return TrustedIssuerRegistry.from_document(trust_document(**kwargs))


def build_artefact(
    *,
    signing_key: SigningKey = ISSUER_KEY,
    key_id: str = "isk-2026-01",
    issuer: str = ISSUER_ID,
    authority_id: str = "auth-001",
    account_reference: str = "acct-canary",
    delegate_fingerprint: str | None = None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    scope: dict | None = None,
    tamper: dict | None = None,
) -> dict:
    """A complete, signed issuer artefact.

    ``tamper`` is applied to the payload AFTER signing, which is exactly
    what an attacker who intercepts a genuine delegation can do.
    """
    payload: dict = {
        "format": ARTEFACT_FORMAT,
        "issuer": issuer,
        "authority_id": authority_id,
        "principal": {"account_reference": account_reference},
        "scope": (
            scope
            if scope is not None
            else {
                "spend_ceiling": "500.00",
                "denomination": "USD",
            }
        ),
    }
    if delegate_fingerprint is not None:
        payload["delegate"] = {"key_fingerprint": delegate_fingerprint}
    if not_before is not None:
        payload["not_before"] = not_before.isoformat().replace("+00:00", "Z")
    if not_after is not None:
        payload["not_after"] = not_after.isoformat().replace("+00:00", "Z")

    signature = signing_key.sign(jcs.canonicalize(payload)).signature
    document = {
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "key_id": key_id,
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }
    if tamper:
        document["payload"] = {**payload, **tamper}
    return document


def claim(artefact: dict, *, issuer: str = ISSUER_ID, authority_id: str = "auth-001"):
    return DelegatedAuthorityClaim(
        issuer=issuer,
        external_reference_id=authority_id,
        evidence={ARTEFACT_EVIDENCE_KEY: artefact},
    )


def context(
    *,
    organisation_id: str | None = None,
    principal_id: str | None = None,
    account_reference: str | None = "acct-canary",
    delegate_fingerprint: str | None = None,
) -> ExecutionContext:
    binding: dict[str, str] = {}
    if account_reference is not None:
        binding["issuer_account_reference"] = account_reference
    if delegate_fingerprint is not None:
        binding["issuer_delegate_key_fingerprint"] = delegate_fingerprint
    return ExecutionContext(
        trusted_authority_construction(),
        organisation_id=organisation_id or str(uuid4()),
        principal_id=principal_id or str(uuid4()),
        principal_binding=binding,
    )


def provider(
    *,
    revocations: RevocationSnapshot | None = None,
    now: datetime | None = None,
    **registry_kwargs,
) -> TrustedIssuerAuthorityProvider:
    return TrustedIssuerAuthorityProvider(
        registry(**registry_kwargs),
        revocations or RevocationSnapshot(),
        now=now,
    )


# =============================================================================
# Trust configuration
# =============================================================================


class TestTrustConfiguration:
    def test_a_well_formed_document_loads(self) -> None:
        reg = registry()
        issuer = reg.issuer(ISSUER_ID)
        assert issuer is not None
        assert issuer.keys[0].fingerprint == public_key_fingerprint(_public(ISSUER_KEY))

    def test_a_declared_fingerprint_that_disagrees_is_refused(self) -> None:
        document = trust_document()
        document["issuers"][0]["keys"][0]["fingerprint"] = "f" * 64
        with pytest.raises(IssuerTrustConfigError, match="declared fingerprint"):
            TrustedIssuerRegistry.from_document(document)

    def test_private_key_material_is_refused_not_ignored(self) -> None:
        document = trust_document()
        document["issuers"][0]["keys"][0]["private_key"] = "anything"
        with pytest.raises(IssuerTrustConfigError, match="forbidden key"):
            TrustedIssuerRegistry.from_document(document)

    def test_pem_private_material_anywhere_is_refused(self) -> None:
        document = trust_document()
        document["issuers"][0][
            "display_name"
        ] = "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"
        with pytest.raises(IssuerTrustConfigError, match="PEM private key material"):
            TrustedIssuerRegistry.from_document(document)

    def test_an_issuer_with_no_principal_binding_is_refused(self) -> None:
        """Otherwise its delegations would fit any principal in the org."""
        document = trust_document()
        del document["issuers"][0]["principal_claim_bindings"]
        with pytest.raises(IssuerTrustConfigError, match="principal_claim_bindings"):
            TrustedIssuerRegistry.from_document(document)

    def test_delegate_binding_needs_a_binding_key(self) -> None:
        document = trust_document()
        document["issuers"][0]["expresses_delegate_binding"] = True
        with pytest.raises(IssuerTrustConfigError, match="delegate_binding_key"):
            TrustedIssuerRegistry.from_document(document)

    def test_an_all_zero_public_key_is_refused(self) -> None:
        document = trust_document()
        document["issuers"][0]["keys"][0]["public_key"] = "00" * 32
        document["issuers"][0]["keys"][0].pop("fingerprint")
        with pytest.raises(IssuerTrustConfigError, match="all zeroes"):
            TrustedIssuerRegistry.from_document(document)

    def test_no_configuration_yields_an_empty_registry(self, monkeypatch) -> None:
        monkeypatch.delenv(TRUST_INLINE_ENV, raising=False)
        monkeypatch.delenv(TRUST_FILE_ENV, raising=False)
        assert not load_registry_from_environment()

    def test_a_malformed_configuration_raises_rather_than_loading_empty(self, monkeypatch) -> None:
        """A broken trust file must fail the deployment, not come up trusting
        nobody and refusing traffic it should serve."""
        monkeypatch.delenv(TRUST_FILE_ENV, raising=False)
        monkeypatch.setenv(TRUST_INLINE_ENV, "{not json")
        with pytest.raises(IssuerTrustConfigError):
            load_registry_from_environment()

    def test_both_configuration_sources_at_once_is_refused(self, monkeypatch) -> None:
        monkeypatch.setenv(TRUST_INLINE_ENV, json.dumps(trust_document()))
        monkeypatch.setenv(TRUST_FILE_ENV, "/nonexistent")
        with pytest.raises(IssuerTrustConfigError, match="exactly one"):
            load_registry_from_environment()

    def test_a_file_configuration_loads(self, monkeypatch, tmp_path) -> None:
        path = tmp_path / "trust.json"
        path.write_text(json.dumps(trust_document()), encoding="utf-8")
        monkeypatch.delenv(TRUST_INLINE_ENV, raising=False)
        monkeypatch.setenv(TRUST_FILE_ENV, str(path))
        assert load_registry_from_environment().issuer(ISSUER_ID) is not None

    def test_fingerprints_are_reportable_for_the_release_record(self) -> None:
        listed = registry(include_rotated=True).fingerprints()[ISSUER_ID]
        assert len(listed) == 2
        assert all(entry.endswith(":active") for entry in listed)


# =============================================================================
# Bounded parsing
# =============================================================================


class TestBoundedParsing:
    def test_an_oversized_artefact_is_refused_before_parsing(self) -> None:
        bounds = ArtefactBounds(max_bytes=128)
        with pytest.raises(ArtefactParseError, match="byte limit"):
            parse_authority_artefact(build_artefact(), bounds=bounds)

    def test_deep_nesting_is_refused(self) -> None:
        nested: dict = {"a": 1}
        for _ in range(20):
            nested = {"a": nested}
        artefact = build_artefact(scope={"spend_ceiling": "1.00"})
        artefact["payload"]["scope"]["nested"] = nested
        with pytest.raises(ArtefactParseError, match="nesting depth"):
            parse_authority_artefact(artefact)

    def test_an_over_long_array_is_refused(self) -> None:
        artefact = build_artefact(scope={"payees": [f"0x{index:040x}" for index in range(200)]})
        with pytest.raises(ArtefactParseError, match="array length"):
            parse_authority_artefact(artefact)

    def test_duplicate_keys_are_refused_rather_than_resolved(self) -> None:
        raw = '{"payload": {"a": 1, "a": 2}, "signature": {}}'
        with pytest.raises(ArtefactParseError, match="duplicate key"):
            parse_authority_artefact(raw)

    def test_a_floating_point_amount_is_refused(self) -> None:
        artefact = build_artefact(scope={"spend_ceiling": 500.0})
        with pytest.raises(ArtefactParseError, match="floating-point"):
            parse_authority_artefact(artefact)

    def test_an_unknown_format_is_refused(self) -> None:
        artefact = build_artefact()
        artefact["payload"]["format"] = "something-else-v9"
        with pytest.raises(ArtefactParseError, match="unknown artefact format"):
            parse_authority_artefact(artefact)

    def test_an_unsupported_algorithm_is_refused(self) -> None:
        artefact = build_artefact()
        artefact["signature"]["algorithm"] = "rsa-pss"
        with pytest.raises(ArtefactParseError, match="unsupported signature algorithm"):
            parse_authority_artefact(artefact)

    def test_a_naive_validity_instant_is_refused(self) -> None:
        artefact = build_artefact()
        artefact["payload"]["not_after"] = "2030-01-01T00:00:00"
        with pytest.raises(ArtefactParseError, match="explicit UTC offset"):
            parse_authority_artefact(artefact)

    def test_key_ordering_does_not_change_the_digest(self) -> None:
        """The signature covers the canonical form, so a re-ordered payload
        is the same payload and must hash identically."""
        artefact = build_artefact()
        reordered = {
            "signature": artefact["signature"],
            "payload": dict(reversed(list(artefact["payload"].items()))),
        }
        assert (
            parse_authority_artefact(artefact).artefact_digest
            == parse_authority_artefact(reordered).artefact_digest
        )


# =============================================================================
# Verification
# =============================================================================


class TestVerification:
    def test_a_genuine_delegation_verifies(self) -> None:
        resolved = provider().resolve(claim(build_artefact()), context())
        assert resolved.is_verified
        assert resolved.reference.verified_at is not None
        assert dict(resolved.scope) == {"max_amount": "500.00", "currency": "USD"}

    def test_an_unconfigured_issuer_does_not_verify(self) -> None:
        artefact = build_artefact(issuer="somebody-else")
        resolved = provider().resolve(claim(artefact, issuer="somebody-else"), context())
        assert not resolved.is_verified
        assert AuthorityVerificationFailure.AUTHORITY_NOT_FOUND in resolved.failure_codes

    def test_a_disabled_issuer_does_not_verify(self) -> None:
        resolved = provider(issuer_status="disabled").resolve(claim(build_artefact()), context())
        assert AuthorityVerificationFailure.AUTHORITY_REVOKED in resolved.failure_codes

    def test_an_attacker_signature_does_not_verify(self) -> None:
        artefact = build_artefact(signing_key=ATTACKER_KEY)
        resolved = provider().resolve(claim(artefact), context())
        assert AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID in resolved.failure_codes

    def test_a_tampered_payload_does_not_verify(self) -> None:
        """The exact move: intercept a real delegation, raise the ceiling."""
        artefact = build_artefact(
            tamper={
                "format": ARTEFACT_FORMAT,
                "issuer": ISSUER_ID,
                "authority_id": "auth-001",
                "principal": {"account_reference": "acct-canary"},
                "scope": {"spend_ceiling": "5000000.00", "denomination": "USD"},
            }
        )
        resolved = provider().resolve(claim(artefact), context())
        assert AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID in resolved.failure_codes

    def test_an_unknown_key_id_does_not_verify(self) -> None:
        artefact = build_artefact(key_id="isk-does-not-exist")
        resolved = provider().resolve(claim(artefact), context())
        assert AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID in resolved.failure_codes

    def test_a_retired_key_cannot_authenticate_new_authority(self) -> None:
        resolved = provider(key_status="retired").resolve(claim(build_artefact()), context())
        assert AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID in resolved.failure_codes

    def test_a_revoked_key_in_configuration_does_not_verify(self) -> None:
        resolved = provider(key_status="revoked").resolve(claim(build_artefact()), context())
        assert AuthorityVerificationFailure.AUTHORITY_REVOKED in resolved.failure_codes

    def test_a_key_past_its_validity_window_cannot_sign_new_authority(self) -> None:
        resolved = provider(
            key_not_after="2020-01-01T00:00:00Z",
        ).resolve(claim(build_artefact()), context())
        assert AuthorityVerificationFailure.AUTHORITY_SIGNATURE_INVALID in resolved.failure_codes

    def test_rotation_keeps_both_keys_verifying_while_both_are_active(self) -> None:
        reg = provider(include_rotated=True)
        assert reg.resolve(claim(build_artefact()), context()).is_verified
        rotated = build_artefact(signing_key=ROTATED_KEY, key_id="isk-2026-02")
        assert reg.resolve(claim(rotated), context()).is_verified

    def test_a_claim_naming_a_different_issuer_from_the_artefact_is_refused(
        self,
    ) -> None:
        artefact = build_artefact()
        mismatched = DelegatedAuthorityClaim(
            issuer="somebody-else",
            external_reference_id="auth-001",
            evidence={ARTEFACT_EVIDENCE_KEY: artefact},
        )
        resolved = provider().resolve(mismatched, context())
        assert AuthorityVerificationFailure.AUTHORITY_DIGEST_MISMATCH in resolved.failure_codes

    def test_a_claim_naming_a_different_authority_id_is_refused(self) -> None:
        artefact = build_artefact(authority_id="auth-002")
        resolved = provider().resolve(claim(artefact), context())
        assert AuthorityVerificationFailure.AUTHORITY_DIGEST_MISMATCH in resolved.failure_codes

    def test_a_claim_with_no_artefact_is_refused(self) -> None:
        bare = DelegatedAuthorityClaim(issuer=ISSUER_ID, external_reference_id="auth-001")
        resolved = provider().resolve(bare, context())
        assert AuthorityVerificationFailure.AUTHORITY_NOT_FOUND in resolved.failure_codes

    def test_resolving_no_claim_is_a_fault_not_a_verdict(self) -> None:
        with pytest.raises(AuthorityProviderFault):
            provider().resolve(None, context())


class TestValidityWindow:
    def test_a_delegation_that_has_not_started_is_refused(self) -> None:
        now = datetime.now(UTC)
        artefact = build_artefact(not_before=now + timedelta(hours=1))
        resolved = provider(now=now).resolve(claim(artefact), context())
        assert AuthorityVerificationFailure.AUTHORITY_NOT_YET_VALID in resolved.failure_codes

    def test_an_expired_delegation_is_refused(self) -> None:
        now = datetime.now(UTC)
        artefact = build_artefact(not_after=now - timedelta(seconds=1))
        resolved = provider(now=now).resolve(claim(artefact), context())
        assert AuthorityVerificationFailure.AUTHORITY_EXPIRED in resolved.failure_codes

    def test_expiry_is_exclusive_at_the_instant_itself(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        artefact = build_artefact(not_after=now)
        resolved = provider(now=now).resolve(claim(artefact), context())
        assert AuthorityVerificationFailure.AUTHORITY_EXPIRED in resolved.failure_codes


class TestPrincipalBinding:
    """The step that stops principal A's real delegation being spent by B."""

    def test_a_delegation_for_another_principal_is_refused(self) -> None:
        artefact = build_artefact(account_reference="acct-somebody-else")
        resolved = provider().resolve(claim(artefact), context(account_reference="acct-canary"))
        assert AuthorityVerificationFailure.AUTHORITY_PRINCIPAL_MISMATCH in resolved.failure_codes

    def test_a_principal_with_no_recorded_identity_cannot_use_any_delegation(
        self,
    ) -> None:
        resolved = provider().resolve(claim(build_artefact()), context(account_reference=None))
        assert AuthorityVerificationFailure.AUTHORITY_PRINCIPAL_MISMATCH in resolved.failure_codes

    def test_a_delegation_stating_no_principal_is_refused(self) -> None:
        artefact = build_artefact()
        del artefact["payload"]["principal"]["account_reference"]
        artefact["signature"]["value"] = base64.b64encode(
            ISSUER_KEY.sign(jcs.canonicalize(artefact["payload"])).signature
        ).decode("ascii")
        resolved = provider().resolve(claim(artefact), context())
        assert AuthorityVerificationFailure.AUTHORITY_PRINCIPAL_MISMATCH in resolved.failure_codes


class TestDelegateBinding:
    def test_an_issuer_that_expresses_no_binding_reports_unsupported(self) -> None:
        resolved = provider().resolve(claim(build_artefact()), context())
        assert resolved.delegate_binding_status is DelegateBindingStatus.UNSUPPORTED

    def test_a_matching_delegate_key_is_bound(self) -> None:
        fingerprint = "a" * 64
        artefact = build_artefact(delegate_fingerprint=fingerprint)
        resolved = provider(expresses_delegate_binding=True).resolve(
            claim(artefact), context(delegate_fingerprint=fingerprint)
        )
        assert resolved.is_verified
        assert resolved.delegate_binding_status is DelegateBindingStatus.BOUND

    def test_a_different_delegate_key_is_not_bound(self) -> None:
        artefact = build_artefact(delegate_fingerprint="b" * 64)
        resolved = provider(expresses_delegate_binding=True).resolve(
            claim(artefact), context(delegate_fingerprint="a" * 64)
        )
        assert resolved.delegate_binding_status is DelegateBindingStatus.NOT_BOUND
        assert AuthorityVerificationFailure.AUTHORITY_DELEGATE_NOT_BOUND in resolved.failure_codes

    def test_a_missing_delegate_claim_is_not_bound(self) -> None:
        resolved = provider(expresses_delegate_binding=True).resolve(
            claim(build_artefact()), context(delegate_fingerprint="a" * 64)
        )
        assert AuthorityVerificationFailure.AUTHORITY_DELEGATE_NOT_BOUND in resolved.failure_codes


class TestScopeTranslation:
    def test_configured_fields_are_translated_to_neutral_keys(self) -> None:
        resolved = provider().resolve(claim(build_artefact()), context())
        assert set(resolved.scope) == {"max_amount", "currency"}

    def test_an_unmapped_field_is_carried_through_rather_than_dropped(self) -> None:
        """Downstream it becomes an unsupported constraint and fails closed;
        dropping it would silently broaden what the issuer granted."""
        artefact = build_artefact(scope={"spend_ceiling": "10.00", "velocity_rule": "3-per-day"})
        resolved = provider().resolve(claim(artefact), context())
        assert resolved.scope["velocity_rule"] == "3-per-day"


class TestRevocationInMemory:
    def _revoked(self, subject: RevocationSubject, subject_id: str, issuer: str | None):
        return RevocationSnapshot(revoked=frozenset({(subject.value, issuer or "*", subject_id)}))

    def test_a_revoked_issuer_stops_everything_it_signed(self) -> None:
        snapshot = self._revoked(RevocationSubject.ISSUER, ISSUER_ID, None)
        resolved = provider(revocations=snapshot).resolve(claim(build_artefact()), context())
        assert AuthorityVerificationFailure.AUTHORITY_REVOKED in resolved.failure_codes

    def test_a_revoked_signing_key_stops_its_delegations(self) -> None:
        snapshot = self._revoked(
            RevocationSubject.ISSUER_KEY,
            public_key_fingerprint(_public(ISSUER_KEY)),
            ISSUER_ID,
        )
        resolved = provider(revocations=snapshot).resolve(claim(build_artefact()), context())
        assert AuthorityVerificationFailure.AUTHORITY_REVOKED in resolved.failure_codes

    def test_a_revoked_delegation_reference_stops_only_itself(self) -> None:
        snapshot = self._revoked(RevocationSubject.AUTHORITY_REFERENCE, "auth-001", ISSUER_ID)
        assert (
            AuthorityVerificationFailure.AUTHORITY_REVOKED
            in provider(revocations=snapshot)
            .resolve(claim(build_artefact()), context())
            .failure_codes
        )
        other = build_artefact(authority_id="auth-002")
        assert (
            provider(revocations=snapshot)
            .resolve(claim(other, authority_id="auth-002"), context())
            .is_verified
        )

    def test_a_revocation_for_another_issuer_does_not_apply(self) -> None:
        snapshot = self._revoked(
            RevocationSubject.ISSUER_KEY,
            public_key_fingerprint(_public(ISSUER_KEY)),
            "a-different-issuer",
        )
        assert (
            provider(revocations=snapshot).resolve(claim(build_artefact()), context()).is_verified
        )


# =============================================================================
# End to end, against a real database
# =============================================================================


pg = pytest.mark.skipif(
    not (INTEGRATION_ENABLED and DATABASE_URL),
    reason="issuer trust integration tests require INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = await Database.create(DATABASE_URL, min_size=2, max_size=8)
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
async def org_and_agent(db: Database) -> tuple[UUID, UUID]:
    org_id, agent_id = uuid4(), uuid4()
    async with db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
            VALUES ($1, $2, 'enterprise', $3, sha256($4::BYTEA))
            """,
            org_id,
            f"gate3-{org_id}",
            f"gate3-{org_id}@invalid.test",
            str(org_id).encode(),
        )
        await conn.execute(
            """
            INSERT INTO agents (
                id, org_id, name, public_key, public_key_fingerprint, trust_score,
                status, daily_limit_usd, per_action_limit_usd, allowed_actions,
                blocked_actions, rate_limit_per_minute, metadata
            ) VALUES (
                $1, $2, $3, decode(repeat('00', 32), 'hex'), $4, 95, 'active',
                10000, 10000, ARRAY['financial_transaction']::TEXT[],
                ARRAY[]::TEXT[], 600, '{"sandbox": true}'::JSONB
            )
            """,
            agent_id,
            org_id,
            f"gate3-agent-{agent_id}",
            uuid4().hex + uuid4().hex,
        )
    return org_id, agent_id


def executor(org_id: UUID) -> AuthenticatedExecutorContext:
    key_id = "gate3-executor-key"
    return AuthenticatedExecutorContext(
        organisation_id=org_id,
        api_key_id=key_id,
        scopes=frozenset({"write"}),
        binding_digest=executor_binding_digest(organisation_id=org_id, api_key_id=key_id),
    )


def payment_payload(amount: str = "12.00") -> dict:
    return {
        "amount": amount,
        "currency": "USD",
        "recipient": "0x" + "ab" * 20,
        "chain": "base",
    }


@pg
class TestPrincipalBindingStore:
    async def test_a_binding_round_trips(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        await set_principal_binding(
            db,
            organisation_id=org_id,
            agent_id=agent_id,
            issuer=ISSUER_ID,
            binding_key="issuer_account_reference",
            binding_value="acct-canary",
            changed_by="gate3-test",
            approval_reference="CHG-3-1",
            reason="canary provisioning",
        )
        loaded = await load_principal_binding(db, agent_id=agent_id, issuer=ISSUER_ID)
        assert loaded == {"issuer_account_reference": "acct-canary"}

    async def test_a_binding_is_scoped_to_its_issuer(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        await set_principal_binding(
            db,
            organisation_id=org_id,
            agent_id=agent_id,
            issuer=ISSUER_ID,
            binding_key="issuer_account_reference",
            binding_value="acct-canary",
            changed_by="gate3-test",
            approval_reference="CHG-3-2",
            reason="scoped",
        )
        assert await load_principal_binding(db, agent_id=agent_id, issuer="other-issuer") == {}

    async def test_clearing_a_binding_removes_the_identity(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        await set_principal_binding(
            db,
            organisation_id=org_id,
            agent_id=agent_id,
            issuer=ISSUER_ID,
            binding_key="issuer_account_reference",
            binding_value="acct-canary",
            changed_by="gate3-test",
            approval_reference="CHG-3-3",
            reason="on",
        )
        assert await clear_principal_binding(
            db,
            organisation_id=org_id,
            agent_id=agent_id,
            issuer=ISSUER_ID,
            binding_key="issuer_account_reference",
            changed_by="gate3-test",
            approval_reference="CHG-3-4",
            reason="off",
        )
        assert await load_principal_binding(db, agent_id=agent_id, issuer=ISSUER_ID) == {}

    async def test_an_unreadable_binding_store_is_not_silently_empty(self) -> None:
        import asyncpg

        class Broken:
            def acquire(self):  # noqa: ANN201 - test double
                raise asyncpg.UndefinedTableError("missing")

        with pytest.raises(PrincipalBindingUnavailable):
            await load_principal_binding(Broken(), agent_id=uuid4(), issuer=ISSUER_ID)


@pg
class TestRevocationStore:
    async def test_revoking_and_reinstating_a_key(self, db) -> None:
        fingerprint = uuid4().hex + uuid4().hex
        await set_revocation(
            db,
            subject_type=RevocationSubject.ISSUER_KEY,
            subject_id=fingerprint,
            issuer=ISSUER_ID,
            revoked=True,
            changed_by="incident-commander",
            approval_reference="INC-3-1",
            reason="key compromise",
        )
        snapshot = await load_revocations(
            db, subjects=[(RevocationSubject.ISSUER_KEY, fingerprint, ISSUER_ID)]
        )
        assert snapshot.is_revoked(RevocationSubject.ISSUER_KEY, fingerprint, issuer=ISSUER_ID)

        await set_revocation(
            db,
            subject_type=RevocationSubject.ISSUER_KEY,
            subject_id=fingerprint,
            issuer=ISSUER_ID,
            revoked=False,
            changed_by="incident-commander",
            approval_reference="INC-3-2",
            reason="false alarm",
        )
        snapshot = await load_revocations(
            db, subjects=[(RevocationSubject.ISSUER_KEY, fingerprint, ISSUER_ID)]
        )
        assert not snapshot.is_revoked(RevocationSubject.ISSUER_KEY, fingerprint, issuer=ISSUER_ID)

    async def test_a_key_revocation_needs_an_issuer(self, db) -> None:
        with pytest.raises(ValueError, match="must name the issuer"):
            await set_revocation(
                db,
                subject_type=RevocationSubject.ISSUER_KEY,
                subject_id="a" * 64,
                revoked=True,
                changed_by="x",
                approval_reference="y",
                reason="z",
            )

    async def test_one_issuers_revocation_does_not_reach_another(self, db) -> None:
        fingerprint = uuid4().hex + uuid4().hex
        await set_revocation(
            db,
            subject_type=RevocationSubject.ISSUER_KEY,
            subject_id=fingerprint,
            issuer="issuer-a",
            revoked=True,
            changed_by="incident-commander",
            approval_reference="INC-3-3",
            reason="compromise at issuer-a",
        )
        snapshot = await load_revocations(
            db,
            subjects=[
                (RevocationSubject.ISSUER_KEY, fingerprint, "issuer-a"),
                (RevocationSubject.ISSUER_KEY, fingerprint, "issuer-b"),
            ],
        )
        assert snapshot.is_revoked(RevocationSubject.ISSUER_KEY, fingerprint, issuer="issuer-a")
        assert not snapshot.is_revoked(RevocationSubject.ISSUER_KEY, fingerprint, issuer="issuer-b")

    async def test_an_unreadable_revocation_store_fails_closed(self) -> None:
        import asyncpg

        class Broken:
            def acquire(self):  # noqa: ANN201 - test double
                raise asyncpg.UndefinedTableError("missing")

        with pytest.raises(AuthorityProviderFault):
            await build_authority_provider(
                Broken(),
                claim=claim(build_artefact()),
                registry=registry(),
            )


@pg
class TestEndToEnd:
    """A delegation that reaches a real decision, and the ways it must not."""

    async def _bind(self, db, org_id, agent_id, value="acct-canary") -> None:
        await set_principal_binding(
            db,
            organisation_id=org_id,
            agent_id=agent_id,
            issuer=ISSUER_ID,
            binding_key="issuer_account_reference",
            binding_value=value,
            changed_by="gate3-test",
            approval_reference="CHG-3-E2E",
            reason="end-to-end",
        )

    async def test_a_verified_delegation_narrows_an_allowed_payment(
        self, db, org_and_agent
    ) -> None:
        org_id, agent_id = org_and_agent
        await self._bind(db, org_id, agent_id)
        agent = await db.get_agent_by_id(agent_id)
        service = AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET, trust_registry=registry()
        )
        artefact = build_artefact(scope={"spend_ceiling": "500.00", "denomination": "USD"})
        result = await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload("12.00"),
            executor=executor(org_id),
            issuance_ref=f"e2e-{uuid4()}",
            authority_claim=claim(artefact),
        )
        assert result.decision is Decision.ALLOW
        assert result.authority_token is not None
        assert result.authority_scope_digest is not None

    async def test_a_payment_above_the_delegated_ceiling_is_blocked(
        self, db, org_and_agent
    ) -> None:
        org_id, agent_id = org_and_agent
        await self._bind(db, org_id, agent_id)
        agent = await db.get_agent_by_id(agent_id)
        service = AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET, trust_registry=registry()
        )
        artefact = build_artefact(scope={"spend_ceiling": "10.00", "denomination": "USD"})
        result = await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload("500.00"),
            executor=executor(org_id),
            issuance_ref=f"e2e-over-{uuid4()}",
            authority_claim=claim(artefact),
        )
        assert result.decision is Decision.BLOCK
        assert result.authority_token is None

    async def test_a_delegation_for_another_account_is_blocked(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        await self._bind(db, org_id, agent_id, value="acct-ours")
        agent = await db.get_agent_by_id(agent_id)
        service = AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET, trust_registry=registry()
        )
        artefact = build_artefact(account_reference="acct-theirs")
        result = await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref=f"e2e-wrong-{uuid4()}",
            authority_claim=claim(artefact),
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_VERIFICATION_FAILED in result.reasons

    async def test_an_unbound_principal_cannot_use_a_genuine_delegation(
        self, db, org_and_agent
    ) -> None:
        """No binding recorded at all: the delegation verifies cryptographically
        and still cannot be tied to this principal."""
        org_id, agent_id = org_and_agent
        agent = await db.get_agent_by_id(agent_id)
        service = AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET, trust_registry=registry()
        )
        result = await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref=f"e2e-unbound-{uuid4()}",
            authority_claim=claim(build_artefact()),
        )
        assert result.decision is Decision.BLOCK

    async def test_revoking_the_delegation_stops_the_next_issuance(self, db, org_and_agent) -> None:
        org_id, agent_id = org_and_agent
        await self._bind(db, org_id, agent_id)
        agent = await db.get_agent_by_id(agent_id)
        service = AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET, trust_registry=registry()
        )
        reference = f"auth-{uuid4()}"
        artefact = build_artefact(authority_id=reference)

        before = await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref=f"e2e-before-{uuid4()}",
            authority_claim=claim(artefact, authority_id=reference),
        )
        assert before.decision is Decision.ALLOW

        await set_revocation(
            db,
            subject_type=RevocationSubject.AUTHORITY_REFERENCE,
            subject_id=reference,
            issuer=ISSUER_ID,
            revoked=True,
            changed_by="incident-commander",
            approval_reference="INC-3-E2E",
            reason="customer reported compromise",
        )

        after = await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref=f"e2e-after-{uuid4()}",
            authority_claim=claim(artefact, authority_id=reference),
        )
        assert after.decision is Decision.BLOCK
        assert after.authority_token is None

    async def test_no_configured_issuers_reports_provider_unavailable(
        self, db, org_and_agent
    ) -> None:
        """A deployment that trusts nobody says so, rather than blaming the
        caller's artefact."""
        org_id, agent_id = org_and_agent
        agent = await db.get_agent_by_id(agent_id)
        service = AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET, trust_registry=TrustedIssuerRegistry.empty()
        )
        result = await service.evaluate(
            agent=agent,
            action_type=ACTION,
            payload=payment_payload(),
            executor=executor(org_id),
            issuance_ref=f"e2e-notrust-{uuid4()}",
            authority_claim=claim(build_artefact()),
        )
        assert result.decision is Decision.BLOCK
        assert DecisionReason.AUTHORITY_PROVIDER_UNAVAILABLE in result.reasons

    async def test_an_unresolvable_provider_never_falls_back_to_no_delegation(
        self, db, org_and_agent
    ) -> None:
        """Presenting authority must never quietly take the wider path."""
        _org_id, _agent_id = org_and_agent
        service = AuthorityEvaluationService(
            db, server_secret=SERVER_SECRET, trust_registry=TrustedIssuerRegistry.empty()
        )
        with pytest.raises(AuthorityUnresolvable):
            await service.provider_for(claim(build_artefact()))
