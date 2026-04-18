"""Phase 4B — GDPR erasure tests.

Two tiers:

* Unit tests (always run) exercise the Python wrapper: legal-basis
  whitelisting, required requested_by, is_row_erased predicate.

* Integration tests (gated on INNTRIS_DB_INTEGRATION=1) exercise the
  actual DB function against Postgres. They are the only place we can
  verify the preservation invariants end-to-end: action_hash /
  signature / merkle_* unchanged, payload tombstoned, IP/UA NULLed,
  erasure_requests row created with correct rows_affected.
"""

from __future__ import annotations

import os
import uuid

import pytest

from api.erasure import ErasureResult, erase_personal_data, is_row_erased


# -----------------------------------------------------------------------------
# Unit tests — wrapper validation
# -----------------------------------------------------------------------------

class _FakeConn:
    """Minimal stub so we can assert what the wrapper *would* send."""

    def __init__(self, fake_request_id: uuid.UUID | None = None,
                 fake_rows: int = 0) -> None:
        self.calls: list[tuple[str, tuple]] = []
        self._request_id = fake_request_id or uuid.uuid4()
        self._rows = fake_rows

    async def fetchval(self, query: str, *args):
        self.calls.append((query, args))
        if "app.erase_personal_data" in query:
            return self._request_id
        if "rows_affected" in query:
            return self._rows
        raise AssertionError(f"unexpected query: {query}")


async def test_erase_rejects_unknown_legal_basis() -> None:
    conn = _FakeConn()
    with pytest.raises(ValueError, match="unsupported legal_basis"):
        await erase_personal_data(
            conn,  # type: ignore[arg-type]
            organization_id=uuid.uuid4(),
            requested_by="ops@inntris.com",
            legal_basis="gdpr_17",  # typo
        )
    # No DB work should have happened.
    assert conn.calls == []


async def test_erase_requires_requested_by() -> None:
    conn = _FakeConn()
    with pytest.raises(ValueError, match="requested_by is required"):
        await erase_personal_data(
            conn,  # type: ignore[arg-type]
            organization_id=uuid.uuid4(),
            requested_by="   ",
            legal_basis="gdpr_art17",
        )
    assert conn.calls == []


async def test_erase_happy_path_returns_request_id_and_rows() -> None:
    expected_id = uuid.uuid4()
    conn = _FakeConn(fake_request_id=expected_id, fake_rows=17)
    result = await erase_personal_data(
        conn,  # type: ignore[arg-type]
        organization_id=uuid.uuid4(),
        requested_by="dpo@inntris.com",
        legal_basis="ccpa_1798_105",
        reason="Data subject request #4821",
    )
    assert isinstance(result, ErasureResult)
    assert result.request_id == expected_id
    assert result.rows_affected == 17
    # Both queries ran: the SELECT app.erase_personal_data() and the
    # rows_affected lookup.
    assert len(conn.calls) == 2
    assert "app.erase_personal_data" in conn.calls[0][0]
    assert "rows_affected" in conn.calls[1][0]


async def test_erase_trims_requested_by() -> None:
    conn = _FakeConn(fake_rows=0)
    await erase_personal_data(
        conn,  # type: ignore[arg-type]
        organization_id=uuid.uuid4(),
        requested_by="  ops@inntris.com  ",
        legal_basis="operator_request",
    )
    _, args = conn.calls[0]
    # args = (org, agent, requested_by, basis, reason)
    assert args[2] == "ops@inntris.com"


def test_is_row_erased_true_for_tombstone() -> None:
    assert is_row_erased({"erased": True, "erased_at": "2026-04-18"})


def test_is_row_erased_false_for_live_payload() -> None:
    assert not is_row_erased({"action_type": "web_fetch", "url": "https://example.com"})


def test_is_row_erased_false_for_empty_dict() -> None:
    assert not is_row_erased({})


# -----------------------------------------------------------------------------
# Integration tests — real Postgres with migration 006 applied
# -----------------------------------------------------------------------------

_integration = pytest.mark.skipif(
    os.getenv("INNTRIS_DB_INTEGRATION") != "1" or not os.getenv("DATABASE_URL"),
    reason="erasure integration test requires INNTRIS_DB_INTEGRATION=1 and DATABASE_URL",
)


@_integration
@pytest.mark.asyncio
async def test_integration_erasure_preserves_forensic_fields() -> None:
    """The load-bearing test: after erasure, a row must still carry the
    Merkle leaf data so on-chain proofs continue to verify, but payload
    and client-identifying fields must be gone."""
    import asyncpg

    conn = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        # Seed: one org, one agent, one audit log with real-shaped data.
        org_id = await conn.fetchval(
            """
            INSERT INTO organizations (name, contact_email, api_key_hash)
            VALUES ('erasure-test-org', 'ops@example.com', decode('00','hex'))
            RETURNING id
            """
        )
        agent_id = await conn.fetchval(
            """
            INSERT INTO agents (
                organization_id, name, public_key, public_key_fingerprint, status
            )
            VALUES ($1, 'erasure-test-agent', '\\x00', repeat('0', 64), 'active')
            RETURNING id
            """,
            org_id,
        )
        log_id = await conn.fetchval(
            """
            INSERT INTO audit_logs (
                agent_id, action_type, action_hash, payload, verdict,
                signature, signature_valid, trust_score_at_time,
                request_ip, request_user_agent, merkle_leaf_index,
                chain_previous_hash
            )
            VALUES (
                $1, 'web_fetch', repeat('a', 64),
                $2::jsonb, 'approved',
                '\\x010203', true, 100,
                '203.0.113.42', 'curl/8.1.2', 42, repeat('b', 64)
            )
            RETURNING id
            """,
            agent_id,
            '{"url":"https://example.com","user_email":"subject@example.com"}',
        )

        # Capture forensic fields pre-erasure.
        before = await conn.fetchrow(
            "SELECT action_hash, signature, merkle_leaf_index, chain_previous_hash "
            "FROM audit_logs WHERE id = $1",
            log_id,
        )

        result = await erase_personal_data(
            conn,
            organization_id=org_id,
            requested_by="dpo@example.com",
            legal_basis="gdpr_art17",
            reason="DSR-2026-001",
        )

        after = await conn.fetchrow(
            "SELECT action_hash, signature, merkle_leaf_index, "
            "chain_previous_hash, payload, request_ip, request_user_agent "
            "FROM audit_logs WHERE id = $1",
            log_id,
        )

        # Preserved: proof artifacts are identical bit-for-bit.
        assert after["action_hash"] == before["action_hash"]
        assert after["signature"] == before["signature"]
        assert after["merkle_leaf_index"] == before["merkle_leaf_index"]
        assert after["chain_previous_hash"] == before["chain_previous_hash"]

        # Redacted: payload is a tombstone, IP/UA gone.
        import json
        payload = json.loads(after["payload"])
        assert payload.get("erased") is True
        assert payload.get("erasure_request_id") == str(result.request_id)
        assert "user_email" not in payload
        assert after["request_ip"] is None
        assert after["request_user_agent"] is None

        assert result.rows_affected == 1

        # Idempotency: re-running is a no-op on already-tombstoned rows.
        again = await erase_personal_data(
            conn,
            organization_id=org_id,
            requested_by="dpo@example.com",
            legal_basis="gdpr_art17",
            reason="DSR-2026-001 retry",
        )
        assert again.rows_affected == 0
    finally:
        # Clean up test data so re-runs of the suite stay isolated.
        await conn.execute(
            "DELETE FROM erasure_requests WHERE organization_id = $1",
            org_id,
        )
        await conn.execute("DELETE FROM audit_logs WHERE agent_id = $1", agent_id)
        await conn.execute("DELETE FROM agents WHERE id = $1", agent_id)
        await conn.execute("DELETE FROM organizations WHERE id = $1", org_id)
        await conn.close()


@_integration
@pytest.mark.asyncio
async def test_integration_erasure_preserves_test_request_flag() -> None:
    """The anchor worker's ``test_request`` filter must keep working after
    erasure — otherwise dev rows would start flowing into Merkle batches
    once they're redacted."""
    import asyncpg, json

    conn = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        org_id = await conn.fetchval(
            "INSERT INTO organizations (name, contact_email, api_key_hash) "
            "VALUES ('erasure-test-flag', 'x@example.com', decode('00','hex')) "
            "RETURNING id"
        )
        agent_id = await conn.fetchval(
            "INSERT INTO agents (organization_id, name, public_key, "
            "public_key_fingerprint, status) VALUES ($1, 'a', '\\x00', "
            "repeat('0', 64), 'active') RETURNING id",
            org_id,
        )
        log_id = await conn.fetchval(
            """
            INSERT INTO audit_logs (
                agent_id, action_type, action_hash, payload, verdict,
                signature, signature_valid, trust_score_at_time, metadata
            ) VALUES (
                $1, 'web_fetch', repeat('a', 64), '{}'::jsonb, 'approved',
                '\\x01', true, 100, '{"test_request": true}'::jsonb
            )
            RETURNING id
            """,
            agent_id,
        )

        await erase_personal_data(
            conn,
            organization_id=org_id,
            requested_by="dpo@example.com",
            legal_basis="gdpr_art17",
        )

        meta = json.loads(
            await conn.fetchval(
                "SELECT metadata FROM audit_logs WHERE id = $1", log_id
            )
        )
        assert meta.get("test_request") is True
        assert meta.get("erased") is True
    finally:
        await conn.execute(
            "DELETE FROM erasure_requests WHERE organization_id = $1", org_id
        )
        await conn.execute("DELETE FROM audit_logs WHERE agent_id = $1", agent_id)
        await conn.execute("DELETE FROM agents WHERE id = $1", agent_id)
        await conn.execute("DELETE FROM organizations WHERE id = $1", org_id)
        await conn.close()
