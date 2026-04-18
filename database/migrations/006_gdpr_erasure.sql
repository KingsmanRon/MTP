-- =============================================================================
-- MIGRATION 006: GDPR erasure with forensic-integrity preservation (Phase 4B)
-- =============================================================================
-- The ``audit_logs`` table is designed append-only: its rows are leaves of a
-- Merkle tree whose root is anchored on-chain, so a full row DELETE would
-- silently invalidate every published proof for that leaf's batch.
--
-- GDPR Article 17 ("right to erasure") requires that when a data subject
-- requests deletion of personal data, we remove it — but the law explicitly
-- carves out retention necessary for "establishment, exercise or defence of
-- legal claims" (Art. 17(3)(e)). That carve-out is what lets us keep the
-- *cryptographic proof* that a row existed (action_hash, signature,
-- merkle_leaf_index) while redacting the *personal data* (payload, IP,
-- user-agent, metadata).
--
-- Post-erasure, for an erased row:
--   * action_hash is unchanged — the Merkle proof still verifies.
--   * signature is unchanged — the original Ed25519 signature still
--     validates the original action_hash, so non-repudiation holds for
--     parties who still hold the original payload.
--   * payload is replaced with a tombstone JSON containing {erased: true,
--     erased_at: timestamp, erasure_request_id: uuid}.
--   * request_ip, request_user_agent, metadata are scrubbed.
--   * An erasure_requests row records who requested the erasure, when,
--     and the legal basis — this itself becomes evidence that the
--     redaction was compliant, not covert.
--
-- This migration is additive. It does not require RLS to already be
-- enforced; the function runs as SECURITY DEFINER under the inntris_api
-- role so it respects the role's grants rather than the caller's.

BEGIN;

-- -----------------------------------------------------------------------------
-- Ledger: every erasure request is itself an immutable record.
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS erasure_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    subject_agent_id UUID REFERENCES agents(id) ON DELETE RESTRICT,
    requested_by TEXT NOT NULL,        -- email / operator id, not a user FK
    legal_basis TEXT NOT NULL,         -- "gdpr_art17", "ccpa_1798.105", ...
    reason TEXT,                       -- free-form justification
    rows_affected INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,

    CONSTRAINT erasure_legal_basis_nonempty CHECK (LENGTH(TRIM(legal_basis)) > 0),
    CONSTRAINT erasure_requested_by_nonempty CHECK (LENGTH(TRIM(requested_by)) > 0)
);

CREATE INDEX IF NOT EXISTS idx_erasure_requests_org
    ON erasure_requests(organization_id);

COMMENT ON TABLE erasure_requests IS
    'Append-only ledger of GDPR Article 17 / CCPA 1798.105 erasure requests. '
    'See docs/runbooks/secrets_rotation.md for operator procedure.';

-- -----------------------------------------------------------------------------
-- The redaction function.
--
-- Scope: one organization (tenant) and optionally one agent within it.
-- Touches: audit_logs.payload / metadata / request_ip / request_user_agent.
-- Preserves: id, agent_id, timestamp, action_type, action_hash, verdict,
--            signature, signature_valid, merkle_root_id, merkle_leaf_index,
--            chain_previous_hash, policy_hash. These are either proof
--            artifacts or non-PII categorical fields.
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.erase_personal_data(
    p_org_id UUID,
    p_agent_id UUID,               -- NULL = all agents of this org
    p_requested_by TEXT,
    p_legal_basis TEXT,
    p_reason TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_request_id UUID;
    v_affected INTEGER;
BEGIN
    -- 1. Record the request *before* touching any data. If the UPDATE
    --    below fails for any reason, we still have the intent recorded.
    INSERT INTO erasure_requests (
        organization_id, subject_agent_id, requested_by, legal_basis, reason
    ) VALUES (
        p_org_id, p_agent_id, p_requested_by, p_legal_basis, p_reason
    )
    RETURNING id INTO v_request_id;

    -- 2. Redact. The payload tombstone carries the erasure_request_id so a
    --    forensic examiner can trace *why* a row is opaque.
    UPDATE audit_logs AS al
    SET
        payload = jsonb_build_object(
            'erased', true,
            'erased_at', NOW(),
            'erasure_request_id', v_request_id
        ),
        metadata = CASE
            -- Preserve the `test_request` flag because the anchor worker's
            -- filter relies on it; erasing it would push a test row into a
            -- production Merkle batch.
            WHEN (al.metadata->>'test_request')::boolean IS TRUE
                THEN jsonb_build_object('test_request', true, 'erased', true)
            ELSE jsonb_build_object('erased', true)
        END,
        request_ip = NULL,
        request_user_agent = NULL
    FROM agents a
    WHERE al.agent_id = a.id
      AND a.organization_id = p_org_id
      AND (p_agent_id IS NULL OR al.agent_id = p_agent_id)
      -- Idempotency: do not re-erase an already-tombstoned row.
      AND COALESCE((al.payload->>'erased')::boolean, false) = false;

    GET DIAGNOSTICS v_affected = ROW_COUNT;

    UPDATE erasure_requests
        SET rows_affected = v_affected,
            completed_at = NOW()
        WHERE id = v_request_id;

    RETURN v_request_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION app.erase_personal_data(UUID, UUID, TEXT, TEXT, TEXT) IS
    'GDPR Art. 17 erasure: replace audit_logs.payload with a tombstone, '
    'null out request_ip / request_user_agent, and record the request in '
    'erasure_requests. Preserves action_hash / signature / merkle_* so '
    'on-chain proofs continue to verify.';

-- -----------------------------------------------------------------------------
-- Revoke erasure authority by default. Operators grant EXECUTE to a named
-- role only when an erasure process is approved, so the path is never
-- available by accident in a default deployment.
-- -----------------------------------------------------------------------------

REVOKE ALL ON FUNCTION app.erase_personal_data(UUID, UUID, TEXT, TEXT, TEXT) FROM PUBLIC;

COMMIT;
