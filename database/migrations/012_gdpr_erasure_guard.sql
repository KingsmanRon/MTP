-- =============================================================================
-- MIGRATION 012: Authorised GDPR erasure guard
-- =============================================================================
-- Migration 006 introduced forensic preserving erasure, but its tenant join
-- used agents.organization_id. The canonical tenant column is agents.org_id,
-- so no rows could be erased on the current schema. Its audit_logs UPDATE was
-- also rejected by the table's immutability trigger.
--
-- This forward migration repairs both controls without weakening the forensic
-- boundary. app.erase_personal_data creates a pending ledger row and exposes
-- its id through a transaction local capability only while its UPDATE runs.
-- The audit trigger accepts that capability only when:
--
--   * the ledger row exists, is pending, and covers the audit row's tenant;
--   * only payload, metadata, request_ip, and request_user_agent change;
--   * payload and metadata are exact, bounded tombstones; and
--   * request_ip and request_user_agent are cleared.
--
-- Every other column remains immutable. Merkle fields retain their existing
-- one time NULL to non NULL anchoring transition.

CREATE OR REPLACE FUNCTION public.prevent_audit_log_modification()
RETURNS TRIGGER AS $$
DECLARE
    v_erasure_request_id UUID;
    v_expected_metadata JSONB;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'SECURITY VIOLATION: Audit logs are immutable. DELETE operations are prohibited.';
    END IF;

    IF TG_OP <> 'UPDATE' THEN
        RETURN NEW;
    END IF;

    -- A malformed capability is an attempted bypass, not an ordinary update.
    BEGIN
        v_erasure_request_id := NULLIF(
            pg_catalog.current_setting('app.erasure_request_id', true),
            ''
        )::UUID;
    EXCEPTION
        WHEN invalid_text_representation THEN
            RAISE EXCEPTION
                'SECURITY VIOLATION: Invalid erasure capability.';
    END;

    IF v_erasure_request_id IS NOT NULL THEN
        -- The capability must identify a pending ledger row whose tenant and
        -- optional agent scope cover this exact audit row.
        PERFORM 1
        FROM public.erasure_requests AS er
        JOIN public.agents AS a ON a.id = OLD.agent_id
        WHERE er.id = v_erasure_request_id
          AND er.completed_at IS NULL
          AND er.organization_id = a.org_id
          AND (er.subject_agent_id IS NULL OR er.subject_agent_id = OLD.agent_id);

        IF NOT FOUND THEN
            RAISE EXCEPTION
                'SECURITY VIOLATION: Erasure capability has no matching pending ledger row.';
        END IF;

        -- Compare the complete records with only the four authorised erasure
        -- fields removed. This automatically protects columns added later.
        IF (pg_catalog.to_jsonb(OLD) - ARRAY[
                'payload', 'metadata', 'request_ip', 'request_user_agent'
            ]) IS DISTINCT FROM
           (pg_catalog.to_jsonb(NEW) - ARRAY[
                'payload', 'metadata', 'request_ip', 'request_user_agent'
            ]) THEN
            RAISE EXCEPTION
                'SECURITY VIOLATION: Erasure cannot modify forensic audit fields.';
        END IF;

        v_expected_metadata := CASE
            WHEN COALESCE(OLD.metadata, '{}'::JSONB) @> '{"test_request": true}'::JSONB
                THEN pg_catalog.jsonb_build_object(
                    'test_request', true,
                    'erased', true
                )
            ELSE pg_catalog.jsonb_build_object('erased', true)
        END;

        -- Exact objects prevent arbitrary data from being smuggled into an
        -- erasure tombstone. A parseable erased_at timestamp is mandatory.
        IF NEW.payload IS DISTINCT FROM pg_catalog.jsonb_build_object(
                'erased', true,
                'erased_at', NEW.payload->'erased_at',
                'erasure_request_id', v_erasure_request_id
            )
           OR pg_catalog.jsonb_typeof(NEW.payload->'erased_at') <> 'string'
           OR NULLIF(NEW.payload->>'erased_at', '') IS NULL
           OR NEW.metadata IS DISTINCT FROM v_expected_metadata
           OR NEW.request_ip IS NOT NULL
           OR NEW.request_user_agent IS NOT NULL THEN
            RAISE EXCEPTION
                'SECURITY VIOLATION: Erasure must write the authorised tombstone only.';
        END IF;

        -- Validate the timestamp after the structural checks so missing or
        -- non string values receive the same controlled security error.
        BEGIN
            PERFORM (NEW.payload->>'erased_at')::TIMESTAMPTZ;
        EXCEPTION
            WHEN invalid_datetime_format OR datetime_field_overflow THEN
                RAISE EXCEPTION
                    'SECURITY VIOLATION: Erasure tombstone has an invalid timestamp.';
        END;

        RETURN NEW;
    END IF;

    -- Preserve the anchor worker contract: each Merkle field may move from
    -- NULL to a value once. Neither may be cleared or overwritten, and every
    -- non Merkle field is compared automatically.
    IF OLD.merkle_root_id IS DISTINCT FROM NEW.merkle_root_id
       OR OLD.merkle_leaf_index IS DISTINCT FROM NEW.merkle_leaf_index THEN
        IF (NEW.merkle_root_id IS NOT DISTINCT FROM OLD.merkle_root_id
                OR (OLD.merkle_root_id IS NULL AND NEW.merkle_root_id IS NOT NULL))
           AND (NEW.merkle_leaf_index IS NOT DISTINCT FROM OLD.merkle_leaf_index
                OR (OLD.merkle_leaf_index IS NULL AND NEW.merkle_leaf_index IS NOT NULL))
           AND (pg_catalog.to_jsonb(OLD) - ARRAY[
                    'merkle_root_id', 'merkle_leaf_index'
               ]) IS NOT DISTINCT FROM
               (pg_catalog.to_jsonb(NEW) - ARRAY[
                    'merkle_root_id', 'merkle_leaf_index'
               ]) THEN
            RETURN NEW;
        END IF;
    END IF;

    RAISE EXCEPTION
        'SECURITY VIOLATION: Audit logs are immutable outside authorised erasure and one time Merkle anchoring.';
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;


CREATE OR REPLACE FUNCTION app.erase_personal_data(
    p_org_id UUID,
    p_agent_id UUID,
    p_requested_by TEXT,
    p_legal_basis TEXT,
    p_reason TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_request_id UUID;
    v_affected INTEGER;
    v_erased_at TIMESTAMPTZ := pg_catalog.clock_timestamp();
BEGIN
    IF p_requested_by IS NULL OR pg_catalog.btrim(p_requested_by) = '' THEN
        RAISE EXCEPTION 'requested_by is required'
            USING ERRCODE = '22023';
    END IF;

    IF p_legal_basis IS NULL OR p_legal_basis NOT IN (
        'gdpr_art17', 'ccpa_1798_105', 'operator_request'
    ) THEN
        RAISE EXCEPTION 'unsupported legal_basis'
            USING ERRCODE = '22023';
    END IF;

    IF p_agent_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM public.agents AS a
        WHERE a.id = p_agent_id
          AND a.org_id = p_org_id
    ) THEN
        RAISE EXCEPTION 'agent does not belong to the requested organization'
            USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.erasure_requests (
        organization_id,
        subject_agent_id,
        requested_by,
        legal_basis,
        reason
    ) VALUES (
        p_org_id,
        p_agent_id,
        pg_catalog.btrim(p_requested_by),
        p_legal_basis,
        p_reason
    )
    RETURNING id INTO v_request_id;

    -- The immutability trigger accepts this transaction local capability only
    -- while the matching ledger row remains pending.
    PERFORM pg_catalog.set_config(
        'app.erasure_request_id',
        v_request_id::TEXT,
        true
    );

    UPDATE public.audit_logs AS al
    SET
        payload = pg_catalog.jsonb_build_object(
            'erased', true,
            'erased_at', v_erased_at,
            'erasure_request_id', v_request_id
        ),
        metadata = CASE
            WHEN COALESCE(al.metadata, '{}'::JSONB) @> '{"test_request": true}'::JSONB
                THEN pg_catalog.jsonb_build_object(
                    'test_request', true,
                    'erased', true
                )
            ELSE pg_catalog.jsonb_build_object('erased', true)
        END,
        request_ip = NULL,
        request_user_agent = NULL
    FROM public.agents AS a
    WHERE al.agent_id = a.id
      AND a.org_id = p_org_id
      AND (p_agent_id IS NULL OR al.agent_id = p_agent_id);

    GET DIAGNOSTICS v_affected = ROW_COUNT;

    -- Clear the capability before completing the ledger row. The trigger also
    -- requires completed_at IS NULL, providing a second fail closed boundary.
    PERFORM pg_catalog.set_config('app.erasure_request_id', '', true);

    UPDATE public.erasure_requests
    SET rows_affected = v_affected,
        completed_at = pg_catalog.clock_timestamp()
    WHERE id = v_request_id;

    RETURN v_request_id;
END;
$$ LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

COMMENT ON FUNCTION app.erase_personal_data(UUID, UUID, TEXT, TEXT, TEXT) IS
    'Authorised GDPR/CCPA erasure. Writes a scoped ledger backed tombstone '
    'while preserving all cryptographic and forensic audit fields.';

-- Application roles cannot mint ledger rows or invoke the SECURITY DEFINER
-- function. Operators grant EXECUTE temporarily to a dedicated erasure role.
REVOKE ALL ON TABLE public.erasure_requests FROM PUBLIC, inntris_api, inntris_worker;
REVOKE ALL ON FUNCTION app.erase_personal_data(UUID, UUID, TEXT, TEXT, TEXT)
    FROM PUBLIC, inntris_api, inntris_worker;
