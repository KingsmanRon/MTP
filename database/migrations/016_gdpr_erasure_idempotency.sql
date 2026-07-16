-- Make repeated erasure requests idempotent without trusting client supplied
-- erasure markers. A row is skipped only when it is the exact tombstone
-- produced by a completed, tenant scoped erasure request.

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
      AND (p_agent_id IS NULL OR al.agent_id = p_agent_id)
      AND NOT (
          al.payload = pg_catalog.jsonb_build_object(
              'erased', true,
              'erased_at', al.payload->'erased_at',
              'erasure_request_id', al.payload->'erasure_request_id'
          )
          AND pg_catalog.jsonb_typeof(al.payload->'erased_at') = 'string'
          AND NULLIF(al.payload->>'erased_at', '') IS NOT NULL
          AND EXISTS (
              SELECT 1
              FROM public.erasure_requests AS completed_erasure
              WHERE completed_erasure.id::TEXT = al.payload->>'erasure_request_id'
                AND completed_erasure.organization_id = p_org_id
                AND completed_erasure.completed_at IS NOT NULL
                AND (
                    completed_erasure.subject_agent_id IS NULL
                    OR completed_erasure.subject_agent_id = al.agent_id
                )
          )
          AND COALESCE(
              al.metadata IN (
                  '{"erased": true}'::JSONB,
                  '{"test_request": true, "erased": true}'::JSONB
              ),
              false
          )
          AND al.request_ip IS NULL
          AND al.request_user_agent IS NULL
      );

    GET DIAGNOSTICS v_affected = ROW_COUNT;

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
    'Authorised idempotent GDPR/CCPA erasure. Writes a scoped ledger backed '
    'tombstone while preserving all cryptographic and forensic audit fields.';

REVOKE ALL ON FUNCTION app.erase_personal_data(UUID, UUID, TEXT, TEXT, TEXT)
    FROM PUBLIC, inntris_api, inntris_worker;
