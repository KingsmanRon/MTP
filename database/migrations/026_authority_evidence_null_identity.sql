-- =============================================================================
-- 026 — Forensic identity CHECKs must fail closed on NULL
-- =============================================================================
-- 025 wrote the body/column identity constraints as:
--
--     decision_body ->> 'audit_id' = audit_log_id::TEXT
--
-- The ``->>`` operator yields SQL NULL both when the key is absent and when
-- its value is JSON null. `NULL = <value>` is UNKNOWN, and a CHECK constraint
-- accepts UNKNOWN. So the three constraints enforced "if the body states an
-- identity, it must match" -- and said nothing at all about a body that
-- states no identity.
--
-- That is the wrong default for a forensic record. The receipt is built from
-- decision_body, so a body missing its own audit_id, agent_id or
-- organisation_id is not a permissive edge case: it is evidence that cannot
-- say who it is about, stored under columns that claim it can.
--
-- IS NOT DISTINCT FROM compares NULL as a value rather than as unknown, so
-- it returns FALSE (not UNKNOWN) when the body side is missing and the column
-- side is not. The columns are all NOT NULL, so the only way to satisfy these
-- is to state the identity and state it correctly.
--
-- RELEASE GATE: like 0019-0021, this runs on an undeployed draft branch and
-- is a Phase-7A release migration gate. It only replaces three CHECK
-- constraints, so it takes a brief ACCESS EXCLUSIVE lock on
-- authority_decision_evidence to validate existing rows; that table is new in
-- this branch and has never held production data.
-- =============================================================================

ALTER TABLE authority_decision_evidence
    DROP CONSTRAINT IF EXISTS authority_decision_evidence_body_audit_id;
ALTER TABLE authority_decision_evidence
    ADD CONSTRAINT authority_decision_evidence_body_audit_id
        CHECK (decision_body ->> 'audit_id' IS NOT DISTINCT FROM audit_log_id::TEXT);

ALTER TABLE authority_decision_evidence
    DROP CONSTRAINT IF EXISTS authority_decision_evidence_body_agent_id;
ALTER TABLE authority_decision_evidence
    ADD CONSTRAINT authority_decision_evidence_body_agent_id
        CHECK (decision_body ->> 'agent_id' IS NOT DISTINCT FROM agent_id::TEXT);

ALTER TABLE authority_decision_evidence
    DROP CONSTRAINT IF EXISTS authority_decision_evidence_body_org_id;
ALTER TABLE authority_decision_evidence
    ADD CONSTRAINT authority_decision_evidence_body_org_id
        CHECK (decision_body ->> 'organisation_id' IS NOT DISTINCT FROM org_id::TEXT);

-- --- Drift guard ---------------------------------------------------------
-- Prove the new semantics rather than merely proving the constraints exist:
-- a constraint present but still written with plain equality would pass a
-- name check and fail the property.
DO $$
DECLARE
    v_org UUID := gen_random_uuid();
    v_agent UUID := gen_random_uuid();
    v_audit UUID;
    v_case TEXT;
    v_body JSONB;
    v_accepted BOOLEAN;
BEGIN
    INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
        VALUES (v_org, 'migration-026-guard', 'enterprise',
                'migration-026-guard@invalid.test', sha256(v_org::TEXT::BYTEA));
    INSERT INTO agents (
        id, org_id, name, public_key, public_key_fingerprint, trust_score,
        status, daily_limit_usd, per_action_limit_usd, allowed_actions,
        blocked_actions, rate_limit_per_minute, metadata
    ) VALUES (
        v_agent, v_org, 'migration-026-guard', decode(repeat('00', 32), 'hex'),
        repeat('a', 64), 80, 'active', 100, 100,
        ARRAY['financial_transaction']::TEXT[], ARRAY[]::TEXT[], 60,
        '{"sandbox": true}'::JSONB
    );

    FOR v_case, v_body IN
        SELECT * FROM (VALUES
            ('missing audit_id',       jsonb_build_object('agent_id', v_agent::TEXT, 'organisation_id', v_org::TEXT)),
            ('null audit_id',          jsonb_build_object('audit_id', NULL, 'agent_id', v_agent::TEXT, 'organisation_id', v_org::TEXT)),
            ('missing agent_id',       jsonb_build_object('organisation_id', v_org::TEXT)),
            ('null agent_id',          jsonb_build_object('agent_id', NULL, 'organisation_id', v_org::TEXT)),
            ('missing organisation_id', jsonb_build_object('agent_id', v_agent::TEXT)),
            ('null organisation_id',   jsonb_build_object('agent_id', v_agent::TEXT, 'organisation_id', NULL))
        ) AS t(c, b)
    LOOP
        INSERT INTO audit_logs (
            agent_id, action_type, action_hash, payload, verdict, verdict_reason,
            signature, signature_valid, trust_score_at_time, metadata
        ) VALUES (
            v_agent, 'authority_decision', repeat('b', 64), '{}'::JSONB,
            'approved', 'migration guard', 'GUARD', FALSE, 0,
            '{"test_request": true}'::JSONB
        ) RETURNING id INTO v_audit;

        v_accepted := TRUE;
        BEGIN
            INSERT INTO authority_decision_evidence (
                audit_log_id, agent_id, org_id, recorded_at, decision_body,
                sandbox, audit_action_type
            ) VALUES (
                v_audit, v_agent, v_org, NOW(),
                CASE WHEN v_body ? 'audit_id' THEN v_body
                     ELSE v_body END,
                TRUE, 'authority_decision'
            );
        EXCEPTION WHEN check_violation THEN
            v_accepted := FALSE;
        END;

        IF v_accepted THEN
            RAISE EXCEPTION
                'authority_decision_evidence accepted a body with %; the '
                'identity CHECKs still treat NULL as satisfied', v_case;
        END IF;
    END LOOP;

    -- Roll the whole guard back: it exists to prove behaviour, not to leave
    -- fixture rows behind in a migrated database.
    RAISE EXCEPTION 'migration-026-guard-passed';
EXCEPTION WHEN OTHERS THEN
    IF SQLERRM <> 'migration-026-guard-passed' THEN
        RAISE;
    END IF;
END;
$$;
