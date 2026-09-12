-- =============================================================================
-- 028 — Authority configuration is read-only at runtime
-- =============================================================================
-- Phase 7A, Gate 2, hardening 027 before any reader consults it.
--
-- Two changes, both narrowing:
--
-- 1. The runtime role loses INSERT and UPDATE on the rollout controls.
--    There is no authority-management write surface, so there is no
--    justification for the role that serves requests to mutate the trust
--    configuration those requests are judged against. Read-only is the
--    whole of the runtime's business here.
--
--    This is deliberately not "revoke later, once the management surface
--    exists". A grant nothing needs is a grant that will be used by
--    accident, and the window between shipping the tables and shipping
--    their reader is exactly when nobody is watching them.
--
-- 2. ``requirement_enforcement`` can no longer be engaged globally.
--    It is the one control that WEAKENS enforcement, and a global row
--    would be a single switch that silently suspends every organisation's
--    requirement at once. Suspension must name the organisation it
--    applies to. ``authority_issuance`` is unaffected: halting issuance
--    platform-wide fails in the safe direction, so it may stay global.
--
-- LOCK PROFILE: the REVOKEs take a brief ACCESS EXCLUSIVE on the two new
-- tables. The CHECK constraint takes ACCESS EXCLUSIVE and scans the table
-- it is added to; both tables are empty in every environment (nothing
-- writes them yet), so the scan is trivial. Should that ever stop being
-- true, the same constraint can be added NOT VALID and validated
-- separately. No existing table is touched, rewritten or scanned.
-- =============================================================================

-- --- 1. Runtime configuration access is SELECT only -----------------------
REVOKE INSERT, UPDATE ON authority_requirements FROM inntris_worker;
REVOKE INSERT, UPDATE ON authority_controls FROM inntris_worker;

-- --- 2. No global suppression of requirement enforcement ------------------
-- A row engaging requirement_enforcement must name an organisation. Written
-- as a CHECK rather than a partial unique index because the rule is about
-- what a row may BE, not about how many of them may exist.
ALTER TABLE authority_controls
    DROP CONSTRAINT IF EXISTS authority_control_enforcement_is_org_scoped;
ALTER TABLE authority_controls
    ADD CONSTRAINT authority_control_enforcement_is_org_scoped
    CHECK (control <> 'requirement_enforcement' OR org_id IS NOT NULL);

COMMENT ON CONSTRAINT authority_control_enforcement_is_org_scoped
    ON authority_controls IS
    'requirement_enforcement weakens enforcement, so it must name the '
    'organisation it suspends. authority_issuance may be global because '
    'halting issuance fails safe.';

-- --- Drift guard ----------------------------------------------------------
-- Prove the PROPERTIES. A REVOKE that silently did nothing, or a CHECK
-- written against the wrong column, would leave the same table names in
-- place and the same privileges quietly available.
DO $$
DECLARE
    v_org UUID := gen_random_uuid();
    v_accepted BOOLEAN;
    v_table TEXT;
    v_privilege TEXT;
BEGIN
    FOREACH v_table IN ARRAY ARRAY['authority_requirements', 'authority_controls']
    LOOP
        FOREACH v_privilege IN ARRAY ARRAY['INSERT', 'UPDATE', 'DELETE']
        LOOP
            IF EXISTS (
                SELECT 1 FROM information_schema.role_table_grants
                WHERE grantee = 'inntris_worker'
                  AND table_name = v_table
                  AND privilege_type = v_privilege
            ) THEN
                RAISE EXCEPTION
                    '028 drift: the runtime role still holds % on %; authority '
                    'configuration must be read-only at runtime',
                    v_privilege, v_table;
            END IF;
        END LOOP;

        IF NOT EXISTS (
            SELECT 1 FROM information_schema.role_table_grants
            WHERE grantee = 'inntris_worker'
              AND table_name = v_table
              AND privilege_type = 'SELECT'
        ) THEN
            RAISE EXCEPTION
                '028 drift: the runtime role cannot SELECT %; the reader needs it',
                v_table;
        END IF;
    END LOOP;

    INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
    VALUES (v_org, '028-drift-' || v_org, 'free', v_org || '@drift.invalid',
            sha256(v_org::TEXT::BYTEA));

    -- A GLOBAL requirement_enforcement row must be impossible.
    v_accepted := TRUE;
    BEGIN
        INSERT INTO authority_controls
            (control, org_id, engaged, reason, changed_by, approval_reference)
        VALUES ('requirement_enforcement', NULL, TRUE, 'drift', 'drift', 'drift');
    EXCEPTION WHEN check_violation THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION
            '028 drift: a GLOBAL requirement_enforcement row was accepted; one '
            'switch must not be able to suspend every organisation at once';
    END IF;

    -- ...while an ORG-scoped one is still allowed, and a GLOBAL
    -- authority_issuance halt remains available.
    INSERT INTO authority_controls
        (control, org_id, engaged, reason, changed_by, approval_reference)
    VALUES ('requirement_enforcement', v_org, TRUE, 'drift', 'drift', 'drift');
    INSERT INTO authority_controls
        (control, org_id, engaged, reason, changed_by, approval_reference)
    VALUES ('authority_issuance', NULL, TRUE, 'drift', 'drift', 'drift');

    DELETE FROM authority_controls WHERE org_id = v_org OR org_id IS NULL;
    DELETE FROM organizations WHERE id = v_org;
END;
$$;
