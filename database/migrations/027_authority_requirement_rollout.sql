-- =============================================================================
-- 027 — Server-controlled delegated-authority requirement rollout
-- =============================================================================
-- Phase 7A, Gate 2.
--
-- Until now the delegated-authority requirement was answered from
-- ``INNTRIS_AUTHORITY_REQUIRED_ORGS``: a comma-separated environment variable,
-- organisation-granularity only, changed by a redeploy, with no record of who
-- changed it or why. That is adequate for a branch nobody has enrolled in. It
-- is not adequate for a production control that decides whether real money can
-- move without a delegation.
--
-- This migration moves the answer into the database, where it gains:
--
--   * per-organisation / per-principal / per-action-class granularity, so a
--     tenant can enable the requirement for one agent and one action class
--     before enabling it for everything;
--   * a safe default -- an organisation with no row is NOT required, which is
--     exactly today's behaviour for every existing organisation;
--   * an immutable audit trail, because every write goes through
--     ``administrative_audit_events`` in the same transaction;
--   * two kill switches (see ``authority_controls``).
--
-- RELEASE GATE: this runs on an undeployed release branch. Both tables are
-- new, so the ACCESS EXCLUSIVE locks taken here are on empty relations nothing
-- is reading. No existing table is rewritten and no existing column changes
-- type; the only touch to a deployed table is the pair of GRANTs at the end.
-- =============================================================================

-- --- Requirement configuration -------------------------------------------
-- The specificity ladder, most specific first:
--
--   (agent_id, action_class)  -- this principal doing this class of act
--   (agent_id, NULL)          -- this principal doing anything
--   (NULL,     action_class)  -- anyone in the org doing this class of act
--   (NULL,     NULL)          -- the whole organisation
--
-- Exactly one row wins. A more specific row overrides a broader one in BOTH
-- directions, so an organisation-wide requirement can be lifted for a single
-- principal without deleting the organisation-wide row. That matters during a
-- rollout: the fix for "we enabled this too widely" must not be "delete the
-- control and lose the audit trail of what it used to be".
CREATE TABLE IF NOT EXISTS authority_requirements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- NULL = every principal in the organisation. The composite foreign key
    -- is MATCH SIMPLE, so a NULL agent_id skips it; a non-NULL one must name
    -- an agent THIS organisation owns. A row cannot be pointed at another
    -- tenant's principal.
    agent_id UUID,
    -- NULL = every action class. Stored as the action type string Core uses.
    action_class VARCHAR(100),
    required BOOLEAN NOT NULL,
    reason TEXT NOT NULL,
    changed_by VARCHAR(255) NOT NULL,
    approval_reference VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A NOT NULL discriminator so uniqueness needs no NULL semantics. A UUID
    -- rendered as text can never equal '*', so the two cases cannot collide.
    scope_key TEXT GENERATED ALWAYS AS (
        COALESCE(agent_id::TEXT, '*') || '|' || COALESCE(action_class, '*')
    ) STORED,
    CONSTRAINT authority_requirement_agent_owned
        FOREIGN KEY (agent_id, org_id) REFERENCES agents (id, org_id)
        ON DELETE CASCADE,
    CONSTRAINT authority_requirement_action_class_not_blank
        CHECK (action_class IS NULL OR BTRIM(action_class) <> ''),
    CONSTRAINT authority_requirement_reason_not_blank
        CHECK (BTRIM(reason) <> ''),
    CONSTRAINT authority_requirement_changed_by_not_blank
        CHECK (BTRIM(changed_by) <> ''),
    CONSTRAINT authority_requirement_approval_not_blank
        CHECK (BTRIM(approval_reference) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_authority_requirements_scope
    ON authority_requirements (org_id, scope_key);

-- The hot path reads by (org_id, agent_id) and picks the winner in SQL.
CREATE INDEX IF NOT EXISTS idx_authority_requirements_lookup
    ON authority_requirements (org_id, agent_id);

-- --- Kill switches --------------------------------------------------------
-- Two named controls, each engageable globally (org_id NULL) or for one
-- organisation. ``engaged = TRUE`` always means "the switch is pulled".
--
--   requirement_enforcement -- pulled: requirements are NOT enforced in this
--       scope. This is the rollback for a requirement rolled out too widely,
--       and it is the one control here that WEAKENS enforcement. It is
--       therefore audited on write and logged loudly on every use.
--
--   authority_issuance -- pulled: no NEW execution authority is issued in
--       this scope. Consumption of authority already issued is unaffected:
--       halting that would strand grants an executor is mid-way through and
--       turn one uncertain payment into an unanswerable one. This control
--       fails in the safe direction, so it has no counterpart risk.
--
-- A global row and an organisation row may both exist. Global wins when
-- engaged: a platform-wide halt is not something one tenant can opt out of.
CREATE TABLE IF NOT EXISTS authority_controls (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    control VARCHAR(64) NOT NULL,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    engaged BOOLEAN NOT NULL,
    reason TEXT NOT NULL,
    changed_by VARCHAR(255) NOT NULL,
    approval_reference VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scope_key TEXT GENERATED ALWAYS AS (COALESCE(org_id::TEXT, '*')) STORED,
    CONSTRAINT authority_control_known CHECK (
        control IN ('requirement_enforcement', 'authority_issuance')
    ),
    CONSTRAINT authority_control_reason_not_blank CHECK (BTRIM(reason) <> ''),
    CONSTRAINT authority_control_changed_by_not_blank CHECK (BTRIM(changed_by) <> ''),
    CONSTRAINT authority_control_approval_not_blank
        CHECK (BTRIM(approval_reference) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_authority_controls_scope
    ON authority_controls (control, scope_key);

COMMENT ON TABLE authority_requirements IS
    'Server-controlled delegated-authority requirement. Absence of a row means not required.';
COMMENT ON TABLE authority_controls IS
    'Named kill switches for the authority subsystem. engaged = TRUE means the switch is pulled.';

-- --- Row level security ---------------------------------------------------
ALTER TABLE authority_requirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_requirements FORCE ROW LEVEL SECURITY;
ALTER TABLE authority_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_controls FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS authority_requirements_tenant_scope ON authority_requirements;
CREATE POLICY authority_requirements_tenant_scope
    ON authority_requirements
    FOR ALL
    TO inntris_api
    USING (org_id = app.current_tenant())
    WITH CHECK (org_id = app.current_tenant());

-- Deliberately NOT `FOR ALL`: a tenant session may read which controls apply
-- to it, and may not write one. Engaging a kill switch is a platform
-- operation carrying an approval reference, performed by the system role.
-- The global row (org_id IS NULL) is invisible to tenants by design -- a
-- platform-wide halt is not a tenant-visible setting.
DROP POLICY IF EXISTS authority_controls_tenant_read ON authority_controls;
CREATE POLICY authority_controls_tenant_read
    ON authority_controls
    FOR SELECT
    TO inntris_api
    USING (org_id = app.current_tenant());

REVOKE ALL ON TABLE authority_requirements FROM PUBLIC;
REVOKE ALL ON TABLE authority_controls FROM PUBLIC;
GRANT SELECT ON authority_requirements TO inntris_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON authority_requirements TO inntris_worker;
GRANT SELECT ON authority_controls TO inntris_api;
GRANT SELECT, INSERT, UPDATE ON authority_controls TO inntris_worker;

-- Supabase defines anon/authenticated; a plain PostgreSQL database does not.
-- Guard the REVOKE so the same migration tree stays portable, matching the
-- convention established in 020_rls_hardening.sql.
DO $$
DECLARE
    client_role TEXT;
    target_table TEXT;
BEGIN
    FOREACH client_role IN ARRAY ARRAY['anon', 'authenticated']
    LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = client_role) THEN
            FOREACH target_table IN ARRAY ARRAY['authority_requirements', 'authority_controls']
            LOOP
                EXECUTE format(
                    'REVOKE ALL PRIVILEGES ON TABLE public.%I FROM %I',
                    target_table, client_role
                );
            END LOOP;
        END IF;
    END LOOP;
END;
$$;

-- --- Drift guard ----------------------------------------------------------
-- Prove the PROPERTIES, not merely that objects with the right names exist.
-- A unique index present but written over the wrong columns would pass a name
-- check and silently permit two contradictory requirement rows for one scope,
-- whereupon "is authority required here" would have two answers.
DO $$
DECLARE
    v_org UUID := gen_random_uuid();
    v_other_org UUID := gen_random_uuid();
    v_agent UUID := gen_random_uuid();
    v_other_agent UUID := gen_random_uuid();
    v_rls BOOLEAN;
    v_forced BOOLEAN;
    v_accepted BOOLEAN;
    v_table TEXT;
BEGIN
    FOREACH v_table IN ARRAY ARRAY['authority_requirements', 'authority_controls']
    LOOP
        SELECT c.relrowsecurity, c.relforcerowsecurity
          INTO v_rls, v_forced
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relname = v_table;
        IF v_rls IS DISTINCT FROM TRUE OR v_forced IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION
                'migration 027 drift: % must have row level security enabled and forced',
                v_table;
        END IF;
    END LOOP;

    -- Fixtures. Two organisations so the cross-tenant test has a real target.
    INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
        VALUES (v_org, 'migration-027-guard', 'enterprise',
                'migration-027-guard@invalid.test', sha256(v_org::TEXT::BYTEA)),
               (v_other_org, 'migration-027-guard-other', 'enterprise',
                'migration-027-guard-other@invalid.test', sha256(v_other_org::TEXT::BYTEA));
    INSERT INTO agents (
        id, org_id, name, public_key, public_key_fingerprint, trust_score,
        status, daily_limit_usd, per_action_limit_usd, allowed_actions,
        blocked_actions, rate_limit_per_minute, metadata
    ) VALUES
        (v_agent, v_org, 'migration-027-guard', decode(repeat('00', 32), 'hex'),
         repeat('a', 64), 80, 'active', 100, 100,
         ARRAY['financial_transaction']::TEXT[], ARRAY[]::TEXT[], 60,
         '{"sandbox": true}'::JSONB),
        (v_other_agent, v_other_org, 'migration-027-guard-other',
         decode(repeat('00', 32), 'hex'), repeat('b', 64), 80, 'active', 100, 100,
         ARRAY['financial_transaction']::TEXT[], ARRAY[]::TEXT[], 60,
         '{"sandbox": true}'::JSONB);

    -- 1. A requirement row may not name an agent another organisation owns.
    BEGIN
        INSERT INTO authority_requirements (
            org_id, agent_id, action_class, required, reason, changed_by,
            approval_reference
        ) VALUES (v_org, v_other_agent, 'financial_transaction', TRUE,
                  'guard', 'guard', 'guard');
        v_accepted := TRUE;
    EXCEPTION WHEN foreign_key_violation THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION
            'migration 027 drift: a requirement accepted another tenant''s principal';
    END IF;

    -- 2. One scope, one answer.
    INSERT INTO authority_requirements (
        org_id, agent_id, action_class, required, reason, changed_by,
        approval_reference
    ) VALUES (v_org, v_agent, 'financial_transaction', TRUE, 'guard', 'guard', 'guard');
    BEGIN
        INSERT INTO authority_requirements (
            org_id, agent_id, action_class, required, reason, changed_by,
            approval_reference
        ) VALUES (v_org, v_agent, 'financial_transaction', FALSE,
                  'guard', 'guard', 'guard');
        v_accepted := TRUE;
    EXCEPTION WHEN unique_violation THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION
            'migration 027 drift: two contradictory requirements for one scope were accepted';
    END IF;

    -- 3. The org-wide row and the per-agent row are DIFFERENT scopes: the
    --    generated discriminator must not collapse them.
    INSERT INTO authority_requirements (
        org_id, agent_id, action_class, required, reason, changed_by,
        approval_reference
    ) VALUES (v_org, NULL, NULL, TRUE, 'guard', 'guard', 'guard');

    -- 4. Unknown control names are refused, so a typo cannot create a switch
    --    that looks configured and is never read.
    BEGIN
        INSERT INTO authority_controls (control, org_id, engaged, reason,
                                        changed_by, approval_reference)
        VALUES ('requirement_enforcment', v_org, TRUE, 'guard', 'guard', 'guard');
        v_accepted := TRUE;
    EXCEPTION WHEN check_violation THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION 'migration 027 drift: an unknown control name was accepted';
    END IF;

    -- 5. Global and per-organisation control rows coexist for one control.
    INSERT INTO authority_controls (control, org_id, engaged, reason,
                                    changed_by, approval_reference)
    VALUES ('authority_issuance', NULL, FALSE, 'guard', 'guard', 'guard'),
           ('authority_issuance', v_org, TRUE, 'guard', 'guard', 'guard');

    DELETE FROM authority_controls WHERE org_id = v_org OR org_id IS NULL;
    DELETE FROM authority_requirements WHERE org_id = v_org;
    DELETE FROM agents WHERE id IN (v_agent, v_other_agent);
    DELETE FROM organizations WHERE id IN (v_org, v_other_org);
END;
$$;
