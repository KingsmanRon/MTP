-- =============================================================================
-- 027 — Server-controlled delegated-authority requirement rollout
-- =============================================================================
-- Phase 7A, Gate 2, on the corrected Phase-6 lineage.
--
-- Today the delegated-authority requirement is answered from
-- ``INNTRIS_AUTHORITY_REQUIRED_ORGS``: a comma-separated environment variable,
-- organisation granularity only, changed by a redeploy, with no record of who
-- changed it or why. Adequate for a branch nobody has enrolled in; not
-- adequate for a production control deciding whether money may move without a
-- delegation.
--
-- This moves the answer into the database, where it gains per-organisation /
-- per-principal / per-action-class granularity, a safe default, and an
-- approval reference on every row.
--
-- DEFAULT BEHAVIOUR IS UNCHANGED. An organisation with no row is NOT
-- required, which is exactly what every existing organisation gets today.
-- This migration enrols nobody.
--
-- LOCK PROFILE: both tables are new. The ACCESS EXCLUSIVE locks taken to
-- create them are on relations that do not yet exist, so nothing can be
-- waiting on them. No existing table is rewritten, no existing column changes
-- type, and no existing index is rebuilt. The only statements touching
-- deployed objects are the GRANTs, which take a brief ACCESS EXCLUSIVE on the
-- new tables only, and the trigger creation on the new tables.
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
-- principal WITHOUT deleting the organisation-wide row. That matters during a
-- rollout: the fix for "we enabled this too widely" must not be "delete the
-- control", which would destroy the record of what it used to be.
CREATE TABLE IF NOT EXISTS authority_requirements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- NULL = every principal in the organisation. The composite foreign key
    -- below is MATCH SIMPLE, so a NULL agent_id skips it entirely; a non-NULL
    -- one must name an agent THIS organisation owns. A row therefore cannot
    -- be pointed at another tenant's principal.
    agent_id UUID,
    -- NULL = every action class. Stored as the action type string Core uses.
    action_class VARCHAR(100),
    required BOOLEAN NOT NULL,
    reason TEXT NOT NULL,
    changed_by VARCHAR(255) NOT NULL,
    approval_reference VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A NOT NULL discriminator, so uniqueness needs no NULL semantics: in
    -- PostgreSQL two rows that are NULL in the same column do not conflict,
    -- which would permit two contradictory org-wide rows. A UUID rendered as
    -- text can never equal '*', so the wildcard cannot collide with an id.
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

-- The hot path reads every row for one organisation and picks the winner.
CREATE INDEX IF NOT EXISTS idx_authority_requirements_lookup
    ON authority_requirements (org_id, agent_id);

-- --- Kill switches --------------------------------------------------------
-- Two named controls, each engageable globally (org_id NULL) or for one
-- organisation. ``engaged = TRUE`` always means "the switch is pulled",
-- whichever direction that happens to push the system.
--
--   requirement_enforcement -- pulled: requirements are NOT enforced in this
--       scope. This is the rollback for a requirement rolled out too widely,
--       and it is the only control here that WEAKENS enforcement, so it
--       carries an approval reference like everything else and is meant to be
--       loud in the logs when used.
--
--   authority_issuance -- pulled: no NEW execution authority is issued in
--       this scope. Consumption of already-issued authority is deliberately
--       unaffected: halting that would strand grants an executor is part way
--       through and turn one uncertain payment into an unanswerable one.
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
    'Server-controlled delegated-authority requirement. No row means not required.';
COMMENT ON TABLE authority_controls IS
    'Named kill switches for the authority subsystem. engaged = TRUE means pulled.';

-- ``updated_at`` is evidence of when a control last changed, so it is
-- maintained by the database rather than trusted to every writer.
DROP TRIGGER IF EXISTS update_authority_requirements_updated_at ON authority_requirements;
CREATE TRIGGER update_authority_requirements_updated_at
    BEFORE UPDATE ON authority_requirements
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_authority_controls_updated_at ON authority_controls;
CREATE TRIGGER update_authority_controls_updated_at
    BEFORE UPDATE ON authority_controls
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- --- Row level security ---------------------------------------------------
ALTER TABLE authority_requirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_requirements FORCE ROW LEVEL SECURITY;
ALTER TABLE authority_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_controls FORCE ROW LEVEL SECURITY;

-- A tenant session may see the requirements that apply to it and nothing
-- else. It may not write one: enabling or lifting a requirement carries an
-- approval reference and is a platform operation.
DROP POLICY IF EXISTS authority_requirements_tenant_read ON authority_requirements;
CREATE POLICY authority_requirements_tenant_read
    ON authority_requirements
    FOR SELECT
    TO inntris_api
    USING (org_id = app.current_tenant());

-- Same for controls. The GLOBAL row (org_id IS NULL) is deliberately
-- invisible to tenants: a platform-wide halt is not a tenant-visible setting,
-- and `org_id = app.current_tenant()` is never true for NULL.
DROP POLICY IF EXISTS authority_controls_tenant_read ON authority_controls;
CREATE POLICY authority_controls_tenant_read
    ON authority_controls
    FOR SELECT
    TO inntris_api
    USING (org_id = app.current_tenant());

REVOKE ALL ON TABLE authority_requirements FROM PUBLIC;
REVOKE ALL ON TABLE authority_controls FROM PUBLIC;
GRANT SELECT ON authority_requirements TO inntris_api;
GRANT SELECT ON authority_controls TO inntris_api;
-- No DELETE. Lifting a requirement is an UPDATE to required = FALSE, which
-- keeps the row, its reason and its approval reference. Granting DELETE would
-- make "lose the audit trail" the easiest way to undo a mistake. Cascades
-- from organizations/agents still work: referential actions run as the table
-- owner, not as the deleting role.
GRANT SELECT, INSERT, UPDATE ON authority_requirements TO inntris_worker;
GRANT SELECT, INSERT, UPDATE ON authority_controls TO inntris_worker;

-- Supabase defines anon/authenticated; a plain PostgreSQL database does not.
-- Guard the REVOKE so the same tree stays portable, matching the convention
-- established in 020_rls_hardening.sql.
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
-- Prove the PROPERTIES, not that objects with the right names exist. A unique
-- index present but written over the wrong columns would pass a name check
-- and still permit two contradictory rows for one scope -- whereupon "is
-- authority required here" would have two answers.
DO $$
DECLARE
    v_org UUID := gen_random_uuid();
    v_agent UUID := gen_random_uuid();
    v_accepted BOOLEAN;
    v_table TEXT;
    v_rls BOOLEAN;
    v_forced BOOLEAN;
BEGIN
    FOREACH v_table IN ARRAY ARRAY['authority_requirements', 'authority_controls']
    LOOP
        SELECT relrowsecurity, relforcerowsecurity INTO v_rls, v_forced
        FROM pg_class WHERE oid = format('public.%I', v_table)::regclass;
        IF NOT v_rls OR NOT v_forced THEN
            RAISE EXCEPTION
                '027 drift: % must have row level security ENABLED and FORCED', v_table;
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1 FROM information_schema.role_table_grants
        WHERE grantee = 'inntris_worker'
          AND table_name IN ('authority_requirements', 'authority_controls')
          AND privilege_type = 'DELETE'
    ) THEN
        RAISE EXCEPTION
            '027 drift: the runtime role must not hold DELETE on the rollout '
            'controls; lifting a requirement is an UPDATE that keeps the record';
    END IF;

    -- Two org-wide rows for one organisation must be impossible. Without the
    -- generated scope_key this would succeed, because NULL <> NULL.
    INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
    VALUES (v_org, '027-drift-' || v_org, 'free', v_org || '@drift.invalid',
            sha256(v_org::TEXT::BYTEA));

    INSERT INTO authority_requirements
        (org_id, agent_id, action_class, required, reason, changed_by, approval_reference)
    VALUES (v_org, NULL, NULL, TRUE, 'drift', 'drift', 'drift');

    v_accepted := TRUE;
    BEGIN
        INSERT INTO authority_requirements
            (org_id, agent_id, action_class, required, reason, changed_by, approval_reference)
        VALUES (v_org, NULL, NULL, FALSE, 'drift', 'drift', 'drift');
    EXCEPTION WHEN unique_violation THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION
            '027 drift: two organisation-wide requirement rows were accepted for '
            'one organisation; the scope uniqueness is not doing its job';
    END IF;

    -- A requirement must not be able to name another tenant's principal.
    v_accepted := TRUE;
    BEGIN
        INSERT INTO authority_requirements
            (org_id, agent_id, action_class, required, reason, changed_by, approval_reference)
        VALUES (v_org, v_agent, NULL, TRUE, 'drift', 'drift', 'drift');
    EXCEPTION WHEN foreign_key_violation THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION
            '027 drift: a requirement naming an agent this organisation does not '
            'own was accepted; the composite foreign key is not doing its job';
    END IF;

    -- An unknown control name must be refused, so a typo cannot create a
    -- switch nothing reads and everyone believes in.
    v_accepted := TRUE;
    BEGIN
        INSERT INTO authority_controls
            (control, org_id, engaged, reason, changed_by, approval_reference)
        VALUES ('not_a_real_control', v_org, TRUE, 'drift', 'drift', 'drift');
    EXCEPTION WHEN check_violation THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION '027 drift: an unknown control name was accepted';
    END IF;

    DELETE FROM organizations WHERE id = v_org;
END;
$$;
