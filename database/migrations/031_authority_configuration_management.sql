-- =============================================================================
-- 031 — A trusted identity for authority-configuration changes, and a
--       platform scope for the administrative audit record
-- =============================================================================
-- Phase 7A, Gate 2, invariant 7: a configuration mutation and its
-- administrative audit record must commit in ONE transaction. 027 created the
-- tables, 028 made them read-only to the runtime role, 029 and 030 gave the
-- writer its lock hierarchy. What was still missing is the identity that may
-- perform such a change at all, and an audit record able to describe one.
--
-- TWO THINGS ARE ADDED, AND NOTHING IS WEAKENED
--
-- 1. ``inntris_authority_admin`` -- a login role that may read and write the
--    two configuration tables and append to administrative_audit_events, and
--    can do nothing else. The runtime role keeps exactly the privileges 028
--    left it: SELECT and no more. Making the runtime role able to perform a
--    configuration change would have removed the property 028 exists to
--    provide, so the management path gets its own identity instead.
--
--    It is NOBYPASSRLS. The configuration tables are ENABLE + FORCE row level
--    security, so it is given an explicit policy on those two tables rather
--    than a cluster-wide bypass: the grant is then visible in pg_policies,
--    scoped to the two tables it is for, and cannot silently extend to a
--    table added later.
--
-- 2. A ``scope`` discriminator on administrative_audit_events, and org_id
--    becomes nullable.
--
--    A platform-wide authority_issuance halt has no organisation, and org_id
--    was NOT NULL with a foreign key, so the existing table could not record
--    one. Dropping NOT NULL alone would let ANY administrative event lose its
--    organisation silently, which is worse than not recording it -- so the
--    nullability is paired with an explicit scope that says which kind of
--    event this is, and a CHECK that makes the two agree. An organisation
--    event without an organisation, or a platform event with one, is now a
--    constraint violation rather than a quiet ambiguity.
--
--    This EXTENDS the one existing administrative audit mechanism. A second,
--    parallel audit table for authority configuration would mean two places
--    to look for "who changed what", and two things to keep immutable.
--
-- WHY NO AUDIT TRIGGER ON THE CONFIGURATION TABLES
-- An AFTER trigger writing the audit row would make the audit automatic, and
-- it is tempting. It is not done here, deliberately:
--
--   * the audit record needs the actor, the reason and the approval
--     reference. A trigger can only see what is in the row, so those would
--     have to be smuggled through session GUCs -- unset by an emergency
--     operator, and then the audit records nobody;
--   * it would make every direct SQL write to these tables acquire whatever
--     the audit path acquires, inside arbitrary transactions whose lock graph
--     nobody has proved. The Gate-7 deadlock came from exactly that shape.
--
-- The management primitive writes both rows explicitly instead, in one
-- transaction, configuration first. See docs/runbooks/authority_requirement_rollout.md.
--
-- LOCK PROFILE: one role, two policies, one nullability change and one added
-- column with a fast default. The added CHECKs are NOT VALID then VALIDATEd,
-- so administrative_audit_events is never held under ACCESS EXCLUSIVE for a
-- scan. No configuration table is rewritten.
-- =============================================================================

-- --- 1. The trusted management identity -----------------------------------
DO $$
DECLARE
    admin_exists BOOLEAN;
    admin_super BOOLEAN;
    admin_bypass BOOLEAN;
BEGIN
    SELECT TRUE, rolsuper, rolbypassrls
      INTO admin_exists, admin_super, admin_bypass
      FROM pg_roles WHERE rolname = 'inntris_authority_admin';

    IF admin_exists AND (admin_super OR admin_bypass) THEN
        RAISE EXCEPTION
            'inntris_authority_admin already exists with SUPERUSER or '
            'BYPASSRLS; refusing to narrow it implicitly -- review it first';
    END IF;

    IF admin_exists IS NOT TRUE THEN
        -- No password here. Migration history is replayed into environments
        -- that must not share a credential; deployment provisions it the way
        -- it provisions the runtime role.
        CREATE ROLE inntris_authority_admin
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOBYPASSRLS
            NOINHERIT
            CONNECTION LIMIT 5;
    ELSE
        ALTER ROLE inntris_authority_admin
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOBYPASSRLS
            NOINHERIT
            CONNECTION LIMIT 5;
    END IF;
END $$;

ALTER ROLE inntris_authority_admin
    SET search_path = pg_catalog, public;
ALTER ROLE inntris_authority_admin
    SET statement_timeout = '30s';
ALTER ROLE inntris_authority_admin
    SET idle_in_transaction_session_timeout = '15s';

GRANT USAGE ON SCHEMA public TO inntris_authority_admin;

-- Exactly the reach a configuration change needs. No DELETE: 027 chose to
-- keep superseded configuration as history rather than let it be erased, and
-- that choice is not this migration's to reverse.
GRANT SELECT, INSERT, UPDATE ON authority_requirements TO inntris_authority_admin;
GRANT SELECT, INSERT, UPDATE ON authority_controls TO inntris_authority_admin;
GRANT SELECT, INSERT ON administrative_audit_events TO inntris_authority_admin;
-- Reading the scope it is about to configure: the organisation must exist,
-- and a principal-scoped requirement must name an agent that organisation
-- owns. The composite foreign key enforces the latter; this lets the
-- primitive fail with a clear message instead of a constraint violation.
GRANT SELECT ON organizations TO inntris_authority_admin;
GRANT SELECT ON agents TO inntris_authority_admin;

-- FORCE row level security applies to every non-BYPASSRLS role, so without a
-- policy the grants above would read and write nothing at all. The policy is
-- unrestricted WITHIN these two tables, which is the whole of this role's
-- purpose, and is confined to this role.
DROP POLICY IF EXISTS authority_requirements_management ON authority_requirements;
CREATE POLICY authority_requirements_management
    ON authority_requirements
    FOR ALL
    TO inntris_authority_admin
    USING (TRUE)
    WITH CHECK (TRUE);

DROP POLICY IF EXISTS authority_controls_management ON authority_controls;
CREATE POLICY authority_controls_management
    ON authority_controls
    FOR ALL
    TO inntris_authority_admin
    USING (TRUE)
    WITH CHECK (TRUE);

-- administrative_audit_events has had row level security ENABLED since
-- migration 020 with deliberately NO policy: it is a system table that only
-- BYPASSRLS server paths were ever meant to touch. A NOBYPASSRLS role needs
-- one, or its INSERT grant above would be silently inert -- and the failure
-- mode would be a management change that cannot record itself.
--
-- INSERT and SELECT are separate policies rather than FOR ALL so the two
-- permissions are individually visible in pg_policies. SELECT is required as
-- well as INSERT: the primitive uses RETURNING, and PostgreSQL applies a
-- SELECT policy to an INSERT that returns rows. UPDATE and DELETE are absent
-- here and ungranted above, and the table's own triggers refuse both anyway.
DROP POLICY IF EXISTS administrative_audit_events_management_append
    ON administrative_audit_events;
CREATE POLICY administrative_audit_events_management_append
    ON administrative_audit_events
    FOR INSERT
    TO inntris_authority_admin
    WITH CHECK (TRUE);

DROP POLICY IF EXISTS administrative_audit_events_management_read
    ON administrative_audit_events;
CREATE POLICY administrative_audit_events_management_read
    ON administrative_audit_events
    FOR SELECT
    TO inntris_authority_admin
    USING (TRUE);

COMMENT ON ROLE inntris_authority_admin IS
    'Trusted authority-configuration management login. May change '
    'authority_requirements / authority_controls and append the matching '
    'administrative_audit_events row, and nothing else.';


-- --- 2. A platform scope for the administrative audit record --------------
ALTER TABLE administrative_audit_events
    ADD COLUMN IF NOT EXISTS scope VARCHAR(20) NOT NULL DEFAULT 'organisation';

ALTER TABLE administrative_audit_events
    ALTER COLUMN org_id DROP NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'administrative_event_scope_known'
           AND conrelid = 'administrative_audit_events'::REGCLASS
    ) THEN
        ALTER TABLE administrative_audit_events
            ADD CONSTRAINT administrative_event_scope_known
            CHECK (scope IN ('organisation', 'platform')) NOT VALID;
        ALTER TABLE administrative_audit_events
            VALIDATE CONSTRAINT administrative_event_scope_known;
    END IF;

    -- The pairing is the point: nullability on its own would let an
    -- organisation event silently lose its organisation.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'administrative_event_scope_matches_org'
           AND conrelid = 'administrative_audit_events'::REGCLASS
    ) THEN
        ALTER TABLE administrative_audit_events
            ADD CONSTRAINT administrative_event_scope_matches_org
            CHECK ((scope = 'organisation') = (org_id IS NOT NULL)) NOT VALID;
        ALTER TABLE administrative_audit_events
            VALIDATE CONSTRAINT administrative_event_scope_matches_org;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_administrative_audit_events_platform_time
    ON administrative_audit_events (created_at DESC)
    WHERE org_id IS NULL;

COMMENT ON COLUMN administrative_audit_events.scope IS
    'organisation = org_id names the tenant; platform = a change with no '
    'tenant, such as a platform-wide authority_issuance halt.';


-- --- Drift guard ----------------------------------------------------------
-- Proves the PROPERTIES this increment depends on, not the names of things.
DO $$
DECLARE
    v_org UUID := gen_random_uuid();
    v_count BIGINT;
    v_accepted BOOLEAN;
    v_super BOOLEAN;
    v_bypass BOOLEAN;
BEGIN
    SELECT rolsuper, rolbypassrls INTO v_super, v_bypass
      FROM pg_roles WHERE rolname = 'inntris_authority_admin';
    IF v_super IS NULL THEN
        RAISE EXCEPTION '031 drift: inntris_authority_admin was not created';
    END IF;
    IF v_super OR v_bypass THEN
        RAISE EXCEPTION
            '031 drift: the management role is SUPERUSER or BYPASSRLS; it '
            'must reach the configuration tables through its policy only';
    END IF;

    -- 028 must still hold: the RUNTIME role cannot change configuration.
    IF has_table_privilege('inntris_worker', 'authority_requirements', 'INSERT')
       OR has_table_privilege('inntris_worker', 'authority_requirements', 'UPDATE')
       OR has_table_privilege('inntris_worker', 'authority_controls', 'INSERT')
       OR has_table_privilege('inntris_worker', 'authority_controls', 'UPDATE') THEN
        RAISE EXCEPTION
            '031 drift: the runtime role can write authority configuration; '
            'the management identity exists so that it does not have to';
    END IF;

    -- The management role must be able to, and must not be able to DELETE.
    IF NOT (has_table_privilege('inntris_authority_admin', 'authority_requirements', 'INSERT')
        AND has_table_privilege('inntris_authority_admin', 'authority_requirements', 'UPDATE')
        AND has_table_privilege('inntris_authority_admin', 'authority_controls', 'INSERT')
        AND has_table_privilege('inntris_authority_admin', 'authority_controls', 'UPDATE')
        AND has_table_privilege('inntris_authority_admin', 'administrative_audit_events', 'INSERT')) THEN
        RAISE EXCEPTION
            '031 drift: the management role cannot perform a configuration '
            'change together with its audit record';
    END IF;
    IF has_table_privilege('inntris_authority_admin', 'authority_requirements', 'DELETE')
       OR has_table_privilege('inntris_authority_admin', 'authority_controls', 'DELETE')
       OR has_table_privilege('inntris_authority_admin', 'administrative_audit_events', 'DELETE') THEN
        RAISE EXCEPTION
            '031 drift: the management role can DELETE configuration or audit '
            'history; superseded configuration is kept, not erased';
    END IF;

    -- The tenant role must remain read-only on configuration and blind to
    -- the administrative audit trail.
    IF has_table_privilege('inntris_api', 'authority_requirements', 'INSERT')
       OR has_table_privilege('inntris_api', 'authority_controls', 'INSERT')
       OR has_table_privilege('inntris_api', 'administrative_audit_events', 'SELECT') THEN
        RAISE EXCEPTION
            '031 drift: the tenant role reaches authority configuration '
            'writes or the administrative audit trail';
    END IF;

    SELECT COUNT(*) INTO v_count FROM pg_policies
     WHERE schemaname = 'public'
       AND tablename IN ('authority_requirements', 'authority_controls')
       AND 'inntris_authority_admin' = ANY(roles);
    IF v_count <> 2 THEN
        RAISE EXCEPTION
            '031 drift: expected one management policy on each configuration '
            'table, found %', v_count;
    END IF;

    -- A grant without a policy on an RLS table is an inert grant. The
    -- management role must be able to APPEND its audit record and read it
    -- back through RETURNING, and must reach neither UPDATE nor DELETE.
    SELECT COUNT(*) INTO v_count FROM pg_policies
     WHERE schemaname = 'public'
       AND tablename = 'administrative_audit_events'
       AND 'inntris_authority_admin' = ANY(roles)
       AND cmd IN ('INSERT', 'SELECT');
    IF v_count <> 2 THEN
        RAISE EXCEPTION
            '031 drift: the management role has an INSERT grant on '
            'administrative_audit_events with no matching policy, so it '
            'cannot record the change it just made; found % policies', v_count;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_policies
         WHERE schemaname = 'public'
           AND tablename = 'administrative_audit_events'
           AND 'inntris_authority_admin' = ANY(roles)
           AND cmd IN ('ALL', 'UPDATE', 'DELETE')
    ) THEN
        RAISE EXCEPTION
            '031 drift: a management policy on administrative_audit_events '
            'reaches UPDATE or DELETE; the audit trail is append only';
    END IF;

    -- The write probes below all insert. administrative_audit_events is
    -- append only -- its own triggers refuse DELETE -- so they run inside a
    -- subtransaction that is ALWAYS rolled back, and the migration leaves no
    -- 'drift' rows behind in a real audit trail.
    BEGIN
        -- A PLATFORM event must be recordable...
        INSERT INTO administrative_audit_events
            (org_id, scope, event_type, actor, approval_reference, details)
        VALUES (NULL, 'platform', '031.drift', 'drift', 'drift', '{}'::JSONB);

        -- ...and the two halves of the scope must be unable to disagree.
        v_accepted := TRUE;
        BEGIN
            INSERT INTO administrative_audit_events
                (org_id, scope, event_type, actor, approval_reference, details)
            VALUES (NULL, 'organisation', '031.drift', 'drift', 'drift', '{}'::JSONB);
        EXCEPTION WHEN check_violation THEN
            v_accepted := FALSE;
        END;
        IF v_accepted THEN
            RAISE EXCEPTION
                '031 drift: an organisation-scoped administrative event was '
                'accepted with no organisation';
        END IF;

        INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
        VALUES (v_org, '031-drift-' || v_org, 'free', v_org || '@drift.invalid',
                sha256(v_org::TEXT::BYTEA));

        v_accepted := TRUE;
        BEGIN
            INSERT INTO administrative_audit_events
                (org_id, scope, event_type, actor, approval_reference, details)
            VALUES (v_org, 'platform', '031.drift', 'drift', 'drift', '{}'::JSONB);
        EXCEPTION WHEN check_violation THEN
            v_accepted := FALSE;
        END;
        IF v_accepted THEN
            RAISE EXCEPTION
                '031 drift: a platform-scoped administrative event was '
                'accepted with an organisation';
        END IF;

        -- Existing writers must keep working unchanged: no scope supplied.
        INSERT INTO administrative_audit_events
            (org_id, event_type, actor, approval_reference, details)
        VALUES (v_org, '031.drift', 'drift', 'drift', '{}'::JSONB);
        SELECT COUNT(*) INTO v_count FROM administrative_audit_events
         WHERE event_type = '031.drift' AND org_id = v_org AND scope = 'organisation';
        IF v_count <> 1 THEN
            RAISE EXCEPTION
                '031 drift: an existing administrative writer that supplies '
                'no scope no longer produces an organisation-scoped event';
        END IF;

        RAISE EXCEPTION 'administrative-audit-drift-probe-complete';
    EXCEPTION WHEN OTHERS THEN
        -- Anything that is not the sentinel is a real drift failure.
        IF SQLERRM <> 'administrative-audit-drift-probe-complete' THEN
            RAISE;
        END IF;
    END;
END;
$$;
