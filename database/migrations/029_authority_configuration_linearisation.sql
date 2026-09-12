-- =============================================================================
-- 029 — Authority configuration changes serialise against fresh consumption
-- =============================================================================
-- Phase 7A, Gate 2. 027 created the tables, 028 made them read-only at
-- runtime, and the reader landed with consume-time re-checking. What was
-- missing is linearisation: a configuration change could commit between a
-- consuming transaction reading the configuration and that transaction
-- committing, so a spend could commit under a configuration that was no
-- longer current.
--
-- The model is one advisory lock namespace per organisation:
--
--     authority-config:<org_id>
--     authority-config:global            when org_id IS NULL
--
-- Fresh consumption takes it SHARED and holds it to commit. Every mutation
-- of the configuration takes it EXCLUSIVE and holds it to commit. Shared
-- holders do not block one another, so concurrent consumption in one
-- organisation is unaffected; a writer waits for the consumers already in
-- flight, and consumers starting after the writer holds it wait for the
-- writer. Different organisations never block each other.
--
-- The acceptance statement this buys:
--
--     If a configuration change commits before a fresh consumption commits,
--     that consumption either observed the new configuration, or was
--     already linearised before the change because it held the shared lock
--     that prevented the change from committing.
--
-- WHY A TRIGGER AND NOT ONLY APPLICATION CODE
-- Because the application management surface does not exist yet, and when
-- it does it must not be the only thing standing between a configuration
-- write and an unserialised spend. A writer that forgets the lock is
-- exactly the failure this is guarding, so the database takes it.
--
-- LOCK ORDER -- READ THIS BEFORE ADDING A MANAGEMENT PATH
--
--     GRANT -> TOKEN -> CONFIG -> FORENSIC CHAIN -> PRINCIPAL ROW
--           -> GRANT ROW -> claim/audit
--
-- A management path must take CONFIG (exclusive) and only THEN do its
-- administrative audit work. It must never take the forensic chain lock
-- first and the configuration lock second: consumption holds CONFIG before
-- CHAIN, so the reverse order is the ABBA shape Gate 7 was opened to
-- remove. This trigger takes CONFIG at the moment the configuration row is
-- written, so a path that writes its audit row FIRST would still invert.
-- Write the configuration row before the audit row.
--
-- LOCK PROFILE: creates one function and six row triggers on two tables
-- that are empty in every environment. No existing table is touched.
-- =============================================================================

-- The namespace half of the advisory key, in ONE place. Application code
-- calls this function too, so there is exactly one definition of the
-- namespace and no second copy to fall out of step.
CREATE OR REPLACE FUNCTION authority_config_lock_namespace()
RETURNS TEXT AS $$
    SELECT 'authority-config'::TEXT;
$$ LANGUAGE sql IMMUTABLE;

COMMENT ON FUNCTION authority_config_lock_namespace() IS
    'The namespace half of the authority-config advisory lock key. Readers '
    'and writers must both derive their key from this, so they cannot drift.';


CREATE OR REPLACE FUNCTION authority_configuration_write_lock()
RETURNS TRIGGER AS $$
DECLARE
    v_org UUID;
    v_key TEXT;
BEGIN
    -- Moving a configuration row between organisations would mean two
    -- different locks govern one statement, and whichever we took would be
    -- the wrong one for the other organisation. A configuration row belongs
    -- to the organisation it configures; there is no meaningful transfer.
    IF TG_OP = 'UPDATE' AND NEW.org_id IS DISTINCT FROM OLD.org_id THEN
        RAISE EXCEPTION
            'authority configuration cannot be moved between organisations '
            '(% -> %); delete and recreate it under the owning organisation',
            OLD.org_id, NEW.org_id;
    END IF;

    IF TG_OP = 'DELETE' THEN
        v_org := OLD.org_id;
    ELSE
        v_org := NEW.org_id;
    END IF;

    -- A global row (org_id IS NULL) has its own key. Global
    -- authority_issuance is an issuance control and is deliberately not
    -- consulted by fresh consumption, so this key exists for writer/writer
    -- serialisation rather than to gate any spend.
    --
    -- The TWO-INT advisory form is used deliberately. Both halves are
    -- derived by hashtext INSIDE PostgreSQL, so the application and this
    -- trigger cannot drift apart through a difference in string formatting
    -- -- which is the one way a reader and a writer could believe they are
    -- serialising on the same key while addressing two different locks.
    -- A hash collision merely serialises two organisations that did not
    -- need it; it can never produce a missed lock.
    v_key := COALESCE(v_org::TEXT, 'global');
    PERFORM pg_advisory_xact_lock(
        hashtext(authority_config_lock_namespace()), hashtext(v_key)
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION authority_configuration_write_lock() IS
    'Takes the EXCLUSIVE authority-config:<org> advisory lock for the '
    'affected organisation, held until commit, so a configuration change '
    'cannot commit while a fresh consumption holds the shared form.';

DROP TRIGGER IF EXISTS authority_requirements_write_lock ON authority_requirements;
CREATE TRIGGER authority_requirements_write_lock
    BEFORE INSERT OR UPDATE OR DELETE ON authority_requirements
    FOR EACH ROW
    EXECUTE FUNCTION authority_configuration_write_lock();

DROP TRIGGER IF EXISTS authority_controls_write_lock ON authority_controls;
CREATE TRIGGER authority_controls_write_lock
    BEFORE INSERT OR UPDATE OR DELETE ON authority_controls
    FOR EACH ROW
    EXECUTE FUNCTION authority_configuration_write_lock();

-- --- Drift guard ----------------------------------------------------------
DO $$
DECLARE
    v_org UUID := gen_random_uuid();
    v_other UUID := gen_random_uuid();
    v_held BIGINT;
    v_classid INTEGER;
    v_objid INTEGER;
    v_accepted BOOLEAN;
    v_id UUID;
BEGIN
    INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
    VALUES (v_org, '029-drift-' || v_org, 'free', v_org || '@drift.invalid',
            sha256(v_org::TEXT::BYTEA));
    INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
    VALUES (v_other, '029-drift-' || v_other, 'free', v_other || '@drift.invalid',
            sha256(v_other::TEXT::BYTEA));

    SELECT hashtext(authority_config_lock_namespace()) INTO v_classid;
    SELECT hashtext(v_org::TEXT) INTO v_objid;

    -- An INSERT must leave this transaction holding the exclusive lock.
    INSERT INTO authority_requirements
        (org_id, agent_id, action_class, required, reason, changed_by, approval_reference)
    VALUES (v_org, NULL, NULL, FALSE, 'drift', 'drift', 'drift')
    RETURNING id INTO v_id;

    SELECT COUNT(*) INTO v_held FROM pg_locks
    WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
      AND objsubid = 2
      AND classid = v_classid::OID AND objid = v_objid::OID;
    IF v_held = 0 THEN
        RAISE EXCEPTION
            '029 drift: an INSERT into authority_requirements did not take the '
            'exclusive authority-config lock for its organisation';
    END IF;

    -- ...and so must an UPDATE of a control row.
    INSERT INTO authority_controls
        (control, org_id, engaged, reason, changed_by, approval_reference)
    VALUES ('authority_issuance', v_org, FALSE, 'drift', 'drift', 'drift');

    -- Moving a row between organisations must be refused outright.
    v_accepted := TRUE;
    BEGIN
        UPDATE authority_requirements SET org_id = v_other WHERE id = v_id;
    EXCEPTION WHEN raise_exception THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION
            '029 drift: a configuration row was moved between organisations; '
            'two different locks would govern one statement';
    END IF;

    DELETE FROM authority_requirements WHERE org_id = v_org;
    DELETE FROM authority_controls WHERE org_id = v_org;
    DELETE FROM organizations WHERE id IN (v_org, v_other);
END;
$$;
