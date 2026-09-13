-- =============================================================================
-- 030 — The global configuration lock ranks above the per-organisation one
-- =============================================================================
-- Phase 7A, Gate 2. 029 gave every configuration scope its own advisory key
-- and made writers take it EXCLUSIVE from a BEFORE trigger. That serialises
-- a writer against readers OF THE SAME SCOPE, and independent review found
-- the gap that leaves:
--
--     issuance for organisation A        takes  authority-config:<A>  SHARED
--     a GLOBAL authority_issuance halt   takes  authority-config:global EXCLUSIVE
--
-- Those two keys do not conflict. But the effective configuration for
-- organisation A CONSULTS the global row -- a global halt stops issuance
-- everywhere. So a global halt could commit while issuance for A was already
-- in flight, and that issuance could still commit a grant afterwards: a
-- grant issued under a halt that was already in force.
--
-- The scope that is READ has to be the scope that is LOCKED. Issuance reads
-- global and organisation rows, so it must hold both keys.
--
-- THE HIERARCHY
--
--     ISSUANCE          CONFIG_GLOBAL shared  -> CONFIG_ORG shared
--                       -> principal -> grant -> reservation
--
--     CONSUMPTION       CONFIG_ORG shared -> forensic chain -> principal
--                       -> grant
--
--     WRITER            CONFIG_GLOBAL exclusive
--                       -> CONFIG_ORG exclusive   (org-scoped rows only)
--                       -> any administrative audit work
--
-- Consumption deliberately does NOT take CONFIG_GLOBAL. The only global
-- control is authority_issuance, which halts NEW issuance; it must not
-- invalidate authority that was already issued, and consumption does not
-- consult it. Adding the global key to consumption would make every spend
-- on the platform serialise behind one lock for no decision it affects.
--
-- WHY THE WRITER TAKES THE GLOBAL KEY EVEN FOR AN ORGANISATION ROW
-- Unconditionally, and FIRST, on every configuration write. Two reasons:
--
--   1. It is what makes the hierarchy total. A transaction that mutates a
--      global row and an organisation row -- in either statement order --
--      can then only ever go CONFIG_GLOBAL -> CONFIG_ORG. The reverse edge
--      is unconstructible, so no pair of writers can form a cycle.
--   2. It gives issuance a wait-free path past the organisation key: a
--      transaction can only hold CONFIG_ORG exclusive if it also holds
--      CONFIG_GLOBAL exclusive, which it cannot while an issuer holds
--      CONFIG_GLOBAL shared. An issuer that is past the global key can
--      never queue behind a configuration writer.
--
-- And the cost is bounded: configuration writes are rare, operator-driven
-- and already serialised per scope. What they now also serialise against is
-- each other, platform-wide, which is what "one operator changes policy at
-- a time" should have meant all along.
--
-- NO KEY IS COMPUTED OUTSIDE THE DATABASE
-- ``authority_config_lock_key()`` is added here so the global key exists in
-- exactly ONE place. This trigger calls it and so does the application:
-- neither formats the string 'global' itself. A reader and a writer that
-- each built the key their own way would believe they were serialising
-- while addressing two different locks -- serialisation that looks present
-- in the code and is absent at runtime, which is the failure this whole
-- mechanism exists to prevent.
--
-- LOCK PROFILE: creates two functions, replaces one, and touches no table.
-- The 029 triggers are kept as they are and pick up the new body.
-- =============================================================================

-- The global half of the key namespace, in ONE place.
CREATE OR REPLACE FUNCTION authority_config_global_lock_key()
RETURNS TEXT AS $$
    SELECT 'global'::TEXT;
$$ LANGUAGE sql IMMUTABLE;

COMMENT ON FUNCTION authority_config_global_lock_key() IS
    'The object half of the authority-config advisory key for PLATFORM-WIDE '
    'configuration. Callers must not spell this literal themselves.';


-- The object half of the key for any configuration scope. NULL means the
-- global scope, which is how a global control row is stored.
CREATE OR REPLACE FUNCTION authority_config_lock_key(p_org UUID)
RETURNS TEXT AS $$
    SELECT COALESCE(p_org::TEXT, authority_config_global_lock_key());
$$ LANGUAGE sql IMMUTABLE;

COMMENT ON FUNCTION authority_config_lock_key(UUID) IS
    'The object half of the authority-config advisory key for one scope. '
    'The application derives its keys through this same function, so a '
    'reader and a writer cannot drift onto different locks.';


CREATE OR REPLACE FUNCTION authority_configuration_write_lock()
RETURNS TRIGGER AS $$
DECLARE
    v_org UUID;
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

    -- ALWAYS the global key first, for every configuration row, whatever
    -- its scope. This is the top of the hierarchy: taking it here means an
    -- organisation-scoped write can never be the first to hold the
    -- organisation key, so CONFIG_ORG -> CONFIG_GLOBAL cannot be built.
    --
    -- The TWO-INT advisory form is used deliberately, and both halves are
    -- derived by PostgreSQL, so the application and this trigger cannot
    -- drift apart through a difference in string formatting. A hash
    -- collision merely serialises two scopes that did not need it; it can
    -- never produce a missed lock.
    PERFORM pg_advisory_xact_lock(
        hashtext(authority_config_lock_namespace()),
        hashtext(authority_config_lock_key(NULL))
    );

    -- ...and then the organisation key, when the row is organisation
    -- scoped. Re-taking the global key for a global row would be harmless
    -- (advisory locks nest) but saying so once is clearer.
    IF v_org IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(
            hashtext(authority_config_lock_namespace()),
            hashtext(authority_config_lock_key(v_org))
        );
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION authority_configuration_write_lock() IS
    'Takes the EXCLUSIVE authority-config locks for the row being written, '
    'global first and then the organisation, held until commit. A global '
    'halt therefore cannot commit underneath an issuance already in flight '
    'for any organisation.';


-- --- Drift guard ----------------------------------------------------------
-- Proves the PROPERTIES the hierarchy depends on, not the names of things:
-- that a global write takes exactly the global key, that an organisation
-- write takes the global key as well as its own, that the refusal to move a
-- row between organisations survives, and that both tables actually carry a
-- row trigger for all three DML operations. Acquisition ORDER is not
-- observable from inside one transaction and is proved by the deterministic
-- two-connection tests instead.
DO $$
DECLARE
    v_org UUID := gen_random_uuid();
    v_other UUID := gen_random_uuid();
    v_classid INTEGER;
    v_global_objid INTEGER;
    v_org_objid INTEGER;
    v_total BIGINT;
    v_accepted BOOLEAN;
    v_id UUID;
    v_triggers BIGINT;
BEGIN
    SELECT hashtext(authority_config_lock_namespace()) INTO v_classid;
    SELECT hashtext(authority_config_lock_key(NULL)) INTO v_global_objid;
    SELECT hashtext(authority_config_lock_key(v_org)) INTO v_org_objid;

    IF v_global_objid = v_org_objid THEN
        RAISE EXCEPTION
            '030 drift: the global configuration key collides with an '
            'organisation key; the hierarchy would be one lock, not two';
    END IF;

    -- Both tables must be covered for INSERT, UPDATE and DELETE. A writer
    -- reaching one of these tables through an uncovered operation would
    -- bypass the hierarchy entirely.
    SELECT COUNT(*) INTO v_triggers
    FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    JOIN pg_proc p ON p.oid = t.tgfoid
    WHERE NOT t.tgisinternal
      AND p.proname = 'authority_configuration_write_lock'
      AND c.relname IN ('authority_requirements', 'authority_controls')
      -- BEFORE (tgtype bit 1) and FOR EACH ROW (bit 0), covering
      -- INSERT (bit 2), DELETE (bit 3) and UPDATE (bit 4).
      AND (t.tgtype & 1) = 1
      AND (t.tgtype & 2) = 2
      AND (t.tgtype & 4) = 4
      AND (t.tgtype & 8) = 8
      AND (t.tgtype & 16) = 16;
    IF v_triggers <> 2 THEN
        RAISE EXCEPTION
            '030 drift: expected a BEFORE INSERT OR UPDATE OR DELETE row '
            'trigger taking the configuration locks on both configuration '
            'tables, found % ', v_triggers;
    END IF;

    INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
    VALUES (v_org, '030-drift-' || v_org, 'free', v_org || '@drift.invalid',
            sha256(v_org::TEXT::BYTEA));
    INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
    VALUES (v_other, '030-drift-' || v_other, 'free', v_other || '@drift.invalid',
            sha256(v_other::TEXT::BYTEA));

    -- A GLOBAL row takes the global key and NOTHING else. Counting every
    -- advisory lock this backend holds in the namespace is what proves the
    -- "nothing else": naming the key we expect would not.
    INSERT INTO authority_controls
        (control, org_id, engaged, reason, changed_by, approval_reference)
    VALUES ('authority_issuance', NULL, FALSE, 'drift', 'drift', 'drift');

    SELECT COUNT(*) INTO v_total FROM pg_locks
    WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
      AND objsubid = 2 AND classid = v_classid::OID;
    IF v_total <> 1 THEN
        RAISE EXCEPTION
            '030 drift: a global configuration write holds % configuration '
            'locks, expected exactly the global one', v_total;
    END IF;

    SELECT COUNT(*) INTO v_total FROM pg_locks
    WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
      AND objsubid = 2 AND classid = v_classid::OID AND objid = v_global_objid::OID;
    IF v_total = 0 THEN
        RAISE EXCEPTION
            '030 drift: a global configuration write did not take the global '
            'configuration lock';
    END IF;

    -- An ORGANISATION row takes its own key IN ADDITION to the global one.
    INSERT INTO authority_requirements
        (org_id, agent_id, action_class, required, reason, changed_by, approval_reference)
    VALUES (v_org, NULL, NULL, FALSE, 'drift', 'drift', 'drift')
    RETURNING id INTO v_id;

    SELECT COUNT(*) INTO v_total FROM pg_locks
    WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
      AND objsubid = 2 AND classid = v_classid::OID AND objid = v_org_objid::OID;
    IF v_total = 0 THEN
        RAISE EXCEPTION
            '030 drift: an organisation-scoped configuration write did not '
            'take its organisation configuration lock';
    END IF;

    SELECT COUNT(*) INTO v_total FROM pg_locks
    WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
      AND objsubid = 2 AND classid = v_classid::OID AND objid = v_global_objid::OID;
    IF v_total = 0 THEN
        RAISE EXCEPTION
            '030 drift: an organisation-scoped configuration write did not '
            'take the global configuration lock; CONFIG_ORG -> CONFIG_GLOBAL '
            'would be constructible';
    END IF;

    -- The 029 refusal must survive the replacement.
    v_accepted := TRUE;
    BEGIN
        UPDATE authority_requirements SET org_id = v_other WHERE id = v_id;
    EXCEPTION WHEN raise_exception THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION
            '030 drift: a configuration row was moved between organisations; '
            'two different locks would govern one statement';
    END IF;

    DELETE FROM authority_requirements WHERE org_id = v_org;
    DELETE FROM authority_controls WHERE org_id IS NULL AND reason = 'drift';
    DELETE FROM organizations WHERE id IN (v_org, v_other);
END;
$$;
