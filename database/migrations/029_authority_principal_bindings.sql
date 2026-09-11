-- =============================================================================
-- 029 — Server-only binding between a principal and an external issuer identity
-- =============================================================================
-- Phase 7A, Gate 3.
--
-- A verified delegation says "the holder of account X may spend up to Y". For
-- that to mean anything, Core must be able to answer: is the agent in front of
-- me actually account X? That answer has to come from somewhere the caller
-- cannot write.
--
-- WHY NOT agents.metadata
-- -----------------------
-- The obvious place was the agent's metadata. It is not usable, and this is
-- the reason recorded so nobody moves it there later:
--
--   * POST /agents/register copies request metadata onto the agent, minus a
--     lifecycle blocklist (api/legacy_main.py);
--   * the public registration route does the same with adapter metadata.
--
-- So a caller can choose their own agent's metadata. If the issuer binding
-- lived there, an attacker could register an agent declaring somebody else's
-- issuer account reference, present that account's genuine delegation, and
-- have it verify -- the signature is real, the delegation is real, and the
-- only thing tying it to a principal would be a field the attacker wrote.
--
-- This table is written by the system role through an administrative path
-- that records an actor and an approval reference. It is never written from a
-- registration request.
--
-- RELEASE GATE: the table is new, so the ACCESS EXCLUSIVE lock is on an empty
-- relation. No existing table is rewritten.
-- =============================================================================

CREATE TABLE IF NOT EXISTS authority_principal_bindings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL,
    -- Bindings are per issuer. A value meaningful to one issuer must never be
    -- accepted as identity for another, even if the two happen to spell their
    -- account references the same way.
    issuer TEXT NOT NULL,
    binding_key VARCHAR(100) NOT NULL,
    binding_value TEXT NOT NULL,
    reason TEXT NOT NULL,
    changed_by VARCHAR(255) NOT NULL,
    approval_reference VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT authority_binding_agent_owned
        FOREIGN KEY (agent_id, org_id) REFERENCES agents (id, org_id)
        ON DELETE CASCADE,
    CONSTRAINT authority_binding_issuer_not_blank CHECK (BTRIM(issuer) <> ''),
    CONSTRAINT authority_binding_key_not_blank CHECK (BTRIM(binding_key) <> ''),
    CONSTRAINT authority_binding_value_not_blank CHECK (BTRIM(binding_value) <> ''),
    CONSTRAINT authority_binding_reason_not_blank CHECK (BTRIM(reason) <> ''),
    CONSTRAINT authority_binding_changed_by_not_blank CHECK (BTRIM(changed_by) <> ''),
    CONSTRAINT authority_binding_approval_not_blank
        CHECK (BTRIM(approval_reference) <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_authority_principal_bindings
    ON authority_principal_bindings (agent_id, issuer, binding_key);

-- The hot path reads every binding for one (agent, issuer) pair.
CREATE INDEX IF NOT EXISTS idx_authority_principal_bindings_lookup
    ON authority_principal_bindings (agent_id, issuer);

COMMENT ON TABLE authority_principal_bindings IS
    'Server-only mapping from a principal to its identity at an external issuer. Never written from a registration request.';

-- --- Row level security ---------------------------------------------------
ALTER TABLE authority_principal_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_principal_bindings FORCE ROW LEVEL SECURITY;

-- A tenant session may SEE which bindings apply to it and may not write one:
-- writing is what a caller must not be able to do, and a tenant-authenticated
-- admin route is still driven by a request.
DROP POLICY IF EXISTS authority_principal_bindings_tenant_read
    ON authority_principal_bindings;
CREATE POLICY authority_principal_bindings_tenant_read
    ON authority_principal_bindings
    FOR SELECT
    TO inntris_api
    USING (org_id = app.current_tenant());

REVOKE ALL ON TABLE authority_principal_bindings FROM PUBLIC;
GRANT SELECT ON authority_principal_bindings TO inntris_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON authority_principal_bindings TO inntris_worker;

DO $$
DECLARE
    client_role TEXT;
BEGIN
    FOREACH client_role IN ARRAY ARRAY['anon', 'authenticated']
    LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = client_role) THEN
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE public.authority_principal_bindings FROM %I',
                client_role
            );
        END IF;
    END LOOP;
END;
$$;

-- --- Drift guard ----------------------------------------------------------
DO $$
DECLARE
    v_org UUID := gen_random_uuid();
    v_other_org UUID := gen_random_uuid();
    v_agent UUID := gen_random_uuid();
    v_other_agent UUID := gen_random_uuid();
    v_rls BOOLEAN;
    v_forced BOOLEAN;
    v_accepted BOOLEAN;
BEGIN
    SELECT c.relrowsecurity, c.relforcerowsecurity INTO v_rls, v_forced
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relname = 'authority_principal_bindings';
    IF v_rls IS DISTINCT FROM TRUE OR v_forced IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION
            'migration 029 drift: authority_principal_bindings must have RLS enabled and forced';
    END IF;

    INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
        VALUES (v_org, 'migration-029-guard', 'enterprise',
                'migration-029-guard@invalid.test', sha256(v_org::TEXT::BYTEA)),
               (v_other_org, 'migration-029-guard-other', 'enterprise',
                'migration-029-guard-other@invalid.test', sha256(v_other_org::TEXT::BYTEA));
    INSERT INTO agents (
        id, org_id, name, public_key, public_key_fingerprint, trust_score,
        status, daily_limit_usd, per_action_limit_usd, allowed_actions,
        blocked_actions, rate_limit_per_minute, metadata
    ) VALUES
        (v_agent, v_org, 'migration-029-guard', decode(repeat('00', 32), 'hex'),
         repeat('c', 64), 80, 'active', 100, 100,
         ARRAY['financial_transaction']::TEXT[], ARRAY[]::TEXT[], 60,
         '{"sandbox": true}'::JSONB),
        (v_other_agent, v_other_org, 'migration-029-guard-other',
         decode(repeat('00', 32), 'hex'), repeat('d', 64), 80, 'active', 100, 100,
         ARRAY['financial_transaction']::TEXT[], ARRAY[]::TEXT[], 60,
         '{"sandbox": true}'::JSONB);

    -- 1. A binding may not be written against another tenant's principal.
    BEGIN
        INSERT INTO authority_principal_bindings (
            org_id, agent_id, issuer, binding_key, binding_value, reason,
            changed_by, approval_reference
        ) VALUES (v_org, v_other_agent, 'guard-issuer', 'account_reference',
                  'acct-1', 'guard', 'guard', 'guard');
        v_accepted := TRUE;
    EXCEPTION WHEN foreign_key_violation THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION
            'migration 029 drift: a binding was accepted against another tenant''s principal';
    END IF;

    -- 2. One (agent, issuer, key) holds one value.
    INSERT INTO authority_principal_bindings (
        org_id, agent_id, issuer, binding_key, binding_value, reason,
        changed_by, approval_reference
    ) VALUES (v_org, v_agent, 'guard-issuer', 'account_reference', 'acct-1',
              'guard', 'guard', 'guard');
    BEGIN
        INSERT INTO authority_principal_bindings (
            org_id, agent_id, issuer, binding_key, binding_value, reason,
            changed_by, approval_reference
        ) VALUES (v_org, v_agent, 'guard-issuer', 'account_reference', 'acct-2',
                  'guard', 'guard', 'guard');
        v_accepted := TRUE;
    EXCEPTION WHEN unique_violation THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION
            'migration 029 drift: one principal held two identities at one issuer';
    END IF;

    -- 3. The same key under a DIFFERENT issuer is a different binding.
    INSERT INTO authority_principal_bindings (
        org_id, agent_id, issuer, binding_key, binding_value, reason,
        changed_by, approval_reference
    ) VALUES (v_org, v_agent, 'other-guard-issuer', 'account_reference', 'acct-9',
              'guard', 'guard', 'guard');

    DELETE FROM authority_principal_bindings WHERE org_id = v_org;
    DELETE FROM agents WHERE id IN (v_agent, v_other_agent);
    DELETE FROM organizations WHERE id IN (v_org, v_other_org);
END;
$$;
