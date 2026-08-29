-- =============================================================================
-- MIGRATION 020: Production RLS hardening
-- =============================================================================
-- Goal:
--   * Close direct PostgREST access to security-sensitive system tables.
--   * Re-enable tenant RLS on agents/audit_logs (policies already exist).
--   * Enable fail-closed RLS on shared/system-only tables that are accessed by
--     Inntris server roles, not directly by browser clients.
--   * Prevent future postgres-owned tables from automatically granting access
--     to Supabase anon/authenticated roles.
--
-- Production architecture:
--   * inntris_worker is the server/worker login role and BYPASSRLS by design.
--   * admin tenant operations downgrade with SET LOCAL ROLE inntris_api and use
--     app.current_tenant() policies.
--   * public receipt verification is served by Inntris Core, not direct table
--     access from the browser.
--
-- This migration deliberately does NOT FORCE ROW LEVEL SECURITY. The trusted
-- server role already has BYPASSRLS and must continue to operate the verification
-- and anchor pipelines. RLS is the browser/direct-DB isolation boundary.
-- =============================================================================

-- Refuse to harden into a broken server posture. If the production worker role
-- has drifted, stop the migration rather than enabling RLS and discovering the
-- mismatch after deploy.
DO $$
DECLARE
    worker_bypass boolean;
BEGIN
    SELECT rolbypassrls INTO worker_bypass
    FROM pg_roles
    WHERE rolname = 'inntris_worker';

    IF worker_bypass IS DISTINCT FROM true THEN
        RAISE EXCEPTION
            'RLS hardening requires inntris_worker with BYPASSRLS; refusing migration';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'inntris_api') THEN
        RAISE EXCEPTION
            'RLS hardening requires inntris_api tenant role; refusing migration';
    END IF;
END $$;

-- Tenant-scoped tables. Their inntris_api policies were installed by migration
-- 005 and fail closed when app.current_org_id is absent.
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- System/shared tables. They intentionally have no policy for anon,
-- authenticated, or inntris_api. Trusted server paths run as inntris_worker
-- (BYPASSRLS); service_role remains an emergency/operator bypass supplied by
-- Supabase.
ALTER TABLE merkle_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE administrative_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_token_consumptions ENABLE ROW LEVEL SECURITY;

-- Defense in depth: remove table privileges from direct Supabase client roles.
-- RLS would already deny them, but privilege revocation means an accidental
-- permissive policy added later is not sufficient by itself to expose data.
REVOKE ALL PRIVILEGES ON TABLE agents FROM anon, authenticated;
REVOKE ALL PRIVILEGES ON TABLE audit_logs FROM anon, authenticated;
REVOKE ALL PRIVILEGES ON TABLE merkle_proofs FROM anon, authenticated;
REVOKE ALL PRIVILEGES ON TABLE administrative_audit_events FROM anon, authenticated;
REVOKE ALL PRIVILEGES ON TABLE approval_token_consumptions FROM anon, authenticated;

-- Existing tenant-scoped auxiliary/security tables already have RLS enabled,
-- but Supabase's broad table grants are unnecessary because Inntris does not
-- use direct browser-to-PostgREST access. Tighten those grants too.
REVOKE ALL PRIVILEGES ON TABLE
    organizations,
    agent_key_history,
    agent_policies,
    api_keys,
    erasure_requests,
    policy_rules,
    rate_limit_windows,
    security_alerts,
    spend_reservations,
    verify_request_idempotency,
    webhook_deliveries
FROM anon, authenticated;

-- Stop the same exposure pattern from reappearing for future tables created by
-- postgres-owned Alembic migrations. Explicit grants can still be added in a
-- future migration if Inntris intentionally introduces direct PostgREST access.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    REVOKE ALL ON TABLES FROM anon, authenticated;

-- Assertions: these are intentionally inside the migration so a partial or
-- environment-specific application fails loudly instead of silently leaving a
-- sensitive table exposed.
DO $$
DECLARE
    table_name text;
    rls_on boolean;
    leaked_grant boolean;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'agents',
        'audit_logs',
        'merkle_proofs',
        'administrative_audit_events',
        'approval_token_consumptions'
    ]
    LOOP
        SELECT c.relrowsecurity INTO rls_on
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = table_name;

        IF rls_on IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'RLS is not enabled on public.%', table_name;
        END IF;

        SELECT EXISTS (
            SELECT 1
            FROM information_schema.role_table_grants g
            WHERE g.table_schema = 'public'
              AND g.table_name = table_name
              AND g.grantee IN ('anon', 'authenticated')
        ) INTO leaked_grant;

        IF leaked_grant THEN
            RAISE EXCEPTION
                'direct anon/authenticated table privilege remains on public.%',
                table_name;
        END IF;
    END LOOP;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'agents'
          AND policyname = 'agents_tenant_scope'
          AND 'inntris_api' = ANY(roles)
    ) THEN
        RAISE EXCEPTION 'agents_tenant_scope policy is missing';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'audit_logs'
          AND policyname = 'audit_logs_tenant_scope'
          AND 'inntris_api' = ANY(roles)
    ) THEN
        RAISE EXCEPTION 'audit_logs_tenant_scope policy is missing';
    END IF;
END $$;
