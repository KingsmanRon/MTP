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
-- Supabase defines anon/authenticated; a plain PostgreSQL CI database does not.
-- Guard every role-specific REVOKE so the same migration tree remains portable
-- and can still be replayed from zero outside Supabase.
DO $$
DECLARE
    client_role text;
BEGIN
    FOREACH client_role IN ARRAY ARRAY['anon', 'authenticated']
    LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = client_role) THEN
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE public.agents FROM %I',
                client_role
            );
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE public.audit_logs FROM %I',
                client_role
            );
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE public.merkle_proofs FROM %I',
                client_role
            );
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE public.administrative_audit_events FROM %I',
                client_role
            );
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE public.approval_token_consumptions FROM %I',
                client_role
            );

            -- Existing tenant-scoped auxiliary/security tables already have RLS
            -- enabled. Inntris does not use direct browser-to-PostgREST access,
            -- so their broad Supabase client grants are unnecessary too.
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE '
                'public.organizations, '
                'public.agent_key_history, '
                'public.agent_policies, '
                'public.api_keys, '
                'public.erasure_requests, '
                'public.policy_rules, '
                'public.rate_limit_windows, '
                'public.security_alerts, '
                'public.spend_reservations, '
                'public.verify_request_idempotency, '
                'public.webhook_deliveries FROM %I',
                client_role
            );

            -- Stop the same exposure pattern from reappearing for future tables
            -- created by postgres-owned Alembic migrations. Vanilla CI may not
            -- have a role named postgres when POSTGRES_USER is overridden, so
            -- this Supabase-specific default-privilege hardening is conditional.
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgres') THEN
                EXECUTE format(
                    'ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public '
                    'REVOKE ALL ON TABLES FROM %I',
                    client_role
                );
            END IF;
        END IF;
    END LOOP;
END $$;

-- Assertions: these are intentionally inside the migration so a partial or
-- environment-specific application fails loudly instead of silently leaving a
-- sensitive table exposed. On plain PostgreSQL, where anon/authenticated do not
-- exist, the leaked-grant predicate naturally returns false.
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
