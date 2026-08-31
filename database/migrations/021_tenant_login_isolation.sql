-- =============================================================================
-- MIGRATION 021: Add an isolated tenant login identity
-- =============================================================================
-- Additive phase only:
--   * creates the unprivileged login used by the future tenant pool;
--   * grants only the ability to SET ROLE inntris_api;
--   * gives the login zero direct table privileges;
--   * forces RLS on the original tenant-policy tables.
--
-- No password is stored here. No application route is switched by this
-- migration. Production credentials are an operator concern.
-- =============================================================================

DO $$
DECLARE
    server_version integer := current_setting('server_version_num')::integer;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'inntris_api') THEN
        RAISE EXCEPTION 'tenant login isolation requires inntris_api';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'inntris_worker') THEN
        RAISE EXCEPTION 'tenant login isolation requires inntris_worker';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'inntris_tenant_login') THEN
        CREATE ROLE inntris_tenant_login
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOBYPASSRLS
            NOINHERIT;
    ELSE
        ALTER ROLE inntris_tenant_login
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOBYPASSRLS
            NOINHERIT;
    END IF;

    -- Re-establish the one permitted membership deterministically.
    REVOKE inntris_api FROM inntris_tenant_login;

    IF server_version >= 160000 THEN
        -- PG16+: inheritance and SET capability are membership options.
        EXECUTE
            'GRANT inntris_api TO inntris_tenant_login '
            'WITH INHERIT FALSE, SET TRUE';
    ELSE
        -- PG15: role-level NOINHERIT is the available inheritance control.
        GRANT inntris_api TO inntris_tenant_login;
    END IF;
END $$;

-- The login identity owns nothing. All data access begins only after
-- SET LOCAL ROLE inntris_api inside a transaction.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM inntris_tenant_login;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM inntris_tenant_login;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM inntris_tenant_login;

-- Table owners must not silently bypass tenant policy. BYPASSRLS system roles
-- remain able to perform their documented system-plane work.
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_rules FORCE ROW LEVEL SECURITY;
ALTER TABLE security_alerts FORCE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE rate_limit_windows FORCE ROW LEVEL SECURITY;
