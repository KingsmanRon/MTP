-- =============================================================================
-- MIGRATION 021: Add an isolated tenant login identity
-- =============================================================================
-- Additive phase only:
--   * creates the unprivileged login used by the future tenant pool;
--   * grants only the ability to SET ROLE inntris_api;
--   * gives the login zero direct table/sequence privileges;
--   * constrains role resource use and search_path;
--   * forces RLS on every current public table.
--
-- No password is stored here. No application route is switched by this
-- migration. Production credentials are an operator concern.
--
-- IMPORTANT FOR FUTURE ALEMBIC DATA MIGRATIONS:
-- FORCE ROW LEVEL SECURITY removes the table-owner bypass. PostgreSQL roles
-- with SUPERUSER/BYPASSRLS still bypass RLS, which is why the migration
-- identity is asserted below to retain one of those attributes. Do not run
-- data migrations through inntris_tenant_login or another non-bypass owner.
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
            NOINHERIT
            CONNECTION LIMIT 20;
    ELSE
        ALTER ROLE inntris_tenant_login
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOBYPASSRLS
            NOINHERIT
            CONNECTION LIMIT 20;
    END IF;

    -- Re-establish the one permitted membership deterministically.
    REVOKE inntris_api FROM inntris_tenant_login;

    IF server_version >= 160000 THEN
        -- PG16+ (including production PG17): inheritance and SET capability
        -- are membership options.
        EXECUTE
            'GRANT inntris_api TO inntris_tenant_login '
            'WITH INHERIT FALSE, SET TRUE';
    ELSE
        -- PG15: role-level NOINHERIT is the available inheritance control.
        GRANT inntris_api TO inntris_tenant_login;
    END IF;
END $$;

-- Login-level guardrails. Role GUCs apply when the tenant login authenticates.
-- SET ROLE does not apply ALTER ROLE ... SET values for the target role, so the
-- application also pins search_path transaction-locally after SET LOCAL ROLE.
ALTER ROLE inntris_tenant_login SET search_path TO pg_catalog, public;
ALTER ROLE inntris_tenant_login SET statement_timeout TO '30s';
ALTER ROLE inntris_tenant_login SET idle_in_transaction_session_timeout TO '15s';
ALTER ROLE inntris_api SET search_path TO pg_catalog, public;

-- The login identity owns nothing. All data access begins only after
-- SET LOCAL ROLE inntris_api inside a transaction.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM inntris_tenant_login;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM inntris_tenant_login;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM inntris_tenant_login;
REVOKE CREATE ON SCHEMA public FROM inntris_api, inntris_tenant_login;
REVOKE CREATE ON SCHEMA app FROM inntris_api, inntris_tenant_login;

-- FORCE RLS is intentionally database-wide for Inntris public tables. System
-- roles with BYPASSRLS retain their documented system-plane access; ordinary
-- table ownership no longer bypasses policy. Fail before DDL if the migration
-- identity could not safely perform this change in production.
DO $$
DECLARE
    target_table text;
    table_owner oid;
    current_role_oid oid;
    migration_super boolean;
    migration_bypass boolean;
BEGIN
    SELECT oid, rolsuper, rolbypassrls
      INTO current_role_oid, migration_super, migration_bypass
      FROM pg_roles
     WHERE rolname = current_user;

    IF current_role_oid IS NULL THEN
        RAISE EXCEPTION 'cannot resolve migration database identity';
    END IF;
    IF NOT (migration_super OR migration_bypass) THEN
        RAISE EXCEPTION
            'FORCE RLS migration requires a SUPERUSER or BYPASSRLS migration identity';
    END IF;

    FOREACH target_table IN ARRAY ARRAY[
        'administrative_audit_events',
        'agent_key_history',
        'agent_policies',
        'agents',
        'alembic_version',
        'api_keys',
        'approval_token_consumptions',
        'audit_logs',
        'erasure_requests',
        'merkle_proofs',
        'organizations',
        'policy_rules',
        'rate_limit_windows',
        'security_alerts',
        'spend_reservations',
        'verify_request_idempotency',
        'webhook_deliveries'
    ]
    LOOP
        SELECT c.relowner
          INTO table_owner
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = target_table
           AND c.relkind IN ('r', 'p');

        IF table_owner IS NULL THEN
            RAISE EXCEPTION 'expected public.% to exist before FORCE RLS', target_table;
        END IF;

        IF NOT migration_super AND table_owner <> current_role_oid THEN
            RAISE EXCEPTION
                'current migration role % does not own public.% (owner=%)',
                current_user,
                target_table,
                pg_get_userbyid(table_owner);
        END IF;

        EXECUTE format(
            'ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',
            target_table
        );
        EXECUTE format(
            'ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',
            target_table
        );
    END LOOP;
END $$;
