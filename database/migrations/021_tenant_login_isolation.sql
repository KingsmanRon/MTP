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
-- FORCE RLS SEMANTICS:
-- FORCE ROW LEVEL SECURITY closes the table-owner exemption only. SUPERUSER
-- and BYPASSRLS roles still bypass row security unconditionally. Production
-- postgres currently has BYPASSRLS, so FORCE does not constrain that migration
-- identity today. It is defence in depth if ownership or role attributes later
-- change; future migration conventions must re-check the effective identity.
-- =============================================================================

DO $$
DECLARE
    server_version integer := current_setting('server_version_num')::integer;
    migration_super boolean;
    migration_createrole boolean;
    has_api_admin boolean;
    has_tenant_admin boolean;
    tenant_exists boolean;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'inntris_api') THEN
        RAISE EXCEPTION 'tenant login isolation requires inntris_api';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'inntris_worker') THEN
        RAISE EXCEPTION 'tenant login isolation requires inntris_worker';
    END IF;

    SELECT rolsuper, rolcreaterole
      INTO migration_super, migration_createrole
      FROM pg_roles
     WHERE rolname = current_user;

    IF migration_super IS NULL THEN
        RAISE EXCEPTION 'cannot resolve migration role %', current_user;
    END IF;
    IF NOT migration_super AND NOT migration_createrole THEN
        RAISE EXCEPTION
            'migration role % requires CREATEROLE to provision inntris_tenant_login',
            current_user;
    END IF;

    -- PostgreSQL 16+ role administration is deliberately explicit: a
    -- non-superuser needs ADMIN OPTION on inntris_api to grant/revoke its
    -- membership or alter that role. CI superusers would otherwise hide a
    -- production-only release failure here.
    SELECT EXISTS (
        SELECT 1
          FROM pg_auth_members m
          JOIN pg_roles parent ON parent.oid = m.roleid
          JOIN pg_roles member_role ON member_role.oid = m.member
         WHERE parent.rolname = 'inntris_api'
           AND member_role.rolname = current_user
           AND m.admin_option
    ) INTO has_api_admin;

    IF NOT migration_super AND NOT has_api_admin THEN
        RAISE EXCEPTION
            'migration role % requires ADMIN OPTION on inntris_api',
            current_user;
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'inntris_tenant_login'
    ) INTO tenant_exists;

    -- If the role already exists, a non-superuser must also be allowed to
    -- administer it before ALTER ROLE is attempted. On first creation a
    -- CREATEROLE user receives ADMIN OPTION on the role automatically.
    IF tenant_exists AND NOT migration_super THEN
        SELECT EXISTS (
            SELECT 1
              FROM pg_auth_members m
              JOIN pg_roles parent ON parent.oid = m.roleid
              JOIN pg_roles member_role ON member_role.oid = m.member
             WHERE parent.rolname = 'inntris_tenant_login'
               AND member_role.rolname = current_user
               AND m.admin_option
        ) INTO has_tenant_admin;

        IF NOT has_tenant_admin THEN
            RAISE EXCEPTION
                'migration role % requires ADMIN OPTION on existing inntris_tenant_login',
                current_user;
        END IF;
    END IF;

    IF NOT tenant_exists THEN
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

    -- Re-establish the one permitted direct membership deterministically.
    -- Guard the REVOKE so a first migration does not emit a misleading warning.
    IF EXISTS (
        SELECT 1
          FROM pg_auth_members m
          JOIN pg_roles parent ON parent.oid = m.roleid
          JOIN pg_roles child ON child.oid = m.member
         WHERE parent.rolname = 'inntris_api'
           AND child.rolname = 'inntris_tenant_login'
    ) THEN
        REVOKE inntris_api FROM inntris_tenant_login;
    END IF;

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
-- A role switch does not apply ALTER ROLE ... SET values for the target role,
-- so the application also pins these values transaction-locally.
ALTER ROLE inntris_tenant_login SET search_path TO pg_catalog, public;
ALTER ROLE inntris_tenant_login SET statement_timeout TO '30s';
ALTER ROLE inntris_tenant_login SET idle_in_transaction_session_timeout TO '15s';
ALTER ROLE inntris_api SET search_path TO pg_catalog, public;

-- The login identity owns nothing. All data access begins only after a
-- transaction-local role switch to inntris_api.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM inntris_tenant_login;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM inntris_tenant_login;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM inntris_tenant_login;
REVOKE CREATE ON SCHEMA public FROM inntris_api, inntris_tenant_login;
REVOKE CREATE ON SCHEMA app FROM inntris_api, inntris_tenant_login;

-- FORCE RLS is intentionally database-wide for Inntris public tables. It
-- removes only the ordinary table-owner exemption. SUPERUSER/BYPASSRLS roles
-- retain unrestricted access; production postgres currently falls in that
-- category. Fail before DDL if the migration identity cannot own/alter these
-- tables or is not the reviewed privileged migration plane.
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
            'FORCE RLS migration requires the reviewed SUPERUSER/BYPASSRLS migration plane';
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
