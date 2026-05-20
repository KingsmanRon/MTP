-- =============================================================================
-- MIGRATION 008: Supabase compatibility fix for migration 005's role attributes
-- =============================================================================
-- Background:
--   Migration 005_rls_policies.sql creates ``inntris_worker`` with BYPASSRLS
--   and ``inntris_api`` with NOLOGIN. On Supabase the migration is typically
--   executed by the project's ``postgres`` role, which is NOT a true cluster
--   superuser. PostgreSQL silently downgrades BYPASSRLS to false in that
--   scenario, and NOLOGIN may be flipped to LOGIN if the migration runs via
--   the Supabase SQL editor (which connects with elevated permissions but
--   not full superuser).
--
--   Effect: ``inntris_worker`` cannot see RLS-protected rows, so every admin
--   API call returns empty results. The user-visible symptom is "Invalid
--   API key" because /admin/organization returns nothing.
--
-- This migration:
--   * Re-applies the intended role attributes idempotently.
--   * Is safe to run as the Supabase ``postgres`` role; that role has
--     ``rolcreaterole`` and can grant ``BYPASSRLS`` to other roles even
--     though it isn't itself a superuser.
--
-- When to run:
--   Once, manually, in the Supabase SQL editor after deploying. If you
--   change DATABASE_URL to a non-Supabase Postgres later, you can drop this
--   migration — it's a no-op if the attributes are already correct.
-- =============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'inntris_worker') THEN
        IF NOT (SELECT rolbypassrls FROM pg_roles WHERE rolname = 'inntris_worker') THEN
            ALTER ROLE inntris_worker BYPASSRLS;
            RAISE NOTICE 'Granted BYPASSRLS to inntris_worker';
        END IF;
        IF NOT (SELECT rolcanlogin FROM pg_roles WHERE rolname = 'inntris_worker') THEN
            ALTER ROLE inntris_worker LOGIN;
            RAISE NOTICE 'Granted LOGIN to inntris_worker';
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'inntris_api') THEN
        IF (SELECT rolcanlogin FROM pg_roles WHERE rolname = 'inntris_api') THEN
            ALTER ROLE inntris_api NOLOGIN;
            RAISE NOTICE 'Set inntris_api to NOLOGIN';
        END IF;
    END IF;
END $$;

-- Verification query — run separately to confirm attributes stuck:
--   SELECT rolname, rolbypassrls, rolcanlogin
--   FROM pg_roles
--   WHERE rolname IN ('inntris_worker', 'inntris_api');
--
-- Expected:
--   inntris_worker | true  | true
--   inntris_api    | false | false
