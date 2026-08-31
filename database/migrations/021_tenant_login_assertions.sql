-- Shared postconditions for migration 021 and scripts/verify_tenant_role.py.
-- Read-only: this block changes no privileges or data.

DO $$
DECLARE
    tenant_oid oid;
    tenant_super boolean;
    tenant_bypass boolean;
    tenant_inherit boolean;
    worker_bypass boolean;
    leaked_acl_count integer;
    target_table text;
    rls_on boolean;
    force_rls boolean;
    has_policy boolean;
    server_version integer := current_setting('server_version_num')::integer;
    membership_inherit boolean;
    membership_set boolean;
    privileged_role text;
BEGIN
    SELECT oid, rolsuper, rolbypassrls, rolinherit
      INTO tenant_oid, tenant_super, tenant_bypass, tenant_inherit
      FROM pg_roles
     WHERE rolname = 'inntris_tenant_login';

    IF tenant_oid IS NULL THEN
        RAISE EXCEPTION 'inntris_tenant_login is missing';
    END IF;
    IF tenant_super OR tenant_bypass THEN
        RAISE EXCEPTION 'inntris_tenant_login is privileged';
    END IF;
    IF tenant_inherit THEN
        RAISE EXCEPTION 'inntris_tenant_login must be NOINHERIT';
    END IF;

    SELECT rolbypassrls INTO worker_bypass
      FROM pg_roles
     WHERE rolname = 'inntris_worker';
    IF worker_bypass IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'inntris_worker must remain BYPASSRLS';
    END IF;

    IF pg_has_role('inntris_tenant_login', 'inntris_worker', 'MEMBER')
       OR pg_has_role('inntris_tenant_login', 'inntris_worker', 'USAGE')
       OR pg_has_role('inntris_api', 'inntris_worker', 'MEMBER') THEN
        RAISE EXCEPTION 'tenant authority can reach inntris_worker';
    END IF;

    FOREACH privileged_role IN ARRAY ARRAY['service_role', 'postgres', 'supabase_admin']
    LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = privileged_role)
           AND (
               pg_has_role('inntris_tenant_login', privileged_role, 'MEMBER')
               OR pg_has_role('inntris_tenant_login', privileged_role, 'USAGE')
           ) THEN
            RAISE EXCEPTION 'inntris_tenant_login can reach privileged role %',
                privileged_role;
        END IF;
    END LOOP;

    -- PG16+ stores inherit/set behaviour on the membership grant itself.
    IF server_version >= 160000 THEN
        EXECUTE $q$
            SELECT m.inherit_option, m.set_option
              FROM pg_auth_members m
              JOIN pg_roles parent ON parent.oid = m.roleid
              JOIN pg_roles child ON child.oid = m.member
             WHERE parent.rolname = 'inntris_api'
               AND child.rolname = 'inntris_tenant_login'
        $q$ INTO membership_inherit, membership_set;

        IF membership_inherit IS DISTINCT FROM false
           OR membership_set IS DISTINCT FROM true THEN
            RAISE EXCEPTION
                'PG16+ tenant membership must be INHERIT FALSE, SET TRUE';
        END IF;
    ELSE
        IF NOT pg_has_role('inntris_tenant_login', 'inntris_api', 'MEMBER') THEN
            RAISE EXCEPTION 'tenant login cannot SET ROLE inntris_api';
        END IF;
    END IF;

    -- Direct grants and PUBLIC grants are forbidden for the login identity.
    -- We inspect ACL grantees directly so the intentional SET ROLE membership
    -- in inntris_api is not mistaken for a direct privilege.
    SELECT count(*)
      INTO leaked_acl_count
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, '{}'::aclitem[])) acl
     WHERE n.nspname = 'public'
       AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND acl.grantee IN (0, tenant_oid)
       AND acl.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE');

    IF leaked_acl_count <> 0 THEN
        RAISE EXCEPTION
            'inntris_tenant_login or PUBLIC has direct public-schema table privileges';
    END IF;

    FOREACH target_table IN ARRAY ARRAY[
        'organizations',
        'agents',
        'audit_logs',
        'policy_rules',
        'security_alerts',
        'api_keys',
        'rate_limit_windows'
    ]
    LOOP
        SELECT c.relrowsecurity, c.relforcerowsecurity
          INTO rls_on, force_rls
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = target_table;

        IF rls_on IS DISTINCT FROM true OR force_rls IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'tenant table public.% must have ENABLE + FORCE RLS',
                target_table;
        END IF;

        SELECT EXISTS (
            SELECT 1
              FROM pg_policies p
             WHERE p.schemaname = 'public'
               AND p.tablename = target_table
               AND 'inntris_api' = ANY(p.roles)
        ) INTO has_policy;

        IF NOT has_policy THEN
            RAISE EXCEPTION
                'tenant table public.% lacks an inntris_api policy', target_table;
        END IF;
    END LOOP;
END $$;
