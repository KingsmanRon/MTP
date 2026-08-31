-- Shared postconditions for migration 021 and scripts/verify_tenant_role.py.
-- Read-only: this block changes no privileges or data.

DO $$
DECLARE
    tenant_oid oid;
    tenant_super boolean;
    tenant_bypass boolean;
    tenant_inherit boolean;
    tenant_connlimit integer;
    tenant_config text[];
    worker_bypass boolean;
    leaked_acl_count integer;
    leaked_effective_table_count integer;
    reachable_definer_count integer;
    unknown_table_count integer;
    target_table text;
    rls_on boolean;
    force_rls boolean;
    has_policy boolean;
    server_version integer := current_setting('server_version_num')::integer;
    membership_inherit boolean;
    membership_set boolean;
    privileged_role text;
BEGIN
    SELECT oid, rolsuper, rolbypassrls, rolinherit, rolconnlimit, rolconfig
      INTO tenant_oid, tenant_super, tenant_bypass, tenant_inherit,
           tenant_connlimit, tenant_config
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
    IF tenant_connlimit <> 20 THEN
        RAISE EXCEPTION 'inntris_tenant_login connection limit must be 20';
    END IF;
    IF tenant_config IS NULL
       OR NOT ('search_path=pg_catalog, public' = ANY(tenant_config))
       OR NOT ('statement_timeout=30s' = ANY(tenant_config))
       OR NOT ('idle_in_transaction_session_timeout=15s' = ANY(tenant_config)) THEN
        RAISE EXCEPTION 'inntris_tenant_login role GUC guardrails are missing';
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
        -- Keep role existence and reachability as nested checks. pg_has_role()
        -- raises for a missing role, and SQL boolean expressions are not a
        -- safe short-circuit boundary across environments.
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = privileged_role) THEN
            IF pg_has_role('inntris_tenant_login', privileged_role, 'MEMBER')
               OR pg_has_role('inntris_tenant_login', privileged_role, 'USAGE') THEN
                RAISE EXCEPTION 'inntris_tenant_login can reach privileged role %',
                    privileged_role;
            END IF;
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

    IF has_schema_privilege('inntris_tenant_login', 'public', 'CREATE')
       OR has_schema_privilege('inntris_api', 'public', 'CREATE')
       OR has_schema_privilege('inntris_tenant_login', 'app', 'CREATE')
       OR has_schema_privilege('inntris_api', 'app', 'CREATE') THEN
        RAISE EXCEPTION 'tenant authority must not create objects in public/app';
    END IF;

    -- Direct grants and PUBLIC grants are forbidden for the login identity.
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

    -- Also check effective pre-SET-ROLE privileges. This catches PUBLIC grants
    -- without relying on information_schema.role_table_grants.
    SELECT count(*)
      INTO leaked_effective_table_count
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND (
           has_table_privilege(
               'inntris_tenant_login',
               format('%I.%I', n.nspname, c.relname),
               'SELECT'
           )
           OR has_table_privilege(
               'inntris_tenant_login',
               format('%I.%I', n.nspname, c.relname),
               'INSERT'
           )
           OR has_table_privilege(
               'inntris_tenant_login',
               format('%I.%I', n.nspname, c.relname),
               'UPDATE'
           )
           OR has_table_privilege(
               'inntris_tenant_login',
               format('%I.%I', n.nspname, c.relname),
               'DELETE'
           )
       );

    IF leaked_effective_table_count <> 0 THEN
        RAISE EXCEPTION
            'inntris_tenant_login has effective table privileges before SET ROLE';
    END IF;

    -- SECURITY DEFINER is an alternate privilege path. Tenant login can SET
    -- ROLE inntris_api, so neither identity may execute a definer function in
    -- Inntris-owned schemas unless an explicit allowlist is added here.
    SELECT count(*)
      INTO reachable_definer_count
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('public', 'app')
       AND p.prosecdef
       AND (
           has_function_privilege('inntris_tenant_login', p.oid, 'EXECUTE')
           OR has_function_privilege('inntris_api', p.oid, 'EXECUTE')
       );

    IF reachable_definer_count <> 0 THEN
        RAISE EXCEPTION
            'tenant authority can execute SECURITY DEFINER function(s) in public/app';
    END IF;

    -- RLS drift guard: every public table must be known and FORCE RLS. Tables
    -- carrying tenant policies must retain at least one inntris_api policy.
    SELECT count(*)
      INTO unknown_table_count
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind IN ('r', 'p')
       AND c.relname <> ALL(ARRAY[
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
       ]);

    IF unknown_table_count <> 0 THEN
        RAISE EXCEPTION
            'unknown public table(s) are outside the reviewed RLS classification';
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
        SELECT c.relrowsecurity, c.relforcerowsecurity
          INTO rls_on, force_rls
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = target_table;

        IF rls_on IS DISTINCT FROM true OR force_rls IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'public.% must have ENABLE + FORCE RLS', target_table;
        END IF;
    END LOOP;

    FOREACH target_table IN ARRAY ARRAY[
        'agent_key_history',
        'agent_policies',
        'agents',
        'api_keys',
        'audit_logs',
        'organizations',
        'policy_rules',
        'rate_limit_windows',
        'security_alerts',
        'spend_reservations',
        'verify_request_idempotency',
        'webhook_deliveries'
    ]
    LOOP
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
