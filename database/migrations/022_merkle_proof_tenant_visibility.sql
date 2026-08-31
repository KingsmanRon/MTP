-- =============================================================================
-- MIGRATION 022: Tenant-safe Merkle anchor visibility
-- =============================================================================
-- The tenant route boundary introduced in 0017 moved /admin/audit/* reads onto
-- inntris_api. merkle_proofs deliberately remained RLS-protected and policyless,
-- so an otherwise-correct LEFT JOIN from a tenant-owned audit row could not see
-- its anchor row. The admin list therefore received transaction_hash = NULL and
-- rendered confirmed Base anchors as "Pending".
--
-- This policy is intentionally narrow:
--   * SELECT only;
--   * inntris_api only (never anon/authenticated/PUBLIC);
--   * a Merkle row is visible only when at least one audit record in the current
--     authenticated tenant references that exact batch;
--   * worker/system paths remain unchanged.
--
-- A Merkle batch can contain receipts from more than one tenant. The API only
-- returns the anchor/proof material required by authenticated audit endpoints;
-- database credentials are never exposed to customers. Keeping the predicate
-- tied to tenant-owned audit rows prevents global batch enumeration while still
-- allowing /admin/audit/search and /admin/audit/{id}/proof to function under the
-- non-BYPASSRLS tenant identity.
-- =============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'inntris_api') THEN
        RAISE EXCEPTION 'Merkle tenant visibility requires inntris_api';
    END IF;
END $$;

ALTER TABLE public.merkle_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.merkle_proofs FORCE ROW LEVEL SECURITY;

-- The table privilege is necessary for RLS to be evaluated at all. RLS remains
-- the row boundary; this does not make the table globally readable.
GRANT SELECT ON TABLE public.merkle_proofs TO inntris_api;

DROP POLICY IF EXISTS merkle_proofs_tenant_anchor_read ON public.merkle_proofs;
CREATE POLICY merkle_proofs_tenant_anchor_read
    ON public.merkle_proofs
    FOR SELECT
    TO inntris_api
    USING (
        EXISTS (
            SELECT 1
            FROM public.audit_logs al
            JOIN public.agents a ON a.id = al.agent_id
            WHERE al.merkle_root_id = merkle_proofs.id
              AND a.org_id = app.current_tenant()
        )
    );

-- Direct browser/PostgREST roles must never inherit this access.
DO $$
DECLARE
    client_role text;
BEGIN
    FOREACH client_role IN ARRAY ARRAY['anon', 'authenticated']
    LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = client_role) THEN
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE public.merkle_proofs FROM %I',
                client_role
            );
        END IF;
    END LOOP;
END $$;

-- Fail the migration if any security property drifted.
DO $$
DECLARE
    rls_on boolean;
    force_rls boolean;
    leaked_grant boolean;
BEGIN
    SELECT c.relrowsecurity, c.relforcerowsecurity
      INTO rls_on, force_rls
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relname = 'merkle_proofs';

    IF rls_on IS DISTINCT FROM true OR force_rls IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'public.merkle_proofs must retain ENABLE + FORCE RLS';
    END IF;

    IF NOT has_table_privilege('inntris_api', 'public.merkle_proofs', 'SELECT') THEN
        RAISE EXCEPTION 'inntris_api requires SELECT on public.merkle_proofs';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_policies p
         WHERE p.schemaname = 'public'
           AND p.tablename = 'merkle_proofs'
           AND p.policyname = 'merkle_proofs_tenant_anchor_read'
           AND p.cmd = 'SELECT'
           AND 'inntris_api' = ANY(p.roles)
    ) THEN
        RAISE EXCEPTION 'merkle_proofs_tenant_anchor_read policy is missing';
    END IF;

    SELECT EXISTS (
        SELECT 1
          FROM information_schema.role_table_grants g
         WHERE g.table_schema = 'public'
           AND g.table_name = 'merkle_proofs'
           AND g.grantee IN ('anon', 'authenticated')
    ) INTO leaked_grant;

    IF leaked_grant THEN
        RAISE EXCEPTION 'direct anon/authenticated Merkle proof privilege remains';
    END IF;
END $$;
