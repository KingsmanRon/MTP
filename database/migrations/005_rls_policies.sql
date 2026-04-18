-- =============================================================================
-- MIGRATION 005: Row-Level Security policies for tenant isolation (Phase 1C.1)
-- =============================================================================
-- Pre-migration posture: schemas.sql enables RLS on five tables
-- (organizations, agents, audit_logs, policy_rules, security_alerts) but no
-- CREATE POLICY statements exist, and the application connects as a
-- superuser. Effect: RLS is declared but never enforced — the threat model's
-- §I2/§E1 residual (R2 in docs/THREAT_MODEL.md §4) stays open.
--
-- This migration is **additive**:
--   * Adds two roles (``inntris_api``, ``inntris_worker``).
--   * Creates ``app.set_tenant(uuid)`` and ``app.current_tenant()`` helpers.
--   * Enables RLS on the two remaining tenant-scoped tables
--     (``api_keys``, ``rate_limit_windows``) that schemas.sql missed.
--   * Writes FOR ALL policies for all seven tenant-scoped tables, gated by
--     ``app.current_org_id`` set via ``set_config``.
--   * Grants table-level privileges to the new roles.
--
-- What is NOT changed:
--   * ``merkle_proofs`` remains RLS-disabled — it is a system/shared table
--     with no tenant column. The anchor worker writes to it; the public
--     verify path reads from it via joins. Access control is upstream.
--   * Existing connections continue to use whatever role the operator
--     configured. Nothing here forces the app to connect as
--     ``inntris_api``/``inntris_worker``; that switch is opt-in via the
--     deployment's DATABASE_URL.
--
-- Threat coverage: closes docs/THREAT_MODEL.md §4 R2 once the app DSN is
-- flipped to ``inntris_worker`` and admin requests are routed through
-- ``Database.acquire_as_tenant`` (see api/database.py).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Roles
-- -----------------------------------------------------------------------------
-- ``inntris_api``  — NOLOGIN, RLS-enforced. Acquired via ``SET LOCAL ROLE``
--                    inside a transaction. This is the role under which
--                    tenant-scoped admin queries execute.
-- ``inntris_worker`` — LOGIN, BYPASSRLS. The pool connects as this role so
--                      the /verify, public, and anchor-worker paths bypass
--                      RLS; admin paths downgrade via SET LOCAL ROLE.
--
-- Idempotent: if the role already exists the DO block is a no-op.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'inntris_api') THEN
        CREATE ROLE inntris_api NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'inntris_worker') THEN
        CREATE ROLE inntris_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS;
    END IF;
END $$;

-- ``inntris_worker`` must be able to ``SET LOCAL ROLE inntris_api`` when an
-- admin request arrives. Membership grant makes that switch legal.
GRANT inntris_api TO inntris_worker;


-- -----------------------------------------------------------------------------
-- 2. Tenant-context helpers
-- -----------------------------------------------------------------------------
-- All policies below read ``app.current_org_id`` via ``current_setting`` with
-- ``missing_ok=true`` and ``NULLIF`` around the empty string so a missing
-- setting fails closed (predicate evaluates to ``x = NULL`` → false → denied)
-- rather than raising on the uuid cast.

CREATE SCHEMA IF NOT EXISTS app;

CREATE OR REPLACE FUNCTION app.set_tenant(org_id uuid)
RETURNS void
LANGUAGE sql
AS $$
    SELECT set_config('app.current_org_id', org_id::text, true);
$$;

CREATE OR REPLACE FUNCTION app.current_tenant()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
    SELECT NULLIF(current_setting('app.current_org_id', true), '')::uuid;
$$;

GRANT USAGE ON SCHEMA app TO inntris_api, inntris_worker;
GRANT EXECUTE ON FUNCTION app.set_tenant(uuid), app.current_tenant()
    TO inntris_api, inntris_worker;


-- -----------------------------------------------------------------------------
-- 3. Enable RLS on tables schemas.sql missed
-- -----------------------------------------------------------------------------
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limit_windows ENABLE ROW LEVEL SECURITY;


-- -----------------------------------------------------------------------------
-- 4. Policies
-- -----------------------------------------------------------------------------
-- Pattern: FOR ALL TO inntris_api with matching USING + WITH CHECK so the
-- policy governs reads, inserts, updates, and deletes identically. An empty
-- or missing tenant context yields NULL from app.current_tenant(), so every
-- predicate is NULL → row invisible and writes rejected.

-- organizations: caller sees only their own org row. No writes from the API
-- role (orgs are created via public registration or operator tooling, both
-- of which run as inntris_worker/superuser and bypass RLS).
DROP POLICY IF EXISTS organizations_tenant_scope ON organizations;
CREATE POLICY organizations_tenant_scope ON organizations
    FOR ALL
    TO inntris_api
    USING (id = app.current_tenant())
    WITH CHECK (id = app.current_tenant());

-- agents: tenant column is org_id.
DROP POLICY IF EXISTS agents_tenant_scope ON agents;
CREATE POLICY agents_tenant_scope ON agents
    FOR ALL
    TO inntris_api
    USING (org_id = app.current_tenant())
    WITH CHECK (org_id = app.current_tenant());

-- audit_logs: tenant column is indirect via agents.org_id. EXISTS keeps the
-- predicate correlated-subquery-cheap; the agent lookup hits the PK.
DROP POLICY IF EXISTS audit_logs_tenant_scope ON audit_logs;
CREATE POLICY audit_logs_tenant_scope ON audit_logs
    FOR ALL
    TO inntris_api
    USING (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = audit_logs.agent_id
              AND a.org_id = app.current_tenant()
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = audit_logs.agent_id
              AND a.org_id = app.current_tenant()
        )
    );

-- policy_rules: a rule is tenant-scoped by either org_id (org-wide rule) or
-- agent_id (agent-specific rule, inheriting the agent's org).
DROP POLICY IF EXISTS policy_rules_tenant_scope ON policy_rules;
CREATE POLICY policy_rules_tenant_scope ON policy_rules
    FOR ALL
    TO inntris_api
    USING (
        (org_id IS NOT NULL AND org_id = app.current_tenant())
        OR (agent_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = policy_rules.agent_id
              AND a.org_id = app.current_tenant()
        ))
    )
    WITH CHECK (
        (org_id IS NOT NULL AND org_id = app.current_tenant())
        OR (agent_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = policy_rules.agent_id
              AND a.org_id = app.current_tenant()
        ))
    );

-- security_alerts: org_id nullable (alert may precede org assignment) — scope
-- strictly on non-null org_id. A NULL org_id alert is a platform event,
-- never visible to a tenant.
DROP POLICY IF EXISTS security_alerts_tenant_scope ON security_alerts;
CREATE POLICY security_alerts_tenant_scope ON security_alerts
    FOR ALL
    TO inntris_api
    USING (org_id IS NOT NULL AND org_id = app.current_tenant())
    WITH CHECK (org_id IS NOT NULL AND org_id = app.current_tenant());

-- api_keys: tenant column is org_id.
DROP POLICY IF EXISTS api_keys_tenant_scope ON api_keys;
CREATE POLICY api_keys_tenant_scope ON api_keys
    FOR ALL
    TO inntris_api
    USING (org_id = app.current_tenant())
    WITH CHECK (org_id = app.current_tenant());

-- rate_limit_windows: tenant column is indirect via agents.org_id.
DROP POLICY IF EXISTS rate_limit_windows_tenant_scope ON rate_limit_windows;
CREATE POLICY rate_limit_windows_tenant_scope ON rate_limit_windows
    FOR ALL
    TO inntris_api
    USING (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = rate_limit_windows.agent_id
              AND a.org_id = app.current_tenant()
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = rate_limit_windows.agent_id
              AND a.org_id = app.current_tenant()
        )
    );


-- -----------------------------------------------------------------------------
-- 5. Grants
-- -----------------------------------------------------------------------------
-- Tenant role (inntris_api) gets row-filtered SELECT/INSERT/UPDATE/DELETE on
-- its domain. DELETE on audit_logs is blocked at the trigger layer
-- (prevent_audit_log_modification) regardless of policy. merkle_proofs and
-- security_alerts.INSERT are not granted — those are system operations.

GRANT USAGE ON SCHEMA public TO inntris_api, inntris_worker;

-- Organizations: read-only for tenants (they cannot create/rename/delete
-- their own org through the API).
GRANT SELECT ON organizations TO inntris_api;

-- Agents: full CRUD within the tenant.
GRANT SELECT, INSERT, UPDATE, DELETE ON agents TO inntris_api;

-- Audit logs: SELECT and INSERT only. UPDATE at the tenant role would be
-- rejected by the immutability trigger (database/schemas.sql:315-365) even
-- if we granted it; we deny at the privilege layer too for defense in depth.
GRANT SELECT, INSERT ON audit_logs TO inntris_api;

-- Policy rules: full CRUD (tenant defines their own rules).
GRANT SELECT, INSERT, UPDATE, DELETE ON policy_rules TO inntris_api;

-- Security alerts: SELECT and UPDATE (acknowledge/resolve). INSERT happens
-- server-side via triggers/system code, not through the tenant role.
GRANT SELECT, UPDATE ON security_alerts TO inntris_api;

-- API keys: full CRUD — tenants rotate their own keys.
GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO inntris_api;

-- Rate limit windows: SELECT and INSERT/UPDATE for counter increments.
GRANT SELECT, INSERT, UPDATE ON rate_limit_windows TO inntris_api;

-- Worker role: broad privileges including merkle_proofs. BYPASSRLS handles
-- row visibility; table privileges still need explicit grants.
GRANT SELECT, INSERT, UPDATE, DELETE
    ON organizations, agents, audit_logs, policy_rules, security_alerts,
       api_keys, rate_limit_windows, merkle_proofs
    TO inntris_worker;

-- Future sequences: grants on sequences are per-sequence. This schema uses
-- uuid_generate_v4() defaults rather than serial columns, so no sequence
-- grants are required today. If a future migration adds a SERIAL/BIGSERIAL
-- column, add its sequence grant here.
