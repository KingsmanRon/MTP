-- =============================================================================
-- MIGRATION 010: Agent governing policies (AI PR Guard — Tier A)
-- =============================================================================
-- Stores the .inntris.yml an org registers for an agent so /verify can, server
-- side, (a) reject a submitted policy hash that does not match the registered
-- one, and (b) re-derive a change's minimum action type from the registered
-- mapping and refuse a weaker assertion. This makes the backend -- not the
-- client-signed action_type -- the security boundary.
--
-- One active policy per agent; re-registration deactivates the prior row and
-- inserts a new version, preserving history.
--
-- Tenant isolation follows migration 005: RLS scopes rows to the agent's org
-- for the inntris_api role; inntris_worker (the /verify path) bypasses RLS.
-- =============================================================================

CREATE TABLE IF NOT EXISTS agent_policies (
    id                 uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id           uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    policy_hash        varchar(64) NOT NULL,
    mapping            jsonb NOT NULL DEFAULT '{}'::jsonb,
    protected_branches jsonb NOT NULL DEFAULT '[]'::jsonb,
    version            integer NOT NULL DEFAULT 1,
    active             boolean NOT NULL DEFAULT true,
    registered_by      text,
    created_at         timestamptz NOT NULL DEFAULT now()
);

-- At most one active policy per agent. The /verify lookup selects WHERE active.
CREATE UNIQUE INDEX IF NOT EXISTS agent_policies_one_active
    ON agent_policies (agent_id)
    WHERE active;

-- History lookups by agent.
CREATE INDEX IF NOT EXISTS agent_policies_agent_idx
    ON agent_policies (agent_id);

-- -----------------------------------------------------------------------------
-- Row-Level Security (tenant scope via agents.org_id, as in migration 005)
-- -----------------------------------------------------------------------------
ALTER TABLE agent_policies ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS agent_policies_tenant_scope ON agent_policies;
CREATE POLICY agent_policies_tenant_scope ON agent_policies
    FOR ALL
    TO inntris_api
    USING (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = agent_policies.agent_id
              AND a.org_id = app.current_tenant()
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = agent_policies.agent_id
              AND a.org_id = app.current_tenant()
        )
    );

-- -----------------------------------------------------------------------------
-- Grants
-- -----------------------------------------------------------------------------
-- Tenant role: full CRUD within its org (registration runs as inntris_api).
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_policies TO inntris_api;

-- Worker role: BYPASSRLS; the /verify read path runs here. Table privileges
-- still need an explicit grant.
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_policies TO inntris_worker;
