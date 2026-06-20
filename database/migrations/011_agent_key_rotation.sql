-- =============================================================================
-- MIGRATION 011: Agent signing-key rotation + history
-- =============================================================================
-- Each agent holds an Ed25519 keypair; the CI workflow stores the private seed
-- as a GitHub Secret. If that secret leaks, an attacker can mint signed
-- /verify requests. Rotation replaces the agent's public key in place --
-- preserving its trust score, history, and registered policy -- so the leaked
-- key is dead immediately without re-creating the agent. Retired keys are
-- recorded for forensics (scope the blast radius of a leak by fingerprint).
--
-- Tenant isolation follows migration 005.
-- =============================================================================

ALTER TABLE agents ADD COLUMN IF NOT EXISTS key_version integer NOT NULL DEFAULT 1;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS key_rotated_at timestamptz;

CREATE TABLE IF NOT EXISTS agent_key_history (
    id                     uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id               uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    public_key_fingerprint varchar(64) NOT NULL,
    key_version            integer NOT NULL,
    retired_at             timestamptz NOT NULL DEFAULT now(),
    retired_by             text,
    reason                 text
);

CREATE INDEX IF NOT EXISTS agent_key_history_agent_idx
    ON agent_key_history (agent_id);

-- -----------------------------------------------------------------------------
-- Row-Level Security (tenant scope via agents.org_id, as in migration 005)
-- -----------------------------------------------------------------------------
ALTER TABLE agent_key_history ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS agent_key_history_tenant_scope ON agent_key_history;
CREATE POLICY agent_key_history_tenant_scope ON agent_key_history
    FOR ALL
    TO inntris_api
    USING (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = agent_key_history.agent_id
              AND a.org_id = app.current_tenant()
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = agent_key_history.agent_id
              AND a.org_id = app.current_tenant()
        )
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_key_history TO inntris_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_key_history TO inntris_worker;
