-- Durable security state for approval token consumption, administrative
-- changes, and deterministic per agent audit chain ordering.

LOCK TABLE audit_logs IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS chain_sequence BIGINT;

-- The audit table is intentionally update protected. Temporarily disable only
-- that trigger while the migration assigns deterministic legacy positions.
ALTER TABLE audit_logs DISABLE TRIGGER protect_audit_logs_update;

WITH ranked AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY agent_id
               ORDER BY timestamp ASC, id ASC
           ) AS sequence_value
    FROM audit_logs
)
UPDATE audit_logs AS target
SET chain_sequence = ranked.sequence_value
FROM ranked
WHERE target.id = ranked.id
  AND target.chain_sequence IS NULL;

ALTER TABLE audit_logs ENABLE TRIGGER protect_audit_logs_update;

ALTER TABLE audit_logs
    ALTER COLUMN chain_sequence SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_agent_chain_sequence
    ON audit_logs(agent_id, chain_sequence);

CREATE OR REPLACE FUNCTION assign_audit_chain_sequence()
RETURNS TRIGGER AS $$
DECLARE
    v_previous_hash VARCHAR(64);
    v_previous_sequence BIGINT;
BEGIN
    -- Serialise every append for one agent. This is the same advisory lock key
    -- used by the application and remains held until the transaction ends.
    PERFORM pg_advisory_xact_lock(hashtext(NEW.agent_id::TEXT)::BIGINT);

    SELECT action_hash, chain_sequence
    INTO v_previous_hash, v_previous_sequence
    FROM audit_logs
    WHERE agent_id = NEW.agent_id
    ORDER BY chain_sequence DESC
    LIMIT 1;

    NEW.chain_sequence := COALESCE(v_previous_sequence, 0) + 1;
    NEW.chain_previous_hash := v_previous_hash;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS assign_audit_chain_sequence_before_insert ON audit_logs;
CREATE TRIGGER assign_audit_chain_sequence_before_insert
    BEFORE INSERT ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION assign_audit_chain_sequence();

CREATE TABLE IF NOT EXISTS approval_token_consumptions (
    token_id TEXT PRIMARY KEY,
    token_digest BYTEA NOT NULL UNIQUE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    action_hash VARCHAR(64) NOT NULL,
    audit_log_id UUID NOT NULL UNIQUE REFERENCES audit_logs(id) ON DELETE RESTRICT,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT approval_token_id_not_blank CHECK (BTRIM(token_id) <> ''),
    CONSTRAINT approval_token_digest_length CHECK (LENGTH(token_digest) = 32),
    CONSTRAINT approval_token_action_hash_format CHECK (action_hash ~ '^[a-f0-9]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_approval_token_consumptions_agent_time
    ON approval_token_consumptions(agent_id, consumed_at DESC);

CREATE TABLE IF NOT EXISTS administrative_audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    event_type VARCHAR(100) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    approval_reference VARCHAR(255) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT administrative_event_type_not_blank CHECK (BTRIM(event_type) <> ''),
    CONSTRAINT administrative_actor_not_blank CHECK (BTRIM(actor) <> ''),
    CONSTRAINT administrative_approval_not_blank CHECK (BTRIM(approval_reference) <> '')
);

CREATE INDEX IF NOT EXISTS idx_administrative_audit_events_org_time
    ON administrative_audit_events(org_id, created_at DESC);

CREATE OR REPLACE FUNCTION prevent_security_state_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION '% is append only', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS protect_token_consumptions_update ON approval_token_consumptions;
CREATE TRIGGER protect_token_consumptions_update
    BEFORE UPDATE ON approval_token_consumptions
    FOR EACH ROW EXECUTE FUNCTION prevent_security_state_modification();

DROP TRIGGER IF EXISTS protect_token_consumptions_delete ON approval_token_consumptions;
CREATE TRIGGER protect_token_consumptions_delete
    BEFORE DELETE ON approval_token_consumptions
    FOR EACH ROW EXECUTE FUNCTION prevent_security_state_modification();

DROP TRIGGER IF EXISTS protect_administrative_events_update ON administrative_audit_events;
CREATE TRIGGER protect_administrative_events_update
    BEFORE UPDATE ON administrative_audit_events
    FOR EACH ROW EXECUTE FUNCTION prevent_security_state_modification();

DROP TRIGGER IF EXISTS protect_administrative_events_delete ON administrative_audit_events;
CREATE TRIGGER protect_administrative_events_delete
    BEFORE DELETE ON administrative_audit_events
    FOR EACH ROW EXECUTE FUNCTION prevent_security_state_modification();

REVOKE ALL ON TABLE approval_token_consumptions FROM PUBLIC, inntris_api;
REVOKE ALL ON TABLE administrative_audit_events FROM PUBLIC, inntris_api;
GRANT SELECT, INSERT ON approval_token_consumptions TO inntris_worker;
GRANT SELECT, INSERT ON administrative_audit_events TO inntris_worker;

COMMENT ON TABLE approval_token_consumptions IS
    'Durable single use authority for signed execution approval tokens.';
COMMENT ON TABLE administrative_audit_events IS
    'Immutable approval evidence for tenant administrative security changes.';
