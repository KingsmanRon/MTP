-- =============================================================================
-- INNTRIS CORE - DATABASE SCHEMA
-- =============================================================================
-- Version: 1.0.0
-- Database: PostgreSQL 15+ with TimescaleDB extension (optional)
-- Purpose: Forensic-grade audit infrastructure for AI Agent verification
-- Security: Append-only audit logs, strict foreign keys, row-level security
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Attempt TimescaleDB if available (graceful fallback)
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TimescaleDB not available, using standard partitioning';
END $$;

-- =============================================================================
-- ENUM TYPES
-- =============================================================================

CREATE TYPE billing_tier AS ENUM ('free', 'starter', 'professional', 'enterprise');
CREATE TYPE agent_status AS ENUM ('active', 'suspended', 'revoked', 'pending_verification');
CREATE TYPE action_verdict AS ENUM ('approved', 'blocked', 'rate_limited', 'signature_invalid');
CREATE TYPE alert_severity AS ENUM ('low', 'medium', 'high', 'critical');

-- =============================================================================
-- TABLE: organizations
-- =============================================================================
-- Parent entity for all agents. Represents the company/individual operating agents.

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    billing_tier billing_tier NOT NULL DEFAULT 'free',
    contact_email VARCHAR(255) NOT NULL,
    webhook_url TEXT,
    api_key_hash BYTEA NOT NULL,  -- SHA-256 hash of API key
    daily_limit_usd DECIMAL(15, 2) NOT NULL DEFAULT 500.00,
    monthly_limit_usd DECIMAL(15, 2) NOT NULL DEFAULT 10000.00,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT org_name_not_empty CHECK (LENGTH(TRIM(name)) > 0),
    CONSTRAINT org_email_format CHECK (contact_email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT org_daily_limit_positive CHECK (daily_limit_usd >= 0),
    CONSTRAINT org_monthly_limit_positive CHECK (monthly_limit_usd >= 0)
);

CREATE INDEX idx_organizations_billing_tier ON organizations(billing_tier);
CREATE INDEX idx_organizations_created_at ON organizations(created_at);

-- =============================================================================
-- TABLE: agents
-- =============================================================================
-- Registered AI agents with Ed25519 public keys for signature verification.

CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    public_key BYTEA NOT NULL,  -- Ed25519 public key (32 bytes)
    public_key_fingerprint VARCHAR(64) NOT NULL,  -- SHA-256 fingerprint for quick lookup
    trust_score INTEGER NOT NULL DEFAULT 50,
    status agent_status NOT NULL DEFAULT 'pending_verification',
    daily_limit_usd DECIMAL(15, 2) NOT NULL DEFAULT 100.00,
    per_action_limit_usd DECIMAL(15, 2) NOT NULL DEFAULT 50.00,
    allowed_actions TEXT[] DEFAULT ARRAY['financial_transaction', 'email_send', 'api_call'],
    blocked_actions TEXT[] DEFAULT ARRAY[]::TEXT[],
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
    last_action_at TIMESTAMPTZ,
    total_actions_count BIGINT NOT NULL DEFAULT 0,
    total_blocked_count BIGINT NOT NULL DEFAULT 0,
    consecutive_success_count INTEGER NOT NULL DEFAULT 0,  -- For trust score adjustment
    metadata JSONB NOT NULL DEFAULT '{"sandbox": true}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT agent_public_key_length CHECK (LENGTH(public_key) = 32),
    CONSTRAINT agent_trust_score_range CHECK (trust_score >= 0 AND trust_score <= 100),
    CONSTRAINT agent_daily_limit_positive CHECK (daily_limit_usd >= 0),
    CONSTRAINT agent_per_action_limit_positive CHECK (per_action_limit_usd >= 0),
    CONSTRAINT agent_rate_limit_positive CHECK (rate_limit_per_minute > 0),
    CONSTRAINT agent_production_approval_required CHECK (
        COALESCE(
            metadata @> '{"sandbox": true}'::JSONB
            OR (
                metadata @> '{"sandbox": false}'::JSONB
                AND JSONB_TYPEOF(metadata->'production_approval_reference') = 'string'
                AND BTRIM(metadata->>'production_approval_reference') <> ''
                AND JSONB_TYPEOF(metadata->'production_approved_at') = 'string'
                AND BTRIM(metadata->>'production_approved_at') <> ''
                AND JSONB_TYPEOF(metadata->'production_approved_by') = 'string'
                AND BTRIM(metadata->>'production_approved_by') <> ''
            ),
            FALSE
        )
    )
);

CREATE UNIQUE INDEX idx_agents_public_key_fingerprint ON agents(public_key_fingerprint);
CREATE INDEX idx_agents_org_id ON agents(org_id);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_trust_score ON agents(trust_score);

-- =============================================================================
-- TABLE: policy_rules
-- =============================================================================
-- Configurable policy rules per organization or agent.

CREATE TABLE policy_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    rule_name VARCHAR(255) NOT NULL,
    rule_type VARCHAR(50) NOT NULL,  -- 'limit', 'allowlist', 'blocklist', 'time_window'
    conditions JSONB NOT NULL DEFAULT '{}',
    action_on_match VARCHAR(50) NOT NULL DEFAULT 'block',  -- 'block', 'allow', 'alert', 'require_approval'
    priority INTEGER NOT NULL DEFAULT 100,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT policy_has_target CHECK (org_id IS NOT NULL OR agent_id IS NOT NULL),
    CONSTRAINT policy_priority_positive CHECK (priority > 0)
);

CREATE INDEX idx_policy_rules_org_id ON policy_rules(org_id) WHERE org_id IS NOT NULL;
CREATE INDEX idx_policy_rules_agent_id ON policy_rules(agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX idx_policy_rules_active ON policy_rules(is_active) WHERE is_active = TRUE;

-- =============================================================================
-- TABLE: audit_logs (APPEND-ONLY - FORENSIC GRADE)
-- =============================================================================
-- Immutable audit trail for all agent actions. This is court-admissible evidence.
-- SECURITY: No UPDATE or DELETE operations allowed via application code.

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,  -- RESTRICT: Cannot delete agent with logs
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action_type VARCHAR(100) NOT NULL,
    action_hash VARCHAR(64) NOT NULL,  -- SHA-256 of payload for integrity verification
    -- Full action details, stored as submitted. NOT encrypted: the /verify
    -- request path inserts this column directly. Field-level encryption in
    -- this schema currently covers webhook signing secrets only
    -- (organizations.webhook_secret_ciphertext, migration 013). Envelope
    -- encryption for this column is planned; until it ships, treat every
    -- payload field as readable at the database layer.
    payload JSONB NOT NULL,
    verdict action_verdict NOT NULL,
    verdict_reason TEXT,
    signature BYTEA NOT NULL,  -- Original Ed25519 signature from agent
    signature_valid BOOLEAN NOT NULL,
    request_ip INET,
    request_user_agent TEXT,
    response_time_ms INTEGER,
    trust_score_at_time INTEGER NOT NULL,
    merkle_root_id UUID,  -- Set when batched into merkle tree
    merkle_leaf_index INTEGER,  -- Position in the merkle tree
    chain_previous_hash VARCHAR(64),  -- Hash of previous log entry (local chain)
    -- SHA-256 over the agent's effective controls at verification time:
    -- status, allow/block lists, spend limits, rate limit, trust score.
    -- NOT the hash of a registered .inntris.yml document — that lives on
    -- agent_policies.policy_hash. Named policy_hash before migration 017.
    effective_controls_hash CHAR(64),
    metadata JSONB DEFAULT '{}',

    CONSTRAINT audit_action_hash_format CHECK (LENGTH(action_hash) = 64),
    CONSTRAINT audit_signature_not_empty CHECK (LENGTH(signature) > 0)
);

-- Time-based partitioning for audit_logs
-- Check if TimescaleDB is available and create hypertable, otherwise use standard partitioning
DO $$
BEGIN
    -- Try to create a hypertable (TimescaleDB)
    PERFORM create_hypertable('audit_logs', 'timestamp',
        chunk_time_interval => INTERVAL '1 day',
        if_not_exists => TRUE
    );
    RAISE NOTICE 'Created TimescaleDB hypertable for audit_logs';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TimescaleDB not available, creating standard partitioned table';
    -- Note: Standard partitioning would require recreating the table as partitioned
    -- For simplicity, we'll use the non-partitioned table with proper indexes
END $$;

-- Critical indexes for audit queries
CREATE INDEX idx_audit_logs_agent_id_timestamp ON audit_logs(agent_id, timestamp DESC);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_action_type ON audit_logs(action_type);
CREATE INDEX idx_audit_logs_verdict ON audit_logs(verdict);
CREATE INDEX idx_audit_logs_merkle_root_id ON audit_logs(merkle_root_id) WHERE merkle_root_id IS NOT NULL;
CREATE INDEX idx_audit_logs_signature_valid ON audit_logs(signature_valid) WHERE signature_valid = FALSE;

-- =============================================================================
-- TABLE: merkle_proofs
-- =============================================================================
-- Blockchain anchoring records. Links audit batches to on-chain merkle roots.

CREATE TABLE merkle_proofs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    root_hash VARCHAR(64) NOT NULL UNIQUE,  -- keccak256 merkle root
    transaction_hash VARCHAR(66),  -- Ethereum tx hash (0x + 64 chars)
    block_number BIGINT,
    chain_id INTEGER NOT NULL DEFAULT 8453,  -- Base L2 chain ID
    contract_address VARCHAR(42) NOT NULL,  -- 0x + 40 chars
    log_count INTEGER NOT NULL,
    start_timestamp TIMESTAMPTZ NOT NULL,
    end_timestamp TIMESTAMPTZ NOT NULL,
    leaf_hashes TEXT[] NOT NULL,  -- Array of all leaf hashes in order
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending', 'submitted', 'confirmed', 'failed', 'dead_letter'
    gas_used BIGINT,
    gas_price_gwei DECIMAL(18, 9),
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ,  -- NULL = retry immediately; set on failure for exponential backoff (Phase 0.6)
    dead_lettered_at TIMESTAMPTZ,  -- Set when retry_count is exhausted; requires manual intervention (Phase 0.6)
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed_at TIMESTAMPTZ,

    CONSTRAINT merkle_root_hash_format CHECK (LENGTH(root_hash) = 64),
    CONSTRAINT merkle_tx_hash_format CHECK (transaction_hash IS NULL OR LENGTH(transaction_hash) = 66),
    CONSTRAINT merkle_log_count_positive CHECK (log_count > 0)
);

CREATE INDEX idx_merkle_proofs_status ON merkle_proofs(status);
CREATE INDEX idx_merkle_proofs_created_at ON merkle_proofs(created_at DESC);
CREATE INDEX idx_merkle_proofs_block_number ON merkle_proofs(block_number) WHERE block_number IS NOT NULL;
CREATE INDEX idx_merkle_proofs_retry_due ON merkle_proofs (next_retry_at) WHERE status IN ('pending', 'failed');
CREATE INDEX idx_merkle_proofs_dead_letter ON merkle_proofs (dead_lettered_at DESC) WHERE status = 'dead_letter';

-- =============================================================================
-- TABLE: security_alerts
-- =============================================================================
-- High-priority security events requiring immediate attention.

CREATE TABLE security_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    alert_type VARCHAR(100) NOT NULL,
    severity alert_severity NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}',  -- Supporting data for investigation
    audit_log_ids UUID[] DEFAULT ARRAY[]::UUID[],  -- Related audit entries
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by VARCHAR(255),
    acknowledged_at TIMESTAMPTZ,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_by VARCHAR(255),
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_alerts_severity ON security_alerts(severity);
CREATE INDEX idx_security_alerts_agent_id ON security_alerts(agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX idx_security_alerts_unresolved ON security_alerts(created_at DESC) WHERE resolved = FALSE;

-- =============================================================================
-- TABLE: rate_limit_windows
-- =============================================================================
-- Sliding window rate limiting state per agent.

CREATE TABLE rate_limit_windows (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    window_type VARCHAR(20) NOT NULL,  -- 'minute', 'hour', 'day'
    window_start TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    amount_usd DECIMAL(15, 2) NOT NULL DEFAULT 0,

    CONSTRAINT rate_limit_unique_window UNIQUE (agent_id, window_type, window_start)
);

CREATE INDEX idx_rate_limit_agent_window ON rate_limit_windows(agent_id, window_type, window_start DESC);

-- =============================================================================
-- TABLE: api_keys
-- =============================================================================
-- API key management for organizations accessing the Core API.

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key_hash BYTEA NOT NULL UNIQUE,  -- SHA-256 hash of the API key
    key_prefix VARCHAR(8) NOT NULL,  -- 8 random key chars for identification
    name VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT ARRAY['read', 'verify'],
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT api_key_name_not_empty CHECK (LENGTH(TRIM(name)) > 0)
);

CREATE INDEX idx_api_keys_org_id ON api_keys(org_id);
CREATE INDEX idx_api_keys_active ON api_keys(is_active) WHERE is_active = TRUE;

-- =============================================================================
-- FUNCTIONS & TRIGGERS
-- =============================================================================

-- Function to update 'updated_at' timestamp automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at triggers
CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_agents_updated_at
    BEFORE UPDATE ON agents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_policy_rules_updated_at
    BEFORE UPDATE ON policy_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to prevent deletion of audit_logs (FORENSIC PROTECTION)
-- CRITICAL: Allow ONLY merkle field updates for blockchain anchoring
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    -- DELETE is always prohibited
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'SECURITY VIOLATION: Audit logs are immutable. DELETE operations are prohibited.';
        RETURN NULL;
    END IF;

    -- UPDATE: Allow ONLY merkle field updates when they are NULL (first-time anchoring)
    IF TG_OP = 'UPDATE' THEN
        -- Check if ONLY merkle fields are being updated
        IF (OLD.merkle_root_id IS NULL AND NEW.merkle_root_id IS NOT NULL) OR
           (OLD.merkle_leaf_index IS NULL AND NEW.merkle_leaf_index IS NOT NULL) THEN
            -- Verify that NO OTHER fields are being changed (nonce removed - not a column)
            IF (OLD.id, OLD.agent_id, OLD.action_type, OLD.action_hash, OLD.payload,
                OLD.verdict, OLD.verdict_reason, OLD.signature, OLD.signature_valid,
                OLD.request_ip, OLD.request_user_agent, OLD.response_time_ms,
                OLD.trust_score_at_time, OLD.chain_previous_hash, OLD.metadata,
                OLD.timestamp, OLD.effective_controls_hash)
            IS DISTINCT FROM
               (NEW.id, NEW.agent_id, NEW.action_type, NEW.action_hash, NEW.payload,
                NEW.verdict, NEW.verdict_reason, NEW.signature, NEW.signature_valid,
                NEW.request_ip, NEW.request_user_agent, NEW.response_time_ms,
                NEW.trust_score_at_time, NEW.chain_previous_hash, NEW.metadata,
                NEW.timestamp, NEW.effective_controls_hash) THEN
                RAISE EXCEPTION 'SECURITY VIOLATION: Only merkle_root_id and merkle_leaf_index can be updated, and only when NULL.';
                RETURN NULL;
            END IF;
            -- Allow the merkle field update
            RETURN NEW;
        ELSE
            RAISE EXCEPTION 'SECURITY VIOLATION: Audit logs are immutable. Only merkle anchoring fields can be updated once.';
            RETURN NULL;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- CRITICAL: Prevent any modification to audit_logs
CREATE TRIGGER protect_audit_logs_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_modification();

CREATE TRIGGER protect_audit_logs_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_modification();

-- Function to increment agent action counters and track consecutive successes
CREATE OR REPLACE FUNCTION update_agent_action_stats()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE agents SET
        total_actions_count = total_actions_count + 1,
        total_blocked_count = total_blocked_count + CASE WHEN NEW.verdict != 'approved' THEN 1 ELSE 0 END,
        -- Track consecutive successes for trust score adjustment
        consecutive_success_count = CASE
            WHEN NEW.verdict = 'approved' THEN consecutive_success_count + 1
            ELSE 0  -- Reset on any failure
        END,
        last_action_at = NEW.timestamp
    WHERE id = NEW.agent_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_agent_stats_on_audit
    AFTER INSERT ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION update_agent_action_stats();

-- Function to create security alert on signature failure
CREATE OR REPLACE FUNCTION create_signature_failure_alert()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.signature_valid = FALSE
       AND NEW.verdict = 'signature_invalid'
       AND NOT COALESCE((NEW.metadata->>'non_cryptographic')::boolean, false) THEN
        INSERT INTO security_alerts (
            agent_id,
            org_id,
            alert_type,
            severity,
            title,
            description,
            evidence,
            audit_log_ids
        )
        SELECT
            NEW.agent_id,
            a.org_id,
            'SIGNATURE_VERIFICATION_FAILED',
            'critical',
            'Invalid Signature Detected - Potential Attack',
            'An action was attempted with an invalid cryptographic signature. This may indicate a compromised agent or replay attack.',
            jsonb_build_object(
                'action_type', NEW.action_type,
                'action_hash', NEW.action_hash,
                'request_ip', NEW.request_ip,
                'timestamp', NEW.timestamp
            ),
            ARRAY[NEW.id]
        FROM agents a
        WHERE a.id = NEW.agent_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER alert_on_signature_failure
    AFTER INSERT ON audit_logs
    FOR EACH ROW
    WHEN (
        NEW.signature_valid = FALSE
        AND NEW.verdict = 'signature_invalid'
        AND NOT COALESCE((NEW.metadata->>'non_cryptographic')::boolean, false)
    )
    EXECUTE FUNCTION create_signature_failure_alert();

-- =============================================================================
-- ROW LEVEL SECURITY (RLS)
-- =============================================================================

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_alerts ENABLE ROW LEVEL SECURITY;

-- Policies will be configured per-application role
-- Example: Service role has full access, authenticated users see only their org

-- =============================================================================
-- INITIAL SEED DATA (Optional - Remove in Production)
-- =============================================================================

-- Uncomment for development/testing:
-- INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash)
-- VALUES (
--     '00000000-0000-0000-0000-000000000001',
--     'Inntris Test Organization',
--     'enterprise',
--     'admin@inntris-test.local',
--     decode(encode(digest('test-api-key-do-not-use-in-production', 'sha256'), 'hex'), 'hex')
-- );

-- =============================================================================
-- GRANTS (Configure based on your role setup)
-- =============================================================================

-- Example grants for a 'inntris_api' role:
-- GRANT SELECT, INSERT ON audit_logs TO inntris_api;
-- GRANT SELECT, INSERT, UPDATE ON agents TO inntris_api;
-- GRANT SELECT ON organizations TO inntris_api;
-- GRANT SELECT, INSERT, UPDATE ON merkle_proofs TO inntris_api;
-- GRANT SELECT, INSERT, UPDATE ON security_alerts TO inntris_api;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limit_windows TO inntris_api;

-- =============================================================================
-- END OF SCHEMA
-- =============================================================================
