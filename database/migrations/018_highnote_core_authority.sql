-- Durable request idempotency and expiring spend reservations for synchronous
-- execution adapters such as Highnote Collaborative Authorization.

-- Retain public verification material across agent-key rotation. Historical
-- rows created before this migration may remain NULL because a fingerprint is
-- not sufficient to reconstruct a public key. Future rotations persist only
-- the retiring public key; private seed material never enters Core.
ALTER TABLE agent_key_history
    ADD COLUMN IF NOT EXISTS public_key BYTEA;

COMMENT ON COLUMN agent_key_history.public_key IS
    'Retired raw Ed25519 public key used to verify historical audit signatures.';

CREATE TABLE IF NOT EXISTS verify_request_idempotency (
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    request_ref TEXT NOT NULL,
    action_hash VARCHAR(64) NOT NULL,
    nonce TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'processing',
    verdict action_verdict,
    violation_code TEXT,
    http_status SMALLINT,
    audit_log_id UUID REFERENCES audit_logs(id) ON DELETE RESTRICT,
    verdict_reason TEXT,
    approval_token_id TEXT,
    approval_token_expires_at TIMESTAMPTZ,
    trust_score INTEGER,
    response_timestamp TIMESTAMPTZ,
    limits_remaining JSONB,
    sandbox BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (agent_id, request_ref),
    CONSTRAINT verify_request_ref_not_blank CHECK (
        BTRIM(request_ref) <> '' AND LENGTH(request_ref) <= 512
    ),
    CONSTRAINT verify_request_action_hash_format CHECK (
        action_hash ~ '^[a-f0-9]{64}$'
    ),
    CONSTRAINT verify_request_nonce_not_blank CHECK (
        BTRIM(nonce) <> '' AND LENGTH(nonce) <= 64
    ),
    CONSTRAINT verify_request_state_valid CHECK (state IN ('processing', 'completed')),
    CONSTRAINT verify_request_http_status_valid CHECK (
        http_status IS NULL OR http_status BETWEEN 200 AND 599
    ),
    CONSTRAINT verify_request_completion_consistent CHECK (
        (state = 'processing' AND completed_at IS NULL)
        OR (
            state = 'completed'
            AND completed_at IS NOT NULL
            AND verdict IS NOT NULL
            AND http_status IS NOT NULL
            AND audit_log_id IS NOT NULL
            AND response_timestamp IS NOT NULL
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_verify_request_idempotency_created
    ON verify_request_idempotency(created_at DESC);

COMMENT ON TABLE verify_request_idempotency IS
    'Durable exact retry state for authenticated POST /verify callers.';
COMMENT ON COLUMN verify_request_idempotency.request_ref IS
    'Caller reference also carried in the signed payload as payload.request_ref.';

CREATE TABLE IF NOT EXISTS spend_reservations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    action_hash VARCHAR(64) NOT NULL,
    approval_token_id TEXT NOT NULL UNIQUE,
    amount_usd DECIMAL(15, 2) NOT NULL,
    status TEXT NOT NULL DEFAULT 'reserved',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    release_reason TEXT,
    CONSTRAINT spend_reservation_action_hash_format CHECK (
        action_hash ~ '^[a-f0-9]{64}$'
    ),
    CONSTRAINT spend_reservation_token_not_blank CHECK (BTRIM(approval_token_id) <> ''),
    CONSTRAINT spend_reservation_amount_nonnegative CHECK (amount_usd >= 0),
    CONSTRAINT spend_reservation_status_valid CHECK (
        status IN ('reserved', 'consumed', 'released', 'expired')
    ),
    CONSTRAINT spend_reservation_state_timestamps CHECK (
        (status = 'reserved' AND consumed_at IS NULL AND released_at IS NULL)
        OR (status = 'consumed' AND consumed_at IS NOT NULL AND released_at IS NULL)
        OR (status IN ('released', 'expired') AND consumed_at IS NULL AND released_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_spend_reservations_agent_active
    ON spend_reservations(agent_id, created_at DESC)
    WHERE status IN ('reserved', 'consumed');
CREATE UNIQUE INDEX IF NOT EXISTS uq_spend_reservations_agent_active_action
    ON spend_reservations(agent_id, action_hash)
    WHERE status IN ('reserved', 'consumed');
CREATE INDEX IF NOT EXISTS idx_spend_reservations_expiry
    ON spend_reservations(expires_at)
    WHERE status = 'reserved';

COMMENT ON TABLE spend_reservations IS
    'Authorisation spend reservations. Unconsumed reservations expire at approval-token expiry; consumed reservations remain charged pending rail reconciliation.';

ALTER TABLE verify_request_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE spend_reservations ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS verify_request_idempotency_tenant_scope
    ON verify_request_idempotency;
CREATE POLICY verify_request_idempotency_tenant_scope
    ON verify_request_idempotency
    FOR ALL
    TO inntris_api
    USING (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = verify_request_idempotency.agent_id
              AND a.org_id = app.current_tenant()
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = verify_request_idempotency.agent_id
              AND a.org_id = app.current_tenant()
        )
    );

DROP POLICY IF EXISTS spend_reservations_tenant_scope ON spend_reservations;
CREATE POLICY spend_reservations_tenant_scope
    ON spend_reservations
    FOR ALL
    TO inntris_api
    USING (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = spend_reservations.agent_id
              AND a.org_id = app.current_tenant()
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = spend_reservations.agent_id
              AND a.org_id = app.current_tenant()
        )
    );

REVOKE ALL ON TABLE verify_request_idempotency FROM PUBLIC;
REVOKE ALL ON TABLE spend_reservations FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON verify_request_idempotency TO inntris_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON verify_request_idempotency TO inntris_worker;
GRANT SELECT, INSERT, UPDATE ON spend_reservations TO inntris_api;
GRANT SELECT, INSERT, UPDATE ON spend_reservations TO inntris_worker;
