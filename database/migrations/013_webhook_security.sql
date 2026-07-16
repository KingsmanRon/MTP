-- =============================================================================
-- MIGRATION 013: Tenant webhook secrets and durable delivery state
-- =============================================================================
-- Existing HTTP destinations are disabled. Existing HTTPS destinations remain
-- configured but cannot deliver until an administrator creates a tenant scoped
-- signing secret through the rotation endpoint.
-- =============================================================================

UPDATE organizations
SET webhook_url = NULL,
    updated_at = NOW()
WHERE webhook_url IS NOT NULL
  AND webhook_url !~* '^https://';

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS webhook_secret_ciphertext BYTEA;

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS webhook_secret_version INTEGER NOT NULL DEFAULT 0;

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS webhook_secret_rotated_at TIMESTAMPTZ;

ALTER TABLE organizations
    DROP CONSTRAINT IF EXISTS organizations_webhook_https_check;

ALTER TABLE organizations
    ADD CONSTRAINT organizations_webhook_https_check CHECK (
        webhook_url IS NULL OR webhook_url ~ '^https://'
    );

ALTER TABLE organizations
    DROP CONSTRAINT IF EXISTS organizations_webhook_secret_state_check;

ALTER TABLE organizations
    ADD CONSTRAINT organizations_webhook_secret_state_check CHECK (
        (
            webhook_secret_ciphertext IS NULL
            AND webhook_secret_version = 0
            AND webhook_secret_rotated_at IS NULL
        )
        OR
        (
            webhook_secret_ciphertext IS NOT NULL
            AND octet_length(webhook_secret_ciphertext) >= 32
            AND webhook_secret_version > 0
            AND webhook_secret_rotated_at IS NOT NULL
        )
    );

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id             UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event              VARCHAR(100) NOT NULL,
    payload            JSONB NOT NULL,
    status             VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempt_count      SMALLINT NOT NULL DEFAULT 0,
    response_status    INTEGER,
    last_error         VARCHAR(1000),
    next_attempt_at    TIMESTAMPTZ DEFAULT NOW(),
    last_attempt_at    TIMESTAMPTZ,
    delivered_at       TIMESTAMPTZ,
    dead_lettered_at   TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT webhook_deliveries_event_not_empty
        CHECK (length(trim(event)) > 0),
    CONSTRAINT webhook_deliveries_status_check
        CHECK (status IN ('pending', 'delivering', 'retrying', 'delivered', 'dead_letter')),
    CONSTRAINT webhook_deliveries_attempt_count_check
        CHECK (attempt_count >= 0 AND attempt_count <= 3),
    CONSTRAINT webhook_deliveries_response_status_check
        CHECK (response_status IS NULL OR response_status BETWEEN 100 AND 599)
);

CREATE INDEX IF NOT EXISTS webhook_deliveries_org_created_idx
    ON webhook_deliveries (org_id, created_at DESC);

CREATE INDEX IF NOT EXISTS webhook_deliveries_due_idx
    ON webhook_deliveries (next_attempt_at)
    WHERE status IN ('pending', 'retrying');

CREATE INDEX IF NOT EXISTS webhook_deliveries_dead_letter_idx
    ON webhook_deliveries (org_id, dead_lettered_at DESC)
    WHERE status = 'dead_letter';

ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS webhook_deliveries_tenant_scope ON webhook_deliveries;
CREATE POLICY webhook_deliveries_tenant_scope ON webhook_deliveries
    FOR ALL
    TO inntris_api
    USING (org_id = app.current_tenant())
    WITH CHECK (org_id = app.current_tenant());

GRANT SELECT, INSERT, UPDATE ON webhook_deliveries TO inntris_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON webhook_deliveries TO inntris_worker;
