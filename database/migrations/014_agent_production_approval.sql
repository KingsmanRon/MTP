-- Require explicit lifecycle approval before an agent can create records that
-- are eligible for the production anchor set.
--
-- Existing rows without complete approval evidence fail closed into sandbox.
-- Operators must promote them through the tenant scoped admin endpoint after
-- recording the relevant change or approval reference.

LOCK TABLE agents IN SHARE ROW EXCLUSIVE MODE;

-- All rows predate the authenticated promotion contract. Do not trust any
-- lifecycle fields already present: historical public registration accepted
-- caller supplied metadata. Every legacy agent must be reviewed and promoted
-- again through the new tenant scoped endpoint.
UPDATE agents
SET metadata = (
        COALESCE(metadata, '{}'::JSONB)
        - 'production_approval_reference'
        - 'production_approved_at'
        - 'production_approved_by'
    ) || '{"sandbox": true}'::JSONB,
    updated_at = NOW();

ALTER TABLE agents
    ALTER COLUMN metadata SET DEFAULT '{"sandbox": true}'::JSONB,
    ALTER COLUMN metadata SET NOT NULL;

ALTER TABLE agents
    DROP CONSTRAINT IF EXISTS agent_production_approval_required;

ALTER TABLE agents
    ADD CONSTRAINT agent_production_approval_required CHECK (
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
    );

COMMENT ON CONSTRAINT agent_production_approval_required ON agents IS
    'Production agents require explicit tenant approval evidence; all other agents remain sandboxed.';
