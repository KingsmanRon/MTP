-- Bind durable approval token consumption to a stable downstream execution
-- reference so retries after a lost response are idempotent.

ALTER TABLE approval_token_consumptions
    ADD COLUMN IF NOT EXISTS execution_ref TEXT;

ALTER TABLE approval_token_consumptions
    DROP CONSTRAINT IF EXISTS approval_token_execution_ref_not_blank;

ALTER TABLE approval_token_consumptions
    ADD CONSTRAINT approval_token_execution_ref_not_blank CHECK (
        execution_ref IS NULL
        OR (BTRIM(execution_ref) <> '' AND LENGTH(execution_ref) <= 512)
    );

CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_token_consumptions_execution_ref
    ON approval_token_consumptions(agent_id, execution_ref)
    WHERE execution_ref IS NOT NULL;

COMMENT ON COLUMN approval_token_consumptions.execution_ref IS
    'Stable executor idempotency key. The same token and reference replay returns the original audit receipt.';
