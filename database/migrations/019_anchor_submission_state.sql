-- =============================================================================
-- MIGRATION 019: Durable Base submission and reconciliation state
-- =============================================================================
-- A transaction hash is knowable as soon as an Ethereum transaction is signed.
-- Persist that identity before broadcast and receipt polling so an RPC failure
-- cannot make a submitted transaction look like it never existed.
--
-- audit_logs.merkle_root_id remains the immutable batch assignment. Base
-- confirmation is represented only by merkle_proofs.status = 'confirmed'.
-- =============================================================================

ALTER TABLE public.merkle_proofs
    ADD COLUMN IF NOT EXISTS submission_nonce BIGINT,
    ADD COLUMN IF NOT EXISTS prepared_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_reconciliation_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS reconciled_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS reconciliation_source VARCHAR(32);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'merkle_submission_nonce_nonnegative'
          AND conrelid = 'public.merkle_proofs'::regclass
    ) THEN
        ALTER TABLE public.merkle_proofs
            ADD CONSTRAINT merkle_submission_nonce_nonnegative
            CHECK (submission_nonce IS NULL OR submission_nonce >= 0);
    END IF;
END $$;

DROP INDEX IF EXISTS public.idx_merkle_proofs_retry_due;
CREATE INDEX idx_merkle_proofs_retry_due
    ON public.merkle_proofs (next_retry_at, created_at)
    WHERE status IN ('pending', 'prepared', 'submitted', 'failed');

CREATE INDEX IF NOT EXISTS idx_merkle_proofs_transaction_hash
    ON public.merkle_proofs (transaction_hash)
    WHERE transaction_hash IS NOT NULL;

COMMENT ON COLUMN public.merkle_proofs.submission_nonce IS
    'Nonce selected for the currently persisted transaction identity.';
COMMENT ON COLUMN public.merkle_proofs.prepared_at IS
    'When a signed transaction hash and nonce were persisted before broadcast.';
COMMENT ON COLUMN public.merkle_proofs.submitted_at IS
    'When broadcast succeeded or became transport-ambiguous and reconciliation became mandatory.';
COMMENT ON COLUMN public.merkle_proofs.last_reconciliation_at IS
    'Most recent receipt and contract-state reconciliation attempt.';
COMMENT ON COLUMN public.merkle_proofs.reconciled_at IS
    'When stale database state was repaired from confirmed chain evidence.';
COMMENT ON COLUMN public.merkle_proofs.reconciliation_source IS
    'Confirmation evidence source, for example transaction_receipt or contract_state.';
COMMENT ON COLUMN public.audit_logs.merkle_root_id IS
    'Immutable Merkle batch assignment. This does not itself mean the batch is confirmed on Base.';
