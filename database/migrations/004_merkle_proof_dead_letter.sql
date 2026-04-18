-- =============================================================================
-- MIGRATION 004: Bounded merkle-proof retries + dead-letter state
-- =============================================================================
-- Phase 0.6 — prior to this migration the anchor worker re-submitted every
-- proof in `status IN ('pending', 'failed')` on every tick with no spacing
-- and no terminal state. A persistently failing batch (e.g. bad RPC, empty
-- hot wallet) would burn gas on each tick until retry_count reached
-- MAX_RETRIES, at which point the row silently dropped out of the retry
-- query but was never marked as such. Operators had no signal that a batch
-- was stuck.
--
-- This migration:
--   * Adds `next_retry_at` so the worker can back off between attempts.
--   * Adds `dead_lettered_at` so a proof that exhausts its retries enters
--     a terminal state we can see, alert on, and requeue by hand.
--   * Relaxes the status column's informal vocabulary to include
--     'dead_letter'. VARCHAR(20) already fits.
-- =============================================================================

ALTER TABLE merkle_proofs
    ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS dead_lettered_at TIMESTAMPTZ;

-- Fast path for the worker's pending-retry query: rows eligible for another
-- attempt ordered by when they're due.
CREATE INDEX IF NOT EXISTS idx_merkle_proofs_retry_due
    ON merkle_proofs (next_retry_at)
    WHERE status IN ('pending', 'failed');

-- Investigators need a quick way to list terminally-stuck batches.
CREATE INDEX IF NOT EXISTS idx_merkle_proofs_dead_letter
    ON merkle_proofs (dead_lettered_at DESC)
    WHERE status = 'dead_letter';
