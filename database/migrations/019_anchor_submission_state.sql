-- =============================================================================
-- MIGRATION 019: Separate anchor broadcast from anchor confirmation
-- =============================================================================
-- Incident background (production, 2026-08-25):
--   The anchor worker treated "broadcast a transaction" and "observe its
--   receipt" as a single operation. `anchor_batch()` called
--   send_raw_transaction() and then wait_for_transaction_receipt(), and only
--   returned the transaction hash to the database once the receipt arrived.
--
--   When the RPC returned HTTP 403 during receipt polling, the exception
--   discarded a transaction that had already been accepted by the network.
--   The database never learned the hash, marked the proof `failed`, and the
--   worker broadcast the same batch again on the next tick. Base eventually
--   rejected the duplicate with RootAlreadyAnchored(bytes32) — selector
--   0xdb34c203 — which the worker could not decode (the custom errors were
--   absent from its ABI), so it read as a gas-estimation failure and it
--   broadcast again. After five attempts the proof dead-lettered, while the
--   Merkle root was in fact anchored on Base the whole time.
--
-- The database could not represent the state "a transaction exists and we do
-- not yet know its outcome". That state is what this migration adds.
--
-- Columns:
--   * submission_nonce — the account nonce used for the in-flight transaction.
--     Persisted so a replacement transaction reuses the same nonce instead of
--     allocating a new one (the incident logged "nonce too low: next nonce 34,
--     tx nonce 33", the signature of a lost-then-reissued transaction).
--   * submitted_at — when the transaction was broadcast, as distinct from
--     confirmed_at, which means the chain proved it.
--   * reconciled_at — when the proof's status was established by reading the
--     chain rather than by observing our own submission. Distinguishes "we
--     watched this succeed" from "we discovered it had succeeded".
--
-- Status vocabulary gains `submitted`, which schemas.sql already documented
-- but no code ever wrote. The column is VARCHAR(20) with no CHECK constraint,
-- so the vocabulary widens without a constraint change.
--
--   pending      Proof exists. No transaction broadcast yet.
--   submitted    A transaction hash is known. Confirmation is outstanding.
--   confirmed    Base receipt or contract state proves the root is anchored.
--   failed       Retryable. No confirmed anchor has been established.
--   dead_letter  Retries exhausted. Needs reconciliation or an operator.
--
-- Forensic note: this migration deliberately does NOT clear dead_lettered_at
-- when a proof is later reconciled to `confirmed`. A proof that once reached
-- dead-letter keeps that timestamp as incident evidence; reconciled_at records
-- the recovery. Both facts matter and neither overwrites the other.
-- =============================================================================

ALTER TABLE merkle_proofs
    ADD COLUMN IF NOT EXISTS submission_nonce BIGINT,
    ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS reconciled_at TIMESTAMPTZ;

-- The retry query previously matched only ('pending', 'failed'). It must now
-- also pick up `submitted` rows, whose next action is reconciliation (fetch the
-- receipt, read contract state) rather than another broadcast. The old partial
-- index no longer covers the query, so replace it.
DROP INDEX IF EXISTS idx_merkle_proofs_retry_due;

CREATE INDEX IF NOT EXISTS idx_merkle_proofs_retry_due
    ON merkle_proofs (next_retry_at)
    WHERE status IN ('pending', 'submitted', 'failed');

-- Proofs carrying a transaction hash whose outcome is unknown are the rows an
-- operator most needs to find after an RPC incident.
CREATE INDEX IF NOT EXISTS idx_merkle_proofs_awaiting_receipt
    ON merkle_proofs (submitted_at DESC)
    WHERE status = 'submitted';

-- Backfill: any historical row that already carries a transaction_hash but was
-- recorded as `failed` was, by definition, a broadcast whose outcome we did not
-- establish. It is NOT safe to call these confirmed here — that requires
-- reading Base. Leave their status alone and only record what we already know,
-- so the reconciliation tooling can find them.
UPDATE merkle_proofs
SET submitted_at = COALESCE(submitted_at, created_at)
WHERE transaction_hash IS NOT NULL
  AND submitted_at IS NULL;
