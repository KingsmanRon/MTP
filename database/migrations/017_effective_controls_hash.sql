-- =============================================================================
-- MIGRATION 017: Rename audit_logs.policy_hash -> effective_controls_hash
-- =============================================================================
-- The column never held a policy document hash. It holds a SHA-256 over the
-- agent's *effective controls* at decision time — status, allow/block lists,
-- spend limits, rate limit, trust score — computed by
-- api/main.py::_effective_controls_hash.
--
-- The registered .inntris.yml document hash is a different value living on
-- agent_policies.policy_hash. Both are useful and both are exposed, but under
-- one name a receipt read as though it proved "this action was allowed under
-- registered policy version N" when it proved "these were the controls in
-- force". This migration makes the distinction legible in the schema.
--
-- Receipt schema version moves v2 -> v3 with the rename. The fingerprint field
-- set is unchanged in size and sort order (the new key occupies the same
-- position 5 of 7), so only the key name differs.
--
-- Safe to replay: the rename is guarded on the old column still existing, so
-- a fresh install from schemas.sql (which already declares the new name) and
-- an already-migrated database both end in the same state.
--
-- The immutability trigger does NOT need updating: migration 012 replaced
-- prevent_audit_log_modification with a version that does not enumerate this
-- column by name.
-- =============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'audit_logs'
          AND column_name = 'policy_hash'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'audit_logs'
          AND column_name = 'effective_controls_hash'
    ) THEN
        ALTER TABLE public.audit_logs
            RENAME COLUMN policy_hash TO effective_controls_hash;
        RAISE NOTICE 'audit_logs.policy_hash renamed to effective_controls_hash';
    END IF;
END $$;

COMMENT ON COLUMN public.audit_logs.effective_controls_hash IS
    'SHA-256 over the agent effective controls at verification time (status, '
    'allow/block lists, spend limits, rate limit, trust score). NOT a policy '
    'document hash — see agent_policies.policy_hash for the registered '
    '.inntris.yml document hash.';
