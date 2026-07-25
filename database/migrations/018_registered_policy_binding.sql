-- =============================================================================
-- MIGRATION 018: Record the registered policy on each audit row
-- =============================================================================
-- B2.2. A receipt could prove an action occurred and was allowed. It could not
-- prove *which registered policy version* it was allowed under — the audit row
-- carried only the derived effective-controls hash.
--
-- These two columns are written at decision time, deliberately rather than
-- joined at read time: agent_policies holds the CURRENT active policy, so a
-- join would re-label historical receipts with whatever policy is registered
-- today. A receipt has to say what was in force when the decision was made.
--
-- NULL means no policy was registered for that agent at decision time, which
-- is the common case for action types outside the CI-guard set. It does not
-- mean "unknown".
--
-- No change to the receipt fingerprint. The cryptographic binding to policy
-- already exists one layer down: envelope v3 puts registered_policy_hash in
-- the action hash, and the action hash is the anchored Merkle leaf. These
-- columns make that binding legible on the receipt; they do not create it.
-- =============================================================================

ALTER TABLE public.audit_logs
    ADD COLUMN IF NOT EXISTS registered_policy_version INTEGER;

ALTER TABLE public.audit_logs
    ADD COLUMN IF NOT EXISTS registered_policy_hash CHAR(64);

COMMENT ON COLUMN public.audit_logs.registered_policy_version IS
    'agent_policies.version active for this agent at decision time. NULL when '
    'no policy was registered — not "unknown".';

COMMENT ON COLUMN public.audit_logs.registered_policy_hash IS
    'agent_policies.policy_hash active at decision time: the canonical hash of '
    'the registered .inntris.yml document. Distinct from '
    'effective_controls_hash, which commits to the agent control snapshot.';
