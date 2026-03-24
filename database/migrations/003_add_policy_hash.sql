-- =============================================================================
-- MIGRATION 003: Add policy_hash to audit_logs
-- =============================================================================
-- Stores SHA-256 hash of the .inntris.yml policy file at verification time,
-- creating an immutable binding between policy state and verification decision.
-- =============================================================================

-- Step 1: Add policy_hash column (nullable — old records won't have it)
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS policy_hash CHAR(64);

-- Step 2: Update the immutability trigger to include policy_hash
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
            -- Verify that NO OTHER fields are being changed
            IF (OLD.id, OLD.agent_id, OLD.action_type, OLD.action_hash, OLD.payload,
                OLD.verdict, OLD.verdict_reason, OLD.signature, OLD.signature_valid,
                OLD.request_ip, OLD.request_user_agent, OLD.response_time_ms,
                OLD.trust_score_at_time, OLD.chain_previous_hash, OLD.metadata,
                OLD.timestamp, OLD.policy_hash)
            IS DISTINCT FROM
               (NEW.id, NEW.agent_id, NEW.action_type, NEW.action_hash, NEW.payload,
                NEW.verdict, NEW.verdict_reason, NEW.signature, NEW.signature_valid,
                NEW.request_ip, NEW.request_user_agent, NEW.response_time_ms,
                NEW.trust_score_at_time, NEW.chain_previous_hash, NEW.metadata,
                NEW.timestamp, NEW.policy_hash) THEN
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
