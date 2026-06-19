-- =============================================================================
-- MIGRATION 009: CI Guard security invariants
-- =============================================================================
-- 1. Signature alerts fire only for real signature_invalid verdicts.
-- 2. Unsigned partner attestations marked non_cryptographic do not create
--    critical Ed25519 alerts.
-- =============================================================================

CREATE OR REPLACE FUNCTION create_signature_failure_alert()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.signature_valid = FALSE
       AND NEW.verdict = 'signature_invalid'
       AND NOT COALESCE((NEW.metadata->>'non_cryptographic')::boolean, false) THEN
        INSERT INTO security_alerts (
            agent_id,
            org_id,
            alert_type,
            severity,
            title,
            description,
            evidence,
            audit_log_ids
        )
        SELECT
            NEW.agent_id,
            a.org_id,
            'SIGNATURE_VERIFICATION_FAILED',
            'critical',
            'Invalid Signature Detected - Potential Attack',
            'An action was attempted with an invalid cryptographic signature. This may indicate a compromised agent or replay attack.',
            jsonb_build_object(
                'action_type', NEW.action_type,
                'action_hash', NEW.action_hash,
                'request_ip', NEW.request_ip,
                'timestamp', NEW.timestamp
            ),
            ARRAY[NEW.id]
        FROM agents a
        WHERE a.id = NEW.agent_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS alert_on_signature_failure ON audit_logs;
CREATE TRIGGER alert_on_signature_failure
    AFTER INSERT ON audit_logs
    FOR EACH ROW
    WHEN (
        NEW.signature_valid = FALSE
        AND NEW.verdict = 'signature_invalid'
        AND NOT COALESCE((NEW.metadata->>'non_cryptographic')::boolean, false)
    )
    EXECUTE FUNCTION create_signature_failure_alert();
