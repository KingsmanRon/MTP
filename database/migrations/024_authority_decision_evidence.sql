-- =============================================================================
-- 024 — Erasure-safe authority decision evidence
-- =============================================================================
-- Phase 4 records every authority decision, ALLOW and BLOCK alike, and
-- reconstructs the signed v3 decision event from that record.
--
-- Why that is not sufficient on its own
-- ------------------------------------
-- app.erase_personal_data is DELIBERATELY authorised to replace
-- audit_logs.payload and audit_logs.metadata with an erasure tombstone. That
-- is correct behaviour and must not be weakened. But it means audit_logs.payload
-- is not an immutable source: a legitimate GDPR/CCPA erasure would silently turn
-- a previously valid, previously quoted forensic authority event into one that
-- cannot be reconstructed at all.
--
-- Two legitimate requirements collide, so they get two homes:
--
--   audit_logs                    the request record, erasable on demand
--   authority_decision_evidence   the authority commitment, forensic and kept
--
-- What goes in here, and what deliberately does not
-- -------------------------------------------------
-- Only the canonical decision body: identifiers, digests, the decision, its
-- typed reasons, and the policy/authority commitments. NO raw action payload,
-- no amounts, no recipients, no IP address, no user agent -- none of the content
-- erasure exists to remove is retained here.
--
-- The act itself appears only as execution_action_hash. That is a
-- cryptographic commitment to the act, not a description of it: it is what
-- lets a later claim about the act be checked against what was decided.
-- Stating it precisely, without overclaiming: a commitment binds, and the
-- strength of any given commitment against a party who can guess candidate
-- inputs is a property of the input space, not something this table asserts.
-- What this table does assert is narrower and checkable: no raw action
-- payload, recipient or amount is stored in it.
--
-- Append-only for real: UPDATE and DELETE are refused by trigger, so this table
-- cannot become a second, quietly editable version of history.
--
-- RELEASE GATE: like 0019, this migration is written on an undeployed draft
-- branch. railway.json, railway.worker.json and Dockerfile all run
-- `alembic upgrade head` on deploy, so merging it to the deployment branch
-- migrates production. It is a Phase-7A release migration gate, exactly as
-- 023 is, and must not reach production before then.
-- =============================================================================

CREATE TABLE IF NOT EXISTS authority_decision_evidence (
    -- One row per decision, keyed by the decision it describes. RESTRICT so
    -- the evidence cannot be orphaned by removing the audit row.
    audit_log_id UUID PRIMARY KEY
        REFERENCES audit_logs(id) ON DELETE RESTRICT,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    -- The decision instant, copied from audit_logs.timestamp at write time so
    -- the v3 event's recorded_at survives independently of that row.
    recorded_at TIMESTAMPTZ NOT NULL,
    -- The exact canonical v3 decision body. Stored, not re-derived, so the
    -- historical event stays byte-identical even if the builder changes.
    decision_body JSONB NOT NULL,
    -- Sandbox provenance travels with the evidence: a sandbox decision must
    -- stay classified as test activity wherever it is read from.
    sandbox BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_authority_decision_evidence_agent
    ON authority_decision_evidence (agent_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_authority_decision_evidence_org
    ON authority_decision_evidence (org_id);

-- --- Append-only, enforced ---------------------------------------------------
CREATE OR REPLACE FUNCTION prevent_authority_decision_evidence_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION
        'SECURITY VIOLATION: authority decision evidence is append-only. It is '
        'the forensic record that a decision was made; editing or deleting it '
        'would destroy the evidence a published receipt refers to.'
        USING ERRCODE = '42501';
END;
$$;

DROP TRIGGER IF EXISTS protect_authority_decision_evidence_update
    ON authority_decision_evidence;
CREATE TRIGGER protect_authority_decision_evidence_update
    BEFORE UPDATE ON authority_decision_evidence
    FOR EACH ROW
    EXECUTE FUNCTION prevent_authority_decision_evidence_modification();

DROP TRIGGER IF EXISTS protect_authority_decision_evidence_delete
    ON authority_decision_evidence;
CREATE TRIGGER protect_authority_decision_evidence_delete
    BEFORE DELETE ON authority_decision_evidence
    FOR EACH ROW
    EXECUTE FUNCTION prevent_authority_decision_evidence_modification();

-- --- Tenant isolation, matching the posture of 021/023 -----------------------
ALTER TABLE authority_decision_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_decision_evidence FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS authority_decision_evidence_tenant_scope
    ON authority_decision_evidence;
-- Keyed on the row's own org_id, matching execution_authority_grants: the same
-- predicate without a subquery an attacker could hope to influence.
CREATE POLICY authority_decision_evidence_tenant_scope
    ON authority_decision_evidence
    FOR ALL
    TO inntris_api
    USING (org_id = app.current_tenant())
    WITH CHECK (org_id = app.current_tenant());

REVOKE ALL ON TABLE authority_decision_evidence FROM PUBLIC;
-- No UPDATE and no DELETE: the triggers refuse them anyway, and a privilege
-- nobody needs is a privilege nobody should hold.
GRANT SELECT, INSERT ON authority_decision_evidence TO inntris_api;
GRANT SELECT, INSERT ON authority_decision_evidence TO inntris_worker;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON TABLE authority_decision_evidence FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON TABLE authority_decision_evidence FROM authenticated';
    END IF;
END;
$$;

-- --- Drift guard, same shape as 020/023 --------------------------------------
DO $$
DECLARE
    rls_on BOOLEAN;
    rls_forced BOOLEAN;
    leaked_grant BOOLEAN;
BEGIN
    SELECT c.relrowsecurity, c.relforcerowsecurity
      INTO rls_on, rls_forced
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = 'authority_decision_evidence';

    IF rls_on IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'RLS is not enabled on public.authority_decision_evidence';
    END IF;
    IF rls_forced IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'RLS is not FORCED on public.authority_decision_evidence';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM information_schema.role_table_grants g
        WHERE g.table_schema = 'public'
          AND g.table_name = 'authority_decision_evidence'
          AND g.grantee IN ('anon', 'authenticated')
    ) INTO leaked_grant;

    IF leaked_grant THEN
        RAISE EXCEPTION
            'direct anon/authenticated privilege remains on public.authority_decision_evidence';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'authority_decision_evidence'
          AND policyname = 'authority_decision_evidence_tenant_scope'
          AND 'inntris_api' = ANY(roles)
    ) THEN
        RAISE EXCEPTION 'authority_decision_evidence_tenant_scope policy is missing';
    END IF;
END;
$$;
