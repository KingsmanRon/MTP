-- =============================================================================
-- 025 — Authority decision evidence: make contradiction impossible
-- =============================================================================
-- 024 gave the forensic table three independent foreign keys (audit_log_id,
-- agent_id, org_id) plus a decision_body carrying the same three identities
-- again. Nothing tied any of them together. A row could therefore claim an
-- audit id belonging to one agent, an agent belonging to another
-- organisation, and a body naming a third set of identities entirely, and
-- every individual constraint would be satisfied.
--
-- Evidence whose identity fields can disagree is not evidence. This
-- migration makes each of those disagreements unrepresentable, declaratively,
-- so the guarantee holds against every writer rather than against the one
-- code path that happens to write correctly today.
--
-- What is enforced, and by what
-- -----------------------------
--   ownership pair is real          composite FK to agents(id, org_id),
--                                   reusing the agents_id_org_unique
--                                   projection Phase 3 already added
--   audit row belongs to this agent  } one composite FK to
--   audit row IS a decision row      } audit_logs(id, agent_id, action_type)
--   body identities match the row    three CHECK constraints
--
-- The audit_action_type column exists only to give that composite foreign
-- key a constant to match on; a CHECK pins it, so it cannot be used to point
-- at some other kind of audit row.
--
-- RELEASE GATE: like 0019 and 0020, this runs on an undeployed draft branch.
-- It adds a UNIQUE index on audit_logs (id, agent_id, action_type). On a
-- large production audit_logs that index build takes ACCESS EXCLUSIVE for
-- its duration -- the same class of release-gate cost as the
-- agents_id_org_unique index from Phase 3, and it is unmeasured for the same
-- reason: this branch has never run against production data. Phase 7A owns
-- measuring it and choosing a concurrent build if the lock window is too
-- long.
-- =============================================================================

-- --- The projection the composite key needs -----------------------------
-- id is already the primary key, so this unique constraint adds no new
-- uniqueness. It exists solely so (id, agent_id, action_type) can be the
-- target of a foreign key.
ALTER TABLE audit_logs
    DROP CONSTRAINT IF EXISTS audit_logs_id_agent_action_unique;
ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_id_agent_action_unique
        UNIQUE (id, agent_id, action_type);

-- --- Tie the evidence row's identities together -------------------------
ALTER TABLE authority_decision_evidence
    ADD COLUMN IF NOT EXISTS audit_action_type VARCHAR(100)
        NOT NULL DEFAULT 'authority_decision';

ALTER TABLE authority_decision_evidence
    DROP CONSTRAINT IF EXISTS authority_decision_evidence_kind_fixed;
ALTER TABLE authority_decision_evidence
    ADD CONSTRAINT authority_decision_evidence_kind_fixed
        CHECK (audit_action_type = 'authority_decision');

-- The single-column foreign keys are replaced by composite ones that carry
-- the relationships, not just the existence of each id.
ALTER TABLE authority_decision_evidence
    DROP CONSTRAINT IF EXISTS authority_decision_evidence_audit_log_id_fkey;
ALTER TABLE authority_decision_evidence
    DROP CONSTRAINT IF EXISTS authority_decision_evidence_agent_id_fkey;

ALTER TABLE authority_decision_evidence
    DROP CONSTRAINT IF EXISTS authority_decision_evidence_audit_fk;
ALTER TABLE authority_decision_evidence
    ADD CONSTRAINT authority_decision_evidence_audit_fk
        FOREIGN KEY (audit_log_id, agent_id, audit_action_type)
        REFERENCES audit_logs (id, agent_id, action_type)
        ON DELETE RESTRICT;

ALTER TABLE authority_decision_evidence
    DROP CONSTRAINT IF EXISTS authority_decision_evidence_owner_fk;
ALTER TABLE authority_decision_evidence
    ADD CONSTRAINT authority_decision_evidence_owner_fk
        FOREIGN KEY (agent_id, org_id)
        REFERENCES agents (id, org_id)
        ON DELETE RESTRICT;

-- --- The body must describe the row it is stored on ---------------------
-- Without these, the columns could be correct while the signed material
-- built from decision_body named somebody else entirely -- and the receipt
-- follows the body, not the columns.
ALTER TABLE authority_decision_evidence
    DROP CONSTRAINT IF EXISTS authority_decision_evidence_body_audit_id;
ALTER TABLE authority_decision_evidence
    ADD CONSTRAINT authority_decision_evidence_body_audit_id
        CHECK (decision_body ->> 'audit_id' = audit_log_id::TEXT);

ALTER TABLE authority_decision_evidence
    DROP CONSTRAINT IF EXISTS authority_decision_evidence_body_agent_id;
ALTER TABLE authority_decision_evidence
    ADD CONSTRAINT authority_decision_evidence_body_agent_id
        CHECK (decision_body ->> 'agent_id' = agent_id::TEXT);

ALTER TABLE authority_decision_evidence
    DROP CONSTRAINT IF EXISTS authority_decision_evidence_body_org_id;
ALTER TABLE authority_decision_evidence
    ADD CONSTRAINT authority_decision_evidence_body_org_id
        CHECK (decision_body ->> 'organisation_id' = org_id::TEXT);

-- --- Privileges: the writer is the trusted runtime role, not the tenant --
-- inntris_api is the tenant-scoped, RLS-enforced identity used for tenant
-- reads (api/tenant_database.py). The authority decision path writes as the
-- trusted runtime role, so inntris_api never needs INSERT here. Removing it
-- means a compromised tenant session cannot append forensic evidence at all,
-- rather than being stopped only by RLS predicates.
REVOKE INSERT ON TABLE authority_decision_evidence FROM inntris_api;

-- --- Drift guard --------------------------------------------------------
DO $$
DECLARE
    missing TEXT;
BEGIN
    FOREACH missing IN ARRAY ARRAY[
        'authority_decision_evidence_audit_fk',
        'authority_decision_evidence_owner_fk',
        'authority_decision_evidence_body_audit_id',
        'authority_decision_evidence_body_agent_id',
        'authority_decision_evidence_body_org_id',
        'authority_decision_evidence_kind_fixed'
    ] LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE n.nspname = 'public'
              AND t.relname = 'authority_decision_evidence'
              AND c.conname = missing
        ) THEN
            RAISE EXCEPTION 'constraint % is missing from authority_decision_evidence', missing;
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1
        FROM information_schema.role_table_grants g
        WHERE g.table_schema = 'public'
          AND g.table_name = 'authority_decision_evidence'
          AND g.grantee = 'inntris_api'
          AND g.privilege_type = 'INSERT'
    ) THEN
        RAISE EXCEPTION
            'inntris_api still holds INSERT on public.authority_decision_evidence';
    END IF;
END;
$$;
