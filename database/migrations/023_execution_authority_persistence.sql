-- Durable execution authority: persisted grants whose single-use claim,
-- cumulative spend capacity and idempotent retry semantics are all enforced by
-- mechanisms that already exist in this schema.
--
-- Deliberately NOT a parallel authority system:
--
--   * "has this grant been spent" is answered by approval_token_consumptions.
--     That table is already the single-use authority for approval tokens: it
--     has a primary key on token_id, a unique token_digest, a unique
--     (agent_id, execution_ref) partial index for idempotent retries, and
--     append-only triggers. A grant carries an approval_token_id, so claiming
--     the grant IS inserting that row, under the same constraints.
--   * cumulative spend capacity is held in spend_reservations, reserved
--     through the same advisory-locked increment-and-test the /verify path
--     already uses. A grant references its reservation; consuming the grant
--     flips that reservation to 'consumed' through the existing path.
--
-- This table adds only what neither of those holds: the act, the policy
-- snapshot the decision was made under, the executor binding, and the
-- issuance identity that makes issuance itself idempotent.

-- Composite ownership. A grant names both the principal and the organisation
-- it belongs to, and a composite foreign key makes it impossible for those two
-- to disagree: a grant cannot be written, or later re-pointed, at an agent that
-- belongs to a different tenant. agents.id is already unique, so this added
-- UNIQUE is a referencable projection of existing truth, not a new rule.
ALTER TABLE agents
    DROP CONSTRAINT IF EXISTS agents_id_org_unique;
ALTER TABLE agents
    ADD CONSTRAINT agents_id_org_unique UNIQUE (id, org_id);

CREATE TABLE IF NOT EXISTS execution_authority_grants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,

    -- Issuance identity. Two attempts sharing a reference are the same
    -- logical issuance; the digest decides whether they are the same request.
    issuance_ref TEXT NOT NULL,
    issuance_digest VARCHAR(64) NOT NULL,

    -- The act, under inntris-execution-action-v1. Separate from the
    -- client-signed request hash, which is carried alongside it.
    execution_action_hash VARCHAR(64) NOT NULL,
    signed_action_hash VARCHAR(64),

    -- The decision this grant was issued under. policy_revision is the cheap
    -- comparison key; policy_hash is authoritative. Consumption re-derives
    -- both from current state and refuses a grant whose policy has moved.
    policy_hash VARCHAR(64) NOT NULL,
    policy_snapshot_format TEXT NOT NULL,
    policy_revision TEXT NOT NULL,

    -- Executor binding. The digest is the binding; the reference is a label.
    executor_binding_digest VARCHAR(64) NOT NULL,
    executor_reference TEXT,

    consequence_class TEXT,
    domain TEXT NOT NULL,
    -- The action type is part of what the policy snapshot is computed over,
    -- so consumption cannot re-derive the current policy without it.
    action_type VARCHAR(100) NOT NULL,

    -- Digest of the delegated authority this grant was issued under, when one
    -- was presented. Consumption re-resolves the authority and compares: a
    -- scope that was narrowed, revoked or re-issued between the decision and
    -- the execution must not slip through the claim boundary.
    authority_scope_digest VARCHAR(64),

    -- Money held through the existing reservation mechanism.
    amount_usd DECIMAL(15, 2) NOT NULL DEFAULT 0,
    spend_reservation_id UUID REFERENCES spend_reservations(id) ON DELETE RESTRICT,

    -- The single-use claim key. Consuming the grant inserts the matching
    -- approval_token_consumptions row, so single use is enforced by that
    -- table's primary key rather than by anything invented here.
    approval_token_id TEXT NOT NULL UNIQUE,

    single_use BOOLEAN NOT NULL DEFAULT TRUE,
    status TEXT NOT NULL DEFAULT 'active',

    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- expires_at is clamped at issuance to the earliest of the configured
    -- execution-authority TTL, the delegated authority's own expiry, and any
    -- tighter trusted bound. authority_expires_at records the delegated bound
    -- that participated in that clamp, so the constraint below can enforce it.
    expires_at TIMESTAMPTZ NOT NULL,
    authority_expires_at TIMESTAMPTZ,

    -- External side-effect boundary. Authority persistence owns this state;
    -- rail settlement does not live in Core. The critical rule is encoded in
    -- the CHECK below: an unknown outcome never releases reserved spend.
    outcome_state TEXT NOT NULL DEFAULT 'pending',
    outcome_reference TEXT,
    outcome_recorded_at TIMESTAMPTZ,
    outcome_detail TEXT,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    execution_ref TEXT,
    consumption_audit_id UUID UNIQUE REFERENCES audit_logs(id) ON DELETE RESTRICT,

    CONSTRAINT execution_authority_issuance_ref_not_blank CHECK (
        BTRIM(issuance_ref) <> '' AND LENGTH(issuance_ref) <= 512
    ),
    CONSTRAINT execution_authority_issuance_digest_format CHECK (
        issuance_digest ~ '^[a-f0-9]{64}$'
    ),
    CONSTRAINT execution_authority_action_hash_format CHECK (
        execution_action_hash ~ '^[a-f0-9]{64}$'
    ),
    CONSTRAINT execution_authority_signed_hash_format CHECK (
        signed_action_hash IS NULL OR signed_action_hash ~ '^[a-f0-9]{64}$'
    ),
    CONSTRAINT execution_authority_policy_hash_format CHECK (
        policy_hash ~ '^[a-f0-9]{64}$'
    ),
    CONSTRAINT execution_authority_binding_digest_format CHECK (
        executor_binding_digest ~ '^[a-f0-9]{64}$'
    ),
    CONSTRAINT execution_authority_scope_digest_format CHECK (
        authority_scope_digest IS NULL OR authority_scope_digest ~ '^[a-f0-9]{64}$'
    ),
    CONSTRAINT execution_authority_token_not_blank CHECK (
        BTRIM(approval_token_id) <> ''
    ),
    CONSTRAINT execution_authority_action_type_not_blank CHECK (
        BTRIM(action_type) <> ''
    ),
    -- The ownership pair must be one the agents table actually asserts.
    CONSTRAINT execution_authority_owner_fk FOREIGN KEY (agent_id, org_id)
        REFERENCES agents(id, org_id) ON DELETE RESTRICT,
    CONSTRAINT execution_authority_execution_ref_not_blank CHECK (
        execution_ref IS NULL
        OR (BTRIM(execution_ref) <> '' AND LENGTH(execution_ref) <= 512)
    ),
    CONSTRAINT execution_authority_amount_nonnegative CHECK (amount_usd >= 0),
    -- v0.5 is single-use only. There is deliberately no max_consumptions: a
    -- counter would invite a policy that quietly permits several executions
    -- from one decision.
    CONSTRAINT execution_authority_single_use_only CHECK (single_use),
    CONSTRAINT execution_authority_window_ordered CHECK (expires_at > issued_at),
    -- A grant may never outlive the delegated authority it rests on.
    CONSTRAINT execution_authority_within_delegated_validity CHECK (
        authority_expires_at IS NULL OR expires_at <= authority_expires_at
    ),
    CONSTRAINT execution_authority_outcome_state_valid CHECK (
        outcome_state IN ('pending', 'succeeded', 'failed_final', 'outcome_unknown')
    ),
    CONSTRAINT execution_authority_outcome_recorded CHECK (
        (outcome_state = 'pending' AND outcome_recorded_at IS NULL)
        OR (outcome_state <> 'pending' AND outcome_recorded_at IS NOT NULL)
    ),
    -- An outcome only exists for authority that was actually spent.
    CONSTRAINT execution_authority_outcome_requires_consumption CHECK (
        outcome_state = 'pending' OR status = 'consumed'
    ),
    CONSTRAINT execution_authority_status_valid CHECK (
        status IN ('active', 'consumed', 'revoked', 'expired')
    ),
    CONSTRAINT execution_authority_state_timestamps CHECK (
        (status = 'active' AND consumed_at IS NULL AND revoked_at IS NULL)
        OR (
            status = 'consumed'
            AND consumed_at IS NOT NULL
            AND revoked_at IS NULL
            AND consumption_audit_id IS NOT NULL
        )
        OR (status = 'revoked' AND revoked_at IS NOT NULL AND consumed_at IS NULL)
        OR (status = 'expired' AND consumed_at IS NULL AND revoked_at IS NULL)
    )
);

-- Issuance idempotency. Two attempts with the same reference are one logical
-- grant; whether they are the same *request* is decided by comparing digests.
CREATE UNIQUE INDEX IF NOT EXISTS uq_execution_authority_grants_issuance
    ON execution_authority_grants(agent_id, issuance_ref);

CREATE INDEX IF NOT EXISTS idx_execution_authority_grants_agent_time
    ON execution_authority_grants(agent_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_execution_authority_grants_active_expiry
    ON execution_authority_grants(expires_at)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_execution_authority_grants_action
    ON execution_authority_grants(agent_id, execution_action_hash);

COMMENT ON TABLE execution_authority_grants IS
    'Bounded single-use authority to perform one specific act. Single use is enforced by approval_token_consumptions; cumulative spend capacity by spend_reservations.';
COMMENT ON COLUMN execution_authority_grants.approval_token_id IS
    'Claim key into approval_token_consumptions, which is the authority for whether this grant has been spent.';
COMMENT ON COLUMN execution_authority_grants.policy_revision IS
    'Cheap change-detection key. policy_hash is authoritative; consumption re-derives both from current state.';
COMMENT ON COLUMN execution_authority_grants.authority_scope_digest IS
    'Delegated authority identity and scope at issuance. Re-checked at consumption so a changed delegation cannot be spent under the old decision.';
COMMENT ON COLUMN execution_authority_grants.issuance_digest IS
    'Digest of the issuance material. A reused issuance_ref carrying different material is a conflict, not a retry.';

-- ---------------------------------------------------------------------------
-- Lifecycle guard
-- ---------------------------------------------------------------------------
-- The Phase-1 state model in the database, not only in application code:
-- ACTIVE may become CONSUMED, REVOKED or EXPIRED; those three are terminal for
-- new execution and nothing leaves them. The act, the policy binding, the
-- executor binding, the claim key and the reserved amount are immutable for
-- the life of the grant -- a grant whose act could be edited after issuance
-- would authorise something nobody decided on.

CREATE OR REPLACE FUNCTION enforce_execution_authority_transition()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status <> 'active' AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION
            'execution authority grant % is % and cannot transition to %',
            OLD.id, OLD.status, NEW.status;
    END IF;

    IF NEW.status NOT IN ('active', 'consumed', 'revoked', 'expired') THEN
        RAISE EXCEPTION 'unknown execution authority status %', NEW.status;
    END IF;

    -- Outcome transitions. An outcome may be recorded once from 'pending', and
    -- an 'outcome_unknown' may later be RESOLVED by authoritative evidence into
    -- 'succeeded' or 'failed_final'. Nothing returns to 'pending': a timeout is
    -- not proof that no side effect occurred, so an unknown outcome is never
    -- quietly cleared and never releases the spend it reserved.
    IF OLD.outcome_state <> NEW.outcome_state THEN
        IF OLD.outcome_state = 'pending' THEN
            NULL;
        ELSIF OLD.outcome_state = 'outcome_unknown'
              AND NEW.outcome_state IN ('succeeded', 'failed_final') THEN
            NULL;
        ELSE
            RAISE EXCEPTION
                'execution authority outcome % cannot transition to %',
                OLD.outcome_state, NEW.outcome_state;
        END IF;
    END IF;

    -- Everything decided at issuance is immutable for the life of the grant.
    -- A grant whose act, policy binding, executor binding, claim key, reserved
    -- amount or validity window could be edited afterwards would authorise
    -- something nobody decided on.
    IF NEW.id <> OLD.id
       OR NEW.agent_id <> OLD.agent_id
       OR NEW.org_id <> OLD.org_id
       OR NEW.expires_at <> OLD.expires_at
       OR NEW.authority_expires_at IS DISTINCT FROM OLD.authority_expires_at
       OR NEW.issuance_ref <> OLD.issuance_ref
       OR NEW.issuance_digest <> OLD.issuance_digest
       OR NEW.execution_action_hash <> OLD.execution_action_hash
       OR NEW.policy_hash <> OLD.policy_hash
       OR NEW.policy_snapshot_format <> OLD.policy_snapshot_format
       OR NEW.policy_revision <> OLD.policy_revision
       OR NEW.executor_binding_digest <> OLD.executor_binding_digest
       OR NEW.executor_reference IS DISTINCT FROM OLD.executor_reference
       OR NEW.consequence_class IS DISTINCT FROM OLD.consequence_class
       OR NEW.spend_reservation_id IS DISTINCT FROM OLD.spend_reservation_id
       OR NEW.approval_token_id <> OLD.approval_token_id
       OR NEW.amount_usd <> OLD.amount_usd
       OR NEW.issued_at <> OLD.issued_at
       OR NEW.single_use <> OLD.single_use
       OR NEW.signed_action_hash IS DISTINCT FROM OLD.signed_action_hash
       OR NEW.authority_scope_digest IS DISTINCT FROM OLD.authority_scope_digest
       OR NEW.action_type <> OLD.action_type
       OR NEW.domain <> OLD.domain
    THEN
        RAISE EXCEPTION
            'execution authority grant % is immutable except for its lifecycle state',
            OLD.id;
    END IF;

    -- Lifecycle evidence is write-once. Once a consumption or revocation has
    -- been recorded, the record of WHAT happened cannot be rewritten -- only
    -- set, once, at the moment of the transition.
    IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
        RAISE EXCEPTION 'consumed_at is write-once on grant %', OLD.id;
    END IF;
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'revoked_at is write-once on grant %', OLD.id;
    END IF;
    IF OLD.revocation_reason IS NOT NULL
       AND NEW.revocation_reason IS DISTINCT FROM OLD.revocation_reason THEN
        RAISE EXCEPTION 'revocation_reason is write-once on grant %', OLD.id;
    END IF;
    IF OLD.execution_ref IS NOT NULL AND NEW.execution_ref IS DISTINCT FROM OLD.execution_ref THEN
        RAISE EXCEPTION 'execution_ref is write-once on grant %', OLD.id;
    END IF;
    IF OLD.consumption_audit_id IS NOT NULL
       AND NEW.consumption_audit_id IS DISTINCT FROM OLD.consumption_audit_id THEN
        RAISE EXCEPTION 'consumption_audit_id is write-once on grant %', OLD.id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, public;

DROP TRIGGER IF EXISTS protect_execution_authority_transition
    ON execution_authority_grants;
CREATE TRIGGER protect_execution_authority_transition
    BEFORE UPDATE ON execution_authority_grants
    FOR EACH ROW EXECUTE FUNCTION enforce_execution_authority_transition();

DROP TRIGGER IF EXISTS protect_execution_authority_delete
    ON execution_authority_grants;
CREATE TRIGGER protect_execution_authority_delete
    BEFORE DELETE ON execution_authority_grants
    FOR EACH ROW EXECUTE FUNCTION prevent_security_state_modification();

-- ---------------------------------------------------------------------------
-- Tenant isolation
-- ---------------------------------------------------------------------------

ALTER TABLE execution_authority_grants ENABLE ROW LEVEL SECURITY;
-- Migration 021 forced RLS on every public table that existed then; this table
-- did not. Match that posture rather than becoming the one table where the
-- owner exemption still applies.
ALTER TABLE execution_authority_grants FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS execution_authority_grants_tenant_scope
    ON execution_authority_grants;
-- Keyed on the grant's own org_id rather than a join. The composite foreign
-- key above guarantees that column equals the agent's owner, so this is the
-- same predicate without a subquery an attacker could hope to influence.
CREATE POLICY execution_authority_grants_tenant_scope
    ON execution_authority_grants
    FOR ALL
    TO inntris_api
    USING (org_id = app.current_tenant())
    WITH CHECK (org_id = app.current_tenant());

REVOKE ALL ON TABLE execution_authority_grants FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON execution_authority_grants TO inntris_api;
GRANT SELECT, INSERT, UPDATE ON execution_authority_grants TO inntris_worker;

-- Supabase defines anon/authenticated; a plain PostgreSQL database does not.
-- Guard the REVOKE so the same migration tree stays portable, matching the
-- convention established in 020_rls_hardening.sql.
DO $$
DECLARE
    client_role TEXT;
BEGIN
    FOREACH client_role IN ARRAY ARRAY['anon', 'authenticated']
    LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = client_role) THEN
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE public.execution_authority_grants FROM %I',
                client_role
            );
        END IF;
    END LOOP;
END;
$$;

-- Drift guard, same shape as 020. Execution authority is a security-sensitive
-- table: refuse to finish the migration if it lands without RLS, or with a
-- direct browser-role privilege on it.
DO $$
DECLARE
    rls_on BOOLEAN;
    leaked_grant BOOLEAN;
BEGIN
    SELECT c.relrowsecurity INTO rls_on
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = 'execution_authority_grants';

    IF rls_on IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'RLS is not enabled on public.execution_authority_grants';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM information_schema.role_table_grants g
        WHERE g.table_schema = 'public'
          AND g.table_name = 'execution_authority_grants'
          AND g.grantee IN ('anon', 'authenticated')
    ) INTO leaked_grant;

    IF leaked_grant THEN
        RAISE EXCEPTION
            'direct anon/authenticated privilege remains on public.execution_authority_grants';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'execution_authority_grants'
          AND policyname = 'execution_authority_grants_tenant_scope'
          AND 'inntris_api' = ANY(roles)
    ) THEN
        RAISE EXCEPTION 'execution_authority_grants_tenant_scope policy is missing';
    END IF;
END;
$$;
