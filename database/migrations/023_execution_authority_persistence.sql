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

CREATE TABLE IF NOT EXISTS execution_authority_grants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,

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
    expires_at TIMESTAMPTZ NOT NULL,
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

    IF NEW.id <> OLD.id
       OR NEW.agent_id <> OLD.agent_id
       OR NEW.issuance_ref <> OLD.issuance_ref
       OR NEW.issuance_digest <> OLD.issuance_digest
       OR NEW.execution_action_hash <> OLD.execution_action_hash
       OR NEW.policy_hash <> OLD.policy_hash
       OR NEW.executor_binding_digest <> OLD.executor_binding_digest
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

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

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

DROP POLICY IF EXISTS execution_authority_grants_tenant_scope
    ON execution_authority_grants;
CREATE POLICY execution_authority_grants_tenant_scope
    ON execution_authority_grants
    FOR ALL
    TO inntris_api
    USING (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = execution_authority_grants.agent_id
              AND a.org_id = app.current_tenant()
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM agents a
            WHERE a.id = execution_authority_grants.agent_id
              AND a.org_id = app.current_tenant()
        )
    );

REVOKE ALL ON TABLE execution_authority_grants FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON execution_authority_grants TO inntris_api;
GRANT SELECT, INSERT, UPDATE ON execution_authority_grants TO inntris_worker;
