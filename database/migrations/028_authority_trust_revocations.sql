-- =============================================================================
-- 028 — Revocation of issuers, issuer keys, delegate keys and delegations
-- =============================================================================
-- Phase 7A, Gate 3 and Gate 8.
--
-- Trusted issuer material is configured (api/trust/issuer_registry.py) so that
-- it is reviewable in the deployment rather than silently mutable at runtime.
-- Revocation cannot work that way. When an issuer key is compromised at 03:00
-- the answer must change in seconds, and "open a pull request, get a review,
-- wait for a deploy" is not seconds.
--
-- So: trust is configured, distrust is data. A row here overrides the
-- configuration and can never be overridden by it.
--
-- The read is on the delegated-authority path and FAILS CLOSED: if Core
-- cannot establish that an issuer, key or delegation is still live, it does
-- not accept new delegated authority. That is the only safe direction —
-- "we could not check whether this was revoked" and "this was not revoked"
-- are different facts, and treating the first as the second is how a
-- revoked key keeps working.
--
-- Consumption of authority ALREADY issued is deliberately a separate
-- question, answered by the grant's own lifecycle in migration 023.
--
-- RELEASE GATE: the table is new, so the ACCESS EXCLUSIVE lock is on an
-- empty relation. No existing table is rewritten.
-- =============================================================================

CREATE TABLE IF NOT EXISTS authority_trust_revocations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- What kind of thing is being distrusted:
    --   issuer              -- everything this issuer ever signed
    --   issuer_key          -- one signing key, by fingerprint
    --   delegate_key        -- one delegate key, by fingerprint
    --   authority_reference -- one specific delegation, by the issuer's id for it
    subject_type VARCHAR(32) NOT NULL,
    subject_id TEXT NOT NULL,
    -- Scopes a key or reference to the issuer that named it. Two issuers may
    -- legitimately use the same external reference id for different things.
    -- NULL only for subject_type = 'issuer', where the subject IS the issuer.
    issuer TEXT,
    revoked BOOLEAN NOT NULL,
    reason TEXT NOT NULL,
    changed_by VARCHAR(255) NOT NULL,
    approval_reference VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scope_key TEXT GENERATED ALWAYS AS (
        subject_type || '|' || COALESCE(issuer, '*') || '|' || subject_id
    ) STORED,
    CONSTRAINT authority_revocation_subject_known CHECK (
        subject_type IN ('issuer', 'issuer_key', 'delegate_key', 'authority_reference')
    ),
    CONSTRAINT authority_revocation_subject_not_blank CHECK (BTRIM(subject_id) <> ''),
    CONSTRAINT authority_revocation_reason_not_blank CHECK (BTRIM(reason) <> ''),
    CONSTRAINT authority_revocation_changed_by_not_blank CHECK (BTRIM(changed_by) <> ''),
    CONSTRAINT authority_revocation_approval_not_blank
        CHECK (BTRIM(approval_reference) <> ''),
    -- An issuer revocation names no separate issuer column; everything else
    -- must, so a key fingerprint revoked for one issuer cannot silently
    -- distrust an identical fingerprint configured for another.
    CONSTRAINT authority_revocation_issuer_scope CHECK (
        (subject_type = 'issuer' AND issuer IS NULL)
        OR (subject_type <> 'issuer' AND issuer IS NOT NULL AND BTRIM(issuer) <> '')
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_authority_trust_revocations_scope
    ON authority_trust_revocations (scope_key);

-- The hot path asks one question: "of these few subjects, which are revoked".
CREATE INDEX IF NOT EXISTS idx_authority_trust_revocations_live
    ON authority_trust_revocations (subject_type, subject_id)
    WHERE revoked;

COMMENT ON TABLE authority_trust_revocations IS
    'Runtime distrust of issuers, keys and delegations. Overrides configured trust; never overridden by it.';

-- --- Row level security ---------------------------------------------------
-- Revocation is platform trust state, not tenant data: it is not scoped to an
-- organisation and a tenant session has no business reading or writing it.
-- RLS is enabled with NO tenant policy, which denies inntris_api outright,
-- rather than left off — an unprotected public table is exactly what the
-- migration 020 drift guard exists to catch.
ALTER TABLE authority_trust_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_trust_revocations FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE authority_trust_revocations FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON authority_trust_revocations TO inntris_worker;

DO $$
DECLARE
    client_role TEXT;
BEGIN
    FOREACH client_role IN ARRAY ARRAY['anon', 'authenticated']
    LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = client_role) THEN
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE public.authority_trust_revocations FROM %I',
                client_role
            );
        END IF;
    END LOOP;
END;
$$;

-- --- Drift guard ----------------------------------------------------------
DO $$
DECLARE
    v_rls BOOLEAN;
    v_forced BOOLEAN;
    v_accepted BOOLEAN;
BEGIN
    SELECT c.relrowsecurity, c.relforcerowsecurity INTO v_rls, v_forced
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relname = 'authority_trust_revocations';
    IF v_rls IS DISTINCT FROM TRUE OR v_forced IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION
            'migration 028 drift: authority_trust_revocations must have RLS enabled and forced';
    END IF;

    -- 1. A non-issuer subject must name its issuer, so one issuer's
    --    revocation cannot distrust another issuer's identical fingerprint.
    BEGIN
        INSERT INTO authority_trust_revocations (
            subject_type, subject_id, issuer, revoked, reason, changed_by,
            approval_reference
        ) VALUES ('issuer_key', repeat('a', 64), NULL, TRUE, 'guard', 'guard', 'guard');
        v_accepted := TRUE;
    EXCEPTION WHEN check_violation THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION
            'migration 028 drift: a key revocation was accepted without an issuer';
    END IF;

    -- 2. An issuer revocation must NOT also name an issuer column, so there
    --    is exactly one spelling of "distrust this issuer".
    BEGIN
        INSERT INTO authority_trust_revocations (
            subject_type, subject_id, issuer, revoked, reason, changed_by,
            approval_reference
        ) VALUES ('issuer', 'guard-issuer', 'guard-issuer', TRUE, 'guard', 'guard', 'guard');
        v_accepted := TRUE;
    EXCEPTION WHEN check_violation THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION
            'migration 028 drift: an issuer revocation was accepted with a redundant issuer column';
    END IF;

    -- 3. The same subject cannot hold two contradictory answers.
    INSERT INTO authority_trust_revocations (
        subject_type, subject_id, issuer, revoked, reason, changed_by,
        approval_reference
    ) VALUES ('issuer_key', repeat('b', 64), 'guard-issuer', TRUE, 'guard', 'guard', 'guard');
    BEGIN
        INSERT INTO authority_trust_revocations (
            subject_type, subject_id, issuer, revoked, reason, changed_by,
            approval_reference
        ) VALUES ('issuer_key', repeat('b', 64), 'guard-issuer', FALSE, 'guard', 'guard', 'guard');
        v_accepted := TRUE;
    EXCEPTION WHEN unique_violation THEN
        v_accepted := FALSE;
    END;
    IF v_accepted THEN
        RAISE EXCEPTION
            'migration 028 drift: two contradictory revocation rows for one subject were accepted';
    END IF;

    -- 4. The same fingerprint under a DIFFERENT issuer is a different subject.
    INSERT INTO authority_trust_revocations (
        subject_type, subject_id, issuer, revoked, reason, changed_by,
        approval_reference
    ) VALUES ('issuer_key', repeat('b', 64), 'other-guard-issuer', TRUE, 'guard', 'guard', 'guard');

    DELETE FROM authority_trust_revocations WHERE changed_by = 'guard';
END;
$$;
