-- Gate 1: a production-SHAPED staging database at 0018_merkle_anchor_visibility.
-- The cardinality is SYNTHETIC. It is chosen to expose index and constraint
-- lock cost on the tables migrations 023/025/031 actually touch; it is NOT
-- measured production volume and must never be reported as such.
\set ON_ERROR_STOP on
\timing off

-- --- organisations -------------------------------------------------------
INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash,
                           daily_limit_usd, monthly_limit_usd, metadata, created_at)
SELECT gen_random_uuid(),
       'stage-org-' || g,
       (ARRAY['free','starter','professional','enterprise']::billing_tier[])[1 + (g % 4)],
       'org-' || g || '@stage.invalid',
       sha256(('org' || g)::BYTEA),
       50000, 1000000,
       jsonb_build_object('seeded', TRUE, 'cohort', g % 5),
       NOW() - (g || ' days')::INTERVAL
FROM generate_series(1, 25) g;

-- --- principals ----------------------------------------------------------
-- Active, inactive and suspended, spread across every organisation.
INSERT INTO agents (id, org_id, name, public_key, public_key_fingerprint, trust_score,
                    status, daily_limit_usd, per_action_limit_usd, allowed_actions,
                    blocked_actions, rate_limit_per_minute, metadata, created_at, updated_at)
SELECT gen_random_uuid(),
       o.id,
       'stage-agent-' || o.id || ':' || s,
       gen_random_bytes(32),
       encode(sha256((o.id::TEXT || ':' || s)::BYTEA), 'hex'),
       50 + (s * 7) % 50,
       (ARRAY['active','active','active','suspended','revoked']::agent_status[])[1 + (s % 5)],
       10000, 5000,
       ARRAY['financial_transaction','wallet_transaction']::TEXT[],
       ARRAY[]::TEXT[],
       1000,
       jsonb_build_object('sandbox', FALSE,
                          'production_approval_reference', 'stage-seed',
                          'production_approved_at', '2026-01-01T00:00:00Z',
                          'production_approved_by', 'stage-seed'),
       NOW() - (s || ' hours')::INTERVAL, NOW()
FROM organizations o CROSS JOIN generate_series(1, 20) s
WHERE o.name LIKE 'stage-org-%';

-- --- api keys and policies (realistic auxiliary rows) --------------------
INSERT INTO api_keys (id, org_id, key_hash, key_prefix, name, scopes, is_active, created_at)
SELECT gen_random_uuid(), o.id, sha256((o.id::TEXT || ':' || k)::BYTEA),
       substr(md5(o.id::TEXT || ':' || k), 1, 8), 'key-' || k,
       ARRAY['verify','read']::TEXT[], (k % 4) <> 0, NOW()
FROM organizations o CROSS JOIN generate_series(1, 3) k
WHERE o.name LIKE 'stage-org-%';

INSERT INTO agent_policies (id, agent_id, policy_hash, mapping, protected_branches,
                            version, active, registered_by, created_at)
SELECT gen_random_uuid(), a.id, encode(sha256(a.id::TEXT::BYTEA), 'hex'),
       '{"rules": []}'::JSONB, '["main"]'::JSONB, 1, TRUE, 'stage-seed', NOW()
FROM agents a WHERE a.name LIKE 'stage-agent-%';

-- --- historical audit records -------------------------------------------
-- Bulk loaded with triggers suppressed, then the forensic chain is computed
-- exactly as assign_audit_chain_sequence() would have: chain_sequence is the
-- per-agent ordinal and chain_previous_hash is the preceding action_hash.
-- Running 500k rows through the BEFORE+AFTER triggers would take far longer
-- than the rehearsal and would rewrite the agents rows 500k times, which is
-- less production-shaped, not more.
SET session_replication_role = replica;

INSERT INTO audit_logs (id, agent_id, timestamp, action_type, action_hash, payload,
                        verdict, signature, signature_valid, trust_score_at_time,
                        chain_sequence, metadata)
SELECT gen_random_uuid(),
       a.id,
       NOW() - (n || ' minutes')::INTERVAL,
       (ARRAY['financial_transaction','wallet_transaction','code_commit'])[1 + (n % 3)],
       encode(sha256((a.id::TEXT || n)::BYTEA), 'hex'),
       jsonb_build_object('amount', (n % 900) + 1, 'currency', 'USD', 'seq', n),
       (ARRAY['approved','blocked','approved','approved']::action_verdict[])[1 + (n % 4)],
       gen_random_bytes(64),
       TRUE,
       60 + (n % 40),
       n,
       jsonb_build_object('seeded', TRUE)
FROM agents a CROSS JOIN generate_series(1, 1000) n
WHERE a.name LIKE 'stage-agent-%';

-- The chain link, set the way the trigger sets it.
WITH ordered AS (
    SELECT id, LAG(action_hash) OVER (PARTITION BY agent_id ORDER BY chain_sequence) AS prev
    FROM audit_logs
)
UPDATE audit_logs l SET chain_previous_hash = ordered.prev
FROM ordered WHERE ordered.id = l.id AND ordered.prev IS NOT NULL;

SET session_replication_role = origin;

-- --- consumed legacy approval tokens ------------------------------------
-- One consumption per 12th audit row: the legacy single-use record.
INSERT INTO approval_token_consumptions (token_id, token_digest, agent_id, action_hash,
                                         audit_log_id, consumed_at, execution_ref)
SELECT 'legacy-tok-' || l.id,
       substring(sha256(l.id::TEXT::BYTEA) from 1 for 32),
       l.agent_id, l.action_hash, l.id, l.timestamp,
       'legacy-exec-' || l.id
FROM audit_logs l
WHERE (('x' || substr(md5(l.id::TEXT), 1, 8))::BIT(32)::INT % 12) = 0;

-- --- merkle anchors ------------------------------------------------------
INSERT INTO merkle_proofs (id, root_hash, chain_id, contract_address, log_count,
                           start_timestamp, end_timestamp, leaf_hashes, status,
                           retry_count, created_at)
SELECT gen_random_uuid(), encode(sha256(('root' || m)::BYTEA), 'hex'), 8453,
       '0x' || substr(md5('contract'), 1, 40), 100,
       NOW() - ((m + 1) || ' hours')::INTERVAL, NOW() - (m || ' hours')::INTERVAL,
       ARRAY[encode(sha256(('leaf' || m)::BYTEA), 'hex')]::TEXT[],
       (ARRAY['pending','submitted','confirmed','confirmed'])[1 + (m % 4)],
       0, NOW() - (m || ' hours')::INTERVAL
FROM generate_series(1, 20000) m;

-- --- existing administrative audit history ------------------------------
-- These pre-date migration 031 and must survive it as organisation scope.
INSERT INTO administrative_audit_events (id, org_id, event_type, actor,
                                         approval_reference, details, created_at)
SELECT gen_random_uuid(), o.id,
       (ARRAY['agent.production_promoted','organization.webhook_secret_rotated'])[1 + (e % 2)],
       'legacy-operator-' || (e % 7),
       'LEGACY-CHG-' || e,
       jsonb_build_object('legacy', TRUE, 'n', e),
       NOW() - (e || ' minutes')::INTERVAL
FROM organizations o CROSS JOIN generate_series(1, 80) e
WHERE o.name LIKE 'stage-org-%';

ANALYZE;
