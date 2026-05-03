-- Migration 007: Tighten audit_logs grants for inntris_worker
--
-- Filename note: the audit spec called this migration "006" but
-- 006_gdpr_erasure.sql already exists, so this is filed as 007 to
-- preserve migration ordering.
--
-- WARNING: DO NOT APPLY TO PRODUCTION WITHOUT TESTING FIRST.
--
-- The anchor worker depends on UPDATEing merkle_root_id and merkle_leaf_index
-- on audit_logs rows during the anchor flow. This migration revokes
-- broad UPDATE/DELETE and re-grants UPDATE on only those two columns.
--
-- Test path:
--   1. Apply against a Supabase branch DB or staging environment first.
--   2. Trigger an anchor batch end-to-end.
--   3. Confirm the worker can still write merkle_root_id and merkle_leaf_index.
--   4. Confirm no other column updates from inntris_worker succeed.
--   5. Only then apply to production.
--
-- Rollback:
--   GRANT UPDATE, DELETE ON audit_logs TO inntris_worker;
--
-- Defence-in-depth note: tamper-evidence is already enforced by the
-- prevent_audit_log_modification trigger in schemas.sql. This migration
-- is belt-and-braces, narrowing the privilege surface in addition to
-- the trigger control.

REVOKE UPDATE, DELETE ON audit_logs FROM inntris_worker;
GRANT UPDATE (merkle_root_id, merkle_leaf_index) ON audit_logs TO inntris_worker;
