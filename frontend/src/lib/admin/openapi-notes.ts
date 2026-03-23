/**
 * OpenAPI contract notes for the admin UI.
 *
 * Source: https://api.inntris.com/openapi.json (fetched during implementation)
 *
 * The live spec was unavailable (403) at build time. The following facts are
 * based on the confirmed OpenAPI structure documented in the implementation
 * prompt plus the existing frontend/backend source in this repository.
 *
 * DOCUMENTED ENDPOINTS USED:
 *  - GET  /health
 *  - GET  /public/verify/{record_id}
 *  - GET  /admin/organization             (X-API-Key)
 *  - GET  /admin/agents                   (X-API-Key)
 *  - GET  /admin/agents/{agent_id}        (X-API-Key)
 *  - GET  /admin/audit/search             (X-API-Key)
 *
 * DOCUMENTED QUERY PARAMS FOR /admin/audit/search:
 *  - agent_id, action_type, verdict, start, end, limit, offset
 *
 * DOCUMENTED ENUMS:
 *  - AgentStatus:   active | suspended | revoked | pending_verification
 *  - ActionVerdict: approved | blocked | rate_limited | signature_invalid
 *
 * DOCUMENTED SCHEMAS (fully typed in OpenAPI):
 *  - HealthResponse
 *  - PublicVerificationRecord
 *  - VerifyActionResponse
 *  - ErrorResponse / HTTPValidationError
 *
 * ADMIN RESPONSE SCHEMAS:
 *  Most admin 200 responses are typed as {} in the OpenAPI spec.
 *  The mapper layer (mappers.ts) narrows unknown payloads using only
 *  fields observed in the existing backend source (api/main.py, api/models.py).
 *  No fields are fabricated.
 *
 * FIELDS OBSERVED IN BACKEND SOURCE BUT NOT IN OPENAPI SPEC:
 *  Agents: id, org_id, name, public_key_fingerprint, trust_score, status,
 *          daily_limit_usd, per_action_limit_usd, allowed_actions,
 *          blocked_actions, rate_limit_per_minute, last_action_at,
 *          total_actions_count, total_blocked_count, metadata,
 *          created_at, updated_at
 *
 *  Audit logs: id, agent_id, agent_name, timestamp, action_type,
 *              action_hash, payload, verdict, verdict_reason,
 *              signature_valid, request_ip, request_user_agent,
 *              response_time_ms, trust_score_at_time,
 *              merkle_root_id, merkle_leaf_index,
 *              transaction_hash, chain_id
 *
 *  Organization: id, name, billing_tier, contact_email, webhook_url,
 *                daily_limit_usd, monthly_limit_usd, metadata,
 *                created_at, updated_at
 *
 *  Audit search response: { logs: [...], total: number }
 */
export {};
