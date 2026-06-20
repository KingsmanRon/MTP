// =============================================================================
// Admin UI types — grounded in OpenAPI-documented schemas
// =============================================================================

// Documented enums from OpenAPI
export type AgentStatus = "active" | "suspended" | "revoked" | "pending_verification";
export type ActionVerdict = "approved" | "blocked" | "rate_limited" | "signature_invalid";

// Documented schemas — exact fields from OpenAPI spec
export interface HealthResponse {
  status: string;
  version: string;
  database: string;
  redis: string;
  timestamp: string; // date-time
}

export interface PublicVerificationRecord {
  audit_id: string;
  timestamp: string;
  verdict: ActionVerdict;
  verdict_reason: string | null;
  action_type: string;
  agent_id: string;
  agent_name: string;
  organization_name: string;
  trust_score: number;
  risk_level: string | null;
  violations: string[];
  action_hash: string;
  signature_valid: boolean;
  merkle_root: string | null;
  tx_hash: string | null;
  block_number: number | null;
  chain_id: number;
  anchored_at: string | null;
}

export interface VerifyActionResponse {
  verdict: ActionVerdict;
  verdict_reason: string;
  approval_token: string | null;
  trust_score: number;
  audit_id: string;
  timestamp: string;
  limits_remaining?: Record<string, unknown>;
}

export interface ErrorResponse {
  error?: string;
  message?: string;
  detail?: string | Array<{ loc: unknown[]; msg: string; type: string }>;
  details?: string;
  request_id?: string;
}

export interface HTTPValidationError {
  detail: Array<{
    loc: (string | number)[];
    msg: string;
    type: string;
  }>;
}

// =============================================================================
// Admin query params — documented in OpenAPI
// =============================================================================

export interface AuditSearchParams {
  agent_id?: string;
  action_type?: string;
  verdict?: ActionVerdict;
  start?: string; // ISO date-time
  end?: string;   // ISO date-time
  limit?: number;
  offset?: number;
}

// =============================================================================
// Mapped admin types — narrowed from unknown runtime payloads
// These represent the minimum UI-safe shape after mapping.
// Fields are optional because admin response schemas are untyped in OpenAPI.
// =============================================================================

export interface MappedAgent {
  id: string;
  name?: string;
  status?: AgentStatus;
  org_id?: string;
  public_key_fingerprint?: string;
  trust_score?: number;
  total_actions_count?: number;
  total_blocked_count?: number;
  last_action_at?: string | null;
  created_at?: string;
  updated_at?: string;
  daily_limit_usd?: number;
  per_action_limit_usd?: number;
  rate_limit_per_minute?: number;
  allowed_actions?: string[];
  blocked_actions?: string[];
  metadata?: Record<string, unknown>;
}

export interface MappedAuditLog {
  id: string;
  agent_id?: string;
  agent_name?: string;
  timestamp?: string;
  action_type?: string;
  action_hash?: string;
  verdict?: ActionVerdict;
  verdict_reason?: string | null;
  signature_valid?: boolean;
  trust_score_at_time?: number;
  risk_level?: string | null;
  violations?: string[];
  merkle_root_id?: string | null;
  transaction_hash?: string | null;
  chain_id?: number | null;
  response_time_ms?: number | null;
  policy_hash?: string | null;
}

export interface MappedAuditSearchResult {
  logs: MappedAuditLog[];
  total: number;
}

export interface MappedOrganization {
  id?: string;
  name?: string;
  billing_tier?: string;
  contact_email?: string;
  created_at?: string;
}

export interface MappedAuditDetail {
  id: string;
  agent_id?: string;
  agent_name?: string;
  timestamp?: string;
  action_type?: string;
  action_hash?: string;
  payload?: Record<string, unknown> | null;
  verdict?: ActionVerdict;
  verdict_reason?: string | null;
  signature_valid?: boolean;
  trust_score_at_time?: number;
  policy_rule_triggered?: string | null;
  risk_level?: string | null;
  violations?: string[];
  merkle_root_id?: string | null;
  merkle_leaf_index?: number | null;
  response_time_ms?: number | null;
  policy_hash?: string | null;
  metadata?: Record<string, unknown> | null;
}

export interface MappedAuditProof {
  leaf?: string | null;
  proof?: string[];
  positions?: boolean[];
  merkle_root?: string | null;
  tx_hash?: string | null;
  block_number?: number | null;
  anchored_at?: string | null;
  chain_id?: number | null;
  basescan_url?: string | null;
  signature_valid?: boolean | null;
}
