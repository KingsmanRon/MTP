// =============================================================================
// Runtime-safe mappers for untyped admin API responses.
// Each mapper takes `unknown` and narrows to the minimum UI-safe shape.
// No fields are fabricated — if absent, they remain undefined.
// =============================================================================

import type {
  MappedAgent,
  MappedAuditLog,
  MappedAuditSearchResult,
  MappedAuditDetail,
  MappedAuditProof,
  MappedOrganization,
  AgentStatus,
  ActionVerdict,
} from "./types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function strOrNull(v: unknown): string | null | undefined {
  if (v === null) return null;
  return typeof v === "string" ? v : undefined;
}

function num(v: unknown): number | undefined {
  return typeof v === "number" ? v : undefined;
}

function numOrNull(v: unknown): number | null | undefined {
  if (v === null) return null;
  return typeof v === "number" ? v : undefined;
}

function bool(v: unknown): boolean | undefined {
  return typeof v === "boolean" ? v : undefined;
}

function strArr(v: unknown): string[] | undefined {
  if (Array.isArray(v) && v.every((x) => typeof x === "string")) return v;
  return undefined;
}

const VALID_AGENT_STATUSES = new Set<string>([
  "active",
  "suspended",
  "revoked",
  "pending_verification",
]);

function agentStatus(v: unknown): AgentStatus | undefined {
  return typeof v === "string" && VALID_AGENT_STATUSES.has(v)
    ? (v as AgentStatus)
    : undefined;
}

const VALID_VERDICTS = new Set<string>([
  "approved",
  "blocked",
  "rate_limited",
  "signature_invalid",
]);

function verdict(v: unknown): ActionVerdict | undefined {
  return typeof v === "string" && VALID_VERDICTS.has(v)
    ? (v as ActionVerdict)
    : undefined;
}

// ---------------------------------------------------------------------------
// Agent mapper
// ---------------------------------------------------------------------------

export function mapAgent(raw: unknown): MappedAgent | null {
  if (!isRecord(raw)) return null;
  const id = str(raw.id);
  if (!id) return null;
  return {
    id,
    name: str(raw.name),
    status: agentStatus(raw.status),
    org_id: str(raw.org_id),
    public_key_fingerprint: str(raw.public_key_fingerprint),
    trust_score: num(raw.trust_score),
    total_actions_count: num(raw.total_actions_count),
    total_blocked_count: num(raw.total_blocked_count),
    last_action_at: strOrNull(raw.last_action_at),
    created_at: str(raw.created_at),
    updated_at: str(raw.updated_at),
    daily_limit_usd: num(raw.daily_limit_usd),
    per_action_limit_usd: num(raw.per_action_limit_usd),
    rate_limit_per_minute: num(raw.rate_limit_per_minute),
    allowed_actions: strArr(raw.allowed_actions),
    blocked_actions: strArr(raw.blocked_actions),
    metadata: isRecord(raw.metadata) ? raw.metadata : undefined,
  };
}

export function mapAgents(raw: unknown): MappedAgent[] {
  if (Array.isArray(raw)) {
    return raw.map(mapAgent).filter((a): a is MappedAgent => a !== null);
  }
  return [];
}

// ---------------------------------------------------------------------------
// Audit log mapper
// ---------------------------------------------------------------------------

export function mapAuditLog(raw: unknown): MappedAuditLog | null {
  if (!isRecord(raw)) return null;
  const id = str(raw.id);
  if (!id) return null;
  return {
    id,
    agent_id: str(raw.agent_id),
    agent_name: str(raw.agent_name),
    timestamp: str(raw.timestamp),
    action_type: str(raw.action_type),
    action_hash: str(raw.action_hash),
    verdict: verdict(raw.verdict),
    verdict_reason: strOrNull(raw.verdict_reason),
    signature_valid: bool(raw.signature_valid),
    trust_score_at_time: num(raw.trust_score_at_time),
    risk_level: strOrNull(raw.risk_level),
    violations: strArr(raw.violations),
    merkle_root_id: strOrNull(raw.merkle_root_id),
    transaction_hash: strOrNull(raw.transaction_hash),
    chain_id: numOrNull(raw.chain_id),
    response_time_ms: numOrNull(raw.response_time_ms),
    policy_hash: strOrNull(raw.policy_hash),
  };
}

export function mapAuditSearchResult(raw: unknown): MappedAuditSearchResult {
  if (!isRecord(raw)) return { logs: [], total: 0 };
  const logs = Array.isArray(raw.logs)
    ? raw.logs.map(mapAuditLog).filter((l): l is MappedAuditLog => l !== null)
    : [];
  const total = typeof raw.total === "number" ? raw.total : logs.length;
  return { logs, total };
}

// ---------------------------------------------------------------------------
// Organization mapper
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Audit detail mapper
// ---------------------------------------------------------------------------

export function mapAuditDetail(raw: unknown): MappedAuditDetail | null {
  if (!isRecord(raw)) return null;
  const id = str(raw.id);
  if (!id) return null;
  return {
    id,
    agent_id: str(raw.agent_id),
    agent_name: str(raw.agent_name),
    timestamp: str(raw.timestamp),
    action_type: str(raw.action_type),
    action_hash: str(raw.action_hash),
    payload: isRecord(raw.payload) ? raw.payload : null,
    verdict: verdict(raw.verdict),
    verdict_reason: strOrNull(raw.verdict_reason),
    signature_valid: bool(raw.signature_valid),
    trust_score_at_time: num(raw.trust_score_at_time),
    policy_rule_triggered: strOrNull(raw.policy_rule_triggered),
    risk_level: strOrNull(raw.risk_level),
    violations: strArr(raw.violations),
    merkle_root_id: strOrNull(raw.merkle_root_id),
    merkle_leaf_index: numOrNull(raw.merkle_leaf_index) as number | null | undefined,
    response_time_ms: numOrNull(raw.response_time_ms),
    policy_hash: strOrNull(raw.policy_hash),
    metadata: isRecord(raw.metadata) ? raw.metadata : undefined,
  };
}

// ---------------------------------------------------------------------------
// Audit proof mapper
// ---------------------------------------------------------------------------

export function mapAuditProof(raw: unknown): MappedAuditProof {
  if (!isRecord(raw)) return {};
  return {
    leaf: strOrNull(raw.leaf),
    proof: strArr(raw.proof),
    positions: Array.isArray(raw.positions) && raw.positions.every((x: unknown) => typeof x === "boolean")
      ? raw.positions
      : undefined,
    merkle_root: strOrNull(raw.merkle_root),
    tx_hash: strOrNull(raw.tx_hash),
    block_number: numOrNull(raw.block_number) as number | null | undefined,
    anchored_at: strOrNull(raw.anchored_at),
    chain_id: numOrNull(raw.chain_id) as number | null | undefined,
    basescan_url: strOrNull(raw.basescan_url),
  };
}

// ---------------------------------------------------------------------------
// Organization mapper
// ---------------------------------------------------------------------------

export function mapOrganization(raw: unknown): MappedOrganization {
  if (!isRecord(raw)) return {};
  return {
    id: str(raw.id),
    name: str(raw.name),
    billing_tier: str(raw.billing_tier),
    contact_email: str(raw.contact_email),
    created_at: str(raw.created_at),
  };
}
