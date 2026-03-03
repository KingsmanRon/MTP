const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// =============================================================================
// TYPES
// =============================================================================

export type AgentStatus = "active" | "suspended" | "revoked" | "pending_verification";
export type ActionVerdict = "approved" | "blocked" | "rate_limited" | "signature_invalid";
export type BillingTier = "free" | "starter" | "professional" | "enterprise";
export type AlertSeverity = "low" | "medium" | "high" | "critical";

export interface AgentPublicInfo {
  agent_id: string;
  name: string;
  organization_name: string;
  trust_score: number;
  status: AgentStatus;
  is_verified: boolean;
  verified_since: string | null;
  total_actions: number;
  last_action_at: string | null;
}

export interface AgentRecord {
  id: string;
  org_id: string;
  name: string;
  public_key_fingerprint: string;
  trust_score: number;
  status: AgentStatus;
  daily_limit_usd: number;
  per_action_limit_usd: number;
  allowed_actions: string[];
  blocked_actions: string[];
  rate_limit_per_minute: number;
  last_action_at: string | null;
  total_actions_count: number;
  total_blocked_count: number;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface OrganizationRecord {
  id: string;
  name: string;
  billing_tier: BillingTier;
  contact_email: string;
  webhook_url: string | null;
  daily_limit_usd: number;
  monthly_limit_usd: number;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface AuditLog {
  id: string;
  agent_id: string;
  agent_name?: string;
  timestamp: string;
  action_type: string;
  action_hash: string;
  payload: Record<string, unknown>;
  verdict: ActionVerdict;
  verdict_reason: string | null;
  signature_valid: boolean;
  request_ip: string | null;
  request_user_agent: string | null;
  response_time_ms: number | null;
  trust_score_at_time: number;
  // Blockchain Anchoring Fields
  merkle_root_id: string | null;
  merkle_leaf_index: number | null;
  transaction_hash?: string | null; // Added for UI linking
  chain_id?: number | null;         // Added for explorer linking
}

export interface MerkleProof {
  leaf: string;
  proof: string[];
  positions: boolean[];
  merkle_root: string;
  tx_hash: string;
  block_number: number;
  anchored_at: string;
}

export interface SecurityAlert {
  id: string;
  agent_id: string;
  agent_name?: string;
  severity: AlertSeverity;
  alert_type: string;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  acknowledged: boolean;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  resolved: boolean;
  resolved_at: string | null;
  created_at: string;
}

export interface APIKey {
  id: string;
  org_id: string;
  key_prefix: string;
  name: string;
  scopes: string[];
  is_active: boolean;
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export interface UsageMetrics {
  total_verifications: number;
  approved_count: number;
  blocked_count: number;
  total_spend_usd: number;
  active_agents: number;
  period_start: string;
  period_end: string;
  daily_breakdown: {
    date: string;
    verifications: number;
    approved: number;
    blocked: number;
    spend_usd: number;
  }[];
}

export interface HealthResponse {
  status: string;
  version: string;
  database: string;
  redis: string;
  timestamp: string;
}

export interface AgentDashboard {
  agent: {
    id: string;
    name: string;
    status: AgentStatus;
    trust_score: number;
    organization: string;
    daily_limit_usd: number;
    per_action_limit_usd: number;
    rate_limit_per_minute: number;
    total_actions_count: number;
    public_key_fingerprint: string;
  };
  daily_stats: {
    daily_spend: number;
    daily_remaining: number;
    approved_today: number;
    blocked_today: number;
  };
  trust_history: {
    date: string;
    score: number;
  }[];
  recent_activity: {
    id: string;
    action_type: string;
    verdict: ActionVerdict;
    verdict_reason: string | null;
    timestamp: string;
    payload: Record<string, unknown>;
    trust_score_at_time: number;
  }[];
}

// =============================================================================
// API CLIENT
// =============================================================================

class APIError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    public data?: unknown
  ) {
    super(`API Error: ${status} ${statusText}`);
    this.name = "APIError";
  }
}

async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_URL}${endpoint}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const data = await response.json().catch(() => null);
    throw new APIError(response.status, response.statusText, data);
  }

  return response.json();
}

// =============================================================================
// PUBLIC API (No Auth Required)
// =============================================================================

export const publicApi = {
  /**
   * Get public agent information (for trust badge)
   */
  async getAgentPublicInfo(agentId: string): Promise<AgentPublicInfo> {
    return apiRequest<AgentPublicInfo>(`/public/agent/${agentId}`);
  },

  /**
   * Health check
   */
  async health(): Promise<HealthResponse> {
    return apiRequest<HealthResponse>("/health");
  },
};

// =============================================================================
// AUTHENTICATED API
// =============================================================================

export function createAuthenticatedApi(apiKey: string) {
  const authHeaders = { "X-API-Key": apiKey };

  return {
    // =========================================================================
    // AGENTS
    // =========================================================================

    /**
     * List all agents for the organization
     */
    async listAgents(): Promise<AgentRecord[]> {
      return apiRequest<AgentRecord[]>("/admin/agents", {
        headers: authHeaders,
      });
    },

    /**
     * Get a specific agent
     */
    async getAgent(agentId: string): Promise<AgentRecord> {
      return apiRequest<AgentRecord>(`/admin/agents/${agentId}`, {
        headers: authHeaders,
      });
    },

    /**
     * Get agent dashboard data (for portal view)
     */
    async getAgentDashboard(agentId: string): Promise<AgentDashboard> {
      return apiRequest<AgentDashboard>(`/admin/agents/${agentId}/dashboard`, {
        headers: authHeaders,
      });
    },

    /**
     * Register a new agent
     */
    async registerAgent(data: {
      org_id: string;
      name: string;
      public_key: string;
      daily_limit_usd?: number;
      per_action_limit_usd?: number;
      allowed_actions?: string[];
      metadata?: Record<string, unknown>;
    }): Promise<{ agent_id: string; public_key_fingerprint: string; status: string }> {
      return apiRequest("/admin/agents", {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify(data),
      });
    },

    /**
     * Update agent configuration
     */
    async updateAgent(
      agentId: string,
      data: Partial<{
        name: string;
        daily_limit_usd: number;
        per_action_limit_usd: number;
        allowed_actions: string[];
        blocked_actions: string[];
        rate_limit_per_minute: number;
        metadata: Record<string, unknown>;
      }>
    ): Promise<AgentRecord> {
      return apiRequest<AgentRecord>(`/admin/agents/${agentId}`, {
        method: "PATCH",
        headers: authHeaders,
        body: JSON.stringify(data),
      });
    },

    /**
     * Update agent status
     */
    async updateAgentStatus(
      agentId: string,
      status: AgentStatus
    ): Promise<{ agent_id: string; status: string }> {
      return apiRequest(`/admin/agents/${agentId}/status?new_status=${status}`, {
        method: "PATCH",
        headers: authHeaders,
      });
    },

    // =========================================================================
    // AUDIT LOGS
    // =========================================================================

    /**
     * Search audit logs
     */
    async searchAuditLogs(params: {
      agent_id?: string;
      action_type?: string;
      verdict?: ActionVerdict;
      start?: string;
      end?: string;
      limit?: number;
      offset?: number;
    }): Promise<{ logs: AuditLog[]; total: number }> {
      const searchParams = new URLSearchParams();
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) searchParams.set(key, String(value));
      });
      return apiRequest(`/admin/audit/search?${searchParams}`, {
        headers: authHeaders,
      });
    },

    /**
     * Get a specific audit log
     */
    async getAuditLog(logId: string): Promise<AuditLog> {
      return apiRequest<AuditLog>(`/admin/audit/${logId}`, {
        headers: authHeaders,
      });
    },

    /**
     * Get Merkle proof for an audit log
     */
    async getMerkleProof(logId: string): Promise<MerkleProof> {
      return apiRequest<MerkleProof>(`/admin/audit/${logId}/proof`, {
        headers: authHeaders,
      });
    },

    /**
     * Export audit logs
     */
    async exportAuditLogs(params: {
      format: "csv" | "json";
      start?: string;
      end?: string;
      agent_id?: string;
    }): Promise<Blob> {
      const searchParams = new URLSearchParams();
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) searchParams.set(key, String(value));
      });
      const response = await fetch(
        `${API_URL}/admin/audit/export?${searchParams}`,
        { headers: authHeaders }
      );
      return response.blob();
    },

    // =========================================================================
    // ALERTS
    // =========================================================================

    /**
     * List security alerts
     */
    async listAlerts(params: {
      status?: "open" | "acknowledged" | "resolved";
      severity?: AlertSeverity;
      limit?: number;
      offset?: number;
    }): Promise<{ alerts: SecurityAlert[]; total: number }> {
      const searchParams = new URLSearchParams();
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) searchParams.set(key, String(value));
      });
      return apiRequest(`/admin/alerts?${searchParams}`, {
        headers: authHeaders,
      });
    },

    /**
     * Acknowledge an alert
     */
    async acknowledgeAlert(
      alertId: string
    ): Promise<{ alert_id: string; acknowledged: boolean }> {
      return apiRequest(`/admin/alerts/${alertId}/acknowledge`, {
        method: "POST",
        headers: authHeaders,
      });
    },

    /**
     * Resolve an alert
     */
    async resolveAlert(
      alertId: string,
      resolution: string
    ): Promise<{ alert_id: string; resolved: boolean }> {
      return apiRequest(`/admin/alerts/${alertId}/resolve`, {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({ resolution }),
      });
    },

    // =========================================================================
    // API KEYS
    // =========================================================================

    /**
     * List API keys
     */
    async listAPIKeys(): Promise<APIKey[]> {
      return apiRequest<APIKey[]>("/admin/api-keys", {
        headers: authHeaders,
      });
    },

    /**
     * Create a new API key
     */
    async createAPIKey(data: {
      name: string;
      scopes: string[];
      expires_at?: string;
    }): Promise<{ api_key: string; key_id: string }> {
      return apiRequest("/admin/api-keys", {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify(data),
      });
    },

    /**
     * Revoke an API key
     */
    async revokeAPIKey(keyPrefix: string): Promise<{ message: string }> {
      return apiRequest(`/admin/api-keys/${keyPrefix}`, {
        method: "DELETE",
        headers: authHeaders,
      });
    },

    /**
     * Rotate API key
     */
    async rotateAPIKey(): Promise<{ api_key: string; message: string }> {
      return apiRequest("/admin/api-keys/rotate", {
        method: "POST",
        headers: authHeaders,
      });
    },

    // =========================================================================
    // USAGE & METRICS
    // =========================================================================

    /**
     * Get usage metrics
     */
    async getUsageMetrics(params: {
      start: string;
      end: string;
    }): Promise<UsageMetrics> {
      const searchParams = new URLSearchParams(params);
      return apiRequest(`/admin/usage?${searchParams}`, {
        headers: authHeaders,
      });
    },

    /**
     * Get organization info
     */
    async getOrganization(): Promise<OrganizationRecord> {
      return apiRequest<OrganizationRecord>("/admin/organization", {
        headers: authHeaders,
      });
    },
  };
}

// Export a type for the authenticated API
export type AuthenticatedApi = ReturnType<typeof createAuthenticatedApi>;
