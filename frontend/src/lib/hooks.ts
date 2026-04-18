/**
 * React Query hooks for Inntris API.
 *
 * All authenticated requests go through Next.js route handlers at /api/admin/*
 * so the raw API key stays in the server-side encrypted session cookie and is
 * never exposed to the browser (see Phase 0.1 of the enterprise-readiness plan).
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  publicApi,
  type AgentDashboard,
  type AgentRecord,
  type AgentStatus,
  type APIKey,
  type AuditLog,
  type ActionVerdict,
  type AlertSeverity,
  type MerkleProof,
  type OrganizationRecord,
  type SecurityAlert,
  type UsageMetrics,
} from "./api";

// =============================================================================
// INTERNAL HELPERS
// =============================================================================

async function apiJson<T>(
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const res = await fetch(path, {
    cache: "no-store",
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init.headers || {}),
    },
  });

  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    // Body may be empty — fall through to status handling.
  }

  if (!res.ok) {
    const message =
      data && typeof data === "object" && "error" in data && typeof (data as { error: unknown }).error === "string"
        ? (data as { error: string }).error
        : `Request failed (${res.status})`;
    throw new Error(message);
  }

  return data as T;
}

function buildQuery(params: Record<string, unknown>): string {
  const sp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      sp.set(key, String(value));
    }
  }
  const qs = sp.toString();
  return qs ? `?${qs}` : "";
}

// =============================================================================
// AGENT HOOKS
// =============================================================================

export function useAgents() {
  return useQuery({
    queryKey: ["agents"],
    queryFn: () => apiJson<AgentRecord[]>("/api/admin/agents"),
  });
}

export function useAgent(agentId: string) {
  return useQuery({
    queryKey: ["agent", agentId],
    queryFn: () => apiJson<AgentRecord>(`/api/admin/agents/${agentId}`),
    enabled: !!agentId,
  });
}

export function useAgentDashboard(agentId: string) {
  return useQuery({
    queryKey: ["agent-dashboard", agentId],
    queryFn: () =>
      apiJson<AgentDashboard>(`/api/admin/agents/${agentId}/dashboard`),
    enabled: !!agentId,
  });
}

export function useUpdateAgentStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ agentId, status }: { agentId: string; status: AgentStatus }) =>
      apiJson<{ agent_id: string; status: string }>(
        `/api/admin/agents/${agentId}/status`,
        {
          method: "PATCH",
          body: JSON.stringify({ status }),
        }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });
}

// =============================================================================
// AUDIT LOG HOOKS
// =============================================================================

export function useAuditLogs(params: {
  agent_id?: string;
  action_type?: string;
  verdict?: ActionVerdict | string;
  start?: string;
  end?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["audit-logs", params],
    queryFn: () =>
      apiJson<{ logs: AuditLog[]; total: number }>(
        `/api/admin/audit/search${buildQuery(params)}`
      ),
  });
}

export function useAuditLog(logId: string) {
  return useQuery({
    queryKey: ["audit-log", logId],
    queryFn: () => apiJson<AuditLog>(`/api/admin/audit/${logId}`),
    enabled: !!logId,
  });
}

export function useMerkleProof(logId: string, enabled: boolean = true) {
  return useQuery({
    queryKey: ["merkle-proof", logId],
    queryFn: () => apiJson<MerkleProof>(`/api/admin/audit/${logId}/proof`),
    enabled: !!logId && enabled,
  });
}

// =============================================================================
// ALERT HOOKS
// =============================================================================

export function useAlerts(params: {
  status?: "open" | "acknowledged" | "resolved";
  severity?: AlertSeverity;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["alerts", params],
    queryFn: () =>
      apiJson<{ alerts: SecurityAlert[]; total: number }>(
        `/api/admin/alerts${buildQuery(params)}`
      ),
  });
}

export function useAcknowledgeAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (alertId: string) =>
      apiJson<{ alert_id: string; acknowledged: boolean }>(
        `/api/admin/alerts/${alertId}/acknowledge`,
        { method: "POST" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
  });
}

export function useResolveAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ alertId, resolution }: { alertId: string; resolution: string }) =>
      apiJson<{ alert_id: string; resolved: boolean }>(
        `/api/admin/alerts/${alertId}/resolve`,
        {
          method: "POST",
          body: JSON.stringify({ resolution }),
        }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
  });
}

// =============================================================================
// API KEY HOOKS
// =============================================================================

export function useApiKeys() {
  return useQuery({
    queryKey: ["api-keys"],
    queryFn: () => apiJson<APIKey[]>("/api/admin/api-keys"),
  });
}

export function useCreateApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { name: string; scopes: string[]; expires_at?: string }) =>
      apiJson<{ api_key: string; key_id: string }>("/api/admin/api-keys", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
  });
}

export function useRevokeApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (keyPrefix: string) =>
      apiJson<{ message: string }>(
        `/api/admin/api-keys/${encodeURIComponent(keyPrefix)}`,
        { method: "DELETE" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
  });
}

// =============================================================================
// ORGANIZATION & USAGE HOOKS
// =============================================================================

export function useOrganization() {
  return useQuery({
    queryKey: ["organization"],
    queryFn: () => apiJson<OrganizationRecord>("/api/admin/organization"),
  });
}

export function useUsageMetrics(start: string, end: string) {
  return useQuery({
    queryKey: ["usage", start, end],
    queryFn: () =>
      apiJson<UsageMetrics>(
        `/api/admin/usage${buildQuery({ start, end })}`
      ),
    enabled: !!start && !!end,
  });
}

// =============================================================================
// PUBLIC HOOKS
// =============================================================================

export function usePublicVerification(recordId: string) {
  return useQuery({
    queryKey: ["public-verification", recordId],
    queryFn: () => publicApi.getVerificationRecord(recordId),
    enabled: !!recordId,
  });
}

export function usePublicAgent(agentId: string) {
  return useQuery({
    queryKey: ["public-agent", agentId],
    queryFn: () => publicApi.getAgentPublicInfo(agentId),
    enabled: !!agentId,
  });
}

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => publicApi.health(),
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}
