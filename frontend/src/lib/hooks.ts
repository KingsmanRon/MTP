/**
 * React Query hooks for Inntris API
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { createAuthenticatedApi, publicApi } from "./api";

// Get API key from environment or localStorage (for development)
function getApiKey(): string {
  // In production, this should come from a secure auth flow
  // For development, use env variable or default dev key
  if (typeof window !== "undefined") {
    const stored = localStorage.getItem("inntris_api_key");
    if (stored) return stored;
  }
  return process.env.NEXT_PUBLIC_API_KEY || "dev_test_key";
}

// Create authenticated API instance
function getApi() {
  return createAuthenticatedApi(getApiKey());
}

// =============================================================================
// AGENT HOOKS
// =============================================================================

export function useAgents() {
  return useQuery({
    queryKey: ["agents"],
    queryFn: () => getApi().listAgents(),
  });
}

export function useAgent(agentId: string) {
  return useQuery({
    queryKey: ["agent", agentId],
    queryFn: () => getApi().getAgent(agentId),
    enabled: !!agentId,
  });
}

export function useUpdateAgentStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ agentId, status }: { agentId: string; status: string }) =>
      getApi().updateAgentStatus(agentId, status as any),
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
  verdict?: string;
  start?: string;
  end?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["audit-logs", params],
    queryFn: () => getApi().searchAuditLogs(params as any),
  });
}

export function useAuditLog(logId: string) {
  return useQuery({
    queryKey: ["audit-log", logId],
    queryFn: () => getApi().getAuditLog(logId),
    enabled: !!logId,
  });
}

export function useMerkleProof(logId: string) {
  return useQuery({
    queryKey: ["merkle-proof", logId],
    queryFn: () => getApi().getMerkleProof(logId),
    enabled: !!logId,
  });
}

// =============================================================================
// ALERT HOOKS
// =============================================================================

export function useAlerts(params: {
  status?: "open" | "acknowledged" | "resolved";
  severity?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["alerts", params],
    queryFn: () => getApi().listAlerts(params as any),
  });
}

export function useAcknowledgeAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (alertId: string) => getApi().acknowledgeAlert(alertId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
  });
}

export function useResolveAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ alertId, resolution }: { alertId: string; resolution: string }) =>
      getApi().resolveAlert(alertId, resolution),
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
    queryFn: () => getApi().listAPIKeys(),
  });
}

export function useCreateApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { name: string; scopes: string[]; expires_at?: string }) =>
      getApi().createAPIKey(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
  });
}

export function useRevokeApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (keyPrefix: string) => getApi().revokeAPIKey(keyPrefix),
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
    queryFn: () => getApi().getOrganization(),
  });
}

export function useUsageMetrics(start: string, end: string) {
  return useQuery({
    queryKey: ["usage", start, end],
    queryFn: () => getApi().getUsageMetrics({ start, end }),
    enabled: !!start && !!end,
  });
}

// =============================================================================
// PUBLIC HOOKS
// =============================================================================

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
