"use client";

import { Suspense, useState, useCallback, useMemo } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { AdminShell } from "@/components/admin/admin-shell";
import { useAdminFetch } from "@/lib/admin/use-admin-fetch";
import { mapAgents, mapAuditSearchResult } from "@/lib/admin/mappers";
import type { MappedAgent, MappedAuditSearchResult, ActionVerdict } from "@/lib/admin/types";
import { AdminErrorState } from "@/components/admin/error-state";
import { AuditTable } from "@/components/admin/audit-table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { ChevronLeft, ChevronRight, X } from "lucide-react";

const PAGE_SIZE = 25;

const VERDICT_OPTIONS: { value: ActionVerdict | ""; label: string }[] = [
  { value: "", label: "All Verdicts" },
  { value: "approved", label: "Approved" },
  { value: "blocked", label: "Blocked" },
  { value: "rate_limited", label: "Rate Limited" },
  { value: "signature_invalid", label: "Signature Invalid" },
];

function AuditContent() {
  const searchParams = useSearchParams();
  const router = useRouter();

  // Read initial filter state from URL
  const [verdict, setVerdict] = useState(searchParams.get("verdict") ?? "");
  const [agentId, setAgentId] = useState(searchParams.get("agent_id") ?? "");
  const [actionType, setActionType] = useState(searchParams.get("action_type") ?? "");
  const [startDate, setStartDate] = useState(searchParams.get("start") ?? "");
  const [endDate, setEndDate] = useState(searchParams.get("end") ?? "");
  const [offset, setOffset] = useState(Number(searchParams.get("offset")) || 0);

  // Build the query string for the proxy endpoint
  const queryUrl = useMemo(() => {
    const params = new URLSearchParams();
    if (verdict) params.set("verdict", verdict);
    if (agentId) params.set("agent_id", agentId);
    if (actionType) params.set("action_type", actionType);
    if (startDate) params.set("start", startDate);
    if (endDate) params.set("end", endDate);
    params.set("limit", String(PAGE_SIZE));
    params.set("offset", String(offset));
    return `/api/admin/audit/search?${params}`;
  }, [verdict, agentId, actionType, startDate, endDate, offset]);

  const { data: auditData, loading, error, refetch } =
    useAdminFetch<MappedAuditSearchResult>(queryUrl, {
      transform: mapAuditSearchResult,
    });

  // Fetch agent list for filter dropdown
  const { data: agents } = useAdminFetch<MappedAgent[]>("/api/admin/agents", {
    transform: mapAgents,
  });

  // Persist filters in URL
  const updateUrl = useCallback(
    (overrides: Record<string, string>) => {
      const params = new URLSearchParams();
      const merged = {
        verdict,
        agent_id: agentId,
        action_type: actionType,
        start: startDate,
        end: endDate,
        offset: "0",
        ...overrides,
      };
      for (const [k, v] of Object.entries(merged)) {
        if (v) params.set(k, v);
      }
      router.replace(`/admin/audit?${params}`, { scroll: false });
    },
    [verdict, agentId, actionType, startDate, endDate, router]
  );

  const applyFilter = (key: string, value: string) => {
    const setters: Record<string, (v: string) => void> = {
      verdict: setVerdict,
      agent_id: setAgentId,
      action_type: setActionType,
      start: setStartDate,
      end: setEndDate,
    };
    setters[key]?.(value);
    setOffset(0);
    updateUrl({ [key]: value, offset: "0" });
  };

  const clearFilters = () => {
    setVerdict("");
    setAgentId("");
    setActionType("");
    setStartDate("");
    setEndDate("");
    setOffset(0);
    router.replace("/admin/audit", { scroll: false });
  };

  const hasFilters = verdict || agentId || actionType || startDate || endDate;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Audit Log</h1>
        <p className="text-sm text-[#7F8CA3]">
          Search and filter verification records
        </p>
      </div>

      {/* Filters */}
      <Card className="border-[#22314D] bg-[#0D1728]">
        <CardContent className="p-4">
          <div className="flex flex-wrap items-end gap-3">
            {/* Verdict filter */}
            <div className="w-44">
              <label className="mb-1 block text-xs text-[#7F8CA3]">Verdict</label>
              <Select
                value={verdict}
                onChange={(e) => applyFilter("verdict", e.target.value)}
                className="border-[#22314D] bg-[#101C31] text-[#F5F7FB]"
              >
                {VERDICT_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </Select>
            </div>

            {/* Agent filter */}
            {agents && agents.length > 0 && (
              <div className="w-52">
                <label className="mb-1 block text-xs text-[#7F8CA3]">Agent</label>
                <Select
                  value={agentId}
                  onChange={(e) => applyFilter("agent_id", e.target.value)}
                  className="border-[#22314D] bg-[#101C31] text-[#F5F7FB]"
                >
                  <option value="">All Agents</option>
                  {agents.map((agent) => (
                    <option key={agent.id} value={agent.id}>
                      {agent.name || agent.id.slice(0, 12)}
                    </option>
                  ))}
                </Select>
              </div>
            )}

            {/* Action type filter */}
            <div className="w-44">
              <label className="mb-1 block text-xs text-[#7F8CA3]">
                Action Type
              </label>
              <Input
                placeholder="e.g. code_execution"
                value={actionType}
                onChange={(e) => applyFilter("action_type", e.target.value)}
                className="border-[#22314D] bg-[#101C31] text-[#F5F7FB] placeholder:text-[#4A5568]"
              />
            </div>

            {/* Date range */}
            <div className="w-44">
              <label className="mb-1 block text-xs text-[#7F8CA3]">Start</label>
              <Input
                type="date"
                value={startDate}
                onChange={(e) => applyFilter("start", e.target.value)}
                className="border-[#22314D] bg-[#101C31] text-[#F5F7FB]"
              />
            </div>
            <div className="w-44">
              <label className="mb-1 block text-xs text-[#7F8CA3]">End</label>
              <Input
                type="date"
                value={endDate}
                onChange={(e) => applyFilter("end", e.target.value)}
                className="border-[#22314D] bg-[#101C31] text-[#F5F7FB]"
              />
            </div>

            {/* Clear button */}
            {hasFilters && (
              <Button
                variant="ghost"
                size="sm"
                onClick={clearFilters}
                className="text-[#7F8CA3] hover:text-[#F5F7FB]"
              >
                <X className="mr-1 h-3 w-3" />
                Clear
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      <Card className="border-[#22314D] bg-[#0D1728]">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-base text-[#F5F7FB]">
            Results
            {auditData && (
              <span className="ml-2 text-sm font-normal text-[#7F8CA3]">
                ({auditData.total} total)
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {error ? (
            <AdminErrorState
              message="Failed to load audit records"
              detail={error}
              onRetry={refetch}
            />
          ) : loading ? (
            <SkeletonRows count={8} />
          ) : (
            <>
              <AuditTable logs={auditData?.logs ?? []} />

              {/* Pagination */}
              {auditData && auditData.total > PAGE_SIZE && (
                <div className="mt-4 flex items-center justify-between">
                  <p className="text-xs text-[#7F8CA3]">
                    Showing {offset + 1}–
                    {Math.min(offset + PAGE_SIZE, auditData.total)} of{" "}
                    {auditData.total}
                  </p>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={offset === 0}
                      onClick={() => {
                        const newOffset = Math.max(0, offset - PAGE_SIZE);
                        setOffset(newOffset);
                        updateUrl({ offset: String(newOffset) });
                      }}
                      className="border-[#22314D] bg-[#101C31] text-[#AAB7CC]"
                    >
                      <ChevronLeft className="mr-1 h-3 w-3" />
                      Prev
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={offset + PAGE_SIZE >= auditData.total}
                      onClick={() => {
                        const newOffset = offset + PAGE_SIZE;
                        setOffset(newOffset);
                        updateUrl({ offset: String(newOffset) });
                      }}
                      className="border-[#22314D] bg-[#101C31] text-[#AAB7CC]"
                    >
                      Next
                      <ChevronRight className="ml-1 h-3 w-3" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function SkeletonRows({ count }: { count: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="h-10 animate-pulse rounded-lg bg-[#101C31]" />
      ))}
    </div>
  );
}

export default function AdminAuditPage() {
  return (
    <AdminShell>
      <Suspense fallback={<SkeletonRows count={8} />}>
        <AuditContent />
      </Suspense>
    </AdminShell>
  );
}
