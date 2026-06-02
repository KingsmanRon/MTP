"use client";

import { useParams } from "next/navigation";
import { AdminShell } from "@/components/admin/admin-shell";
import { useAdminFetch } from "@/lib/admin/use-admin-fetch";
import { mapAgent, mapAuditSearchResult } from "@/lib/admin/mappers";
import type { MappedAgent, MappedAuditSearchResult, AgentStatus } from "@/lib/admin/types";
import { AdminErrorState } from "@/components/admin/error-state";
import { AdminEmptyState } from "@/components/admin/empty-state";
import { AuditTable } from "@/components/admin/audit-table";
import { CopyableMonoValue } from "@/components/admin/copyable-mono-value";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Bot, FileText, ChevronLeft, ChevronRight } from "lucide-react";
import Link from "next/link";
import { formatDateTime, formatRelative } from "@/lib/utils";
import { useState } from "react";

const statusVariant: Record<AgentStatus, "success" | "destructive" | "warning" | "secondary"> = {
  active: "success",
  suspended: "warning",
  revoked: "destructive",
  pending_verification: "secondary",
};

const statusLabel: Record<AgentStatus, string> = {
  active: "Active",
  suspended: "Suspended",
  revoked: "Revoked",
  pending_verification: "Pending Verification",
};

const PAGE_SIZE = 25;

function AgentDetailContent({ id }: { id: string }) {
  const [offset, setOffset] = useState(0);

  const { data: agent, loading: agentLoading, error: agentError, refetch: refetchAgent } =
    useAdminFetch<MappedAgent>(`/api/admin/agents/${id}`, {
      transform: (raw) => mapAgent(raw) ?? { id },
      refetchInterval: 15_000,
    });

  const { data: auditData, loading: auditLoading, error: auditError, refetch: refetchAudit } =
    useAdminFetch<MappedAuditSearchResult>(
      `/api/admin/audit/search?agent_id=${id}&limit=${PAGE_SIZE}&offset=${offset}`,
      { transform: mapAuditSearchResult, refetchInterval: 30_000 }
    );

  if (agentError) {
    return (
      <div className="space-y-6">
        <BackLink />
        <AdminErrorState
          message="Failed to load agent"
          detail={agentError}
          onRetry={refetchAgent}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <BackLink />

      {/* Agent header card */}
      {agentLoading ? (
        <div className="h-40 animate-pulse rounded-xl bg-[#0D1728]" />
      ) : agent ? (
        <Card className="border-[#22314D] bg-[#0D1728]">
          <CardContent className="p-6">
            <div className="flex items-start justify-between">
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31]">
                    <Bot className="h-5 w-5 text-[#8FB8FF]" />
                  </div>
                  <div>
                    <h1 className="text-xl font-semibold text-[#F5F7FB]">
                      {agent.name || "Unnamed Agent"}
                    </h1>
                    {agent.org_id && (
                      <p className="text-xs text-[#7F8CA3]">Org: {agent.org_id}</p>
                    )}
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-4 text-sm">
                  {agent.status && (
                    <Badge variant={statusVariant[agent.status]}>
                      {statusLabel[agent.status]}
                    </Badge>
                  )}
                  {agent.trust_score !== undefined && (
                    <span className="text-[#AAB7CC]">
                      Trust Score:{" "}
                      <span
                        className={`font-mono font-medium ${
                          agent.trust_score >= 70
                            ? "text-green-400"
                            : agent.trust_score >= 40
                              ? "text-yellow-400"
                              : "text-red-400"
                        }`}
                      >
                        {agent.trust_score}
                      </span>
                    </span>
                  )}
                  {agent.total_actions_count !== undefined && (
                    <span className="text-[#AAB7CC]">
                      Verifications:{" "}
                      <span className="font-mono text-[#F5F7FB]">
                        {agent.total_actions_count}
                      </span>
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Detail fields */}
            <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <DetailField label="Agent ID">
                <CopyableMonoValue value={agent.id} full />
              </DetailField>
              {agent.public_key_fingerprint && (
                <DetailField label="Public Key">
                  <CopyableMonoValue value={agent.public_key_fingerprint} />
                </DetailField>
              )}
              {agent.created_at && (
                <DetailField label="Created">
                  <span className="font-mono text-xs text-[#AAB7CC]">
                    {formatDateTime(agent.created_at)}
                  </span>
                </DetailField>
              )}
              <DetailField label="Last Active">
                <span className="font-mono text-xs text-[#AAB7CC]">
                  {formatRelative(agent.last_action_at)}
                </span>
              </DetailField>
              {agent.daily_limit_usd !== undefined && (
                <DetailField label="Daily Limit">
                  <span className="font-mono text-xs text-[#AAB7CC]">
                    ${agent.daily_limit_usd}
                  </span>
                </DetailField>
              )}
              {agent.rate_limit_per_minute !== undefined && (
                <DetailField label="Rate Limit">
                  <span className="font-mono text-xs text-[#AAB7CC]">
                    {agent.rate_limit_per_minute}/min
                  </span>
                </DetailField>
              )}
            </div>
          </CardContent>
        </Card>
      ) : null}

      {/* Tabs */}
      <Tabs defaultValue="activity">
        <TabsList className="bg-[#0D1728]">
          <TabsTrigger value="activity">Activity</TabsTrigger>
          <TabsTrigger value="policy">Policy</TabsTrigger>
        </TabsList>

        <TabsContent value="activity">
          <Card className="border-[#22314D] bg-[#0D1728]">
            <CardContent className="p-6">
              {auditError ? (
                <AdminErrorState
                  message="Failed to load activity"
                  detail={auditError}
                  onRetry={refetchAudit}
                />
              ) : auditLoading ? (
                <SkeletonRows count={5} />
              ) : (
                <>
                  <AuditTable logs={auditData?.logs ?? []} showAgentName={false} />

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
                          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                          className="border-[#22314D] bg-[#101C31] text-[#AAB7CC]"
                        >
                          <ChevronLeft className="mr-1 h-3 w-3" />
                          Prev
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={offset + PAGE_SIZE >= auditData.total}
                          onClick={() => setOffset(offset + PAGE_SIZE)}
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
        </TabsContent>

        <TabsContent value="policy">
          <Card className="border-[#22314D] bg-[#0D1728]">
            <CardContent className="p-6">
              {/* Only render policy data if agent has policy-related fields */}
              {agent?.allowed_actions && agent.allowed_actions.length > 0 ? (
                <div className="space-y-4">
                  <div>
                    <h3 className="mb-2 text-sm font-medium text-[#C4CFDE]">
                      Allowed Actions
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {agent.allowed_actions.map((action) => (
                        <span
                          key={action}
                          className="rounded-md border border-[#22314D] bg-[#101C31] px-2 py-1 font-mono text-xs text-[#AAB7CC]"
                        >
                          {action}
                        </span>
                      ))}
                    </div>
                  </div>
                  {agent.blocked_actions && agent.blocked_actions.length > 0 && (
                    <div>
                      <h3 className="mb-2 text-sm font-medium text-[#C4CFDE]">
                        Blocked Actions
                      </h3>
                      <div className="flex flex-wrap gap-2">
                        {agent.blocked_actions.map((action) => (
                          <span
                            key={action}
                            className="rounded-md border border-red-500/20 bg-red-500/5 px-2 py-1 font-mono text-xs text-red-400"
                          >
                            {action}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <AdminErrorState
                  message="No policy configured for this agent"
                  detail="Without a policy, verdicts cannot be attributed to a rule. Assign a policy before relying on audit records for compliance purposes."
                />
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function DetailField({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <p className="mb-1 text-xs text-[#7F8CA3]">{label}</p>
      {children}
    </div>
  );
}

function BackLink() {
  return (
    <Link
      href="/admin/agents"
      className="inline-flex items-center gap-1 text-sm text-[#8FB8FF] hover:underline"
    >
      <ArrowLeft className="h-3 w-3" />
      Back to Agents
    </Link>
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

export default function AdminAgentDetailPage() {
  const { id } = useParams<{ id: string }>();
  return (
    <AdminShell>
      <AgentDetailContent id={id} />
    </AdminShell>
  );
}
