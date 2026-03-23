"use client";

import Link from "next/link";
import { AdminShell } from "@/components/admin/admin-shell";
import { useAdminFetch } from "@/lib/admin/use-admin-fetch";
import { mapAgents } from "@/lib/admin/mappers";
import type { MappedAgent, AgentStatus } from "@/lib/admin/types";
import { AdminEmptyState } from "@/components/admin/empty-state";
import { AdminErrorState } from "@/components/admin/error-state";
import { CopyableMonoValue } from "@/components/admin/copyable-mono-value";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableHeader,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
} from "@/components/ui/table";
import { Bot } from "lucide-react";
import { formatDateTime, formatRelative } from "@/lib/utils";

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
  pending_verification: "Pending",
};

function AgentsContent() {
  const { data: agents, loading, error, refetch } = useAdminFetch<MappedAgent[]>(
    "/api/admin/agents",
    { transform: mapAgents }
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Agent Registry</h1>
        <p className="text-sm text-[#7F8CA3]">All registered agents in your organization</p>
      </div>

      {error ? (
        <AdminErrorState message="Failed to load agents" detail={error} onRetry={refetch} />
      ) : loading ? (
        <SkeletonRows count={6} />
      ) : !agents || agents.length === 0 ? (
        <AdminEmptyState icon={Bot} message="No agents found." />
      ) : (
        <div className="rounded-xl border border-[#22314D] bg-[#0D1728]">
          <Table>
            <TableHeader>
              <TableRow className="border-[#22314D] hover:bg-transparent">
                <TableHead className="text-[#7F8CA3]">Agent Name</TableHead>
                <TableHead className="text-[#7F8CA3]">Agent ID</TableHead>
                <TableHead className="text-[#7F8CA3]">Status</TableHead>
                {agents.some((a) => a.trust_score !== undefined) && (
                  <TableHead className="text-[#7F8CA3]">Trust Score</TableHead>
                )}
                {agents.some((a) => a.total_actions_count !== undefined) && (
                  <TableHead className="text-[#7F8CA3]">Verifications</TableHead>
                )}
                <TableHead className="text-[#7F8CA3]">Last Active</TableHead>
                <TableHead className="text-[#7F8CA3]">Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {agents.map((agent) => (
                <TableRow key={agent.id} className="border-[#22314D]">
                  <TableCell>
                    <Link
                      href={`/admin/agents/${agent.id}`}
                      className="text-sm font-medium text-[#F5F7FB] hover:text-[#8FB8FF] hover:underline"
                    >
                      {agent.name || "Unnamed Agent"}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <CopyableMonoValue value={agent.id} />
                  </TableCell>
                  <TableCell>
                    {agent.status ? (
                      <Badge variant={statusVariant[agent.status]}>
                        {statusLabel[agent.status]}
                      </Badge>
                    ) : (
                      <span className="text-xs text-[#7F8CA3]">—</span>
                    )}
                  </TableCell>
                  {agents.some((a) => a.trust_score !== undefined) && (
                    <TableCell>
                      {agent.trust_score !== undefined ? (
                        <TrustScoreDisplay score={agent.trust_score} />
                      ) : (
                        <span className="text-xs text-[#7F8CA3]">—</span>
                      )}
                    </TableCell>
                  )}
                  {agents.some((a) => a.total_actions_count !== undefined) && (
                    <TableCell>
                      <span className="font-mono text-xs text-[#AAB7CC]">
                        {agent.total_actions_count ?? "—"}
                      </span>
                    </TableCell>
                  )}
                  <TableCell>
                    <span className="text-xs text-[#AAB7CC]">
                      {formatRelative(agent.last_action_at)}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span className="text-xs text-[#AAB7CC]">
                      {agent.created_at ? formatDateTime(agent.created_at) : "—"}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}

function TrustScoreDisplay({ score }: { score: number }) {
  const color =
    score >= 70
      ? "text-green-400"
      : score >= 40
        ? "text-yellow-400"
        : "text-red-400";
  return (
    <span className={`font-mono text-xs font-medium ${color}`}>
      {score}
    </span>
  );
}

function SkeletonRows({ count }: { count: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="h-14 animate-pulse rounded-lg bg-[#0D1728]" />
      ))}
    </div>
  );
}

export default function AdminAgentsPage() {
  return (
    <AdminShell>
      <AgentsContent />
    </AdminShell>
  );
}
