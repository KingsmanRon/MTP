"use client";

import { AdminShell } from "@/components/admin/admin-shell";
import { useAdminFetch } from "@/lib/admin/use-admin-fetch";
import { mapAgents, mapAuditSearchResult } from "@/lib/admin/mappers";
import type { MappedAgent, MappedAuditSearchResult } from "@/lib/admin/types";
import { AdminErrorState } from "@/components/admin/error-state";
import { AuditTable } from "@/components/admin/audit-table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Bot, FileSearch, ShieldCheck, Activity } from "lucide-react";
import Link from "next/link";

function DashboardContent() {
  const agents = useAdminFetch<MappedAgent[]>("/api/admin/agents", {
    transform: mapAgents,
  });

  const audit = useAdminFetch<MappedAuditSearchResult>(
    "/api/admin/audit/search?limit=10&offset=0",
    { transform: mapAuditSearchResult }
  );

  const agentList = agents.data ?? [];
  const auditData = audit.data;

  const activeAgents = agentList.filter((a) => a.status === "active").length;
  const totalAgents = agentList.length;

  const loading = agents.loading || audit.loading;

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-[#7F8CA3]">Operational overview</p>
      </div>

      {/* Summary cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <SummaryCard
          icon={Bot}
          label="Total Agents"
          value={loading ? "—" : String(totalAgents)}
          href="/admin/agents"
        />
        <SummaryCard
          icon={ShieldCheck}
          label="Active Agents"
          value={loading ? "—" : String(activeAgents)}
          href="/admin/agents"
        />
        <SummaryCard
          icon={FileSearch}
          label="Audit Records"
          value={loading ? "—" : auditData ? String(auditData.total) : "—"}
          href="/admin/audit"
        />
        <SummaryCard
          icon={Activity}
          label="Recent Activity"
          value={loading ? "—" : auditData ? String(auditData.logs.length) : "0"}
          href="/admin/audit"
        />
      </div>

      {/* Error states */}
      {agents.error && (
        <AdminErrorState
          message="Failed to load agents"
          detail={agents.error}
          onRetry={agents.refetch}
        />
      )}

      {/* Recent activity */}
      <Card className="border-[#22314D] bg-[#0D1728]">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-base text-[#F5F7FB]">
            Recent Activity
          </CardTitle>
          <Link
            href="/admin/audit"
            className="text-xs text-[#8FB8FF] hover:underline"
          >
            View all
          </Link>
        </CardHeader>
        <CardContent>
          {audit.error ? (
            <AdminErrorState
              message="Failed to load audit records"
              detail={audit.error}
              onRetry={audit.refetch}
            />
          ) : audit.loading ? (
            <SkeletonTable rows={5} />
          ) : (
            <AuditTable logs={auditData?.logs ?? []} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function SummaryCard({
  icon: Icon,
  label,
  value,
  href,
}: {
  icon: typeof Bot;
  label: string;
  value: string;
  href: string;
}) {
  return (
    <Link href={href}>
      <Card className="border-[#22314D] bg-[#0D1728] transition-colors hover:bg-[#101C31]">
        <CardContent className="flex items-center gap-4 p-5">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31]">
            <Icon className="h-5 w-5 text-[#8FB8FF]" />
          </div>
          <div>
            <p className="text-2xl font-semibold tabular-nums text-[#F5F7FB]">
              {value}
            </p>
            <p className="text-xs text-[#7F8CA3]">{label}</p>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}

function SkeletonTable({ rows }: { rows: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="h-10 animate-pulse rounded-lg bg-[#101C31]"
        />
      ))}
    </div>
  );
}

export default function AdminDashboardPage() {
  return (
    <AdminShell>
      <DashboardContent />
    </AdminShell>
  );
}
