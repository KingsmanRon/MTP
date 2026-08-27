"use client";

import Link from "next/link";
import {
  Table,
  TableHeader,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
} from "@/components/ui/table";
import { AdminVerdictBadge } from "./verdict-badge";
import { AdminEmptyState } from "./empty-state";
import { ExternalLink, FileSearch, Link2 } from "lucide-react";
import { formatDateTime } from "@/lib/utils";
import type { MappedAuditLog } from "@/lib/admin/types";

export function AuditTable({
  logs,
  showAgentName = true,
}: {
  logs: MappedAuditLog[];
  showAgentName?: boolean;
}) {
  if (logs.length === 0) {
    return (
      <AdminEmptyState
        icon={FileSearch}
        message="No verification records found matching your filters."
      />
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow className="border-tileLine hover:bg-transparent">
          <TableHead className="text-muted-foreground">Audit ID</TableHead>
          <TableHead className="text-muted-foreground">Time</TableHead>
          {showAgentName && (
            <TableHead className="text-muted-foreground">Agent</TableHead>
          )}
          <TableHead className="text-muted-foreground">Action Type</TableHead>
          <TableHead className="text-muted-foreground">Verdict</TableHead>
          <TableHead className="text-muted-foreground">On-chain</TableHead>
          <TableHead className="text-muted-foreground">Receipt</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {logs.map((log) => (
          <TableRow key={log.id} className="border-tileLine">
            <TableCell>
              <Link
                href={`/admin/audit/${log.id}`}
                className="font-mono text-xs text-brandInk hover:underline"
              >
                {log.id.slice(0, 8)}...
              </Link>
            </TableCell>
            <TableCell className="font-mono text-xs text-muted-foreground">
              {log.timestamp ? formatDateTime(log.timestamp) : "—"}
            </TableCell>
            {showAgentName && (
              <TableCell>
                {log.agent_id ? (
                  <Link
                    href={`/admin/agents/${log.agent_id}`}
                    className="text-sm text-brandInk hover:underline"
                  >
                    {log.agent_name || log.agent_id.slice(0, 8)}
                  </Link>
                ) : (
                  <span className="text-sm text-muted-foreground">—</span>
                )}
              </TableCell>
            )}
            <TableCell>
              <span className="font-mono text-xs text-muted-foreground">
                {log.action_type || "—"}
              </span>
            </TableCell>
            <TableCell>
              {log.verdict ? (
                <AdminVerdictBadge verdict={log.verdict} />
              ) : (
                <span className="text-xs text-muted-foreground">—</span>
              )}
            </TableCell>
            <TableCell>
              {log.transaction_hash ? (
                <span className="inline-flex items-center gap-1 text-xs text-success-ink">
                  <Link2 className="h-3 w-3" />
                  Anchored
                </span>
              ) : (
                <span className="text-xs text-muted-foreground">Pending</span>
              )}
            </TableCell>
            <TableCell>
              <Link
                href={`/verify/${log.id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-xs text-brandInk hover:underline"
              >
                View
                <ExternalLink className="h-3 w-3" />
              </Link>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
