"use client";

import { useState } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { VerdictBadge } from "@/components/verdict-badge";
import { TrustScoreBadge } from "@/components/trust-score";
import { LoadingState } from "@/components/loading-state";
import { formatDateTime, truncateHash } from "@/lib/utils";
import { useAuditLogs } from "@/lib/hooks";
import {
  Search,
  Download,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Shield,
  Loader2,
  AlertCircle,
  CheckCircle2,
} from "lucide-react";
import { type ActionVerdict } from "@/lib/api";

export default function AuditSearchPage() {
  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<string>("all");
  const [actionTypeFilter, setActionTypeFilter] = useState<string>("all");
  const [page, setPage] = useState(1);

  // Fetch logs using React Query hook
  const { data: auditData, isLoading: loading, error: queryError } = useAuditLogs({
    limit: 20,
    offset: (page - 1) * 20,
    verdict: verdictFilter !== "all" ? verdictFilter : undefined,
    action_type: actionTypeFilter !== "all" ? actionTypeFilter : undefined,
  });

  const logs = auditData?.logs || [];
  const totalLogs = auditData?.total || 0;
  const error = queryError ? "Could not connect to Audit API. Ensure backend is running." : null;

  // Computed Stats (from current view, ideally fetched from stats API)
  const approvedCount = logs.filter((l) => l.verdict === "approved").length;
  const blockedCount = logs.filter((l) => l.verdict === "blocked").length;
  const alertCount = logs.filter((l) => !l.signature_valid).length;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold sm:text-3xl">Audit Explorer</h1>
          <p className="text-muted-foreground">
            Forensic-grade verification logs anchored on Base L2
          </p>
        </div>
        <Button variant="outline" className="self-start sm:self-auto">
          <Download className="h-4 w-4 mr-2" />
          Export Evidence
        </Button>
      </div>

      {/* Summary Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Total Logs</p>
            <p className="text-2xl font-bold">
              {loading ? "-" : totalLogs.toLocaleString()}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Approved</p>
            <p className="text-2xl font-bold text-success-ink">
              {loading ? "-" : approvedCount}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Blocked</p>
            <p className="text-2xl font-bold text-destructive-ink">
              {loading ? "-" : blockedCount}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Security Alerts</p>
            <p className="text-2xl font-bold text-warning-ink">
              {loading ? "-" : alertCount}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Search and Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap items-center gap-4">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by hash, agent ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
              className="w-36"
            >
              <option value="all">All Verdicts</option>
              <option value="approved">Approved</option>
              <option value="blocked">Blocked</option>
              <option value="signature_invalid">Invalid Sig</option>
            </Select>
            <Select
              value={actionTypeFilter}
              onChange={(e) => setActionTypeFilter(e.target.value)}
              className="w-44"
            >
              <option value="all">All Actions</option>
              <option value="transfer_funds">Transfer Funds</option>
              <option value="email_send">Email</option>
              <option value="api_call">API Call</option>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results Table */}
      <Card>
        <CardHeader>
          <CardTitle>Audit Logs</CardTitle>
          <CardDescription>
            Real-time forensic data. Anchored logs are immutable.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {error ? (
            <div className="flex flex-col items-center justify-center py-10 text-destructive-ink">
              <AlertCircle className="h-10 w-10 mb-2" />
              <p>{error}</p>
            </div>
          ) : loading ? (
            <div className="flex justify-center py-10">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Timestamp</TableHead>
                  <TableHead>Agent</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Hash</TableHead>
                  <TableHead>Verdict</TableHead>
                  <TableHead>Trust</TableHead>
                  <TableHead>Signature</TableHead>
                  <TableHead>Anchored (Base L2)</TableHead>
                  <TableHead className="w-[50px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell className="text-muted-foreground text-sm font-mono">
                      {formatDateTime(log.timestamp)}
                    </TableCell>
                    <TableCell>
                      <div>
                        <code className="text-xs text-primary font-bold">{log.agent_name || "Unknown Agent"}</code>
                        <div className="text-[10px] text-muted-foreground font-mono">{log.agent_id.substring(0, 8)}...</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="text-xs font-mono">
                        {log.action_type}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <code className="text-xs text-muted-foreground bg-muted px-1 py-0.5 rounded">
                        {truncateHash(log.action_hash, 8, 4)}
                      </code>
                    </TableCell>
                    <TableCell>
                      <VerdictBadge verdict={log.verdict} showIcon={false} />
                    </TableCell>
                    <TableCell>
                      <TrustScoreBadge score={log.trust_score_at_time} />
                    </TableCell>
                    <TableCell>
                      {log.signature_valid ? (
                        <div className="flex items-center text-success-ink text-xs font-medium">
                          <CheckCircle2 className="h-3 w-3 mr-1" />
                          Valid
                        </div>
                      ) : (
                        <Badge variant="outline" className="bg-destructive-surface text-destructive-ink border-destructive-line">
                          Invalid
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {log.merkle_root_id ? (
                        <Link href={`/audit/verify/${log.id}`}>
                          <Badge variant="outline" className="bg-info-surface text-info-ink border-info-line cursor-pointer hover:bg-info-surface transition-colors group">
                            <Shield className="h-3 w-3 mr-1 group-hover:text-info-ink" />
                            Anchored
                          </Badge>
                        </Link>
                      ) : (
                        <Badge variant="outline" className="border-border bg-muted text-muted-foreground">
                          Pending Batch
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      <Link href={`/audit/verify/${log.id}`}>
                        <Button variant="ghost" size="icon">
                          <ExternalLink className="h-4 w-4" />
                        </Button>
                      </Link>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          {/* Pagination */}
          <div className="flex items-center justify-between mt-4">
            <p className="text-sm text-muted-foreground">
              Showing {logs.length} of {totalLogs} logs
            </p>
            <div className="flex items-center gap-2">
              <Button 
                variant="outline" 
                size="icon" 
                disabled={page === 1 || loading}
                onClick={() => setPage(p => Math.max(1, p - 1))}
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-sm">Page {page}</span>
              <Button 
                variant="outline" 
                size="icon"
                disabled={logs.length < 20 || loading}
                onClick={() => setPage(p => p + 1)}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
