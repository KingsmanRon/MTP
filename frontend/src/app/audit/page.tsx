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
import { formatDateTime, truncateHash } from "@/lib/utils";
import {
  Search,
  Download,
  Filter,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Shield,
  Calendar,
} from "lucide-react";
import type { ActionVerdict } from "@/lib/api";

// Mock data - comprehensive audit logs
const mockAuditLogs = [
  {
    id: "audit1",
    agent_id: "a1b2c3d4",
    agent_name: "PaymentBot",
    timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    action_type: "financial_transaction",
    action_hash: "sha256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
    payload: { amount: 150.0, currency: "USD", recipient: "user@example.com" },
    verdict: "approved" as ActionVerdict,
    verdict_reason: "All verification checks passed",
    signature_valid: true,
    response_time_ms: 45,
    trust_score_at_time: 85,
    request_ip: "192.168.1.100",
    merkle_root_id: "root1",
    merkle_leaf_index: 42,
  },
  {
    id: "audit2",
    agent_id: "b2c3d4e5",
    agent_name: "DataExporter",
    timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
    action_type: "data_export",
    action_hash: "sha256:b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1",
    payload: { format: "csv", dataset: "analytics", rows: 5000 },
    verdict: "blocked" as ActionVerdict,
    verdict_reason: "Trust score 42 below required 40 for data_export",
    signature_valid: true,
    response_time_ms: 32,
    trust_score_at_time: 42,
    request_ip: "192.168.1.101",
    merkle_root_id: null,
    merkle_leaf_index: null,
  },
  {
    id: "audit3",
    agent_id: "a1b2c3d4",
    agent_name: "PaymentBot",
    timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    action_type: "financial_transaction",
    action_hash: "sha256:c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2",
    payload: { amount: 5000.0, currency: "USD" },
    verdict: "blocked" as ActionVerdict,
    verdict_reason: "Amount $5000 exceeds per-action limit of $500",
    signature_valid: true,
    response_time_ms: 28,
    trust_score_at_time: 85,
    request_ip: "192.168.1.100",
    merkle_root_id: "root1",
    merkle_leaf_index: 41,
  },
  {
    id: "audit4",
    agent_id: "c3d4e5f6",
    agent_name: "EmailAgent",
    timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
    action_type: "email_send",
    action_hash: "sha256:d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2c3",
    payload: { to: "customer@example.com", subject: "Order Confirmation" },
    verdict: "approved" as ActionVerdict,
    verdict_reason: "All verification checks passed",
    signature_valid: true,
    response_time_ms: 38,
    trust_score_at_time: 78,
    request_ip: "192.168.1.102",
    merkle_root_id: "root1",
    merkle_leaf_index: 40,
  },
  {
    id: "audit5",
    agent_id: "d4e5f6g7",
    agent_name: "APIWorker",
    timestamp: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
    action_type: "api_call",
    action_hash: "sha256:e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2c3d4",
    payload: { endpoint: "/api/batch", method: "POST" },
    verdict: "signature_invalid" as ActionVerdict,
    verdict_reason: "Ed25519 signature verification failed. Potential attack detected.",
    signature_valid: false,
    response_time_ms: 12,
    trust_score_at_time: 65,
    request_ip: "203.0.113.45",
    merkle_root_id: "root1",
    merkle_leaf_index: 39,
  },
];

export default function AuditSearchPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<string>("all");
  const [actionTypeFilter, setActionTypeFilter] = useState<string>("all");
  const [agentFilter, setAgentFilter] = useState<string>("all");
  const [dateRange, setDateRange] = useState("7d");
  const [page, setPage] = useState(1);

  const filteredLogs = mockAuditLogs.filter((log) => {
    if (verdictFilter !== "all" && log.verdict !== verdictFilter) return false;
    if (actionTypeFilter !== "all" && log.action_type !== actionTypeFilter) return false;
    if (agentFilter !== "all" && log.agent_id !== agentFilter) return false;
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        log.action_hash.toLowerCase().includes(query) ||
        log.agent_name.toLowerCase().includes(query) ||
        log.id.toLowerCase().includes(query)
      );
    }
    return true;
  });

  // Get unique agents for filter
  const uniqueAgents = Array.from(
    new Map(mockAuditLogs.map((log) => [log.agent_id, { id: log.agent_id, name: log.agent_name }])).values()
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Audit Explorer</h1>
          <p className="text-muted-foreground">
            Search and analyze forensic-grade verification logs
          </p>
        </div>
        <Button variant="outline">
          <Download className="h-4 w-4 mr-2" />
          Export Results
        </Button>
      </div>

      {/* Summary Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Total Logs</p>
            <p className="text-2xl font-bold">{mockAuditLogs.length.toLocaleString()}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Approved</p>
            <p className="text-2xl font-bold text-green-500">
              {mockAuditLogs.filter((l) => l.verdict === "approved").length}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Blocked</p>
            <p className="text-2xl font-bold text-red-500">
              {mockAuditLogs.filter((l) => l.verdict === "blocked").length}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Security Alerts</p>
            <p className="text-2xl font-bold text-yellow-500">
              {mockAuditLogs.filter((l) => !l.signature_valid).length}
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
                placeholder="Search by hash, agent name, or ID..."
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
              <option value="rate_limited">Rate Limited</option>
              <option value="signature_invalid">Invalid Sig</option>
            </Select>
            <Select
              value={actionTypeFilter}
              onChange={(e) => setActionTypeFilter(e.target.value)}
              className="w-44"
            >
              <option value="all">All Actions</option>
              <option value="financial_transaction">Financial</option>
              <option value="email_send">Email</option>
              <option value="api_call">API Call</option>
              <option value="data_export">Data Export</option>
              <option value="admin_action">Admin</option>
            </Select>
            <Select
              value={agentFilter}
              onChange={(e) => setAgentFilter(e.target.value)}
              className="w-40"
            >
              <option value="all">All Agents</option>
              {uniqueAgents.map((agent) => (
                <option key={agent.id} value={agent.id}>
                  {agent.name}
                </option>
              ))}
            </Select>
            <Select
              value={dateRange}
              onChange={(e) => setDateRange(e.target.value)}
              className="w-32"
            >
              <option value="24h">Last 24h</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
              <option value="90d">Last 90 days</option>
              <option value="all">All time</option>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results Table */}
      <Card>
        <CardHeader>
          <CardTitle>Audit Logs</CardTitle>
          <CardDescription>
            {filteredLogs.length} log{filteredLogs.length !== 1 ? "s" : ""} found
          </CardDescription>
        </CardHeader>
        <CardContent>
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
                <TableHead>Anchored</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredLogs.map((log) => (
                <TableRow key={log.id}>
                  <TableCell className="text-muted-foreground text-sm">
                    {formatDateTime(log.timestamp)}
                  </TableCell>
                  <TableCell>
                    <div>
                      <p className="font-medium text-sm">{log.agent_name}</p>
                      <code className="text-xs text-muted-foreground">{log.agent_id}</code>
                    </div>
                  </TableCell>
                  <TableCell>
                    <code className="text-xs">{log.action_type}</code>
                  </TableCell>
                  <TableCell>
                    <code className="text-xs text-muted-foreground">
                      {truncateHash(log.action_hash.replace("sha256:", ""), 8, 4)}
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
                      <Badge variant="outline" className="bg-green-500/10 text-green-500">
                        Valid
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="bg-red-500/10 text-red-500">
                        Invalid
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    {log.merkle_root_id ? (
                      <Link href={`/audit/verify/${log.id}`}>
                        <Badge variant="outline" className="bg-primary/10 text-primary cursor-pointer">
                          <Shield className="h-3 w-3 mr-1" />
                          Verified
                        </Badge>
                      </Link>
                    ) : (
                      <Badge variant="outline" className="text-muted-foreground">
                        Pending
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

          {/* Pagination */}
          <div className="flex items-center justify-between mt-4">
            <p className="text-sm text-muted-foreground">
              Showing {filteredLogs.length} of {mockAuditLogs.length} logs
            </p>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="icon" disabled={page === 1}>
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-sm">Page {page}</span>
              <Button variant="outline" size="icon">
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
