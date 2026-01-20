"use client";

import { useState } from "react";
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
import { formatDateTime, truncateHash } from "@/lib/utils";
import { Search, Download, ChevronLeft, ChevronRight, ExternalLink } from "lucide-react";
import type { ActionVerdict } from "@/lib/api";

// Mock data
const mockLogs = [
  {
    id: "log1",
    timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    action_type: "financial_transaction",
    action_hash: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
    payload: { amount: 150.0, currency: "USD" },
    verdict: "approved" as ActionVerdict,
    verdict_reason: "All verification checks passed",
    response_time_ms: 45,
    trust_score_at_time: 85,
    merkle_root_id: "root1",
  },
  {
    id: "log2",
    timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
    action_type: "api_call",
    action_hash: "b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1",
    payload: { endpoint: "/api/orders", method: "GET" },
    verdict: "approved" as ActionVerdict,
    verdict_reason: "All verification checks passed",
    response_time_ms: 32,
    trust_score_at_time: 85,
    merkle_root_id: "root1",
  },
  {
    id: "log3",
    timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    action_type: "financial_transaction",
    action_hash: "c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2",
    payload: { amount: 5000.0, currency: "USD" },
    verdict: "blocked" as ActionVerdict,
    verdict_reason: "Amount $5000 exceeds per-action limit of $500",
    response_time_ms: 28,
    trust_score_at_time: 85,
    merkle_root_id: null,
  },
  {
    id: "log4",
    timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
    action_type: "email_send",
    action_hash: "d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2c3",
    payload: { to: "customer@example.com", subject: "Order Confirmation" },
    verdict: "approved" as ActionVerdict,
    verdict_reason: "All verification checks passed",
    response_time_ms: 38,
    trust_score_at_time: 84,
    merkle_root_id: "root1",
  },
  {
    id: "log5",
    timestamp: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
    action_type: "api_call",
    action_hash: "e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2c3d4",
    payload: { endpoint: "/api/batch", method: "POST" },
    verdict: "rate_limited" as ActionVerdict,
    verdict_reason: "Rate limit exceeded: 60 requests per minute",
    response_time_ms: 12,
    trust_score_at_time: 84,
    merkle_root_id: null,
  },
];

export default function LogsPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<string>("all");
  const [actionTypeFilter, setActionTypeFilter] = useState<string>("all");
  const [page, setPage] = useState(1);
  const [selectedLog, setSelectedLog] = useState<(typeof mockLogs)[0] | null>(null);

  const filteredLogs = mockLogs.filter((log) => {
    if (verdictFilter !== "all" && log.verdict !== verdictFilter) return false;
    if (actionTypeFilter !== "all" && log.action_type !== actionTypeFilter) return false;
    if (searchQuery && !log.action_hash.includes(searchQuery)) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Activity Logs</h1>
          <p className="text-muted-foreground">
            View your verification history and audit trail
          </p>
        </div>
        <Button variant="outline">
          <Download className="h-4 w-4 mr-2" />
          Export
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by action hash..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
              className="w-40"
            >
              <option value="all">All Verdicts</option>
              <option value="approved">Approved</option>
              <option value="blocked">Blocked</option>
              <option value="rate_limited">Rate Limited</option>
            </Select>
            <Select
              value={actionTypeFilter}
              onChange={(e) => setActionTypeFilter(e.target.value)}
              className="w-48"
            >
              <option value="all">All Actions</option>
              <option value="financial_transaction">Financial Transaction</option>
              <option value="email_send">Email Send</option>
              <option value="api_call">API Call</option>
              <option value="data_export">Data Export</option>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Logs Table */}
      <Card>
        <CardHeader>
          <CardTitle>Verification Logs</CardTitle>
          <CardDescription>
            {filteredLogs.length} log{filteredLogs.length !== 1 ? "s" : ""} found
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Timestamp</TableHead>
                <TableHead>Action Type</TableHead>
                <TableHead>Action Hash</TableHead>
                <TableHead>Verdict</TableHead>
                <TableHead>Response Time</TableHead>
                <TableHead>Trust Score</TableHead>
                <TableHead>Anchored</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredLogs.map((log) => (
                <TableRow
                  key={log.id}
                  className="cursor-pointer"
                  onClick={() => setSelectedLog(log)}
                >
                  <TableCell className="text-muted-foreground">
                    {formatDateTime(log.timestamp)}
                  </TableCell>
                  <TableCell>
                    <code className="text-sm">{log.action_type}</code>
                  </TableCell>
                  <TableCell>
                    <code className="text-xs text-muted-foreground">
                      {truncateHash(log.action_hash, 8, 4)}
                    </code>
                  </TableCell>
                  <TableCell>
                    <VerdictBadge verdict={log.verdict} showIcon={false} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">{log.response_time_ms}ms</TableCell>
                  <TableCell>{log.trust_score_at_time}</TableCell>
                  <TableCell>
                    {log.merkle_root_id ? (
                      <Badge variant="outline" className="bg-green-500/10 text-green-500">
                        Yes
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-muted-foreground">
                        Pending
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="icon">
                      <ExternalLink className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          {/* Pagination */}
          <div className="flex items-center justify-between mt-4">
            <p className="text-sm text-muted-foreground">
              Showing {filteredLogs.length} of {mockLogs.length} logs
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

      {/* Log Detail Panel */}
      {selectedLog && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Log Details</CardTitle>
              <Button variant="ghost" size="sm" onClick={() => setSelectedLog(null)}>
                Close
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="text-sm font-medium">Log ID</label>
                <p className="text-sm text-muted-foreground font-mono">{selectedLog.id}</p>
              </div>
              <div>
                <label className="text-sm font-medium">Timestamp</label>
                <p className="text-sm text-muted-foreground">
                  {formatDateTime(selectedLog.timestamp)}
                </p>
              </div>
              <div>
                <label className="text-sm font-medium">Action Type</label>
                <p className="text-sm">
                  <code>{selectedLog.action_type}</code>
                </p>
              </div>
              <div>
                <label className="text-sm font-medium">Verdict</label>
                <div className="mt-1">
                  <VerdictBadge verdict={selectedLog.verdict} />
                </div>
              </div>
            </div>

            <div>
              <label className="text-sm font-medium">Action Hash</label>
              <code className="block p-2 bg-muted rounded text-xs break-all mt-1">
                {selectedLog.action_hash}
              </code>
            </div>

            <div>
              <label className="text-sm font-medium">Verdict Reason</label>
              <p className="text-sm text-muted-foreground mt-1">{selectedLog.verdict_reason}</p>
            </div>

            <div>
              <label className="text-sm font-medium">Payload</label>
              <pre className="p-3 bg-muted rounded text-xs mt-1 overflow-x-auto">
                {JSON.stringify(selectedLog.payload, null, 2)}
              </pre>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              <div>
                <label className="text-sm font-medium">Response Time</label>
                <p className="text-sm text-muted-foreground">{selectedLog.response_time_ms}ms</p>
              </div>
              <div>
                <label className="text-sm font-medium">Trust Score</label>
                <p className="text-sm text-muted-foreground">{selectedLog.trust_score_at_time}</p>
              </div>
              <div>
                <label className="text-sm font-medium">Merkle Root</label>
                <p className="text-sm text-muted-foreground">
                  {selectedLog.merkle_root_id || "Pending anchor"}
                </p>
              </div>
            </div>

            {selectedLog.merkle_root_id && (
              <Button variant="outline" className="w-full">
                <ExternalLink className="h-4 w-4 mr-2" />
                Verify on Blockchain
              </Button>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
