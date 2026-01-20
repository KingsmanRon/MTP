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
import { formatDateTime, formatRelative } from "@/lib/utils";
import { Download, FileText, FileJson, Calendar, Loader2, CheckCircle, Clock } from "lucide-react";

// Mock export history
const mockExports = [
  {
    id: "export1",
    filename: "audit_logs_2024-01-15_2024-01-22.csv",
    format: "csv",
    date_range: "Jan 15 - Jan 22, 2024",
    records: 15234,
    size: "2.4 MB",
    status: "completed",
    created_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    download_url: "#",
  },
  {
    id: "export2",
    filename: "audit_logs_2024-01-08_2024-01-15.json",
    format: "json",
    date_range: "Jan 8 - Jan 15, 2024",
    records: 12456,
    size: "4.1 MB",
    status: "completed",
    created_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    download_url: "#",
  },
  {
    id: "export3",
    filename: "audit_logs_2024-01-01_2024-01-31.csv",
    format: "csv",
    date_range: "Jan 1 - Jan 31, 2024",
    records: 45678,
    size: "7.8 MB",
    status: "processing",
    created_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    download_url: null,
  },
];

export default function ExportsPage() {
  const [format, setFormat] = useState("csv");
  const [dateRange, setDateRange] = useState("7d");
  const [agentFilter, setAgentFilter] = useState("all");
  const [isExporting, setIsExporting] = useState(false);

  const handleExport = async () => {
    setIsExporting(true);
    // Simulate export
    await new Promise((resolve) => setTimeout(resolve, 2000));
    setIsExporting(false);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Export Audit Logs</h1>
        <p className="text-muted-foreground">
          Generate compliance reports and export audit data
        </p>
      </div>

      {/* Export Configuration */}
      <Card>
        <CardHeader>
          <CardTitle>Create Export</CardTitle>
          <CardDescription>
            Configure and generate a new audit log export
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-4 md:grid-cols-3">
            <div className="space-y-2">
              <label className="text-sm font-medium">Format</label>
              <Select value={format} onChange={(e) => setFormat(e.target.value)}>
                <option value="csv">CSV (Spreadsheet)</option>
                <option value="json">JSON (API/Integration)</option>
                <option value="pdf">PDF (Report)</option>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Date Range</label>
              <Select value={dateRange} onChange={(e) => setDateRange(e.target.value)}>
                <option value="24h">Last 24 hours</option>
                <option value="7d">Last 7 days</option>
                <option value="30d">Last 30 days</option>
                <option value="90d">Last 90 days</option>
                <option value="custom">Custom Range</option>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Agent Filter</label>
              <Select value={agentFilter} onChange={(e) => setAgentFilter(e.target.value)}>
                <option value="all">All Agents</option>
                <option value="agent1">PaymentBot</option>
                <option value="agent2">DataExporter</option>
                <option value="agent3">EmailAgent</option>
              </Select>
            </div>
          </div>

          {dateRange === "custom" && (
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <label className="text-sm font-medium">Start Date</label>
                <Input type="date" />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">End Date</label>
                <Input type="date" />
              </div>
            </div>
          )}

          <div className="p-4 bg-muted rounded-lg">
            <h4 className="font-medium mb-2">Export Preview</h4>
            <div className="grid gap-4 md:grid-cols-3 text-sm">
              <div>
                <p className="text-muted-foreground">Format</p>
                <p className="font-medium uppercase">{format}</p>
              </div>
              <div>
                <p className="text-muted-foreground">Estimated Records</p>
                <p className="font-medium">~15,234</p>
              </div>
              <div>
                <p className="text-muted-foreground">Estimated Size</p>
                <p className="font-medium">~2.4 MB</p>
              </div>
            </div>
          </div>

          <div className="flex justify-end">
            <Button onClick={handleExport} disabled={isExporting}>
              {isExporting ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <Download className="h-4 w-4 mr-2" />
                  Generate Export
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Export History */}
      <Card>
        <CardHeader>
          <CardTitle>Export History</CardTitle>
          <CardDescription>
            Previously generated exports (retained for 30 days)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Filename</TableHead>
                <TableHead>Date Range</TableHead>
                <TableHead>Records</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[100px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mockExports.map((export_) => (
                <TableRow key={export_.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {export_.format === "csv" ? (
                        <FileText className="h-4 w-4 text-green-500" />
                      ) : (
                        <FileJson className="h-4 w-4 text-blue-500" />
                      )}
                      <span className="text-sm font-mono">{export_.filename}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{export_.date_range}</TableCell>
                  <TableCell>{export_.records.toLocaleString()}</TableCell>
                  <TableCell>{export_.size}</TableCell>
                  <TableCell>
                    {export_.status === "completed" ? (
                      <Badge variant="outline" className="bg-green-500/10 text-green-500">
                        <CheckCircle className="h-3 w-3 mr-1" />
                        Completed
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="bg-yellow-500/10 text-yellow-500">
                        <Clock className="h-3 w-3 mr-1" />
                        Processing
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatRelative(export_.created_at)}
                  </TableCell>
                  <TableCell>
                    {export_.status === "completed" && (
                      <Button variant="ghost" size="icon">
                        <Download className="h-4 w-4" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Compliance Templates */}
      <Card>
        <CardHeader>
          <CardTitle>Compliance Templates</CardTitle>
          <CardDescription>
            Pre-configured exports for common compliance requirements
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <button className="p-4 border rounded-lg text-left hover:bg-muted transition">
              <h4 className="font-medium mb-1">SOC 2 Audit</h4>
              <p className="text-sm text-muted-foreground mb-3">
                All access controls, authentication events, and policy violations
              </p>
              <Badge variant="secondary">PDF Report</Badge>
            </button>
            <button className="p-4 border rounded-lg text-left hover:bg-muted transition">
              <h4 className="font-medium mb-1">GDPR Data Access</h4>
              <p className="text-sm text-muted-foreground mb-3">
                Data export and PII access logs for compliance
              </p>
              <Badge variant="secondary">CSV Export</Badge>
            </button>
            <button className="p-4 border rounded-lg text-left hover:bg-muted transition">
              <h4 className="font-medium mb-1">Financial Audit</h4>
              <p className="text-sm text-muted-foreground mb-3">
                All financial transactions with full audit trail
              </p>
              <Badge variant="secondary">JSON + Merkle Proofs</Badge>
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
