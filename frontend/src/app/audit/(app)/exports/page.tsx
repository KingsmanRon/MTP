"use client";

import { useState } from "react";
import { Download, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useAgents } from "@/lib/hooks";

type ExportFormat = "csv" | "json";
type DateRange = "24h" | "7d" | "30d" | "90d" | "custom";

function rangeStart(range: Exclude<DateRange, "custom">): string {
  const hours = { "24h": 24, "7d": 168, "30d": 720, "90d": 2160 }[range];
  return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
}

function filenameFromDisposition(
  disposition: string | null,
  format: ExportFormat,
): string {
  const match = disposition?.match(/filename="?([^";]+)"?/i);
  return match?.[1] || `audit_logs.${format}`;
}

export default function ExportsPage() {
  const { data: agents } = useAgents();
  const [format, setFormat] = useState<ExportFormat>("csv");
  const [dateRange, setDateRange] = useState<DateRange>("7d");
  const [agentId, setAgentId] = useState("");
  const [customStart, setCustomStart] = useState("");
  const [customEnd, setCustomEnd] = useState("");
  const [isExporting, setIsExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleExport = async () => {
    setError(null);
    const params = new URLSearchParams({ format });
    if (agentId) params.set("agent_id", agentId);

    if (dateRange === "custom") {
      if (!customStart || !customEnd) {
        setError("Choose both a start and end date.");
        return;
      }
      const start = new Date(`${customStart}T00:00:00Z`);
      const end = new Date(`${customEnd}T23:59:59.999Z`);
      if (start > end) {
        setError("Start date must be before end date.");
        return;
      }
      params.set("start", start.toISOString());
      params.set("end", end.toISOString());
    } else {
      params.set("start", rangeStart(dateRange));
      params.set("end", new Date().toISOString());
    }

    setIsExporting(true);
    try {
      const response = await fetch(`/api/admin/audit/export?${params.toString()}`);
      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(
          body && typeof body.error === "string"
            ? body.error
            : body && typeof body.detail === "string"
              ? body.detail
              : `Export failed (${response.status})`,
        );
      }

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filenameFromDisposition(
        response.headers.get("content-disposition"),
        format,
      );
      link.click();
      URL.revokeObjectURL(url);
    } catch (exportError) {
      setError(exportError instanceof Error ? exportError.message : "Export failed.");
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Export Audit Logs</h1>
        <p className="text-muted-foreground">
          Download up to 10,000 audit records from the live audit store.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Create Export</CardTitle>
          <CardDescription>
            Exports are generated immediately as CSV or JSON.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-4 md:grid-cols-3">
            <div className="space-y-2">
              <label className="text-sm font-medium">Format</label>
              <Select
                value={format}
                onChange={(event) => setFormat(event.target.value as ExportFormat)}
              >
                <option value="csv">CSV</option>
                <option value="json">JSON</option>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Date Range</label>
              <Select
                value={dateRange}
                onChange={(event) => setDateRange(event.target.value as DateRange)}
              >
                <option value="24h">Last 24 hours</option>
                <option value="7d">Last 7 days</option>
                <option value="30d">Last 30 days</option>
                <option value="90d">Last 90 days</option>
                <option value="custom">Custom range</option>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Agent</label>
              <Select value={agentId} onChange={(event) => setAgentId(event.target.value)}>
                <option value="">All agents</option>
                {(agents ?? []).map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.name}
                  </option>
                ))}
              </Select>
            </div>
          </div>

          {dateRange === "custom" && (
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <label className="text-sm font-medium">Start Date</label>
                <Input
                  type="date"
                  value={customStart}
                  onChange={(event) => setCustomStart(event.target.value)}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">End Date</label>
                <Input
                  type="date"
                  value={customEnd}
                  onChange={(event) => setCustomEnd(event.target.value)}
                />
              </div>
            </div>
          )}

          {error && (
            <p className="rounded-md border border-destructive-line bg-destructive-surface p-3 text-sm text-destructive-ink">
              {error}
            </p>
          )}

          <div className="flex justify-end">
            <Button onClick={handleExport} disabled={isExporting}>
              {isExporting ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Download className="mr-2 h-4 w-4" />
              )}
              {isExporting ? "Generating..." : "Download export"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
