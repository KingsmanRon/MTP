"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select } from "@/components/ui/select";
import { EmptyState } from "@/components/empty-state";
import { LoadingState } from "@/components/loading-state";
import { formatDateTime, formatRelative } from "@/lib/utils";
import { useAlerts, useAcknowledgeAlert, useResolveAlert } from "@/lib/hooks";
import {
  AlertTriangle,
  Shield,
  CheckCircle,
  XCircle,
  Clock,
  ChevronRight,
  AlertCircle,
} from "lucide-react";
import type { AlertSeverity } from "@/lib/api";

const severityColors: Record<AlertSeverity, string> = {
  low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
};

const severityIcons: Record<AlertSeverity, React.ReactNode> = {
  low: <Shield className="h-5 w-5 text-blue-500" />,
  medium: <AlertTriangle className="h-5 w-5 text-yellow-500" />,
  high: <AlertTriangle className="h-5 w-5 text-orange-500" />,
  critical: <XCircle className="h-5 w-5 text-red-500" />,
};

export default function AlertsPage() {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  // Fetch alerts based on status filter
  const apiStatus = statusFilter === "all" ? undefined : statusFilter as "open" | "acknowledged" | "resolved";
  const { data: alertsData, isLoading, error } = useAlerts({
    status: apiStatus,
    severity: severityFilter !== "all" ? severityFilter as AlertSeverity : undefined,
    limit: 100,
  });

  const acknowledgeAlert = useAcknowledgeAlert();
  const resolveAlert = useResolveAlert();

  if (isLoading) {
    return <LoadingState message="Loading alerts..." />;
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <AlertCircle className="h-12 w-12 text-destructive mb-4" />
        <h2 className="text-xl font-semibold mb-2">Failed to load alerts</h2>
        <p className="text-muted-foreground">Please check your API connection and try again.</p>
      </div>
    );
  }

  const alerts = alertsData?.alerts || [];

  const filteredAlerts = alerts.filter((alert) => {
    if (severityFilter !== "all" && alert.severity !== severityFilter) return false;
    return true;
  });

  // Calculate counts - we need separate queries for accurate counts
  const openCount = alerts.filter((a) => !a.acknowledged && !a.resolved).length;
  const acknowledgedCount = alerts.filter((a) => a.acknowledged && !a.resolved).length;
  const resolvedCount = alerts.filter((a) => a.resolved).length;

  const handleAcknowledge = async (alertId: string) => {
    try {
      await acknowledgeAlert.mutateAsync(alertId);
    } catch (err) {
      console.error("Failed to acknowledge alert:", err);
    }
  };

  const handleResolve = async (alertId: string) => {
    try {
      await resolveAlert.mutateAsync({ alertId, resolution: "Resolved via admin dashboard" });
    } catch (err) {
      console.error("Failed to resolve alert:", err);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Security Alerts</h1>
        <p className="text-muted-foreground">
          Monitor and respond to security events across your agents
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card
          className={`cursor-pointer transition ${statusFilter === "open" ? "ring-2 ring-primary" : ""}`}
          onClick={() => setStatusFilter(statusFilter === "open" ? "all" : "open")}
        >
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Open</p>
                <p className="text-2xl font-bold">{openCount}</p>
              </div>
              <div className="p-3 rounded-full bg-red-500/10">
                <XCircle className="h-6 w-6 text-red-500" />
              </div>
            </div>
          </CardContent>
        </Card>
        <Card
          className={`cursor-pointer transition ${statusFilter === "acknowledged" ? "ring-2 ring-primary" : ""}`}
          onClick={() => setStatusFilter(statusFilter === "acknowledged" ? "all" : "acknowledged")}
        >
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Acknowledged</p>
                <p className="text-2xl font-bold">{acknowledgedCount}</p>
              </div>
              <div className="p-3 rounded-full bg-yellow-500/10">
                <Clock className="h-6 w-6 text-yellow-500" />
              </div>
            </div>
          </CardContent>
        </Card>
        <Card
          className={`cursor-pointer transition ${statusFilter === "resolved" ? "ring-2 ring-primary" : ""}`}
          onClick={() => setStatusFilter(statusFilter === "resolved" ? "all" : "resolved")}
        >
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Resolved</p>
                <p className="text-2xl font-bold">{resolvedCount}</p>
              </div>
              <div className="p-3 rounded-full bg-green-500/10">
                <CheckCircle className="h-6 w-6 text-green-500" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center gap-4">
            <div className="w-48">
              <Select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </Select>
            </div>
            {statusFilter !== "all" && (
              <Button variant="ghost" onClick={() => setStatusFilter("all")}>
                Clear Filter
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Alerts List */}
      <div className="space-y-4">
        {filteredAlerts.length === 0 ? (
          <Card>
            <CardContent>
              <EmptyState
                icon={CheckCircle}
                title="No alerts"
                description="No security alerts match your current filters."
              />
            </CardContent>
          </Card>
        ) : (
          filteredAlerts.map((alert) => (
            <Card key={alert.id} className="overflow-hidden">
              <div className="flex">
                {/* Severity Indicator */}
                <div
                  className={`w-1 ${
                    alert.severity === "critical"
                      ? "bg-red-500"
                      : alert.severity === "high"
                      ? "bg-orange-500"
                      : alert.severity === "medium"
                      ? "bg-yellow-500"
                      : "bg-blue-500"
                  }`}
                />
                <CardContent className="flex-1 py-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-4">
                      {severityIcons[alert.severity]}
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <h3 className="font-semibold">{alert.title}</h3>
                          <Badge variant="outline" className={severityColors[alert.severity]}>
                            {alert.severity}
                          </Badge>
                          {alert.resolved && (
                            <Badge variant="outline" className="bg-green-500/10 text-green-500">
                              Resolved
                            </Badge>
                          )}
                          {alert.acknowledged && !alert.resolved && (
                            <Badge variant="outline" className="bg-yellow-500/10 text-yellow-500">
                              Acknowledged
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground mb-2">{alert.description}</p>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span>Agent: {alert.agent_name}</span>
                          <span>Type: {alert.alert_type}</span>
                          <span>{formatRelative(alert.created_at)}</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {!alert.acknowledged && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleAcknowledge(alert.id)}
                          disabled={acknowledgeAlert.isPending}
                        >
                          Acknowledge
                        </Button>
                      )}
                      {alert.acknowledged && !alert.resolved && (
                        <Button
                          size="sm"
                          onClick={() => handleResolve(alert.id)}
                          disabled={resolveAlert.isPending}
                        >
                          Resolve
                        </Button>
                      )}
                      <Button size="sm" variant="ghost">
                        <ChevronRight className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </div>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
