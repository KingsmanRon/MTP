"use client";

import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { StatsCard } from "@/components/stats-card";
import { LoadingState } from "@/components/loading-state";
import { TrustScoreBadge } from "@/components/trust-score";
import { VerdictBadge } from "@/components/verdict-badge";
import { formatRelative, formatCurrency } from "@/lib/utils";
import {
  Shield,
  Bot,
  AlertTriangle,
  DollarSign,
  Activity,
  CheckCircle,
  XCircle,
} from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

// Mock data - in production, this would come from the API
const mockStats = {
  totalAgents: 12,
  activeAgents: 10,
  totalVerifications: 15234,
  approvedCount: 14567,
  blockedCount: 667,
  openAlerts: 3,
  dailySpend: 4523.45,
};

const mockRecentLogs = [
  {
    id: "1",
    agent_name: "PaymentBot",
    action_type: "financial_transaction",
    verdict: "approved" as const,
    trust_score: 85,
    timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
  },
  {
    id: "2",
    agent_name: "DataExporter",
    action_type: "data_export",
    verdict: "blocked" as const,
    trust_score: 42,
    timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
  },
  {
    id: "3",
    agent_name: "EmailAgent",
    action_type: "email_send",
    verdict: "approved" as const,
    trust_score: 78,
    timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
  },
  {
    id: "4",
    agent_name: "APIWorker",
    action_type: "api_call",
    verdict: "rate_limited" as const,
    trust_score: 65,
    timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
  },
];

const mockChartData = [
  { date: "Mon", approved: 2400, blocked: 120 },
  { date: "Tue", approved: 2210, blocked: 98 },
  { date: "Wed", approved: 2890, blocked: 145 },
  { date: "Thu", approved: 2000, blocked: 87 },
  { date: "Fri", approved: 2780, blocked: 110 },
  { date: "Sat", approved: 1890, blocked: 65 },
  { date: "Sun", approved: 2390, blocked: 102 },
];

export default function AdminDashboard() {
  // In production, use actual API calls
  const isLoading = false;

  if (isLoading) {
    return <LoadingState message="Loading dashboard..." />;
  }

  const approvalRate = (
    (mockStats.approvedCount / mockStats.totalVerifications) *
    100
  ).toFixed(1);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of your Inntris deployment and agent activity
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatsCard
          title="Active Agents"
          value={`${mockStats.activeAgents}/${mockStats.totalAgents}`}
          icon={Bot}
          description="Agents currently active"
        />
        <StatsCard
          title="Total Verifications"
          value={mockStats.totalVerifications.toLocaleString()}
          icon={Shield}
          trend={{ value: 12.5, label: "from last week" }}
        />
        <StatsCard
          title="Approval Rate"
          value={`${approvalRate}%`}
          icon={CheckCircle}
          description={`${mockStats.blockedCount} blocked`}
        />
        <StatsCard
          title="Daily Spend"
          value={formatCurrency(mockStats.dailySpend)}
          icon={DollarSign}
          trend={{ value: -3.2, label: "from yesterday" }}
        />
      </div>

      {/* Alerts Banner */}
      {mockStats.openAlerts > 0 && (
        <Card className="border-yellow-500/50 bg-yellow-500/5">
          <CardContent className="flex items-center gap-4 py-4">
            <AlertTriangle className="h-5 w-5 text-yellow-500" />
            <div className="flex-1">
              <p className="font-medium">
                {mockStats.openAlerts} open security alert{mockStats.openAlerts > 1 ? "s" : ""}
              </p>
              <p className="text-sm text-muted-foreground">
                Review and acknowledge alerts to maintain security posture
              </p>
            </div>
            <a
              href="/admin/alerts"
              className="text-sm font-medium text-primary hover:underline"
            >
              View Alerts
            </a>
          </CardContent>
        </Card>
      )}

      {/* Charts and Activity */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Verification Chart */}
        <Card>
          <CardHeader>
            <CardTitle>Verification Activity</CardTitle>
            <CardDescription>Daily verification volume over the past week</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={mockChartData}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="date" className="text-xs" />
                  <YAxis className="text-xs" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "8px",
                    }}
                  />
                  <Line
                    type="monotone"
                    dataKey="approved"
                    stroke="hsl(var(--success))"
                    strokeWidth={2}
                    dot={false}
                  />
                  <Line
                    type="monotone"
                    dataKey="blocked"
                    stroke="hsl(var(--destructive))"
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
            <CardDescription>Latest verification requests</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {mockRecentLogs.map((log) => (
                <div
                  key={log.id}
                  className="flex items-center justify-between py-2 border-b last:border-0"
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-2 h-2 rounded-full ${
                        log.verdict === "approved" ? "bg-green-500" : "bg-red-500"
                      }`}
                    />
                    <div>
                      <p className="font-medium text-sm">{log.agent_name}</p>
                      <p className="text-xs text-muted-foreground">{log.action_type}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <TrustScoreBadge score={log.trust_score} />
                    <VerdictBadge verdict={log.verdict} showIcon={false} />
                    <span className="text-xs text-muted-foreground w-16 text-right">
                      {formatRelative(log.timestamp)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Stats */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-full bg-green-500/10">
                <CheckCircle className="h-6 w-6 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{mockStats.approvedCount.toLocaleString()}</p>
                <p className="text-sm text-muted-foreground">Approved Actions</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-full bg-red-500/10">
                <XCircle className="h-6 w-6 text-red-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{mockStats.blockedCount.toLocaleString()}</p>
                <p className="text-sm text-muted-foreground">Blocked Actions</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-full bg-primary/10">
                <Activity className="h-6 w-6 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-bold">99.8%</p>
                <p className="text-sm text-muted-foreground">Uptime (30 days)</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
