"use client";

import { useMemo, useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { StatsCard } from "@/components/stats-card";
import { LoadingState } from "@/components/loading-state";
import { TrustScoreBadge } from "@/components/trust-score";
import { VerdictBadge } from "@/components/verdict-badge";
import { OnboardingChecklist } from "@/components/onboarding-checklist";
import { formatRelative, formatCurrency } from "@/lib/utils";
import { useAgents, useAuditLogs, useAlerts, useUsageMetrics, useApiKeys } from "@/lib/hooks";
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

export default function AdminDashboard() {
  // Get date range for past 7 days - memoize to prevent infinite re-renders
  const { startDate, endDate } = useMemo(() => {
    const end = new Date();
    const start = new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000);
    return {
      startDate: start.toISOString(),
      endDate: end.toISOString(),
    };
  }, []);

  // Onboarding dismissal state
  const [onboardingDismissed, setOnboardingDismissed] = useState(false);

  // Load dismissal state from localStorage
  useEffect(() => {
    if (typeof window !== "undefined") {
      const dismissed = localStorage.getItem("onboarding_dismissed");
      if (dismissed === "true") {
        setOnboardingDismissed(true);
      }
    }
  }, []);

  const handleDismissOnboarding = () => {
    setOnboardingDismissed(true);
    if (typeof window !== "undefined") {
      localStorage.setItem("onboarding_dismissed", "true");
    }
  };

  // Fetch real data from API
  const { data: agents, isLoading: agentsLoading } = useAgents();
  const { data: auditData, isLoading: auditLoading } = useAuditLogs({ limit: 10 });
  const { data: alertsData, isLoading: alertsLoading } = useAlerts({ status: "open", limit: 10 });
  const { data: usageData, isLoading: usageLoading } = useUsageMetrics(startDate, endDate);
  const { data: apiKeys, isLoading: apiKeysLoading } = useApiKeys();

  const isLoading = agentsLoading || auditLoading || alertsLoading || usageLoading || apiKeysLoading;

  if (isLoading) {
    return <LoadingState message="Loading dashboard..." />;
  }

  // Calculate stats from real data
  const totalAgents = agents?.length || 0;
  const activeAgents = agents?.filter((a) => a.status === "active").length || 0;
  const totalVerifications = usageData?.total_verifications || 0;
  const approvedCount = usageData?.approved_count || 0;
  const blockedCount = usageData?.blocked_count || 0;
  const openAlerts = alertsData?.total || 0;
  const dailySpend = usageData?.total_spend_usd || 0;

  const approvalRate = totalVerifications > 0
    ? ((approvedCount / totalVerifications) * 100).toFixed(1)
    : "0.0";

  // Transform daily breakdown for chart
  const chartData = usageData?.daily_breakdown?.map((day) => ({
    date: new Date(day.date).toLocaleDateString("en-US", { weekday: "short" }),
    approved: day.approved,
    blocked: day.blocked,
  })) || [];

  // Recent logs
  const recentLogs = auditData?.logs || [];

  // Check if onboarding should be shown
  const hasAgents = totalAgents > 0;
  const hasApiKeys = (apiKeys?.length || 0) > 0;
  const hasVerifications = totalVerifications > 0;
  const showOnboarding = !onboardingDismissed && (!hasAgents || !hasApiKeys || !hasVerifications);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of your Inntris deployment and agent activity
        </p>
      </div>

      {/* Onboarding Checklist */}
      {showOnboarding && (
        <OnboardingChecklist
          hasAgents={hasAgents}
          hasApiKeys={hasApiKeys}
          hasVerifications={hasVerifications}
          onDismiss={handleDismissOnboarding}
        />
      )}

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatsCard
          title="Active Agents"
          value={`${activeAgents}/${totalAgents}`}
          icon={Bot}
          description="Agents currently active"
        />
        <StatsCard
          title="Total Verifications"
          value={totalVerifications.toLocaleString()}
          icon={Shield}
          description="Past 7 days"
        />
        <StatsCard
          title="Approval Rate"
          value={`${approvalRate}%`}
          icon={CheckCircle}
          description={`${blockedCount} blocked`}
        />
        <StatsCard
          title="Daily Spend"
          value={formatCurrency(dailySpend)}
          icon={DollarSign}
          description="Today"
        />
      </div>

      {/* Alerts Banner */}
      {openAlerts > 0 && (
        <Card className="border-yellow-500/50 bg-yellow-500/5">
          <CardContent className="flex items-center gap-4 py-4">
            <AlertTriangle className="h-5 w-5 text-yellow-500" />
            <div className="flex-1">
              <p className="font-medium">
                {openAlerts} open security alert{openAlerts > 1 ? "s" : ""}
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
              {chartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={chartData}>
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
                      stroke="hsl(142, 76%, 36%)"
                      strokeWidth={2}
                      dot={false}
                    />
                    <Line
                      type="monotone"
                      dataKey="blocked"
                      stroke="hsl(0, 84%, 60%)"
                      strokeWidth={2}
                      dot={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-muted-foreground">
                  No verification data available
                </div>
              )}
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
              {recentLogs.length > 0 ? (
                recentLogs.map((log) => (
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
                        <p className="font-medium text-sm">{log.agent_name || "Unknown Agent"}</p>
                        <span className="inline-block text-xs font-mono bg-muted px-1.5 py-0.5 rounded">{log.action_type}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <TrustScoreBadge score={log.trust_score_at_time} />
                      <VerdictBadge verdict={log.verdict} showIcon={false} />
                      <span className="text-xs text-muted-foreground w-16 text-right">
                        {formatRelative(log.timestamp)}
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center text-muted-foreground py-8">
                  No recent activity
                </div>
              )}
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
                <p className="text-2xl font-bold">{approvedCount.toLocaleString()}</p>
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
                <p className="text-2xl font-bold">{blockedCount.toLocaleString()}</p>
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
                <p className="text-2xl font-bold">{activeAgents}</p>
                <p className="text-sm text-muted-foreground">Active Agents</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
