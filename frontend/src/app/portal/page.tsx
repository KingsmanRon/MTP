"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { TrustScore } from "@/components/trust-score";
import { StatsCard } from "@/components/stats-card";
import { VerdictBadge } from "@/components/verdict-badge";
import { LoadingState } from "@/components/loading-state";
import { EmptyState } from "@/components/empty-state";
import { formatRelative, formatCurrency, truncateHash } from "@/lib/utils";
import { useAgentDashboard, useAgents } from "@/lib/hooks";
import {
  Shield,
  Activity,
  CheckCircle,
  XCircle,
  Clock,
  TrendingUp,
  Bot,
} from "lucide-react";
import {
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
} from "recharts";

// Helper to get/set selected agent from localStorage
function getStoredAgentId(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("portal_agent_id");
}

function setStoredAgentId(agentId: string) {
  if (typeof window !== "undefined") {
    localStorage.setItem("portal_agent_id", agentId);
  }
}

export default function PortalDashboard() {
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);

  // Load stored agent ID on mount
  useEffect(() => {
    const stored = getStoredAgentId();
    if (stored) setSelectedAgentId(stored);
  }, []);

  // Fetch list of agents for selection
  const { data: agents, isLoading: agentsLoading } = useAgents();

  // Fetch dashboard data for selected agent
  const { data: dashboard, isLoading: dashboardLoading, error } = useAgentDashboard(
    selectedAgentId || ""
  );

  // Auto-select first agent if none selected
  useEffect(() => {
    if (!selectedAgentId && agents && agents.length > 0) {
      const firstAgent = agents[0];
      setSelectedAgentId(firstAgent.id);
      setStoredAgentId(firstAgent.id);
    }
  }, [agents, selectedAgentId]);

  // Handle agent selection change
  const handleAgentChange = (agentId: string) => {
    setSelectedAgentId(agentId);
    setStoredAgentId(agentId);
  };

  if (agentsLoading) {
    return <LoadingState message="Loading agents..." />;
  }

  if (!agents || agents.length === 0) {
    return (
      <EmptyState
        icon={Bot}
        title="No Agents Found"
        description="Register an agent in the Admin Console to use the Portal."
        action={{
          label: "Go to Admin Console",
          href: "/admin/agents",
        }}
      />
    );
  }

  if (!selectedAgentId) {
    return <LoadingState message="Selecting agent..." />;
  }

  if (dashboardLoading) {
    return <LoadingState message="Loading dashboard..." />;
  }

  if (error || !dashboard) {
    return (
      <EmptyState
        icon={Shield}
        title="Error Loading Dashboard"
        description="Failed to load agent dashboard data. Please try again."
      />
    );
  }

  const { agent, daily_stats, trust_history, recent_activity } = dashboard;
  const dailyUsagePercent = agent.daily_limit_usd > 0
    ? (daily_stats.daily_spend / agent.daily_limit_usd) * 100
    : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Agent Dashboard</h1>
          <p className="text-muted-foreground">
            Real-time overview of your agent&apos;s activity and limits
          </p>
        </div>
        {/* Agent Selector */}
        {agents.length > 1 && (
          <select
            value={selectedAgentId}
            onChange={(e) => handleAgentChange(e.target.value)}
            className="px-3 py-2 rounded-md border bg-background text-sm"
          >
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Agent Identity Card */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <TrustScore score={agent.trust_score} size="lg" />
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-2xl font-bold">{agent.name}</h2>
                  <Badge variant={agent.status === "active" ? "success" : "secondary"}>
                    {agent.status}
                  </Badge>
                </div>
                <p className="text-muted-foreground">{agent.organization}</p>
                <code className="text-xs text-muted-foreground">
                  {truncateHash(agent.id, 12, 8)}
                </code>
              </div>
            </div>
            <div className="text-right">
              <p className="text-sm text-muted-foreground">Daily Limit</p>
              <p className="text-2xl font-bold">{formatCurrency(agent.daily_limit_usd)}</p>
              <p className="text-sm text-muted-foreground">
                {formatCurrency(daily_stats.daily_remaining)} remaining
              </p>
            </div>
          </div>
          {/* Daily Usage Bar */}
          <div className="mt-6">
            <div className="flex items-center justify-between text-sm mb-2">
              <span className="text-muted-foreground">Daily Usage</span>
              <span>{dailyUsagePercent.toFixed(1)}%</span>
            </div>
            <div className="h-2 bg-muted rounded-full overflow-hidden">
              <div
                className={`h-full transition-all ${
                  dailyUsagePercent > 80 ? "bg-red-500" : dailyUsagePercent > 50 ? "bg-yellow-500" : "bg-green-500"
                }`}
                style={{ width: `${Math.min(dailyUsagePercent, 100)}%` }}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-4">
        <StatsCard
          title="Total Actions"
          value={agent.total_actions_count.toLocaleString()}
          icon={Activity}
          description="All time"
        />
        <StatsCard
          title="Approved Today"
          value={daily_stats.approved_today.toString()}
          icon={CheckCircle}
          description="Since midnight UTC"
        />
        <StatsCard
          title="Blocked Today"
          value={daily_stats.blocked_today.toString()}
          icon={XCircle}
          description="Policy violations"
        />
        <StatsCard
          title="Per-Action Limit"
          value={formatCurrency(agent.per_action_limit_usd)}
          icon={Shield}
          description="Max per request"
        />
      </div>

      {/* Charts */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Trust Score History */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              Trust Score History
            </CardTitle>
            <CardDescription>Your trust score over the past 7 days</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[250px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trust_history}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="date" className="text-xs" />
                  <YAxis domain={[0, 100]} className="text-xs" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "8px",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="score"
                    stroke="hsl(var(--primary))"
                    fill="hsl(var(--primary))"
                    fillOpacity={0.2}
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              Recent Activity
            </CardTitle>
            <CardDescription>Your latest verification requests</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 max-h-[250px] overflow-y-auto">
              {recent_activity.length > 0 ? (
                recent_activity.map((activity) => (
                  <div
                    key={activity.id}
                    className="flex items-center justify-between py-2 border-b last:border-0"
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-2 h-2 rounded-full ${
                          activity.verdict === "approved"
                            ? "bg-green-500"
                            : activity.verdict === "blocked"
                            ? "bg-red-500"
                            : "bg-yellow-500"
                        }`}
                      />
                      <div>
                        <code className="text-sm">{activity.action_type}</code>
                        <p className="text-xs text-muted-foreground">
                          {formatRelative(activity.timestamp)}
                        </p>
                      </div>
                    </div>
                    <VerdictBadge verdict={activity.verdict} showIcon={false} />
                  </div>
                ))
              ) : (
                <p className="text-sm text-muted-foreground text-center py-4">
                  No recent activity
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Limits Overview */}
      <Card>
        <CardHeader>
          <CardTitle>Current Limits</CardTitle>
          <CardDescription>Your configured verification limits</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="p-4 border rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Daily Limit</span>
                <Badge variant="secondary">{dailyUsagePercent.toFixed(0)}% used</Badge>
              </div>
              <p className="text-xl font-bold">{formatCurrency(agent.daily_limit_usd)}</p>
              <p className="text-sm text-muted-foreground">
                {formatCurrency(daily_stats.daily_spend)} spent today
              </p>
            </div>
            <div className="p-4 border rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Per-Action Limit</span>
              </div>
              <p className="text-xl font-bold">{formatCurrency(agent.per_action_limit_usd)}</p>
              <p className="text-sm text-muted-foreground">Maximum per request</p>
            </div>
            <div className="p-4 border rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Rate Limit</span>
              </div>
              <p className="text-xl font-bold">{agent.rate_limit_per_minute}/min</p>
              <p className="text-sm text-muted-foreground">Requests per minute</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
