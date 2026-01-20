"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { TrustScore } from "@/components/trust-score";
import { StatsCard } from "@/components/stats-card";
import { VerdictBadge } from "@/components/verdict-badge";
import { formatRelative, formatCurrency, truncateHash } from "@/lib/utils";
import {
  Shield,
  Activity,
  CheckCircle,
  XCircle,
  Clock,
  TrendingUp,
} from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
} from "recharts";
import type { ActionVerdict } from "@/lib/api";

// Mock data for the agent portal
const mockAgentInfo = {
  id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  name: "PaymentBot",
  status: "active",
  trust_score: 85,
  organization: "Acme Corporation",
  daily_limit_usd: 10000,
  per_action_limit_usd: 500,
  daily_spend: 2345.67,
  total_actions: 5234,
  approved_today: 142,
  blocked_today: 3,
};

const mockTrustHistory = [
  { date: "Mon", score: 78 },
  { date: "Tue", score: 80 },
  { date: "Wed", score: 82 },
  { date: "Thu", score: 79 },
  { date: "Fri", score: 83 },
  { date: "Sat", score: 85 },
  { date: "Sun", score: 85 },
];

const mockRecentActivity = [
  {
    id: "1",
    action_type: "financial_transaction",
    verdict: "approved" as ActionVerdict,
    timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    payload: { amount: 150.0, currency: "USD" },
  },
  {
    id: "2",
    action_type: "api_call",
    verdict: "approved" as ActionVerdict,
    timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
    payload: { endpoint: "/api/orders" },
  },
  {
    id: "3",
    action_type: "financial_transaction",
    verdict: "blocked" as ActionVerdict,
    timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    payload: { amount: 5000.0, currency: "USD", reason: "Exceeds per-action limit" },
  },
  {
    id: "4",
    action_type: "email_send",
    verdict: "approved" as ActionVerdict,
    timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
    payload: { to: "customer@example.com" },
  },
  {
    id: "5",
    action_type: "api_call",
    verdict: "rate_limited" as ActionVerdict,
    timestamp: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
    payload: { endpoint: "/api/batch" },
  },
];

export default function PortalDashboard() {
  const remainingDailyLimit = mockAgentInfo.daily_limit_usd - mockAgentInfo.daily_spend;
  const dailyUsagePercent = (mockAgentInfo.daily_spend / mockAgentInfo.daily_limit_usd) * 100;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Agent Dashboard</h1>
        <p className="text-muted-foreground">
          Monitor your agent's verification status and activity
        </p>
      </div>

      {/* Agent Identity Card */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <TrustScore score={mockAgentInfo.trust_score} size="lg" />
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-2xl font-bold">{mockAgentInfo.name}</h2>
                  <Badge variant="outline" className="bg-green-500/10 text-green-500">
                    {mockAgentInfo.status}
                  </Badge>
                </div>
                <p className="text-muted-foreground">{mockAgentInfo.organization}</p>
                <code className="text-xs text-muted-foreground">
                  {truncateHash(mockAgentInfo.id, 12, 8)}
                </code>
              </div>
            </div>
            <div className="text-right">
              <p className="text-sm text-muted-foreground">Daily Limit</p>
              <p className="text-2xl font-bold">{formatCurrency(mockAgentInfo.daily_limit_usd)}</p>
              <p className="text-sm text-muted-foreground">
                {formatCurrency(remainingDailyLimit)} remaining
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
                style={{ width: `${dailyUsagePercent}%` }}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-4">
        <StatsCard
          title="Total Actions"
          value={mockAgentInfo.total_actions.toLocaleString()}
          icon={Activity}
          description="All time"
        />
        <StatsCard
          title="Approved Today"
          value={mockAgentInfo.approved_today}
          icon={CheckCircle}
          trend={{ value: 8.2, label: "vs yesterday" }}
        />
        <StatsCard
          title="Blocked Today"
          value={mockAgentInfo.blocked_today}
          icon={XCircle}
          description="Policy violations"
        />
        <StatsCard
          title="Per-Action Limit"
          value={formatCurrency(mockAgentInfo.per_action_limit_usd)}
          icon={Shield}
          description="Max per request"
        />
      </div>

      {/* Charts */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Trust Score History */}
        <Card>
          <CardHeader>
            <CardTitle>Trust Score History</CardTitle>
            <CardDescription>Your trust score over the past 7 days</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[250px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={mockTrustHistory}>
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
            <CardTitle>Recent Activity</CardTitle>
            <CardDescription>Your latest verification requests</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {mockRecentActivity.map((activity) => (
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
              ))}
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
              <p className="text-xl font-bold">{formatCurrency(mockAgentInfo.daily_limit_usd)}</p>
              <p className="text-sm text-muted-foreground">
                {formatCurrency(mockAgentInfo.daily_spend)} spent today
              </p>
            </div>
            <div className="p-4 border rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Per-Action Limit</span>
              </div>
              <p className="text-xl font-bold">{formatCurrency(mockAgentInfo.per_action_limit_usd)}</p>
              <p className="text-sm text-muted-foreground">Maximum per request</p>
            </div>
            <div className="p-4 border rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Rate Limit</span>
              </div>
              <p className="text-xl font-bold">60/min</p>
              <p className="text-sm text-muted-foreground">Requests per minute</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
