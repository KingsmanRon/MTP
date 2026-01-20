"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { TrustScore } from "@/components/trust-score";
import { VerdictBadge } from "@/components/verdict-badge";
import { formatDateTime, formatCurrency, copyToClipboard } from "@/lib/utils";
import {
  ArrowLeft,
  Copy,
  Check,
  Shield,
  AlertTriangle,
  Settings,
  Activity,
  Pause,
  Play,
  Trash2,
} from "lucide-react";
import type { AgentStatus, ActionVerdict } from "@/lib/api";

// Mock data for single agent
const mockAgent = {
  id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  name: "PaymentBot",
  status: "active" as AgentStatus,
  trust_score: 85,
  public_key_fingerprint: "sha256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  daily_limit_usd: 10000,
  per_action_limit_usd: 500,
  allowed_actions: ["financial_transaction", "api_call", "email_send"],
  blocked_actions: ["admin_action"],
  rate_limit_per_minute: 60,
  total_actions_count: 5234,
  total_blocked_count: 127,
  last_action_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
  created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
  updated_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
  metadata: {
    description: "Handles payment processing for e-commerce platform",
    owner: "payments-team@company.com",
  },
};

const mockRecentLogs = [
  {
    id: "log1",
    action_type: "financial_transaction",
    verdict: "approved" as ActionVerdict,
    timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    payload: { amount: 150.0, currency: "USD" },
  },
  {
    id: "log2",
    action_type: "api_call",
    verdict: "approved" as ActionVerdict,
    timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
    payload: { endpoint: "/api/orders" },
  },
  {
    id: "log3",
    action_type: "financial_transaction",
    verdict: "blocked" as ActionVerdict,
    timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    payload: { amount: 5000.0, currency: "USD" },
  },
  {
    id: "log4",
    action_type: "email_send",
    verdict: "approved" as ActionVerdict,
    timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
    payload: { to: "customer@example.com", subject: "Order Confirmation" },
  },
];

const statusColors: Record<AgentStatus, string> = {
  active: "bg-green-500/10 text-green-500 border-green-500/20",
  suspended: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  revoked: "bg-red-500/10 text-red-500 border-red-500/20",
  pending_verification: "bg-blue-500/10 text-blue-500 border-blue-500/20",
};

export default function AgentDetailPage() {
  const params = useParams();
  const [copied, setCopied] = useState(false);
  const [dailyLimit, setDailyLimit] = useState(mockAgent.daily_limit_usd.toString());
  const [perActionLimit, setPerActionLimit] = useState(mockAgent.per_action_limit_usd.toString());

  const handleCopyId = async () => {
    await copyToClipboard(mockAgent.id);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link href="/admin/agents">
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold">{mockAgent.name}</h1>
            <Badge variant="outline" className={statusColors[mockAgent.status]}>
              {mockAgent.status}
            </Badge>
          </div>
          <div className="flex items-center gap-2 mt-1">
            <code className="text-sm text-muted-foreground">{mockAgent.id}</code>
            <button onClick={handleCopyId} className="text-muted-foreground hover:text-foreground">
              {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            </button>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {mockAgent.status === "active" ? (
            <Button variant="outline">
              <Pause className="h-4 w-4 mr-2" />
              Suspend
            </Button>
          ) : (
            <Button variant="outline">
              <Play className="h-4 w-4 mr-2" />
              Activate
            </Button>
          )}
          <Button variant="destructive">
            <Trash2 className="h-4 w-4 mr-2" />
            Revoke
          </Button>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Trust Score</p>
                <p className="text-2xl font-bold">{mockAgent.trust_score}/100</p>
              </div>
              <TrustScore score={mockAgent.trust_score} size="sm" showLabel={false} />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Total Actions</p>
            <p className="text-2xl font-bold">{mockAgent.total_actions_count.toLocaleString()}</p>
            <p className="text-xs text-muted-foreground mt-1">
              {mockAgent.total_blocked_count} blocked
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Daily Limit</p>
            <p className="text-2xl font-bold">{formatCurrency(mockAgent.daily_limit_usd)}</p>
            <p className="text-xs text-muted-foreground mt-1">
              {formatCurrency(mockAgent.per_action_limit_usd)} per action
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Rate Limit</p>
            <p className="text-2xl font-bold">{mockAgent.rate_limit_per_minute}/min</p>
            <p className="text-xs text-muted-foreground mt-1">Requests per minute</p>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="activity">
        <TabsList>
          <TabsTrigger value="activity">
            <Activity className="h-4 w-4 mr-2" />
            Activity
          </TabsTrigger>
          <TabsTrigger value="policies">
            <Shield className="h-4 w-4 mr-2" />
            Policies
          </TabsTrigger>
          <TabsTrigger value="settings">
            <Settings className="h-4 w-4 mr-2" />
            Settings
          </TabsTrigger>
        </TabsList>

        {/* Activity Tab */}
        <TabsContent value="activity">
          <Card>
            <CardHeader>
              <CardTitle>Recent Activity</CardTitle>
              <CardDescription>Latest verification requests from this agent</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Action Type</TableHead>
                    <TableHead>Payload</TableHead>
                    <TableHead>Verdict</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {mockRecentLogs.map((log) => (
                    <TableRow key={log.id}>
                      <TableCell className="text-muted-foreground">
                        {formatDateTime(log.timestamp)}
                      </TableCell>
                      <TableCell>
                        <code className="text-sm">{log.action_type}</code>
                      </TableCell>
                      <TableCell>
                        <code className="text-xs text-muted-foreground">
                          {JSON.stringify(log.payload).slice(0, 50)}...
                        </code>
                      </TableCell>
                      <TableCell>
                        <VerdictBadge verdict={log.verdict} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Policies Tab */}
        <TabsContent value="policies">
          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Allowed Actions</CardTitle>
                <CardDescription>Action types this agent can perform</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {mockAgent.allowed_actions.map((action) => (
                    <Badge key={action} variant="secondary">
                      {action}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Blocked Actions</CardTitle>
                <CardDescription>Action types explicitly blocked</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {mockAgent.blocked_actions.map((action) => (
                    <Badge key={action} variant="destructive">
                      {action}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Settings Tab */}
        <TabsContent value="settings">
          <Card>
            <CardHeader>
              <CardTitle>Agent Configuration</CardTitle>
              <CardDescription>Update agent limits and settings</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Daily Limit (USD)</label>
                  <Input
                    type="number"
                    value={dailyLimit}
                    onChange={(e) => setDailyLimit(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Per-Action Limit (USD)</label>
                  <Input
                    type="number"
                    value={perActionLimit}
                    onChange={(e) => setPerActionLimit(e.target.value)}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Public Key Fingerprint</label>
                <code className="block p-3 bg-muted rounded-md text-sm">
                  {mockAgent.public_key_fingerprint}
                </code>
              </div>
              <div className="flex justify-end">
                <Button>Save Changes</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
