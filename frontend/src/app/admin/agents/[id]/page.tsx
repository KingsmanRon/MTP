"use client";

import { useState, useEffect } from "react";
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
import { LoadingState } from "@/components/loading-state";
import { formatDateTime, formatCurrency, copyToClipboard } from "@/lib/utils";
import { useAgent, useAuditLogs, useUpdateAgentStatus } from "@/lib/hooks";
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
  AlertCircle,
} from "lucide-react";
import type { AgentStatus, ActionVerdict } from "@/lib/api";

const statusColors: Record<AgentStatus, string> = {
  active: "bg-green-500/10 text-green-500 border-green-500/20",
  suspended: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  revoked: "bg-red-500/10 text-red-500 border-red-500/20",
  pending_verification: "bg-blue-500/10 text-blue-500 border-blue-500/20",
};

export default function AgentDetailPage() {
  const params = useParams();
  const agentId = params.id as string;

  const [copied, setCopied] = useState(false);
  const [dailyLimit, setDailyLimit] = useState("");
  const [perActionLimit, setPerActionLimit] = useState("");

  const { data: agent, isLoading: agentLoading, error: agentError } = useAgent(agentId);
  const { data: auditData, isLoading: logsLoading } = useAuditLogs({
    agent_id: agentId,
    limit: 10,
  });
  const updateStatus = useUpdateAgentStatus();

  // Update form state when agent data loads
  useEffect(() => {
    if (agent) {
      setDailyLimit(agent.daily_limit_usd.toString());
      setPerActionLimit(agent.per_action_limit_usd.toString());
    }
  }, [agent]);

  const handleCopyId = async () => {
    if (agent) {
      await copyToClipboard(agent.id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleStatusChange = async (newStatus: AgentStatus) => {
    try {
      await updateStatus.mutateAsync({ agentId, status: newStatus });
    } catch (err) {
      console.error("Failed to update agent status:", err);
    }
  };

  if (agentLoading) {
    return <LoadingState message="Loading agent..." />;
  }

  if (agentError || !agent) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <AlertCircle className="h-12 w-12 text-destructive mb-4" />
        <h2 className="text-xl font-semibold mb-2">Failed to load agent</h2>
        <p className="text-muted-foreground">Please check your API connection and try again.</p>
        <Link href="/admin/agents" className="mt-4">
          <Button variant="outline">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Agents
          </Button>
        </Link>
      </div>
    );
  }

  const recentLogs = auditData?.logs || [];

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
            <h1 className="text-3xl font-bold">{agent.name}</h1>
            <Badge variant="outline" className={statusColors[agent.status]}>
              {agent.status}
            </Badge>
          </div>
          <div className="flex items-center gap-2 mt-1">
            <code className="text-sm text-muted-foreground">{agent.id}</code>
            <button onClick={handleCopyId} className="text-muted-foreground hover:text-foreground">
              {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            </button>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {agent.status === "active" ? (
            <Button
              variant="outline"
              onClick={() => handleStatusChange("suspended")}
              disabled={updateStatus.isPending}
            >
              <Pause className="h-4 w-4 mr-2" />
              Suspend
            </Button>
          ) : agent.status === "suspended" || agent.status === "pending_verification" ? (
            <Button
              variant="outline"
              onClick={() => handleStatusChange("active")}
              disabled={updateStatus.isPending}
            >
              <Play className="h-4 w-4 mr-2" />
              Activate
            </Button>
          ) : null}
          <Button
            variant="destructive"
            onClick={() => handleStatusChange("revoked")}
            disabled={updateStatus.isPending || agent.status === "revoked"}
          >
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
                <p className="text-2xl font-bold">{agent.trust_score}/100</p>
              </div>
              <TrustScore score={agent.trust_score} size="sm" showLabel={false} />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Total Actions</p>
            <p className="text-2xl font-bold">{agent.total_actions_count.toLocaleString()}</p>
            <p className="text-xs text-muted-foreground mt-1">
              {agent.total_blocked_count} blocked
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Daily Limit</p>
            <p className="text-2xl font-bold">{formatCurrency(agent.daily_limit_usd)}</p>
            <p className="text-xs text-muted-foreground mt-1">
              {formatCurrency(agent.per_action_limit_usd)} per action
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Rate Limit</p>
            <p className="text-2xl font-bold">{agent.rate_limit_per_minute}/min</p>
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
                  {recentLogs.map((log) => (
                    <TableRow key={log.id}>
                      <TableCell className="text-muted-foreground">
                        {formatDateTime(log.timestamp)}
                      </TableCell>
                      <TableCell>
                        <span className="inline-block text-sm font-mono bg-muted px-1.5 py-0.5 rounded">{log.action_type}</span>
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
                  {agent.allowed_actions.map((action) => (
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
                  {agent.blocked_actions.map((action) => (
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
                  {agent.public_key_fingerprint}
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
