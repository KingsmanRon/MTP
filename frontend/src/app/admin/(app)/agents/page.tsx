"use client";

import { useState } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { TrustScoreBadge } from "@/components/trust-score";
import { EmptyState } from "@/components/empty-state";
import { LoadingState } from "@/components/loading-state";
import { formatRelative, formatCurrency, truncateHash } from "@/lib/utils";
import { useAgents } from "@/lib/hooks";
import { Bot, Plus, Search, ExternalLink, AlertCircle } from "lucide-react";
import type { AgentStatus } from "@/lib/api";

const statusColors: Record<AgentStatus, string> = {
  active: "bg-green-500/10 text-green-500 border-green-500/20",
  suspended: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  revoked: "bg-red-500/10 text-red-500 border-red-500/20",
  pending_verification: "bg-blue-500/10 text-blue-500 border-blue-500/20",
};

export default function AgentsPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newAgentName, setNewAgentName] = useState("");
  const [newAgentPublicKey, setNewAgentPublicKey] = useState("");

  const { data: agents, isLoading, error } = useAgents();

  if (isLoading) {
    return <LoadingState message="Loading agents..." />;
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <AlertCircle className="h-12 w-12 text-destructive mb-4" />
        <h2 className="text-xl font-semibold mb-2">Failed to load agents</h2>
        <p className="text-muted-foreground">Please check your API connection and try again.</p>
      </div>
    );
  }

  const filteredAgents = (agents || []).filter((agent) =>
    agent.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Agents</h1>
          <p className="text-muted-foreground">
            Manage AI agents registered with your organization
          </p>
        </div>
        <Button onClick={() => setShowCreateDialog(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Register Agent
        </Button>
      </div>

      {/* Search and Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search agents..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Agents Table */}
      <Card>
        <CardHeader>
          <CardTitle>Registered Agents</CardTitle>
          <CardDescription>
            {filteredAgents.length} agent{filteredAgents.length !== 1 ? "s" : ""} registered
          </CardDescription>
        </CardHeader>
        <CardContent>
          {filteredAgents.length === 0 ? (
            <EmptyState
              icon={Bot}
              title="No agents found"
              description="Register your first agent to start verifying AI actions."
              action={
                <Button onClick={() => setShowCreateDialog(true)}>
                  <Plus className="h-4 w-4 mr-2" />
                  Register Agent
                </Button>
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agent</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Trust Score</TableHead>
                  <TableHead>Daily Limit</TableHead>
                  <TableHead>Actions</TableHead>
                  <TableHead>Last Active</TableHead>
                  <TableHead className="w-[50px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAgents.map((agent) => (
                  <TableRow key={agent.id}>
                    <TableCell>
                      <div>
                        <Link
                          href={`/admin/agents/${agent.id}`}
                          className="font-medium hover:underline"
                        >
                          {agent.name}
                        </Link>
                        <p className="text-xs text-muted-foreground font-mono">
                          {truncateHash(agent.id, 8, 4)}
                        </p>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={statusColors[agent.status as AgentStatus]}>
                        {agent.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <TrustScoreBadge score={agent.trust_score} />
                    </TableCell>
                    <TableCell>{formatCurrency(agent.daily_limit_usd)}</TableCell>
                    <TableCell>{agent.total_actions_count.toLocaleString()}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {agent.last_action_at ? formatRelative(agent.last_action_at) : "Never"}
                    </TableCell>
                    <TableCell>
                      <Link href={`/admin/agents/${agent.id}`}>
                        <Button variant="ghost" size="icon">
                          <ExternalLink className="h-4 w-4" />
                        </Button>
                      </Link>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create Agent Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Register New Agent</DialogTitle>
            <DialogDescription>
              Register a new AI agent with your organization. You'll need the agent's Ed25519 public key.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Agent Name</label>
              <Input
                placeholder="e.g., PaymentBot"
                value={newAgentName}
                onChange={(e) => setNewAgentName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Public Key (Base64)</label>
              <Input
                placeholder="Base64-encoded Ed25519 public key"
                value={newAgentPublicKey}
                onChange={(e) => setNewAgentPublicKey(e.target.value)}
                className="font-mono text-sm"
              />
              <p className="text-xs text-muted-foreground">
                The 32-byte Ed25519 public key encoded in Base64
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
              Cancel
            </Button>
            <Button onClick={() => setShowCreateDialog(false)}>
              Register Agent
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
