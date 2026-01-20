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
import { formatRelative, formatCurrency, truncateHash } from "@/lib/utils";
import { Bot, Plus, Search, MoreVertical, Copy, ExternalLink } from "lucide-react";
import type { AgentStatus } from "@/lib/api";

// Mock data
const mockAgents = [
  {
    id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    name: "PaymentBot",
    status: "active" as AgentStatus,
    trust_score: 85,
    public_key_fingerprint: "sha256:a1b2c3d4e5f6...",
    daily_limit_usd: 10000,
    per_action_limit_usd: 500,
    total_actions_count: 5234,
    last_action_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: "b2c3d4e5-f6a7-8901-bcde-f12345678901",
    name: "DataExporter",
    status: "active" as AgentStatus,
    trust_score: 42,
    public_key_fingerprint: "sha256:b2c3d4e5f6a7...",
    daily_limit_usd: 5000,
    per_action_limit_usd: 200,
    total_actions_count: 1892,
    last_action_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    created_at: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: "c3d4e5f6-a7b8-9012-cdef-123456789012",
    name: "EmailAgent",
    status: "suspended" as AgentStatus,
    trust_score: 28,
    public_key_fingerprint: "sha256:c3d4e5f6a7b8...",
    daily_limit_usd: 1000,
    per_action_limit_usd: 50,
    total_actions_count: 456,
    last_action_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
    created_at: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(),
  },
];

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

  const filteredAgents = mockAgents.filter((agent) =>
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
                      <Badge variant="outline" className={statusColors[agent.status]}>
                        {agent.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <TrustScoreBadge score={agent.trust_score} />
                    </TableCell>
                    <TableCell>{formatCurrency(agent.daily_limit_usd)}</TableCell>
                    <TableCell>{agent.total_actions_count.toLocaleString()}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {formatRelative(agent.last_action_at)}
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
