"use client";

import { useState } from "react";
import Link from "next/link";
import { AdminShell } from "@/components/admin/admin-shell";
import { useAdminFetch } from "@/lib/admin/use-admin-fetch";
import { mapAgents } from "@/lib/admin/mappers";
import type { MappedAgent, AgentStatus } from "@/lib/admin/types";
import { AdminEmptyState } from "@/components/admin/empty-state";
import { AdminErrorState } from "@/components/admin/error-state";
import { CopyableMonoValue } from "@/components/admin/copyable-mono-value";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableHeader,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { useRegisterAgent } from "@/lib/hooks";
import { Bot, Plus, Copy, Check } from "lucide-react";
import { formatDateTime, formatRelative, copyToClipboard } from "@/lib/utils";

const statusVariant: Record<AgentStatus, "success" | "destructive" | "warning" | "secondary"> = {
  active: "success",
  suspended: "warning",
  revoked: "destructive",
  pending_verification: "secondary",
};

const statusLabel: Record<AgentStatus, string> = {
  active: "Active",
  suspended: "Suspended",
  revoked: "Revoked",
  pending_verification: "Pending",
};

function AgentsContent() {
  const { data: agents, loading, error, refetch } = useAdminFetch<MappedAgent[]>(
    "/api/admin/agents",
    { transform: mapAgents, refetchInterval: 15_000 }
  );
  const [showRegisterDialog, setShowRegisterDialog] = useState(false);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Agent Registry</h1>
          <p className="text-sm text-[#7F8CA3]">All registered agents in your organization</p>
        </div>
        <Button onClick={() => setShowRegisterDialog(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Register Agent
        </Button>
      </div>

      {error ? (
        <AdminErrorState message="Failed to load agents" detail={error} onRetry={refetch} />
      ) : loading ? (
        <SkeletonRows count={6} />
      ) : !agents || agents.length === 0 ? (
        <AdminEmptyState
          icon={Bot}
          message="No agents found. Click 'Register Agent' to onboard your first agent."
        />
      ) : (
        <div className="rounded-xl border border-[#22314D] bg-[#0D1728]">
          <Table>
            <TableHeader>
              <TableRow className="border-[#22314D] hover:bg-transparent">
                <TableHead className="text-[#7F8CA3]">Agent Name</TableHead>
                <TableHead className="text-[#7F8CA3]">Agent ID</TableHead>
                <TableHead className="text-[#7F8CA3]">Status</TableHead>
                {agents.some((a) => a.trust_score !== undefined) && (
                  <TableHead className="text-[#7F8CA3]">Trust Score</TableHead>
                )}
                {agents.some((a) => a.total_actions_count !== undefined) && (
                  <TableHead className="text-[#7F8CA3]">Verifications</TableHead>
                )}
                <TableHead className="text-[#7F8CA3]">Last Active</TableHead>
                <TableHead className="text-[#7F8CA3]">Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {agents.map((agent) => (
                <TableRow key={agent.id} className="border-[#22314D]">
                  <TableCell>
                    <Link
                      href={`/admin/agents/${agent.id}`}
                      className="text-sm font-medium text-[#F5F7FB] hover:text-[#8FB8FF] hover:underline"
                    >
                      {agent.name || "Unnamed Agent"}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <CopyableMonoValue value={agent.id} />
                  </TableCell>
                  <TableCell>
                    {agent.status ? (
                      <Badge variant={statusVariant[agent.status]}>
                        {statusLabel[agent.status]}
                      </Badge>
                    ) : (
                      <span className="text-xs text-[#7F8CA3]">—</span>
                    )}
                  </TableCell>
                  {agents.some((a) => a.trust_score !== undefined) && (
                    <TableCell>
                      {agent.trust_score !== undefined ? (
                        <TrustScoreDisplay score={agent.trust_score} />
                      ) : (
                        <span className="text-xs text-[#7F8CA3]">—</span>
                      )}
                    </TableCell>
                  )}
                  {agents.some((a) => a.total_actions_count !== undefined) && (
                    <TableCell>
                      <span className="font-mono text-xs text-[#AAB7CC]">
                        {agent.total_actions_count ?? "—"}
                      </span>
                    </TableCell>
                  )}
                  <TableCell>
                    <span className="text-xs text-[#AAB7CC]">
                      {formatRelative(agent.last_action_at)}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span className="text-xs text-[#AAB7CC]">
                      {agent.created_at ? formatDateTime(agent.created_at) : "—"}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <RegisterAgentDialog
        open={showRegisterDialog}
        onOpenChange={setShowRegisterDialog}
        onSuccess={refetch}
      />
    </div>
  );
}

function RegisterAgentDialog({
  open,
  onOpenChange,
  onSuccess,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
}) {
  const registerAgent = useRegisterAgent();
  const [name, setName] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [dailyLimit, setDailyLimit] = useState("100");
  const [perActionLimit, setPerActionLimit] = useState("50");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [createdAgent, setCreatedAgent] = useState<{ agent_id: string; fingerprint: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const reset = () => {
    setName("");
    setPublicKey("");
    setDailyLimit("100");
    setPerActionLimit("50");
    setErrorMessage(null);
    setCreatedAgent(null);
    setCopied(false);
  };

  const handleClose = () => {
    onOpenChange(false);
    setTimeout(reset, 300);
  };

  const handleSubmit = async () => {
    setErrorMessage(null);

    if (!name.trim()) {
      setErrorMessage("Agent name is required");
      return;
    }
    const trimmedKey = publicKey.trim();
    if (!trimmedKey) {
      setErrorMessage("Public key is required");
      return;
    }
    // Backend constraint: min_length=44, max_length=64. Base64 of 32 bytes
    // is 44 chars (with padding); be forgiving about whitespace but reject
    // anything obviously wrong.
    if (trimmedKey.length < 44 || trimmedKey.length > 64) {
      setErrorMessage("Public key must be base64-encoded 32-byte Ed25519 (about 44 chars)");
      return;
    }

    const daily = Number(dailyLimit);
    const perAction = Number(perActionLimit);
    if (!Number.isFinite(daily) || daily < 0) {
      setErrorMessage("Daily limit must be a non-negative number");
      return;
    }
    if (!Number.isFinite(perAction) || perAction < 0) {
      setErrorMessage("Per-action limit must be a non-negative number");
      return;
    }

    try {
      const result = await registerAgent.mutateAsync({
        name: name.trim(),
        public_key: trimmedKey,
        daily_limit_usd: daily,
        per_action_limit_usd: perAction,
      });
      setCreatedAgent({
        agent_id: result.agent_id,
        fingerprint: result.public_key_fingerprint,
      });
      onSuccess();
    } catch (e) {
      setErrorMessage(e instanceof Error ? e.message : "Failed to register agent");
    }
  };

  const handleCopyAgentId = async () => {
    if (!createdAgent) return;
    await copyToClipboard(createdAgent.agent_id);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (createdAgent) {
    return (
      <Dialog open={open} onOpenChange={handleClose}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Agent Registered</DialogTitle>
            <DialogDescription>
              Share the agent ID with the partner — they use it as the{" "}
              <code>agent_id</code> field in every signed /verify call.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-1">
              <label className="text-xs uppercase tracking-wide text-muted-foreground">
                Agent ID
              </label>
              <div className="flex items-center gap-2 rounded-md bg-muted p-3">
                <code className="flex-1 break-all text-sm">{createdAgent.agent_id}</code>
                <Button variant="ghost" size="icon" onClick={handleCopyAgentId}>
                  {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>
            </div>
            <div className="space-y-1">
              <label className="text-xs uppercase tracking-wide text-muted-foreground">
                Public Key Fingerprint
              </label>
              <code className="block break-all rounded-md bg-muted p-3 text-xs text-muted-foreground">
                {createdAgent.fingerprint}
              </code>
            </div>
            <p className="text-xs text-muted-foreground">
              Status is <code>pending_verification</code> until the agent
              successfully completes its first /verify call.
            </p>
          </div>
          <DialogFooter>
            <Button onClick={handleClose}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Register Agent</DialogTitle>
          <DialogDescription>
            Onboard an agent in this organization. The agent operator generates
            an Ed25519 keypair locally and supplies the public key here — Inntris
            never sees the private key.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">Agent Name</label>
            <Input
              placeholder="e.g. Production Trading Bot"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={255}
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">Ed25519 Public Key (base64)</label>
            <Input
              placeholder="44-char base64 string"
              value={publicKey}
              onChange={(e) => setPublicKey(e.target.value)}
              spellCheck={false}
              className="font-mono text-xs"
            />
            <p className="text-xs text-muted-foreground">
              Generate locally:{" "}
              <code className="text-xs">
                python -c &quot;from nacl.signing import SigningKey; import base64;
                sk=SigningKey.generate(); print(base64.b64encode(bytes(sk.verify_key)).decode())&quot;
              </code>
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <label className="text-sm font-medium">Daily Limit (USD)</label>
              <Input
                type="number"
                min="0"
                step="0.01"
                value={dailyLimit}
                onChange={(e) => setDailyLimit(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Per-Action Limit (USD)</label>
              <Input
                type="number"
                min="0"
                step="0.01"
                value={perActionLimit}
                onChange={(e) => setPerActionLimit(e.target.value)}
              />
            </div>
          </div>
          {errorMessage && (
            <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
              {errorMessage}
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={registerAgent.isPending}>
            {registerAgent.isPending ? "Registering..." : "Register Agent"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function TrustScoreDisplay({ score }: { score: number }) {
  const color =
    score >= 70
      ? "text-green-400"
      : score >= 40
        ? "text-yellow-400"
        : "text-red-400";
  return (
    <span className={`font-mono text-xs font-medium ${color}`}>
      {score}
    </span>
  );
}

function SkeletonRows({ count }: { count: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="h-14 animate-pulse rounded-lg bg-[#0D1728]" />
      ))}
    </div>
  );
}

export default function AdminAgentsPage() {
  return (
    <AdminShell>
      <AgentsContent />
    </AdminShell>
  );
}
