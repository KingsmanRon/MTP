"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  FileCode2,
  GitBranch,
  KeyRound,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import type { MappedAgent, MappedAuditLog } from "@/lib/admin/types";
import { AdminVerdictBadge } from "@/components/admin/verdict-badge";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { copyToClipboard, formatDateTime } from "@/lib/utils";

const CI_ACTION_TYPES = [
  "repo_change",
  "ci_workflow_change",
  "protected_branch_merge",
  "production_deployment",
];

function buildWorkflowYaml(agentId: string) {
  return `name: CI Guard
on:
  pull_request:
  push:
    branches:
      - main

jobs:
  inntris-ci-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    steps:
      - uses: actions/checkout@v4
      - uses: inntris/inntris-verify@v1
        with:
          api-url: \${{ secrets.INNTRIS_API_URL }}
          agent-id: ${agentId}
          private-key-b64: \${{ secrets.INNTRIS_PRIVATE_KEY_B64 }}
          action-type: repo_change`;
}

function statusTone(ok: boolean) {
  return ok
    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
    : "border-amber-500/30 bg-amber-500/10 text-amber-300";
}

export function CiGuardPanel({
  agent,
  auditLogs,
}: {
  agent: MappedAgent;
  auditLogs: MappedAuditLog[];
}) {
  const [copied, setCopied] = useState(false);
  const workflowYaml = useMemo(() => buildWorkflowYaml(agent.id), [agent.id]);
  const allowedActions = agent.allowed_actions ?? [];
  const enabledCiActions = CI_ACTION_TYPES.filter((action) =>
    allowedActions.includes(action)
  );
  const blockedCiActions = agent.blocked_actions?.filter((action) =>
    CI_ACTION_TYPES.includes(action)
  ) ?? [];
  const latestCiLogs = auditLogs
    .filter((log) => log.action_type && CI_ACTION_TYPES.includes(log.action_type))
    .slice(0, 5);
  const agentActive = agent.status === "active";
  const hasCiPolicy = enabledCiActions.length > 0;

  const copyYaml = async () => {
    const ok = await copyToClipboard(workflowYaml);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  return (
    <div className="space-y-6">
      <div className="grid gap-3 md:grid-cols-3">
        <StatusTile
          icon={ShieldCheck}
          label="Agent"
          value={agentActive ? "Active" : "Not active"}
          ok={agentActive}
        />
        <StatusTile
          icon={GitBranch}
          label="CI policy"
          value={hasCiPolicy ? `${enabledCiActions.length} action${enabledCiActions.length === 1 ? "" : "s"}` : "Not allowed"}
          ok={hasCiPolicy}
        />
        <StatusTile
          icon={KeyRound}
          label="Secrets"
          value="2 required"
          ok
        />
      </div>

      <div className="rounded-lg border border-[#22314D] bg-[#101C31] p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <FileCode2 className="h-4 w-4 text-[#8FB8FF]" />
            <h2 className="text-sm font-semibold text-[#F5F7FB]">Workflow</h2>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={copyYaml}
            className="border-[#22314D] bg-[#0D1728] text-[#AAB7CC]"
          >
            {copied ? <Check className="mr-2 h-3.5 w-3.5" /> : <Copy className="mr-2 h-3.5 w-3.5" />}
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
        <pre className="mt-4 max-h-[360px] overflow-auto rounded-md border border-[#22314D] bg-[#07101F] p-4 text-xs leading-5 text-[#D7E3F8]">
          <code>{workflowYaml}</code>
        </pre>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_1.4fr]">
        <div className="rounded-lg border border-[#22314D] bg-[#101C31] p-4">
          <h2 className="text-sm font-semibold text-[#F5F7FB]">Secrets</h2>
          <div className="mt-4 space-y-3">
            <SecretRow name="INNTRIS_API_URL" value="Core API base URL" />
            <SecretRow name="INNTRIS_PRIVATE_KEY_B64" value="Agent Ed25519 private key seed" />
          </div>
        </div>

        <div className="rounded-lg border border-[#22314D] bg-[#101C31] p-4">
          <h2 className="text-sm font-semibold text-[#F5F7FB]">Policy Mapping</h2>
          <div className="mt-4 flex flex-wrap gap-2">
            {CI_ACTION_TYPES.map((action) => {
              const allowed = enabledCiActions.includes(action);
              const blocked = blockedCiActions.includes(action);
              return (
                <Badge
                  key={action}
                  variant={allowed ? "success" : blocked ? "destructive" : "secondary"}
                  className="font-mono"
                >
                  {action}
                </Badge>
              );
            })}
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-[#22314D] bg-[#101C31] p-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-[#F5F7FB]">Latest CI Decisions</h2>
          <Link
            href={`/admin/audit?agent_id=${agent.id}`}
            className="inline-flex items-center gap-1 text-xs text-[#8FB8FF] hover:underline"
          >
            Audit log
            <ExternalLink className="h-3 w-3" />
          </Link>
        </div>

        {latestCiLogs.length === 0 ? (
          <div className="mt-4 rounded-md border border-[#22314D] bg-[#07101F] p-4 text-sm text-[#7F8CA3]">
            No CI decisions recorded yet.
          </div>
        ) : (
          <div className="mt-4 divide-y divide-[#22314D] overflow-hidden rounded-md border border-[#22314D]">
            {latestCiLogs.map((log) => (
              <Link
                key={log.id}
                href={`/admin/audit/${log.id}`}
                className="grid gap-3 bg-[#07101F] p-3 transition hover:bg-[#0D1728] sm:grid-cols-[1fr_auto_auto]"
              >
                <div>
                  <p className="font-mono text-xs text-[#F5F7FB]">{log.action_type}</p>
                  <p className="mt-1 text-xs text-[#7F8CA3]">
                    {formatDateTime(log.timestamp)}
                  </p>
                </div>
                {log.verdict && <AdminVerdictBadge verdict={log.verdict} />}
                <span className="font-mono text-xs text-[#7F8CA3]">
                  {log.response_time_ms ?? 0}ms
                </span>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function StatusTile({
  icon: Icon,
  label,
  value,
  ok,
}: {
  icon: typeof ShieldCheck;
  label: string;
  value: string;
  ok: boolean;
}) {
  return (
    <div className={`rounded-lg border p-4 ${statusTone(ok)}`}>
      <div className="flex items-center gap-2">
        {ok ? <CheckCircle2 className="h-4 w-4" /> : <TriangleAlert className="h-4 w-4" />}
        <span className="text-xs font-medium uppercase">{label}</span>
      </div>
      <div className="mt-3 flex items-center gap-2">
        <Icon className="h-4 w-4" />
        <span className="text-sm font-semibold">{value}</span>
      </div>
    </div>
  );
}

function SecretRow({ name, value }: { name: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-[#22314D] bg-[#07101F] p-3">
      <span className="font-mono text-xs text-[#D7E3F8]">{name}</span>
      <span className="text-xs text-[#7F8CA3]">{value}</span>
    </div>
  );
}
