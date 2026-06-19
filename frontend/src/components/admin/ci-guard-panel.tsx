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
import {
  ACTION_TRUST_THRESHOLDS,
  CONTROLLED_ACTIONS,
  type ControlledActionId,
} from "@/lib/agent-controls";
import { copyToClipboard, formatDateTime } from "@/lib/utils";

// The four code/release action types the AI PR Guard verifies. Ordered
// strongest-first to mirror the action's reduction priority.
const CODE_RELEASE_ACTIONS = CONTROLLED_ACTIONS.filter(
  (action) => action.group === "code_release",
);
const CI_ACTION_TYPES = CODE_RELEASE_ACTIONS.map((action) => action.id) as string[];

// The required-paths model the action reads from .inntris.yml. Shown here so a
// buyer can copy a working policy into their repo — the repo file remains the
// source of truth.
const POLICY_YAML = `version: 1

protected_paths:
  - src/auth/**
  - src/session/**
  - src/tenant/**
  - src/phi/**
  - src/patient/**
  - src/middleware.ts
  - database/migrations/**
  - supabase/migrations/**
  - .github/workflows/**
  - infra/**
  - "**/.env*"

low_risk_paths:
  - docs/**
  - README.md
  - src/components/**

mapping:
  ci_workflow_change:
    - .github/workflows/**
  production_deployment:
    - infra/**
    - deploy/**
    - terraform/**
    - k8s/**
  protected_branch_merge:
    - src/auth/**
    - src/session/**
    - src/tenant/**
    - src/phi/**
    - src/patient/**
    - src/middleware.ts
    - database/migrations/**
    - supabase/migrations/**
  repo_change:
    - docs/**
    - README.md
    - src/components/**`;

function buildWorkflowYaml(agentId: string) {
  return `name: Inntris AI PR Guard

on:
  pull_request:
    branches:
      - main

jobs:
  inntris-ai-pr-guard:
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
          policy-file: .inntris.yml
          mode: ai-pr-guard
          fail-on-block: true`;
}

function thresholdLabel(action: string) {
  const threshold = ACTION_TRUST_THRESHOLDS[action as ControlledActionId];
  return threshold == null ? "Attestation" : `Trust ≥ ${threshold}`;
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
  const [copied, setCopied] = useState<"workflow" | "policy" | null>(null);
  const workflowYaml = useMemo(() => buildWorkflowYaml(agent.id), [agent.id]);

  const allowedActions = agent.allowed_actions ?? [];
  const blockedActions = agent.blocked_actions ?? [];
  const enabledCiActions = CI_ACTION_TYPES.filter((action) =>
    allowedActions.includes(action),
  );
  const blockedCiActions = blockedActions.filter((action) =>
    CI_ACTION_TYPES.includes(action),
  );
  const latestCiLogs = auditLogs
    .filter((log) => log.action_type && CI_ACTION_TYPES.includes(log.action_type))
    .slice(0, 5);

  const agentActive = agent.status === "active";
  // "Ready" means every code/release action is allowed, so a verification
  // BLOCK reflects trust score — not an ACTION_NOT_ALLOWED misconfiguration.
  const actionsReady = CI_ACTION_TYPES.every((action) =>
    allowedActions.includes(action),
  );

  const copy = async (which: "workflow" | "policy", value: string) => {
    const ok = await copyToClipboard(value);
    if (ok) {
      setCopied(which);
      setTimeout(() => setCopied((prev) => (prev === which ? null : prev)), 1500);
    }
  };

  return (
    <div className="space-y-6">
      {/* Four product-specific statuses */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatusTile
          icon={ShieldCheck}
          label="Agent"
          value={agentActive ? "Active" : "Suspended"}
          ok={agentActive}
        />
        <StatusTile
          icon={KeyRound}
          label="Required secrets"
          value="Confirm 2 in repo"
          ok={false}
          hint="Set in GitHub repo secrets"
        />
        <StatusTile
          icon={GitBranch}
          label="Code/release actions"
          value={actionsReady ? "Ready" : "Misconfigured"}
          ok={actionsReady}
          hint={actionsReady ? "All 4 allowed" : "Allow all 4 so blocks reflect trust"}
        />
        <StatusTile
          icon={CheckCircle2}
          label="Branch protection"
          value="Manual confirmation"
          ok={false}
          hint="Make the check required on main"
        />
      </div>

      {!actionsReady && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
          <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            One or more code/release actions are blocked for this agent. The guard will
            BLOCK with <span className="font-mono">ACTION_NOT_ALLOWED</span> instead of on
            trust score. Apply the <span className="font-semibold">Regulated AI PR Gate</span>{" "}
            preset in the Policy tab so all four are allowed and trust does the gating.
          </span>
        </div>
      )}

      {/* Workflow */}
      <CodeBlock
        title="Workflow (.github/workflows/inntris-ai-pr-guard.yml)"
        code={workflowYaml}
        copied={copied === "workflow"}
        onCopy={() => copy("workflow", workflowYaml)}
      />

      {/* Policy file */}
      <CodeBlock
        title="Policy (.inntris.yml)"
        code={POLICY_YAML}
        copied={copied === "policy"}
        onCopy={() => copy("policy", POLICY_YAML)}
      />

      <div className="grid gap-4 lg:grid-cols-[1fr_1.4fr]">
        <div className="rounded-lg border border-[#22314D] bg-[#101C31] p-4">
          <h2 className="text-sm font-semibold text-[#F5F7FB]">Secrets</h2>
          <div className="mt-4 space-y-3">
            <SecretRow name="INNTRIS_API_URL" value="Core API base URL" />
            <SecretRow name="INNTRIS_PRIVATE_KEY_B64" value="Agent Ed25519 private key seed" />
          </div>
        </div>

        <div className="rounded-lg border border-[#22314D] bg-[#101C31] p-4">
          <h2 className="text-sm font-semibold text-[#F5F7FB]">Action mapping &amp; gates</h2>
          <p className="mt-1 text-xs text-[#7F8CA3]">
            Changed paths map to the strongest action type. repo_change is attestation;
            the rest BLOCK below their trust threshold.
          </p>
          <div className="mt-4 space-y-2">
            {CODE_RELEASE_ACTIONS.map((action) => {
              const allowed = enabledCiActions.includes(action.id);
              const blocked = blockedCiActions.includes(action.id);
              return (
                <div
                  key={action.id}
                  className="flex items-center justify-between gap-3 rounded-md border border-[#22314D] bg-[#07101F] p-3"
                >
                  <div className="min-w-0">
                    <p className="font-mono text-xs text-[#F5F7FB]">{action.id}</p>
                    <p className="mt-0.5 truncate text-xs text-[#7F8CA3]">
                      {action.description}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <Badge variant="secondary" className="font-mono text-[10px]">
                      {thresholdLabel(action.id)}
                    </Badge>
                    <Badge
                      variant={allowed ? "success" : blocked ? "destructive" : "secondary"}
                      className="text-[10px]"
                    >
                      {allowed ? "Allowed" : blocked ? "Blocked" : "—"}
                    </Badge>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Latest decisions */}
      <div className="rounded-lg border border-[#22314D] bg-[#101C31] p-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-[#F5F7FB]">Latest PR Guard Decisions</h2>
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
            No PR Guard decisions recorded yet.
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

function CodeBlock({
  title,
  code,
  copied,
  onCopy,
}: {
  title: string;
  code: string;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div className="rounded-lg border border-[#22314D] bg-[#101C31] p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <FileCode2 className="h-4 w-4 text-[#8FB8FF]" />
          <h2 className="text-sm font-semibold text-[#F5F7FB]">{title}</h2>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onCopy}
          className="border-[#22314D] bg-[#0D1728] text-[#AAB7CC]"
        >
          {copied ? <Check className="mr-2 h-3.5 w-3.5" /> : <Copy className="mr-2 h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      <pre className="mt-4 max-h-[360px] overflow-auto rounded-md border border-[#22314D] bg-[#07101F] p-4 text-xs leading-5 text-[#D7E3F8]">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function StatusTile({
  icon: Icon,
  label,
  value,
  ok,
  hint,
}: {
  icon: typeof ShieldCheck;
  label: string;
  value: string;
  ok: boolean;
  hint?: string;
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
      {hint && <p className="mt-2 text-[11px] opacity-80">{hint}</p>}
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
