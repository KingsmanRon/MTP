"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  BadgeCheck,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  FileCode2,
  GitBranch,
  KeyRound,
  ShieldCheck,
  TriangleAlert,
  UploadCloud,
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
import { SigningKeyPanel } from "@/components/admin/signing-key-panel";
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

# Block (do not silently attest) when a change cannot be classified.
enforcement:
  fail_closed: true

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

# Merges into these branches are gated as protected_branch_merge (trust >= 80).
protected_branches:
  - main
  - "release/*"
  - production

# Path -> action type. protected_branch_merge is branch-driven (see above),
# not a path mapping.
mapping:
  ci_workflow_change:
    - .github/workflows/**
  production_deployment:
    - infra/**
    - deploy/**
    - terraform/**
    - k8s/**
  repo_change:
    - docs/**
    - README.md
    - src/components/**`;

// The enforced content of the policy above, sent to the server on registration.
// The server derives the canonical hash from exactly these two fields (matching
// the action's canonicalPolicyHash), then binds /verify against it.
const PR_GUARD_POLICY = {
  mapping: {
    ci_workflow_change: [".github/workflows/**"],
    production_deployment: ["infra/**", "deploy/**", "terraform/**", "k8s/**"],
    repo_change: ["docs/**", "README.md", "src/components/**"],
  },
  protected_branches: ["main", "release/*", "production"],
};

type RegistrationState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "unregistered" }
  | { status: "registered"; version: number; policyHash: string };

// The published Inntris action reference. Configurable per deployment so it
// points at whatever action repo/tag is actually published (e.g.
// `inntris/inntris-verify@v1`, `KingsmanRon/MTP@v1`, or a pinned SHA). See
// github-action/RELEASING.md.
const ACTION_REF =
  process.env.NEXT_PUBLIC_INNTRIS_ACTION_REF || "inntris/inntris-verify@v1";

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
      - uses: ${ACTION_REF}
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
    ? "border-success-line bg-success-surface text-success-ink"
    : "border-warning-line bg-warning-surface text-warning-ink";
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

  // Server-side policy binding (Tier A) status + registration.
  const [registration, setRegistration] = useState<RegistrationState>({ status: "loading" });
  const [registering, setRegistering] = useState(false);
  const [regError, setRegError] = useState<string | null>(null);

  const loadRegistration = useCallback(async () => {
    try {
      const res = await fetch(`/api/admin/agents/${agent.id}/policy`);
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body?.detail || body?.error || `Failed (${res.status})`);
      }
      setRegistration(
        body?.registered
          ? { status: "registered", version: body.version, policyHash: body.policy_hash }
          : { status: "unregistered" },
      );
    } catch (error) {
      setRegistration({
        status: "error",
        message: error instanceof Error ? error.message : "Failed to load policy status",
      });
    }
  }, [agent.id]);

  useEffect(() => {
    loadRegistration();
  }, [loadRegistration]);

  const registerPolicy = async () => {
    setRegError(null);
    setRegistering(true);
    try {
      const res = await fetch(`/api/admin/agents/${agent.id}/policy`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(PR_GUARD_POLICY),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body?.detail || body?.error || `Registration failed (${res.status})`);
      }
      setRegistration({
        status: "registered",
        version: body.version,
        policyHash: body.policy_hash,
      });
    } catch (error) {
      setRegError(error instanceof Error ? error.message : "Registration failed");
    } finally {
      setRegistering(false);
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
        <div className="flex items-start gap-2 rounded-lg border border-warning-line bg-warning-surface p-3 text-xs text-warning-ink">
          <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            One or more code/release actions are blocked for this agent. The guard will
            BLOCK with <span className="font-mono">ACTION_NOT_ALLOWED</span> instead of on
            trust score. Apply the <span className="font-semibold">Regulated AI PR Gate</span>{" "}
            preset in the Policy tab so all four are allowed and trust does the gating.
          </span>
        </div>
      )}

      {/* Server-side policy binding (Tier A) */}
      <div className="rounded-lg border border-tileLine bg-card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-start gap-2">
            <BadgeCheck className="mt-0.5 h-4 w-4 text-brandInk" />
            <div>
              <h2 className="text-sm font-semibold text-foreground">Server-side enforcement</h2>
              <p className="mt-1 max-w-xl text-xs leading-5 text-muted-foreground">
                Registering binds <span className="font-mono">/verify</span> to this policy: the
                server rejects a mismatched policy hash and re-derives the required action type
                from the changed files, so a caller cannot downgrade a code/release change. Until
                registered, binding is advisory (logged, not enforced).
              </p>
            </div>
          </div>
          <RegistrationBadge registration={registration} />
        </div>

        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0 text-xs text-muted-foreground">
            {registration.status === "registered" ? (
              <span className="font-mono text-muted-foreground">
                hash {registration.policyHash.slice(0, 12)}… · v{registration.version}
              </span>
            ) : registration.status === "error" ? (
              <span className="text-warning-ink">{registration.message}</span>
            ) : registration.status === "unregistered" ? (
              <span>No policy registered — verifications are not yet bound server-side.</span>
            ) : (
              <span>Checking registration…</span>
            )}
          </div>
          <Button
            type="button"
            size="sm"
            onClick={registerPolicy}
            disabled={registering || registration.status === "loading"}
            className="bg-primary text-white hover:bg-primary/90"
          >
            <UploadCloud className="mr-2 h-3.5 w-3.5" />
            {registering
              ? "Registering…"
              : registration.status === "registered"
                ? "Re-register policy"
                : "Register policy"}
          </Button>
        </div>

        {regError && (
          <div className="mt-3 flex items-start gap-2 rounded-md border border-destructive-line bg-destructive-surface p-2.5 text-xs text-destructive-ink">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            {regError}
          </div>
        )}
      </div>

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
        <div className="space-y-4">
          <div className="rounded-lg border border-tileLine bg-card p-4">
            <h2 className="text-sm font-semibold text-foreground">Secrets</h2>
            <div className="mt-4 space-y-3">
              <SecretRow name="INNTRIS_API_URL" value="Core API base URL" />
              <SecretRow name="INNTRIS_PRIVATE_KEY_B64" value="Agent Ed25519 private key seed" /> {/* gitleaks:allow configuration label, not a secret */}
            </div>
          </div>
          <SigningKeyPanel agent={agent} />
        </div>

        <div className="rounded-lg border border-tileLine bg-card p-4">
          <h2 className="text-sm font-semibold text-foreground">Action mapping &amp; gates</h2>
          <p className="mt-1 text-xs text-muted-foreground">
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
                  className="flex items-center justify-between gap-3 rounded-md border border-tileLine bg-background p-3"
                >
                  <div className="min-w-0">
                    <p className="font-mono text-xs text-foreground">{action.id}</p>
                    <p className="mt-0.5 truncate text-xs text-muted-foreground">
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
      <div className="rounded-lg border border-tileLine bg-card p-4">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-foreground">Latest PR Guard Decisions</h2>
          <Link
            href={`/admin/audit?agent_id=${agent.id}`}
            className="inline-flex items-center gap-1 text-xs text-brandInk hover:underline"
          >
            Audit log
            <ExternalLink className="h-3 w-3" />
          </Link>
        </div>

        {latestCiLogs.length === 0 ? (
          <div className="mt-4 rounded-md border border-tileLine bg-background p-4 text-sm text-muted-foreground">
            No PR Guard decisions recorded yet.
          </div>
        ) : (
          <div className="mt-4 divide-y divide-tileLine overflow-hidden rounded-md border border-tileLine">
            {latestCiLogs.map((log) => (
              <Link
                key={log.id}
                href={`/admin/audit/${log.id}`}
                className="grid gap-3 bg-background p-3 transition hover:bg-tile sm:grid-cols-[1fr_auto_auto]"
              >
                <div>
                  <p className="font-mono text-xs text-foreground">{log.action_type}</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {formatDateTime(log.timestamp)}
                  </p>
                </div>
                {log.verdict && <AdminVerdictBadge verdict={log.verdict} />}
                <span className="font-mono text-xs text-muted-foreground">
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
    <div className="rounded-lg border border-tileLine bg-card p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <FileCode2 className="h-4 w-4 text-brandInk" />
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onCopy}
          className="border-tileLine bg-tile text-muted-foreground"
        >
          {copied ? <Check className="mr-2 h-3.5 w-3.5" /> : <Copy className="mr-2 h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      <pre className="mt-4 max-h-[360px] overflow-auto rounded-md border border-tileLine bg-background p-4 text-xs leading-5 text-brandInk">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function RegistrationBadge({ registration }: { registration: RegistrationState }) {
  if (registration.status === "registered") {
    return (
      <Badge variant="success" className="shrink-0">
        Enforcing · v{registration.version}
      </Badge>
    );
  }
  if (registration.status === "loading") {
    return (
      <Badge variant="secondary" className="shrink-0">
        Checking…
      </Badge>
    );
  }
  return (
    <Badge
      variant="secondary"
      className="shrink-0 border-warning-line bg-warning-surface text-warning-ink"
    >
      Advisory
    </Badge>
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
    <div className="flex items-center justify-between gap-3 rounded-md border border-tileLine bg-background p-3">
      <span className="font-mono text-xs text-brandInk">{name}</span>
      <span className="text-xs text-muted-foreground">{value}</span>
    </div>
  );
}
