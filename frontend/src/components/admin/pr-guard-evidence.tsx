"use client";

import { GitBranch, GitPullRequest, ShieldCheck, ShieldAlert } from "lucide-react";
import type { MappedAuditDetail } from "@/lib/admin/types";
import { Badge } from "@/components/ui/badge";

// Action types governed by the AI PR Guard / .inntris.yml.
const CI_GUARD_ACTIONS = new Set([
  "repo_change",
  "ci_workflow_change",
  "protected_branch_merge",
  "production_deployment",
]);

interface MatchedRule {
  path?: string;
  action_type?: string;
  glob?: string;
  reason?: string;
}

function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function asMatchedRules(v: unknown): MatchedRule[] {
  if (!Array.isArray(v)) return [];
  return v
    .filter((x): x is Record<string, unknown> => typeof x === "object" && x !== null)
    .map((x) => ({
      path: asString(x.path),
      action_type: asString(x.action_type),
      glob: asString(x.glob),
      reason: asString(x.reason),
    }));
}

// True when this audit record looks like an AI PR Guard verification.
export function isPrGuardRecord(record: MappedAuditDetail): boolean {
  const p = record.payload ?? {};
  return (
    (record.action_type ? CI_GUARD_ACTIONS.has(record.action_type) : false) ||
    asStringArray(p.changed_files).length > 0 ||
    asMatchedRules(p.matched_rules).length > 0 ||
    asStringArray(p.risk_flags).length > 0 ||
    typeof p.protected_branch === "string"
  );
}

export function PrGuardEvidence({ record }: { record: MappedAuditDetail }) {
  const p = record.payload ?? {};
  const changedFiles = asStringArray(p.changed_files);
  const matchedRules = asMatchedRules(p.matched_rules);
  const riskFlags = asStringArray(p.risk_flags);
  const protectedBranch = asString(p.protected_branch);
  const baseRef = asString(p.base_ref);
  const headRef = asString(p.head_ref);
  const repo = asString(p.repo);
  const prNumber = typeof p.pull_request === "number" ? p.pull_request : undefined;

  const meta = record.metadata ?? {};
  const policyBinding = asString(meta.policy_binding);
  const enforcing = policyBinding === "registered";

  const blocked = record.verdict === "blocked" || record.verdict === "rate_limited";

  return (
    <div className="space-y-4">
      {/* Why: the asserted category + target + verdict reason */}
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Asserted action type">
          <Badge variant="secondary" className="font-mono">
            {record.action_type ?? "—"}
          </Badge>
        </Field>
        <Field label="Server-side binding">
          {policyBinding ? (
            <span
              className={`inline-flex items-center gap-1.5 text-xs ${
                enforcing ? "text-emerald-300" : "text-amber-300"
              }`}
            >
              {enforcing ? (
                <ShieldCheck className="h-3.5 w-3.5" />
              ) : (
                <ShieldAlert className="h-3.5 w-3.5" />
              )}
              {enforcing ? "Enforcing (policy registered)" : "Advisory (not registered)"}
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          )}
        </Field>
        {(repo || prNumber !== undefined) && (
          <Field label="Pull request">
            <span className="inline-flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
              <GitPullRequest className="h-3.5 w-3.5 text-brandInk" />
              {repo ?? "repo"}
              {prNumber !== undefined ? ` #${prNumber}` : ""}
            </span>
          </Field>
        )}
        {(baseRef || headRef) && (
          <Field label="Branches">
            <span className="inline-flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
              <GitBranch className="h-3.5 w-3.5 text-brandInk" />
              {headRef ?? "?"} → {baseRef ?? "?"}
            </span>
          </Field>
        )}
      </div>

      {protectedBranch && (
        <div className="rounded-lg border border-amber-500/25 bg-amber-500/5 px-4 py-3 text-xs text-amber-200">
          Target branch <span className="font-mono">{baseRef ?? "?"}</span> matched protected
          branch <span className="font-mono">{protectedBranch}</span> — gated as a
          protected-branch merge.
        </div>
      )}

      {riskFlags.length > 0 && (
        <Field label="Risk flags">
          <div className="flex flex-wrap gap-2">
            {riskFlags.map((flag) => (
              <Badge key={flag} variant="secondary" className="font-mono text-[10px]">
                {flag}
              </Badge>
            ))}
          </div>
        </Field>
      )}

      {matchedRules.length > 0 && (
        <div>
          <p className="mb-2 text-xs text-muted-foreground">
            Why this category {blocked ? "blocked" : "was chosen"}
          </p>
          <div className="overflow-hidden rounded-lg border border-tileLine">
            <table className="w-full text-left text-xs">
              <thead className="bg-card text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 font-medium">Path</th>
                  <th className="px-3 py-2 font-medium">Action type</th>
                  <th className="px-3 py-2 font-medium">Matched rule</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-tileLine">
                {matchedRules.map((rule, i) => (
                  <tr key={`${rule.path}-${i}`} className="bg-background">
                    <td className="px-3 py-2 font-mono text-brandInk">{rule.path ?? "—"}</td>
                    <td className="px-3 py-2">
                      <Badge variant="secondary" className="font-mono text-[10px]">
                        {rule.action_type ?? "—"}
                      </Badge>
                    </td>
                    <td className="px-3 py-2 font-mono text-muted-foreground">{rule.glob ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {changedFiles.length > 0 && (
        <Field label={`Changed files (${changedFiles.length})`}>
          <div className="max-h-48 overflow-auto rounded-lg border border-tileLine bg-background p-3">
            <ul className="space-y-1">
              {changedFiles.map((file) => (
                <li key={file} className="font-mono text-xs text-muted-foreground">
                  {file}
                </li>
              ))}
            </ul>
          </div>
        </Field>
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="mb-1.5 text-xs text-muted-foreground">{label}</p>
      {children}
    </div>
  );
}
