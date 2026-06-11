"use client";

import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  DollarSign,
  Gauge,
  Power,
  Save,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import type { AgentStatus, MappedAgent } from "@/lib/admin/types";
import {
  ACTION_TRUST_THRESHOLDS,
  AGENT_CONTROL_PRESETS,
  buildActionPolicyLists,
  CONTROLLED_ACTION_GROUPS,
  CONTROLLED_ACTIONS,
  ControlledActionId,
} from "@/lib/agent-controls";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";

function errorMessage(body: unknown, fallback: string): string {
  if (!body || typeof body !== "object") return fallback;
  const candidate = body as { error?: unknown; detail?: unknown; message?: unknown };
  if (typeof candidate.error === "string") return candidate.error;
  if (typeof candidate.detail === "string") return candidate.detail;
  if (typeof candidate.message === "string") return candidate.message;
  return fallback;
}

export function AgentControlPanel({
  agent,
  onSaved,
}: {
  agent: MappedAgent;
  onSaved: () => void;
}) {
  const initialAllowed = CONTROLLED_ACTIONS.filter((action) =>
    agent.allowed_actions?.includes(action.id),
  ).map((action) => action.id);
  const [allowedActions, setAllowedActions] = useState<Set<ControlledActionId>>(
    new Set(initialAllowed),
  );
  const [dailyLimit, setDailyLimit] = useState(String(agent.daily_limit_usd ?? 0));
  const [perActionLimit, setPerActionLimit] = useState(String(agent.per_action_limit_usd ?? 0));
  const [rateLimit, setRateLimit] = useState(String(agent.rate_limit_per_minute ?? 60));
  // Trust score is normally earned automatically (+1 per approval). This input
  // is the operator override. We track the score the page loaded with so a
  // routine limits/permissions save does not clobber accrual that happened
  // server-side since mount — trust_score is only sent when actually changed.
  const initialTrustScore = agent.trust_score ?? 50;
  const [trustScore, setTrustScore] = useState(String(initialTrustScore));
  const [currentStatus, setCurrentStatus] = useState<AgentStatus | undefined>(agent.status);
  const [saving, setSaving] = useState(false);
  const [changingStatus, setChangingStatus] = useState(false);
  const [message, setMessage] = useState<{ kind: "success" | "error"; text: string } | null>(
    null,
  );

  const setActionDecision = (action: ControlledActionId, decision: "allow" | "block") => {
    setAllowedActions((current) => {
      const next = new Set(current);
      if (decision === "allow") next.add(action);
      else next.delete(action);
      return next;
    });
    setMessage(null);
  };

  const applyPreset = (presetId: string) => {
    const preset = AGENT_CONTROL_PRESETS.find((candidate) => candidate.id === presetId);
    if (!preset) return;
    setAllowedActions(new Set(preset.allowed));
    setDailyLimit(String(preset.dailyLimit));
    setPerActionLimit(String(preset.perActionLimit));
    setRateLimit(String(preset.rateLimit));
    setMessage(null);
  };

  const savePolicy = async () => {
    setMessage(null);
    const daily = Number(dailyLimit);
    const perAction = Number(perActionLimit);
    const rate = Number(rateLimit);

    if (!Number.isFinite(daily) || daily < 0) {
      setMessage({ kind: "error", text: "Daily spend limit must be a non-negative number." });
      return;
    }
    if (!Number.isFinite(perAction) || perAction < 0 || perAction > daily) {
      setMessage({
        kind: "error",
        text: "Per-action spend limit must be non-negative and no greater than the daily limit.",
      });
      return;
    }
    if (!Number.isInteger(rate) || rate < 1 || rate > 10000) {
      setMessage({ kind: "error", text: "Rate limit must be an integer from 1 to 10,000." });
      return;
    }
    const trust = Number(trustScore);
    if (!Number.isInteger(trust) || trust < 0 || trust > 100) {
      setMessage({ kind: "error", text: "Trust score must be an integer from 0 to 100." });
      return;
    }

    const actionPolicy = buildActionPolicyLists(
      agent.allowed_actions,
      agent.blocked_actions,
      allowedActions,
    );

    setSaving(true);
    try {
      const response = await fetch(`/api/admin/agents/${agent.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          daily_limit_usd: daily,
          per_action_limit_usd: perAction,
          rate_limit_per_minute: rate,
          ...actionPolicy,
          // Only override trust when the operator actually changed it, so a
          // routine save does not reset a score that rose via accrual.
          ...(trust !== initialTrustScore ? { trust_score: trust } : {}),
        }),
      });
      const body: unknown = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(errorMessage(body, `Policy update failed (${response.status})`));
      }
      setMessage({
        kind: "success",
        text: "Controls saved. New verification requests use this policy immediately.",
      });
      onSaved();
    } catch (error) {
      setMessage({
        kind: "error",
        text: error instanceof Error ? error.message : "Policy update failed.",
      });
    } finally {
      setSaving(false);
    }
  };

  const changeStatus = async (status: AgentStatus) => {
    setMessage(null);
    setChangingStatus(true);
    try {
      const response = await fetch(`/api/admin/agents/${agent.id}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      const body: unknown = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(errorMessage(body, `Status update failed (${response.status})`));
      }
      setCurrentStatus(status);
      setMessage({
        kind: "success",
        text:
          status === "suspended"
            ? "Agent suspended. All verification requests now fail closed."
            : "Agent activated. Verification requests can proceed under the saved policy.",
      });
      onSaved();
    } catch (error) {
      setMessage({
        kind: "error",
        text: error instanceof Error ? error.message : "Status update failed.",
      });
    } finally {
      setChangingStatus(false);
    }
  };

  const customControls = [
    ...(agent.allowed_actions ?? []),
    ...(agent.blocked_actions ?? []),
  ].filter((action) => !CONTROLLED_ACTIONS.some((controlled) => controlled.id === action));

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-[#22314D] bg-[#101C31]/60 p-5">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
          <div className="flex gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#22314D] bg-[#0D1728] text-[#8FB8FF]">
              <Power className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-medium text-[#F5F7FB]">Emergency execution control</h3>
              <p className="mt-1 text-sm leading-6 text-[#7F8CA3]">
                Suspending an agent makes every new action fail closed before execution.
              </p>
            </div>
          </div>
          {currentStatus === "suspended" ? (
            <Button
              onClick={() => changeStatus("active")}
              disabled={changingStatus}
              className="bg-[#28C281] text-white hover:bg-[#28C281]/90"
            >
              Activate agent
            </Button>
          ) : (
            <Button
              variant="destructive"
              onClick={() => changeStatus("suspended")}
              disabled={changingStatus || currentStatus === "revoked"}
            >
              Suspend agent
            </Button>
          )}
        </div>
      </section>

      <section>
        <div className="mb-3 flex items-center gap-2">
          <SlidersHorizontal className="h-4 w-4 text-[#8FB8FF]" />
          <h3 className="text-sm font-medium text-[#C4CFDE]">Control presets</h3>
        </div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          {AGENT_CONTROL_PRESETS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => applyPreset(preset.id)}
              className="rounded-xl border border-[#22314D] bg-[#101C31] p-4 text-left transition hover:border-[#4C8DFF] hover:bg-[#4C8DFF]/5"
            >
              <p className="text-sm font-medium text-[#F5F7FB]">{preset.label}</p>
              <p className="mt-2 text-xs leading-5 text-[#7F8CA3]">{preset.description}</p>
            </button>
          ))}
        </div>
        <p className="mt-2 text-xs text-[#7F8CA3]">
          Presets stage changes only. Review the controls below, then save.
        </p>
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        <ControlInput
          icon={DollarSign}
          label="Daily spend limit"
          description="Maximum approved spend per UTC day."
          value={dailyLimit}
          onChange={setDailyLimit}
          suffix="USD"
        />
        <ControlInput
          icon={ShieldCheck}
          label="Per-action spend limit"
          description="Maximum amount a single action can request."
          value={perActionLimit}
          onChange={setPerActionLimit}
          suffix="USD"
        />
        <ControlInput
          icon={AlertTriangle}
          label="Rate limit"
          description="Maximum verification requests per minute."
          value={rateLimit}
          onChange={setRateLimit}
          suffix="/ min"
          integer
        />
      </section>

      <section className="rounded-xl border border-[#22314D] bg-[#101C31]/60 p-5">
        <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_220px] md:items-center">
          <div>
            <div className="flex items-center gap-2">
              <Gauge className="h-4 w-4 text-[#8FB8FF]" />
              <h3 className="text-sm font-medium text-[#F5F7FB]">Trust score override</h3>
            </div>
            <p className="mt-2 text-xs leading-5 text-[#7F8CA3]">
              Trust is earned automatically (+1 per approved action) and decays toward 50 over
              time. Set it directly to promote a vetted agent to a higher-trust action, or to
              demote a suspicious one immediately. Runtime and code actions each require a
              minimum trust score in addition to being allowed below.
            </p>
          </div>
          <ControlInput
            icon={Gauge}
            label="Trust score"
            description="Advisory reputation lever, 0–100."
            value={trustScore}
            onChange={setTrustScore}
            suffix="/ 100"
            integer
            min={0}
            max={100}
          />
        </div>
      </section>

      <section>
        <div className="mb-3">
          <h3 className="text-sm font-medium text-[#C4CFDE]">Action permissions</h3>
          <p className="mt-1 text-xs text-[#7F8CA3]">
            Blocked actions receive no approval token and cannot proceed through the protected path.
          </p>
        </div>
        <div className="space-y-5">
          {CONTROLLED_ACTION_GROUPS.map((group) => (
            <div key={group.id}>
              <div className="mb-3">
                <h4 className="text-xs font-medium uppercase tracking-wide text-[#AAB7CC]">
                  {group.label}
                </h4>
                <p className="mt-1 text-xs leading-5 text-[#7F8CA3]">{group.description}</p>
              </div>
              <div className="grid gap-3 md:grid-cols-2">
                {CONTROLLED_ACTIONS.filter((action) => action.group === group.id).map((action) => {
                  const isAllowed = allowedActions.has(action.id);
                  return (
                    <div
                      key={action.id}
                      className={`rounded-xl border p-4 ${
                        isAllowed
                          ? "border-[#28C281]/30 bg-[#28C281]/5"
                          : "border-red-500/25 bg-red-500/5"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <p className="text-sm font-medium text-[#F5F7FB]">{action.label}</p>
                          <p className="mt-1 text-xs leading-5 text-[#7F8CA3]">
                            {action.description}
                          </p>
                          <code className="mt-2 inline-block text-[11px] text-[#8FB8FF]">
                            {action.id}
                          </code>
                          <TrustGateHint actionId={action.id} isAllowed={isAllowed} trust={Number(trustScore)} />
                        </div>
                        <Select
                          aria-label={`${action.label} decision`}
                          value={isAllowed ? "allow" : "block"}
                          onChange={(event) =>
                            setActionDecision(action.id, event.target.value as "allow" | "block")
                          }
                          className="w-24 border-[#22314D] bg-[#0D1728] text-xs"
                        >
                          <option value="allow">Allow</option>
                          <option value="block">Block</option>
                        </Select>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </section>

      {customControls.length > 0 && (
        <section className="rounded-xl border border-[#22314D] bg-[#101C31]/50 p-4">
          <p className="text-xs font-medium uppercase tracking-wide text-[#7F8CA3]">
            Custom controls preserved
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            {Array.from(new Set(customControls)).map((action) => (
              <code
                key={action}
                className="rounded-md border border-[#22314D] bg-[#0D1728] px-2 py-1 text-xs text-[#AAB7CC]"
              >
                {action}
              </code>
            ))}
          </div>
        </section>
      )}

      {message && (
        <div
          className={`flex items-start gap-3 rounded-xl border p-4 text-sm ${
            message.kind === "success"
              ? "border-[#28C281]/30 bg-[#28C281]/10 text-[#C4CFDE]"
              : "border-red-500/30 bg-red-500/10 text-red-300"
          }`}
        >
          {message.kind === "success" ? (
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[#28C281]" />
          ) : (
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
          )}
          {message.text}
        </div>
      )}

      <div className="flex justify-end border-t border-[#22314D] pt-5">
        <Button onClick={savePolicy} disabled={saving} className="bg-[#4C8DFF] text-white">
          <Save className="mr-2 h-4 w-4" />
          {saving ? "Saving controls..." : "Save controls"}
        </Button>
      </div>
    </div>
  );
}

function ControlInput({
  icon: Icon,
  label,
  description,
  value,
  onChange,
  suffix,
  integer = false,
  min,
  max,
}: {
  icon: typeof DollarSign;
  label: string;
  description: string;
  value: string;
  onChange: (value: string) => void;
  suffix: string;
  integer?: boolean;
  min?: number;
  max?: number;
}) {
  const resolvedMin = min ?? (integer ? 1 : 0);
  const resolvedMax = max ?? (integer ? 10000 : undefined);
  return (
    <div className="rounded-xl border border-[#22314D] bg-[#101C31]/60 p-4">
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4 text-[#8FB8FF]" />
        <label className="text-sm font-medium text-[#F5F7FB]">{label}</label>
      </div>
      <p className="mt-2 min-h-10 text-xs leading-5 text-[#7F8CA3]">{description}</p>
      <div className="mt-3 flex items-center gap-2">
        <Input
          aria-label={label}
          type="number"
          min={String(resolvedMin)}
          max={resolvedMax !== undefined ? String(resolvedMax) : undefined}
          step={integer ? "1" : "0.01"}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          className="border-[#22314D] bg-[#0D1728] font-mono"
        />
        <span className="shrink-0 text-xs text-[#7F8CA3]">{suffix}</span>
      </div>
    </div>
  );
}

// Advisory hint tying the trust-score override to each action's gate. Shows the
// required minimum, and warns when an action is allowed but the staged trust
// score is still below the threshold (so it would block at decision time).
function TrustGateHint({
  actionId,
  isAllowed,
  trust,
}: {
  actionId: ControlledActionId;
  isAllowed: boolean;
  trust: number;
}) {
  const threshold = ACTION_TRUST_THRESHOLDS[actionId];
  if (threshold === null) {
    return <p className="mt-2 text-[11px] text-[#7F8CA3]">Pass-through · no trust gate</p>;
  }
  const blockedByTrust = isAllowed && Number.isFinite(trust) && trust < threshold;
  return (
    <p className={`mt-2 text-[11px] ${blockedByTrust ? "text-[#E0A100]" : "text-[#7F8CA3]"}`}>
      Requires trust ≥ {threshold}
      {blockedByTrust ? ` · blocks at ${trust}` : ""}
    </p>
  );
}
