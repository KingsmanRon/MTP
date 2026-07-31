import { Ban, FileCheck2, Globe, KeyRound, Lock } from "lucide-react";
import {
  CodePanel,
  Eyebrow,
  IconTile,
  Num,
  SectionHeading,
  StepNumber,
  Tile,
} from "./primitives";
import { MCP_CONFIG } from "./content";

/* ── 4. Problem ─────────────────────────────────────────────────── */

export function Problem() {
  return (
    <section id="problem" className="scroll-mt-24 border-b border-border bg-background">
      <div className="mx-auto grid max-w-7xl gap-12 px-6 py-20 lg:grid-cols-[1.15fr_0.85fr] lg:gap-16 lg:px-8 lg:py-24">
        <div className="min-w-0">
          <Eyebrow>The problem</Eyebrow>
          <h2 className="mt-4 max-w-2xl text-3xl font-semibold leading-tight tracking-tight text-foreground md:text-4xl">
            Agents act faster than anyone can review them.
          </h2>

          <div className="mt-6 flex max-w-2xl flex-col gap-5 text-base leading-8 text-muted-foreground">
            <p>
              CI tells you whether code builds. It does not tell you whether an AI
              agent was allowed to make repo changes, edit CI/CD workflows, merge
              protected branches, or move money. Those decisions happen in seconds,
              and by the time a human reads the diff the action has already run.
            </p>
            <p>
              Logging after the fact does not help either. A log written by the same
              process that took the action proves nothing to an auditor, a customer,
              or a regulator — it can be edited, replayed, or quietly dropped. What
              is missing is a decision that happened <em>before</em> execution, bound
              to an identity, and recorded somewhere the operator cannot rewrite.
            </p>
            <p>
              The gap shows up first on the actions that cost the most: a payment
              released outside its cap, a data export nobody scoped, a deploy to
              production at 2am. One approval that should never have been given is
              enough to turn an autonomy programme into an incident review.
            </p>
          </div>
        </div>

        <div className="min-w-0">
          <Tile ground="white" interactive={false} className="overflow-hidden">
            <div className="flex items-center gap-3 border-b border-tileLine px-5 py-4">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-destructive/10 text-destructive">
                <Ban className="h-4 w-4" aria-hidden="true" />
              </span>
              <div className="min-w-0">
                <p className="text-sm font-semibold text-destructive">BLOCKED</p>
                <p className="text-xs text-muted-foreground">
                  Daily spending limit exceeded
                </p>
              </div>
            </div>

            <dl className="divide-y divide-tileLine">
              {[
                ["Action", "financial_transaction"],
                ["Amount", "$50,000.00"],
                ["Daily cap", "$500.00"],
                ["Trust score", "50 / 100"],
                ["Decision", "403 — no approval token"],
              ].map(([label, value]) => (
                <div
                  key={label}
                  className="flex items-baseline justify-between gap-4 px-5 py-3"
                >
                  <dt className="text-xs uppercase tracking-[0.12em] text-muted-foreground">
                    {label}
                  </dt>
                  <dd className="min-w-0 text-right">
                    <Num className="text-sm text-foreground">{value}</Num>
                  </dd>
                </div>
              ))}
            </dl>

            <p className="border-t border-tileLine px-5 py-4 text-sm leading-6 text-muted-foreground">
              The agent never received an approval token, so the transfer had nothing
              to execute against. The block is recorded with the same weight as an
              approval.
            </p>
          </Tile>
          <p className="mt-3 text-xs leading-5 text-muted-foreground">
            Illustrative decision. Caps, trust thresholds, and verdicts are the
            values the policy engine actually evaluates.
          </p>
        </div>
      </div>
    </section>
  );
}

/* ── 5. Solution ────────────────────────────────────────────────── */

const SOLUTION_CARDS = [
  {
    icon: KeyRound,
    title: "Cryptographic identity",
    body: "Every agent holds an Ed25519 key pair. Every action is signed. No valid signature, no execution.",
  },
  {
    icon: Lock,
    title: "Policy before execution",
    body: "Rate limits, spend caps, and action allowlists are evaluated before the action runs — not after the damage is done.",
  },
  {
    icon: FileCheck2,
    title: "Tamper-evident audit",
    body: "Every decision is recorded in an append-only log, Merkle-anchored on Base L2. Proves what was allowed to happen, and what actually happened.",
  },
  {
    icon: Globe,
    title: "Independently verifiable",
    body: "Anyone can check a receipt using the on-chain anchor alone. No Inntris account required.",
  },
];

export function Solution() {
  return (
    <section id="solution" className="scroll-mt-24 border-b border-border bg-muted">
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8 lg:py-24">
        <SectionHeading
          eyebrow="The solution"
          title="Four guarantees, enforced in the request path."
          lede="Every high-risk action passes through the same gate: identity, policy, audit, and a receipt anyone can check."
        />

        <div className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {SOLUTION_CARDS.map((card) => {
            const Icon = card.icon;
            return (
              <Tile key={card.title} ground="tinted" className="p-6">
                <IconTile>
                  <Icon className="h-5 w-5" aria-hidden="true" />
                </IconTile>
                <h3 className="mt-5 text-lg font-semibold tracking-tight text-foreground">
                  {card.title}
                </h3>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">
                  {card.body}
                </p>
              </Tile>
            );
          })}
        </div>
      </div>
    </section>
  );
}

/* ── 6. Integration ─────────────────────────────────────────────── */

const INTEGRATION_STEPS: Array<[string, string, string]> = [
  [
    "01",
    "Register the agent",
    "Create the agent in the console. It is issued an Ed25519 key pair and starts at trust score 50.",
  ],
  [
    "02",
    "Add the MCP server",
    "Drop the config into your MCP client. The inntris-guard tool becomes available to the agent.",
  ],
  [
    "03",
    "Set the policy",
    "Choose the action types, trust thresholds, rate limits, and spend caps that gate this agent.",
  ],
  [
    "04",
    "Read the receipts",
    "Every PASS and BLOCK lands in the audit trail with a signature, a policy hash, and an anchor.",
  ],
];

export function Integration() {
  return (
    <section
      id="integration"
      className="scroll-mt-24 border-b border-border bg-background"
    >
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8 lg:py-24">
        <SectionHeading
          eyebrow="Integration"
          title="One config block, then policy does the work."
          lede="Inntris sits in front of the action as an MCP tool call. If /verify returns an error, the tool reports isError and the agent does not proceed."
        />

        <div className="mt-12 grid gap-8 lg:grid-cols-2 lg:gap-12">
          <CodePanel filename="mcp_config.json">{MCP_CONFIG}</CodePanel>

          <div className="flex flex-col gap-3">
            {INTEGRATION_STEPS.map(([step, title, body]) => (
              <Tile
                key={step}
                ground="white"
                className="flex gap-4 p-5"
              >
                <StepNumber>{step}</StepNumber>
                <div className="min-w-0">
                  <p className="text-sm font-medium text-foreground">{title}</p>
                  <p className="mt-1 text-sm leading-6 text-muted-foreground">
                    {body}
                  </p>
                </div>
              </Tile>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ── 7. Verification stream ─────────────────────────────────────── */

const STREAM_PANELS = [
  {
    agent: "payments-agent",
    role: "Payments",
    action: "financial_transaction",
    verdict: "PASS" as const,
    reason: "Within daily cap and per-action cap",
    meta: [
      ["Trust", "85 / 100"],
      ["Amount", "$99.99"],
      ["Latency", "82ms"],
    ],
  },
  {
    agent: "support-agent",
    role: "Support",
    action: "email_send",
    verdict: "PASS" as const,
    reason: "Recipient domain on the allowlist",
    meta: [
      ["Trust", "64 / 100"],
      ["Rate", "12 / 60 per min"],
      ["Latency", "41ms"],
    ],
  },
  {
    agent: "ops-agent",
    role: "Ops",
    action: "production_deployment",
    verdict: "BLOCK" as const,
    reason: "Trust score below the threshold for this action",
    meta: [
      ["Trust", "50 / 100"],
      ["Required", "80 / 100"],
      ["Latency", "37ms"],
    ],
  },
];

export function VerificationStream() {
  return (
    <section
      id="stream"
      className="scroll-mt-24 border-b border-border bg-muted"
    >
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8 lg:py-24">
        <SectionHeading
          eyebrow="Verification stream"
          title="Every agent, every action, one decision path."
          lede="The same policy engine evaluates a payment, an outbound email, and a production deploy. Only the thresholds differ."
        />

        <div className="mt-12 grid gap-5 lg:grid-cols-3">
          {STREAM_PANELS.map((panel) => {
            const passed = panel.verdict === "PASS";
            return (
              <Tile key={panel.agent} ground="tinted" className="overflow-hidden">
                <div className="flex items-center justify-between gap-3 border-b border-tileLine px-5 py-4">
                  <div className="min-w-0">
                    <p className="text-[11px] uppercase tracking-[0.14em] text-muted-foreground">
                      {panel.role}
                    </p>
                    <Num className="mt-1 block truncate text-sm text-foreground">
                      {panel.agent}
                    </Num>
                  </div>
                  <span
                    className={
                      passed
                        ? "shrink-0 rounded-md bg-success/10 px-2.5 py-1 font-mono text-xs font-semibold text-success"
                        : "shrink-0 rounded-md bg-destructive/10 px-2.5 py-1 font-mono text-xs font-semibold text-destructive"
                    }
                  >
                    {panel.verdict}
                  </span>
                </div>

                <div className="px-5 py-4">
                  <Num className="block truncate text-xs text-brandInk">
                    {panel.action}
                  </Num>
                  <p className="mt-2 text-sm leading-6 text-muted-foreground">
                    {panel.reason}
                  </p>
                </div>

                <dl className="grid grid-cols-3 divide-x divide-tileLine border-t border-tileLine">
                  {panel.meta.map(([label, value]) => (
                    <div key={label} className="px-4 py-3">
                      <dt className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
                        {label}
                      </dt>
                      <dd>
                        <Num className="text-xs text-foreground">{value}</Num>
                      </dd>
                    </div>
                  ))}
                </dl>
              </Tile>
            );
          })}
        </div>
      </div>
    </section>
  );
}

/* ── 9. Policy enforcement ──────────────────────────────────────── */

const GUARDRAILS: Array<[string, string, string]> = [
  ["1", "_check_agent_status", "Suspended or revoked agents never reach the limit checks."],
  ["2", "_check_action_allowed", "The action type must be on this agent's allowlist."],
  ["3", "_check_trust_score", "The agent's score must clear the threshold for this action type."],
  ["4", "_check_timestamp", "Stale or replayed requests are rejected on the nonce and clock."],
  ["5", "_check_rate_limits", "Per-minute request counters are reserved atomically."],
  ["6", "_check_spending_limits", "Daily and per-action caps are reserved in the same transaction."],
];

export function PolicyEnforcement() {
  return (
    <section
      id="policy"
      className="scroll-mt-24 border-b border-border bg-background"
    >
      <div className="mx-auto grid max-w-7xl gap-12 px-6 py-20 lg:grid-cols-2 lg:gap-16 lg:px-8 lg:py-24">
        <div className="min-w-0">
          <Eyebrow>Policy enforcement</Eyebrow>
          <h2 className="mt-4 text-3xl font-semibold leading-tight tracking-tight text-foreground md:text-4xl">
            Checks run in a fixed order, and the first failure wins.
          </h2>
          <div className="mt-6 flex flex-col gap-5 text-base leading-8 text-muted-foreground">
            <p>
              The policy engine evaluates in strict priority order. Status is checked
              before anything else, so suspending an agent takes effect on its very
              next request — caps and limits never get a chance to matter.
            </p>
            <p>
              Spend and rate counters are reserved inside a single atomic
              transaction. If either trips, the whole reservation rolls back, which
              closes the check-then-act race that shows up under concurrent load.
            </p>
            <p>
              A financial action that arrives without a readable amount is blocked
              rather than treated as zero.
            </p>
          </div>
        </div>

        <div className="flex min-w-0 flex-col gap-2">
          {GUARDRAILS.map(([order, name, body]) => (
            <Tile key={name} ground="white" className="flex gap-4 p-4">
              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-accent">
                <Num className="text-xs font-semibold text-brandInk">{order}</Num>
              </span>
              <div className="min-w-0">
                <Num className="block truncate text-sm text-foreground">{name}</Num>
                <p className="mt-1 text-sm leading-6 text-muted-foreground">{body}</p>
              </div>
            </Tile>
          ))}
        </div>
      </div>
    </section>
  );
}
