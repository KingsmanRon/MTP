import type { Metadata } from "next";
import Link from "next/link";
import {
  Shield,
  Lock,
  FileSearch,
  Zap,
  Globe,
  Building2,
  Bot,
  CheckCircle,
  ArrowRight,
  Key,
  Database,
} from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";
import { MobileMenu } from "@/components/mobile-menu";
import { SiteFooter } from "@/components/site-footer";
import { VERIFY_TOOL_HREF, VERIFY_TOOL_LABEL } from "@/lib/brand";
import { verdictLabel } from "@/lib/verdict";

export const metadata: Metadata = {
  title: "Documentation — Inntris | AI Agent Governance Integration Guide",
  description:
    "Integrate Inntris into your AI agent stack. MCP server setup, GitHub Action configuration, policy-as-code with .inntris.yml, and cryptographic receipt verification. Get started in under 20 minutes.",
};

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-accent/50 via-transparent to-transparent" />

      {/* Header */}
      <header className="sticky top-0 z-20 border-b border-tileLine bg-background/85 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
          <Link href="/" className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-tileLine bg-tile">
              <InntrisLogo className="h-6 w-6" />
            </div>
            <div>
              <div className="text-lg font-semibold tracking-tight">Inntris</div>
              <div className="text-xs text-muted-foreground">Documentation</div>
            </div>
          </Link>
          <nav className="hidden items-center gap-6 text-sm md:flex">
            <Link href="/admin" className="text-muted-foreground transition hover:text-foreground">Console</Link>
            <Link href="/portal" className="text-muted-foreground transition hover:text-foreground">Portal</Link>
            <Link href="/audit" className="text-muted-foreground transition hover:text-foreground">Audit</Link>
            <Link href={VERIFY_TOOL_HREF} className="text-muted-foreground transition hover:text-foreground">{VERIFY_TOOL_LABEL}</Link>
          </nav>
          <MobileMenu
            links={[
              { href: "/admin", label: "Console" },
              { href: "/portal", label: "Portal" },
              { href: "/audit", label: "Audit" },
              { href: VERIFY_TOOL_HREF, label: VERIFY_TOOL_LABEL },
            ]}
          />
        </div>
      </header>

      <main className="relative">
        {/* Hero Section */}
        <section className="mx-auto max-w-4xl px-6 pb-12 pt-16 text-center lg:px-8 lg:pt-24">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-tileLine bg-tile/90 px-3 py-1.5 text-sm text-muted-foreground">
            <InntrisLogo className="h-4 w-4" />
            Documentation
          </div>

          <h1 className="text-4xl font-semibold leading-tight tracking-tight md:text-6xl">
            Inntris
          </h1>

          <p className="mx-auto mt-5 max-w-2xl text-xl leading-8 text-muted-foreground">
            Runtime verification and cryptographic proof for AI agent actions.
          </p>

          <p className="mx-auto mt-3 max-w-2xl text-lg leading-8 text-muted-foreground">
            Inntris verifies agent actions before execution, signs decisions with agent identity,
            and produces a tamper-evident receipt for every decision.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <a
              href="#getting-started"
              className="rounded-lg bg-primary px-6 py-3 text-sm font-medium text-white transition-opacity hover:opacity-90"
            >
              Get Started
            </a>
            <Link
              href="/verify"
              className="rounded-lg border border-tileLine bg-tile px-6 py-3 text-sm font-medium text-foreground transition hover:bg-card"
            >
              See live verification
            </Link>
          </div>
        </section>

        {/* What Inntris Is */}
        <section className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-semibold tracking-tight">What Inntris Is</h2>
            <p className="mt-3 text-lg text-muted-foreground">
              A policy decision point and evidence system for AI agent actions
            </p>
          </div>

          <div className="rounded-[24px] border border-tileLine bg-tile p-8">
            <p className="text-lg leading-relaxed text-muted-foreground mb-5">
              Inntris is not observability, logging, or prompt guardrails. It is a policy decision
              point and evidence system for AI agent actions.
            </p>
            <ul className="space-y-3">
              {[
                "Verifies actions before execution — financial transactions, API calls, data access, and more",
                "Signs every decision with verifiable agent identity (Ed25519)",
                "Enforces spending limits, rate limits, and action type restrictions before an agent can act",
                "Records tamper-evident evidence for every approval, block, and exception",
              ].map((item) => (
                <li key={item} className="flex items-start gap-3 text-muted-foreground">
                  <CheckCircle className="h-5 w-5 text-success mt-0.5 flex-shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
            <p className="mt-5 text-muted-foreground">
              Built for teams that need stronger control and clearer proof than logs, screenshots,
              or after-the-fact review.
            </p>
          </div>
        </section>

        {/* What We Do */}
        <section className="mx-auto max-w-6xl px-6 py-16 lg:px-8">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-semibold tracking-tight">What We Do</h2>
            <p className="mt-3 text-lg text-muted-foreground">
              Four pillars of trust for autonomous AI systems
            </p>
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            {[
              {
                icon: Key,
                title: "Cryptographic Identity",
                desc: "Every agent gets a unique Ed25519 keypair",
                items: [
                  "Unforgeable digital signatures for every action",
                  "Nonce-based replay attack prevention",
                  "Automatic signature verification on every request",
                ],
              },
              {
                icon: Shield,
                title: "Policy Enforcement",
                desc: "Configurable guardrails for every agent",
                items: [
                  "Daily and per-action spending limits",
                  "Rate limiting to prevent runaway agents",
                  "Action type restrictions (allow/block lists)",
                ],
              },
              {
                icon: FileSearch,
                title: "Tamper-Evident Audit Trail",
                desc: "Verifiable records of every agent decision",
                items: [
                  "Append-only audit logs (immutable)",
                  "Complete payload capture with signatures",
                  "Designed for enterprise audit requirements",
                ],
              },
              {
                icon: Database,
                title: "Blockchain Anchoring",
                desc: "Tamper-proof verification on Base L2",
                items: [
                  "Merkle tree batching (hourly anchors)",
                  "On-chain proof verification",
                  "Independent auditability by anyone",
                ],
              },
            ].map((pillar) => {
              const Icon = pillar.icon;
              return (
                <div key={pillar.title} className="rounded-[24px] border border-tileLine bg-tile p-6">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-tileLine bg-card text-brandInk">
                    <Icon className="h-6 w-6" />
                  </div>
                  <h3 className="text-lg font-semibold text-foreground">{pillar.title}</h3>
                  <p className="mt-1 text-sm text-muted-foreground">{pillar.desc}</p>
                  <ul className="mt-4 space-y-2">
                    {pillar.items.map((item) => (
                      <li key={item} className="flex items-start gap-2 text-sm text-muted-foreground">
                        <CheckCircle className="h-4 w-4 text-success mt-0.5 flex-shrink-0" />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
        </section>

        {/* How It Works */}
        <section id="getting-started" className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-semibold tracking-tight">How It Works</h2>
            <p className="mt-3 text-lg text-muted-foreground">
              Simple integration, powerful protection
            </p>
          </div>

          <div className="space-y-6">
            {[
              {
                step: "1",
                title: "Register Your Agent",
                body: "You generate an Ed25519 keypair locally and register the public key. Registration is sandbox only. A tenant admin must record an approval reference before production use. Your private key never leaves your environment — Inntris only ever stores the public key.",
                code: `POST /admin/organizations   (operator-only, X-Master-Key)
{
  "name": "Acme Corp",
  "contact_email": "security@acme.com"
}

POST /admin/agents          (X-API-Key)
{
  "org_id": "<org-uuid>",
  "name": "PaymentBot",
  "public_key": "<base64-ed25519-public-key>"
}

POST /admin/agents/{agent_id}/promote   (admin scope)
{
  "approval_reference": "CHANGE-1234"
}`,
              },
              {
                step: "2",
                title: "Configure Policies",
                body: "Set spending limits, rate limits, and allowed action types. These guardrails protect you from runaway agents and unauthorized actions.",
                code: `PATCH /admin/agents/{agent_id}
{
  "daily_limit_usd": 10000,
  "per_action_limit_usd": 1000,
  "rate_limit_per_minute": 60,
  "allowed_actions": ["financial_transaction", "email_send"]
}`,
              },
              {
                step: "3",
                title: "Integrate with MCP",
                body: 'Add the Inntris MCP server to your AI agent. The inntris_guard tool automatically intercepts critical actions and verifies them before execution.',
                code: `// claude_desktop_config.json
{
  "mcpServers": {
    "inntris": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "env": {
        "INNTRIS_API_URL": "https://api.inntris.com",
        "INNTRIS_AGENT_ID": "<your-agent-id>",
        "INNTRIS_PRIVATE_KEY_B64": "<agent-ed25519-seed-b64>"
      }
    }
  }
}`,
              },
            ].map((item) => (
              <div key={item.step} className="flex gap-5">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/15 text-sm font-bold text-brandInk">
                  {item.step}
                </div>
                <div className="min-w-0 flex-1">
                  <h3 className="text-xl font-semibold mb-2">{item.title}</h3>
                  <p className="text-muted-foreground mb-4">{item.body}</p>
                  <div className="rounded-2xl border border-tileLine bg-card/70 p-4">
                    <pre className="text-sm text-muted-foreground overflow-x-auto">{item.code}</pre>
                  </div>
                </div>
              </div>
            ))}

            {/* Step 4 — Verify & Audit */}
            <div className="flex gap-5">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/15 text-sm font-bold text-brandInk">
                4
              </div>
              <div className="min-w-0 flex-1">
                <h3 className="text-xl font-semibold mb-2">Verify &amp; Audit</h3>
                <p className="text-muted-foreground mb-4">
                  Every action is cryptographically signed, verified against policies, and logged
                  to an immutable audit trail. Merkle roots are anchored to Base L2 hourly.
                </p>
                <div className="grid gap-4 sm:grid-cols-3">
                  {[
                    { verdict: "approved", desc: "Action verified & logged", color: "hsl(var(--success))", icon: CheckCircle },
                    { verdict: "blocked", desc: "Policy violation", color: "hsl(var(--destructive))", icon: Shield },
                    { verdict: "rate_limited", desc: "Too many requests", color: "hsl(var(--warning))", icon: Zap },
                  ].map((outcome) => {
                    const Icon = outcome.icon;
                    return (
                      <div
                        key={outcome.verdict}
                        className="rounded-2xl border border-tileLine bg-tile p-4 text-center"
                      >
                        <Icon className="h-8 w-8 mx-auto mb-2" style={{ color: outcome.color }} />
                        <p className="font-medium" style={{ color: outcome.color }}>{verdictLabel(outcome.verdict)}</p>
                        <p className="text-xs text-muted-foreground">{outcome.desc}</p>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Verification Receipt */}
        <section className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-semibold tracking-tight">Verification Receipt</h2>
            <p className="mt-3 text-lg text-muted-foreground">
              Every decision produces a signed receipt you can inspect, share, or verify on-chain.
            </p>
          </div>

          <div className="rounded-[24px] border border-tileLine bg-tile p-6 mb-6">
            <pre className="text-sm text-muted-foreground overflow-x-auto">
{`{
  "verdict": "approved",
  "agent_id": "uuid",
  "action_type": "financial_transaction",
  "approval_token": "base64_signed_token",
  "trust_score": 85,
  "audit_id": "uuid",
  "timestamp": "2025-01-15T10:30:01Z",
  "anchored": true,
  "transaction_hash": "0x517853a7400bffc3446fc73711a0cee2f45c82fc1b89d37e76aa3797eb951a77",
  "root_hash": "e56891f1de39aca50725f0e36ee4b1c4fe1c50966f69a1b368e1d691c2466149"
}`}
            </pre>
            <p className="mt-3 text-xs text-muted-foreground">
              The UI presents <code className="font-mono text-brandInk">approved</code> as <code className="font-mono text-brandInk">PASS</code>, <code className="font-mono text-brandInk">blocked</code> as <code className="font-mono text-brandInk">BLOCK</code>, and <code className="font-mono text-brandInk">rate_limited</code> as <code className="font-mono text-brandInk">ESCALATE</code>.
            </p>
          </div>

          <p className="text-muted-foreground mb-5">
            Receipts are stored in the tamper-evident audit trail and Merkle roots are anchored
            to Base L2 hourly. Any record can be independently verified by audit ID or transaction hash.
          </p>

          <Link href="/verify" className="inline-flex items-center gap-2 text-sm font-medium text-brandInk transition hover:text-foreground">
            <ArrowRight className="h-4 w-4" />
            See live verification
          </Link>
        </section>

        {/* Our Goal */}
        <section className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-semibold tracking-tight">Our Goal</h2>
            <p className="mt-3 text-lg text-muted-foreground">
              Building the trust infrastructure for the agentic future
            </p>
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            {[
              {
                icon: Globe,
                title: "Universal Standard",
                body: "Inntris provides a verification layer for teams that need signed decisions, policy enforcement, and tamper-evident audit trails for AI agent actions.",
              },
              {
                icon: Building2,
                title: "Enterprise Ready",
                body: "From startups to regulated enterprises, Inntris scales with your needs. Built for auditability. Designed for enterprise control requirements. Deployment and security requirements are reviewed with each team during evaluation.",
              },
              {
                icon: Lock,
                title: "Liability Clarity",
                body: "When an AI agent takes action, you need proof of what happened and whether it was authorised. Inntris gives you a signed, verifiable record for every decision — before the action runs, not reconstructed after the fact.",
              },
              {
                icon: Bot,
                title: "Agent Ecosystem",
                body: "Compatible with Claude, GPT, Gemini, and any MCP-compatible agent. Native integration with the Model Context Protocol for seamless verification.",
              },
            ].map((goal) => {
              const Icon = goal.icon;
              return (
                <div key={goal.title} className="rounded-[24px] border border-tileLine bg-tile p-6">
                  <Icon className="h-8 w-8 text-brandInk mb-3" />
                  <h3 className="text-lg font-semibold">{goal.title}</h3>
                  <p className="mt-2 text-sm leading-6 text-muted-foreground">{goal.body}</p>
                </div>
              );
            })}
          </div>
        </section>

        {/* Start Here */}
        <section className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-semibold tracking-tight">Start Here</h2>
            <p className="mt-3 text-lg text-muted-foreground">
              The fastest path to production coverage is one high-risk workflow.
            </p>
          </div>

          <div className="rounded-[24px] border border-tileLine bg-tile p-8">
            <p className="text-lg leading-relaxed text-muted-foreground mb-5">
              Pick the action that would create the most loss or exposure if it ran without
              authorization. Inntris instruments that decision boundary, enforces PASS/BLOCK
              policy, and creates a verifiable receipt for every outcome.
            </p>
            <div className="flex flex-wrap gap-3 mb-4">
              <Link
                href="/pilot"
                className="rounded-lg bg-primary px-6 py-3 text-sm font-medium text-white transition-opacity hover:opacity-90"
              >
                Scope a 14-day pilot
              </Link>
              <Link
                href="/verify"
                className="rounded-lg border border-tileLine bg-tile px-6 py-3 text-sm font-medium text-foreground transition hover:bg-card"
              >
                See live verification
              </Link>
            </div>
            <p className="text-sm text-muted-foreground">
              Common starting points include agent spend, production changes, sensitive data
              export, and external tool execution.
            </p>
          </div>
        </section>

        {/* Explore Inntris */}
        <section className="mx-auto max-w-4xl px-6 pb-20 lg:px-8">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-semibold tracking-tight">Explore Inntris</h2>
            <p className="mt-3 text-lg text-muted-foreground">
              Get started with the platform
            </p>
          </div>

          <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { href: VERIFY_TOOL_HREF, icon: Shield, title: "Public Verify", desc: "Inspect a signed receipt" },
              { href: "/admin", icon: Key, title: "Admin Console", desc: "Manage agents & policies" },
              { href: "/portal", icon: Bot, title: "Agent Portal", desc: "Developer tools & testing" },
              { href: "/audit", icon: FileSearch, title: "Audit Explorer", desc: "Search & verify logs" },
            ].map((link) => {
              const Icon = link.icon;
              return (
                <Link
                  key={link.title}
                  href={link.href}
                  className="group rounded-[20px] border border-tileLine bg-tile p-6 text-center transition hover:border-primary/40 hover:bg-card"
                >
                  <Icon className="h-8 w-8 mx-auto mb-3 text-brandInk" />
                  <h3 className="font-semibold">{link.title}</h3>
                  <p className="mt-1 text-sm text-muted-foreground">{link.desc}</p>
                </Link>
              );
            })}
          </div>
        </section>
      </main>

      {/* Footer */}
      <SiteFooter className="border-tileLine" />
    </div>
  );
}
