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

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-[#07111F] text-[#F5F7FB]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(76,141,255,0.14),transparent_32%),radial-gradient(circle_at_80%_30%,rgba(143,184,255,0.08),transparent_24%)]" />

      {/* Header */}
      <header className="sticky top-0 z-20 border-b border-white/8 bg-[#07111F]/85 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
          <Link href="/" className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#0D1728] shadow-[0_0_0_1px_rgba(255,255,255,0.02)]">
              <InntrisLogo className="h-6 w-6" />
            </div>
            <div>
              <div className="text-lg font-semibold tracking-tight">Inntris</div>
              <div className="text-xs text-[#7F8CA3]">Documentation</div>
            </div>
          </Link>
          <nav className="hidden items-center gap-6 text-sm md:flex">
            <Link href="/admin" className="text-[#C4CFDE] transition hover:text-white">Console</Link>
            <Link href="/portal" className="text-[#C4CFDE] transition hover:text-white">Portal</Link>
            <Link href="/audit" className="text-[#C4CFDE] transition hover:text-white">Audit</Link>
            <Link href="/verify" className="text-[#C4CFDE] transition hover:text-white">Verify</Link>
          </nav>
        </div>
      </header>

      <main className="relative">
        {/* Hero Section */}
        <section className="mx-auto max-w-4xl px-6 pb-12 pt-16 text-center lg:px-8 lg:pt-24">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-[#22314D] bg-[#0D1728]/90 px-3 py-1.5 text-sm text-[#AAB7CC]">
            <InntrisLogo className="h-4 w-4" />
            Documentation
          </div>

          <h1 className="text-4xl font-semibold leading-tight tracking-tight md:text-6xl">
            Inntris
          </h1>

          <p className="mx-auto mt-5 max-w-2xl text-xl leading-8 text-[#C4CFDE]">
            Runtime verification and cryptographic proof for AI agent actions.
          </p>

          <p className="mx-auto mt-3 max-w-2xl text-lg leading-8 text-[#AAB7CC]">
            Inntris verifies agent actions before execution, signs decisions with agent identity,
            and produces a tamper-evident receipt for every decision.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <a
              href="#getting-started"
              className="rounded-lg bg-[#28C281] px-6 py-3 text-sm font-medium text-white transition-opacity hover:opacity-90"
            >
              Get Started
            </a>
            <Link
              href="/verify"
              className="rounded-lg border border-[#22314D] bg-[#0D1728] px-6 py-3 text-sm font-medium text-[#F5F7FB] transition hover:bg-[#101C31]"
            >
              See live verification
            </Link>
          </div>
        </section>

        {/* What Inntris Is */}
        <section className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-semibold tracking-tight">What Inntris Is</h2>
            <p className="mt-3 text-lg text-[#AAB7CC]">
              A policy decision point and evidence system for AI agent actions
            </p>
          </div>

          <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-8">
            <p className="text-lg leading-relaxed text-[#C4CFDE] mb-5">
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
                <li key={item} className="flex items-start gap-3 text-[#C4CFDE]">
                  <CheckCircle className="h-5 w-5 text-[#22c55e] mt-0.5 flex-shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
            <p className="mt-5 text-[#AAB7CC]">
              Built for teams that need stronger control and clearer proof than logs, screenshots,
              or after-the-fact review.
            </p>
          </div>
        </section>

        {/* What We Do */}
        <section className="mx-auto max-w-6xl px-6 py-16 lg:px-8">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-semibold tracking-tight">What We Do</h2>
            <p className="mt-3 text-lg text-[#AAB7CC]">
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
                <div key={pillar.title} className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                    <Icon className="h-6 w-6" />
                  </div>
                  <h3 className="text-lg font-semibold text-[#F5F7FB]">{pillar.title}</h3>
                  <p className="mt-1 text-sm text-[#AAB7CC]">{pillar.desc}</p>
                  <ul className="mt-4 space-y-2">
                    {pillar.items.map((item) => (
                      <li key={item} className="flex items-start gap-2 text-sm text-[#C4CFDE]">
                        <CheckCircle className="h-4 w-4 text-[#22c55e] mt-0.5 flex-shrink-0" />
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
            <p className="mt-3 text-lg text-[#AAB7CC]">
              Simple integration, powerful protection
            </p>
          </div>

          <div className="space-y-6">
            {[
              {
                step: "1",
                title: "Register Your Agent",
                body: "Create an organization and register your AI agent. Inntris generates a unique Ed25519 keypair — you keep the private key, we store the public key.",
                code: `POST /admin/organizations
{
  "name": "Acme Corp",
  "contact_email": "security@acme.com"
}

POST /admin/agents
{
  "name": "PaymentBot",
  "description": "Handles customer refunds"
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
        "INNTRIS_API_KEY": "<your-api-key>",
        "INNTRIS_AGENT_ID": "<your-agent-id>"
      }
    }
  }
}`,
              },
            ].map((item) => (
              <div key={item.step} className="flex gap-5">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#4C8DFF]/15 text-sm font-bold text-[#8FB8FF]">
                  {item.step}
                </div>
                <div className="flex-1">
                  <h3 className="text-xl font-semibold mb-2">{item.title}</h3>
                  <p className="text-[#AAB7CC] mb-4">{item.body}</p>
                  <div className="rounded-2xl border border-[#22314D] bg-[#101C31]/70 p-4">
                    <pre className="text-sm text-[#C4CFDE] overflow-x-auto">{item.code}</pre>
                  </div>
                </div>
              </div>
            ))}

            {/* Step 4 — Verify & Audit */}
            <div className="flex gap-5">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#4C8DFF]/15 text-sm font-bold text-[#8FB8FF]">
                4
              </div>
              <div className="flex-1">
                <h3 className="text-xl font-semibold mb-2">Verify &amp; Audit</h3>
                <p className="text-[#AAB7CC] mb-4">
                  Every action is cryptographically signed, verified against policies, and logged
                  to an immutable audit trail. Merkle roots are anchored to Base L2 hourly.
                </p>
                <div className="grid gap-4 sm:grid-cols-3">
                  {[
                    { label: "APPROVED", desc: "Action verified & logged", color: "#22c55e", icon: CheckCircle },
                    { label: "BLOCKED", desc: "Policy violation", color: "#ef4444", icon: Shield },
                    { label: "RATE LIMITED", desc: "Too many requests", color: "#f59e0b", icon: Zap },
                  ].map((outcome) => {
                    const Icon = outcome.icon;
                    return (
                      <div
                        key={outcome.label}
                        className="rounded-2xl border border-[#22314D] bg-[#0D1728] p-4 text-center"
                      >
                        <Icon className="h-8 w-8 mx-auto mb-2" style={{ color: outcome.color }} />
                        <p className="font-medium" style={{ color: outcome.color }}>{outcome.label}</p>
                        <p className="text-xs text-[#7F8CA3]">{outcome.desc}</p>
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
            <p className="mt-3 text-lg text-[#AAB7CC]">
              Every decision produces a signed receipt you can inspect, share, or verify on-chain.
            </p>
          </div>

          <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6 mb-6">
            <pre className="text-sm text-[#C4CFDE] overflow-x-auto">
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
          </div>

          <p className="text-[#AAB7CC] mb-5">
            Receipts are stored in the tamper-evident audit trail and Merkle roots are anchored
            to Base L2 hourly. Any record can be independently verified by audit ID or transaction hash.
          </p>

          <Link href="/verify" className="inline-flex items-center gap-2 text-sm font-medium text-[#8FB8FF] transition hover:text-white">
            <ArrowRight className="h-4 w-4" />
            See live verification
          </Link>
        </section>

        {/* Our Goal */}
        <section className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-semibold tracking-tight">Our Goal</h2>
            <p className="mt-3 text-lg text-[#AAB7CC]">
              Building the trust infrastructure for the agentic future
            </p>
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            {[
              {
                icon: Globe,
                title: "Universal Standard",
                body: 'We aim to become the universal verification standard for AI agents — the "VISA network" for autonomous systems. Any agent, any platform, one trust layer.',
              },
              {
                icon: Building2,
                title: "Enterprise Ready",
                body: "From startups to regulated enterprises, Inntris scales with your needs. Built for auditability. Designed for enterprise control requirements. Optional on-premise deployment available for compliance-heavy industries.",
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
                <div key={goal.title} className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
                  <Icon className="h-8 w-8 text-[#8FB8FF] mb-3" />
                  <h3 className="text-lg font-semibold">{goal.title}</h3>
                  <p className="mt-2 text-sm leading-6 text-[#AAB7CC]">{goal.body}</p>
                </div>
              );
            })}
          </div>
        </section>

        {/* Start Here */}
        <section className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-semibold tracking-tight">Start Here</h2>
            <p className="mt-3 text-lg text-[#AAB7CC]">
              The fastest path to verification coverage is pull request verification.
            </p>
          </div>

          <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-8">
            <p className="text-lg leading-relaxed text-[#C4CFDE] mb-5">
              Add <code className="font-mono text-[#8FB8FF]">inntris-verify</code> to any GitHub repo.
              Every agent-generated PR gets a cryptographic receipt — signed by agent identity and
              anchored to Base L2.
            </p>
            <div className="flex flex-wrap gap-3 mb-4">
              <a
                href="https://github.com/Inntris/agent-orchestrator-guardrails"
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-lg bg-[#28C281] px-6 py-3 text-sm font-medium text-white transition-opacity hover:opacity-90"
              >
                Install GitHub Action
              </a>
              <Link
                href="/verify"
                className="rounded-lg border border-[#22314D] bg-[#0D1728] px-6 py-3 text-sm font-medium text-[#F5F7FB] transition hover:bg-[#101C31]"
              >
                See live verification
              </Link>
            </div>
            <p className="text-sm text-[#7F8CA3]">
              Works with GitHub PR workflows, MCP-compatible agent systems, and custom agent stacks
              via direct API integration.
            </p>
          </div>
        </section>

        {/* Explore Inntris */}
        <section className="mx-auto max-w-4xl px-6 pb-20 lg:px-8">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-semibold tracking-tight">Explore Inntris</h2>
            <p className="mt-3 text-lg text-[#AAB7CC]">
              Get started with the platform
            </p>
          </div>

          <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { href: "/verify", icon: Shield, title: "Public Verify", desc: "Inspect a live receipt" },
              { href: "/admin", icon: Key, title: "Admin Console", desc: "Manage agents & policies" },
              { href: "/portal", icon: Bot, title: "Agent Portal", desc: "Developer tools & testing" },
              { href: "/audit", icon: FileSearch, title: "Audit Explorer", desc: "Search & verify logs" },
            ].map((link) => {
              const Icon = link.icon;
              return (
                <Link
                  key={link.title}
                  href={link.href}
                  className="group rounded-[20px] border border-[#22314D] bg-[#0D1728] p-6 text-center transition hover:border-[#35507A] hover:bg-[#101C31]"
                >
                  <Icon className="h-8 w-8 mx-auto mb-3 text-[#8FB8FF]" />
                  <h3 className="font-semibold">{link.title}</h3>
                  <p className="mt-1 text-sm text-[#7F8CA3]">{link.desc}</p>
                </Link>
              );
            })}
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/8">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-8 lg:px-8">
          <div className="flex items-center gap-2">
            <InntrisLogo className="h-5 w-5" />
            <span className="text-[#7F8CA3]">Inntris Core</span>
          </div>
          <div className="flex items-center gap-6 text-[#7F8CA3]">
            <Link href="/" className="text-sm transition-colors hover:text-white">Home</Link>
            <Link href="/docs" className="text-sm transition-colors hover:text-white">Docs</Link>
            <Link href="/verify" className="text-sm transition-colors hover:text-white">Verify</Link>
            <a
              href="https://github.com/Inntris/agent-orchestrator-guardrails"
              target="_blank"
              rel="noopener noreferrer"
              className="transition-colors hover:text-white"
            >
              <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
