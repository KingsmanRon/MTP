import Link from "next/link";
import {
  Bot,
  Shield,
  Fingerprint,
  Activity,
  CheckCircle2,
  XOctagon,
  Clock,
  Link2,
  ChevronRight,
} from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";

/* ------------------------------------------------------------------ */
/*  Page (Server Component — SSR public preview shell)                 */
/* ------------------------------------------------------------------ */

export default function PortalPreviewPage() {
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
              <div className="text-xs text-[#7F8CA3]">Portal</div>
            </div>
          </Link>
          <nav className="flex items-center gap-3">
            <Link
              href="/verify"
              className="hidden rounded-lg border border-[#22314D] bg-[#0D1728] px-4 py-2 text-sm font-medium text-[#F5F7FB] transition hover:bg-[#101C31] hover:text-white md:inline-flex"
            >
              Verify a Receipt
            </Link>
            <Link
              href="/docs"
              className="hidden rounded-lg border border-[#22314D] bg-[#0D1728] px-4 py-2 text-sm font-medium text-[#F5F7FB] transition hover:bg-[#101C31] hover:text-white md:inline-flex"
            >
              Docs
            </Link>
          </nav>
        </div>
      </header>

      <main className="relative">
        {/* Hero */}
        <section className="mx-auto max-w-4xl px-6 pb-12 pt-16 text-center lg:px-8 lg:pt-24">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-[#22314D] bg-[#0D1728]/90 px-3 py-1.5 text-sm text-[#AAB7CC]">
            <Bot className="h-4 w-4 text-[#8FB8FF]" />
            Inntris Portal
          </div>

          <h1 className="text-3xl font-semibold leading-tight tracking-tight md:text-5xl">
            Inspect agent identity, decisions, and{" "}
            <span className="text-[#4C8DFF]">trust status</span>
          </h1>

          <p className="mx-auto mt-5 max-w-2xl text-lg leading-8 text-[#C4CFDE]">
            View registered agents, signed activity, trust scores, and decision records
            tied to each agent.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <a
              href="/#contact"
              className="rounded-lg bg-[#28C281] px-6 py-3 text-sm font-medium text-white transition-opacity hover:opacity-90"
            >
              Request Access
            </a>
            <Link
              href="/verify"
              className="rounded-lg border border-[#22314D] bg-[#0D1728] px-6 py-3 text-sm font-medium text-[#F5F7FB] transition hover:bg-[#101C31]"
            >
              See Live Verification
            </Link>
          </div>
        </section>

        {/* Preview Panels */}
        <section className="mx-auto max-w-7xl px-6 pb-16 lg:px-8">
          <div className="grid gap-5 md:grid-cols-2">
            {/* Panel 1: Agent Profile */}
            <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                  <Fingerprint className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-[#F5F7FB]">Agent Profile</h3>
              </div>
              <div className="space-y-3">
                {[
                  { label: "Agent name", value: "pr-reviewer-01" },
                  { label: "Agent ID", value: "agt_8f3a21c4...c91e" },
                  { label: "Key status", value: "Valid", color: "text-[#22c55e]" },
                  { label: "Signature status", value: "Ed25519 active", color: "text-[#22c55e]" },
                ].map((row) => (
                  <div
                    key={row.label}
                    className="flex items-center justify-between rounded-xl border border-white/6 bg-[#101C31]/70 px-4 py-3"
                  >
                    <span className="text-xs text-[#7F8CA3]">{row.label}</span>
                    <span className={`text-sm font-mono ${row.color ?? "text-[#AAB7CC]"}`}>
                      {row.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Panel 2: Trust State */}
            <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                  <Shield className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-[#F5F7FB]">Trust State</h3>
              </div>
              <div className="space-y-3">
                <div className="flex items-center justify-between rounded-xl border border-white/6 bg-[#101C31]/70 px-4 py-3">
                  <span className="text-xs text-[#7F8CA3]">Trust score</span>
                  <span className="text-lg font-bold text-[#22c55e]">
                    87<span className="text-sm text-[#7F8CA3]">/100</span>
                  </span>
                </div>
                {[
                  { label: "Policy standing", value: "Good", color: "text-[#22c55e]" },
                  { label: "Last verified action", value: "14 min ago" },
                ].map((row) => (
                  <div
                    key={row.label}
                    className="flex items-center justify-between rounded-xl border border-white/6 bg-[#101C31]/70 px-4 py-3"
                  >
                    <span className="text-xs text-[#7F8CA3]">{row.label}</span>
                    <span className={`text-sm font-mono ${row.color ?? "text-[#AAB7CC]"}`}>
                      {row.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Panel 3: Recent Decisions */}
            <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                  <Activity className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-[#F5F7FB]">Recent Decisions</h3>
              </div>
              <div className="space-y-2">
                {[
                  { verdict: "Permit", rule: "api_call", time: "14:32 UTC" },
                  { verdict: "Block", rule: "data_export", time: "14:28 UTC" },
                  { verdict: "Permit", rule: "api_call", time: "14:21 UTC" },
                  { verdict: "Escalate", rule: "financial_transaction", time: "14:15 UTC" },
                ].map((dec, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between rounded-xl border border-white/6 bg-[#101C31]/70 px-4 py-3"
                  >
                    <div className="flex items-center gap-3">
                      {dec.verdict === "Block" ? (
                        <XOctagon className="h-4 w-4 text-[#ef4444]" />
                      ) : dec.verdict === "Escalate" ? (
                        <Clock className="h-4 w-4 text-[#f59e0b]" />
                      ) : (
                        <CheckCircle2 className="h-4 w-4 text-[#22c55e]" />
                      )}
                      <span
                        className={`text-xs font-bold ${
                          dec.verdict === "Block"
                            ? "text-[#ef4444]"
                            : dec.verdict === "Escalate"
                            ? "text-[#f59e0b]"
                            : "text-[#22c55e]"
                        }`}
                      >
                        {dec.verdict}
                      </span>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className="text-xs font-mono text-[#AAB7CC]">{dec.rule}</span>
                      <span className="text-xs text-[#7F8CA3]">{dec.time}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Panel 4: Linked Workflows */}
            <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                  <Link2 className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-[#F5F7FB]">Linked Workflows</h3>
              </div>
              <div className="space-y-3">
                {[
                  { label: "PR verification", value: "3 checks today" },
                  { label: "Tool execution checks", value: "12 actions" },
                  { label: "External API calls", value: "8 verified" },
                ].map((row) => (
                  <div
                    key={row.label}
                    className="flex items-center justify-between rounded-xl border border-white/6 bg-[#101C31]/70 px-4 py-3"
                  >
                    <span className="text-xs text-[#7F8CA3]">{row.label}</span>
                    <span className="text-sm font-mono text-[#AAB7CC]">{row.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* What teams use this for */}
        <section className="mx-auto max-w-4xl px-6 pb-16 lg:px-8">
          <div className="rounded-[28px] border border-[#22314D] bg-[#0D1728] p-8">
            <h2 className="mb-5 text-lg font-semibold tracking-tight text-[#F5F7FB]">
              What teams use this for
            </h2>
            <div className="grid gap-4 md:grid-cols-3">
              {[
                {
                  icon: Fingerprint,
                  text: "Prove which agent acted",
                },
                {
                  icon: Activity,
                  text: "Review decision history per agent",
                },
                {
                  icon: Shield,
                  text: "Inspect identity-backed execution trails",
                },
              ].map((item) => {
                const Icon = item.icon;
                return (
                  <div
                    key={item.text}
                    className="flex gap-3 rounded-2xl border border-white/6 bg-[#101C31]/70 p-4"
                  >
                    <Icon className="mt-0.5 h-5 w-5 flex-shrink-0 text-[#8FB8FF]" />
                    <p className="text-sm leading-6 text-[#C4CFDE]">{item.text}</p>
                  </div>
                );
              })}
            </div>
            <p className="mt-6 text-sm text-[#7F8CA3]">
              Portal access is available to approved teams managing registered Inntris
              agents.
            </p>
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
            <Link href="/docs" className="text-sm transition-colors hover:text-white">
              Docs
            </Link>
            <Link href="/verify" className="text-sm transition-colors hover:text-white">
              Verify
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
