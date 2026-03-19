import Link from "next/link";
import {
  Shield,
  Lock,
  Fingerprint,
  Settings,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Bot,
} from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";
import { AuthRedirectBanner } from "@/components/auth-redirect-banner";

/* ------------------------------------------------------------------ */
/*  Page (Server Component — SSR public preview shell)                 */
/* ------------------------------------------------------------------ */

export default function AdminPreviewPage() {
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
              <div className="text-xs text-[#7F8CA3]">Console</div>
            </div>
          </Link>
          <nav className="hidden items-center gap-6 text-sm md:flex">
            <Link href="/portal" className="text-[#C4CFDE] transition hover:text-white">Portal</Link>
            <Link href="/audit" className="text-[#C4CFDE] transition hover:text-white">Audit</Link>
            <Link href="/verify" className="text-[#C4CFDE] transition hover:text-white">Verify</Link>
            <Link href="/docs" className="text-[#C4CFDE] transition hover:text-white">Docs</Link>
          </nav>
        </div>
      </header>

      <AuthRedirectBanner dashboardPath="/admin/dashboard" label="Console" />

      <main className="relative">
        {/* Hero */}
        <section className="mx-auto max-w-4xl px-6 pb-12 pt-16 text-center lg:px-8 lg:pt-24">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-[#22314D] bg-[#0D1728]/90 px-3 py-1.5 text-sm text-[#AAB7CC]">
            <Settings className="h-4 w-4 text-[#8FB8FF]" />
            Inntris Console
          </div>

          <h1 className="text-3xl font-semibold leading-tight tracking-tight md:text-5xl">
            Control agent policy{" "}
            <span className="text-[#4C8DFF]">before execution</span>
          </h1>

          <p className="mx-auto mt-5 max-w-2xl text-lg leading-8 text-[#C4CFDE]">
            Define enforcement rules, manage trust thresholds, register identity, and
            control how agent actions are evaluated before they run.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <a
              href="/#contact"
              className="rounded-lg bg-[#28C281] px-6 py-3 text-sm font-medium text-white transition-opacity hover:opacity-90"
            >
              Request Access
            </a>
            <Link
              href="/docs"
              className="rounded-lg border border-[#22314D] bg-[#0D1728] px-6 py-3 text-sm font-medium text-[#F5F7FB] transition hover:bg-[#101C31]"
            >
              Read the Docs
            </Link>
          </div>
        </section>

        {/* Preview Panels */}
        <section className="mx-auto max-w-7xl px-6 pb-16 lg:px-8">
          <div className="grid gap-5 md:grid-cols-2">
            {/* Panel 1: Policy Enforcement */}
            <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                  <Shield className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-[#F5F7FB]">Policy Enforcement</h3>
              </div>
              <div className="space-y-3">
                {[
                  { label: "Fail-closed mode", value: "Enabled", color: "text-[#22c55e]" },
                  { label: "Active rule sets", value: "3 policies" },
                  { label: "Trust threshold", value: "70 / 100" },
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

            {/* Panel 2: Agent Identity */}
            <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                  <Fingerprint className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-[#F5F7FB]">Agent Identity</h3>
              </div>
              <div className="space-y-3">
                {[
                  { label: "Registered agents", value: "4 agents" },
                  { label: "Key status", value: "All valid", color: "text-[#22c55e]" },
                  { label: "Signature enforcement", value: "Required" },
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

            {/* Panel 3: Execution Controls */}
            <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                  <Lock className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-[#F5F7FB]">Execution Controls</h3>
              </div>
              <div className="space-y-3">
                {[
                  { label: "Allowed tools", value: "12 registered" },
                  { label: "Blocked actions", value: "admin_action, data_export" },
                  { label: "Escalation triggers", value: "2 active" },
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

            {/* Panel 4: Governance Summary */}
            <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                  <CheckCircle2 className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-[#F5F7FB]">Governance Summary</h3>
              </div>
              <div className="space-y-3">
                {[
                  { label: "Environments", value: "production, staging" },
                  { label: "Last policy update", value: "2026-03-17" },
                  { label: "Enforcement status", value: "Active", color: "text-[#22c55e]" },
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
                  icon: Shield,
                  text: "Define policy before agents act",
                },
                {
                  icon: Fingerprint,
                  text: "Manage cryptographic identity and trust thresholds",
                },
                {
                  icon: Lock,
                  text: "Enforce fail-closed decisions in production",
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
              This is a controlled Inntris product surface. Access is available to approved
              teams and partners.
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
            <Link href="/" className="text-sm transition-colors hover:text-white">Home</Link>
            <Link href="/docs" className="text-sm transition-colors hover:text-white">Docs</Link>
            <Link href="/verify" className="text-sm transition-colors hover:text-white">Verify</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
