import Link from "next/link";
import {
  Search,
  FileCheck2,
  Clock,
  Link2,
  Shield,
  ChevronRight,
  CheckCircle2,
  XOctagon,
  Fingerprint,
  AlertTriangle,
} from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";
import { AuthRedirectBanner } from "@/components/auth-redirect-banner";

/* ------------------------------------------------------------------ */
/*  Curated preview data                                               */
/* ------------------------------------------------------------------ */

const previewRecords = [
  {
    id: "8f3a..c91e",
    verdict: "BLOCK",
    timestamp: "2026-03-18  14:32 UTC",
    status: "Verified",
  },
  {
    id: "2f41..09aa",
    verdict: "PERMIT",
    timestamp: "2026-03-18  14:28 UTC",
    status: "Verified",
  },
  {
    id: "a1d7..b204",
    verdict: "PERMIT",
    timestamp: "2026-03-18  14:21 UTC",
    status: "Verified",
  },
  {
    id: "c4e9..3f17",
    verdict: "BLOCK",
    timestamp: "2026-03-18  14:15 UTC",
    status: "Anchored",
  },
];

const timelineSteps = [
  { label: "Decision issued", icon: FileCheck2 },
  { label: "Signature validated", icon: CheckCircle2 },
  { label: "Receipt created", icon: Shield },
  { label: "Anchored on Base L2", icon: Link2 },
];

/* ------------------------------------------------------------------ */
/*  Page (Server Component)                                            */
/* ------------------------------------------------------------------ */

export default function AuditPreviewPage() {
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
              <div className="text-xs text-[#7F8CA3]">Audit Explorer</div>
            </div>
          </Link>
          <nav className="hidden items-center gap-6 text-sm md:flex">
            <Link href="/admin" className="text-[#C4CFDE] transition hover:text-white">Console</Link>
            <Link href="/portal" className="text-[#C4CFDE] transition hover:text-white">Portal</Link>
            <Link href="/verify" className="text-[#C4CFDE] transition hover:text-white">Verify</Link>
            <Link href="/docs" className="text-[#C4CFDE] transition hover:text-white">Docs</Link>
          </nav>
        </div>
      </header>

      <AuthRedirectBanner dashboardPath="/audit/search" label="Audit Explorer" />

      <main className="relative">
        {/* Hero */}
        <section className="mx-auto max-w-4xl px-6 pb-12 pt-16 text-center lg:px-8 lg:pt-24">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-[#22314D] bg-[#0D1728]/90 px-3 py-1.5 text-sm text-[#AAB7CC]">
            <Search className="h-4 w-4 text-[#8FB8FF]" />
            Inntris Audit Explorer
          </div>

          <h1 className="text-3xl font-semibold leading-tight tracking-tight md:text-5xl">
            Search the decision trail and{" "}
            <span className="text-[#4C8DFF]">inspect cryptographic evidence</span>
          </h1>

          <p className="mx-auto mt-5 max-w-2xl text-lg leading-8 text-[#C4CFDE]">
            Trace policy outcomes, inspect signed receipts, and review tamper-evident
            records across agent activity.
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
              Verify a Live Receipt
            </Link>
          </div>
        </section>

        {/* Preview Panels */}
        <section className="mx-auto max-w-7xl px-6 pb-16 lg:px-8">
          <div className="grid gap-5 md:grid-cols-2">
            {/* Panel 1: Search and Filter */}
            <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                  <Search className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-[#F5F7FB]">Search and Filter</h3>
              </div>
              <div className="space-y-3">
                {[
                  { label: "Receipt ID", value: "8f3a21c4-...-c91e" },
                  { label: "Agent ID", value: "agent-pr-reviewer-01" },
                  { label: "Outcome", value: "BLOCK / PERMIT" },
                  { label: "Date range", value: "2026-03-12 — 2026-03-18" },
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

            {/* Panel 2: Evidence Timeline */}
            <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                  <Clock className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-[#F5F7FB]">Evidence Timeline</h3>
              </div>
              <div className="relative space-y-4 pl-5">
                <div className="absolute left-[9px] top-1 bottom-1 w-px bg-[#22314D]" />
                {timelineSteps.map((step) => {
                  const Icon = step.icon;
                  return (
                    <div key={step.label} className="relative flex items-center gap-3">
                      <div className="relative z-10 flex h-5 w-5 items-center justify-center rounded-full border border-[#22314D] bg-[#0D1728]">
                        <div className="h-2 w-2 rounded-full bg-[#4C8DFF]" />
                      </div>
                      <div className="flex flex-1 items-center justify-between rounded-xl border border-white/6 bg-[#101C31]/70 px-4 py-3">
                        <span className="text-sm text-[#F5F7FB]">{step.label}</span>
                        <Icon className="h-4 w-4 text-[#7F8CA3]" />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Panel 3: Recent Records */}
            <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                  <FileCheck2 className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-[#F5F7FB]">Recent Records</h3>
              </div>
              <div className="space-y-2">
                {previewRecords.map((rec) => (
                  <div
                    key={rec.id}
                    className="flex items-center justify-between rounded-xl border border-white/6 bg-[#101C31]/70 px-4 py-3"
                  >
                    <div className="flex items-center gap-3">
                      {rec.verdict === "BLOCK" ? (
                        <XOctagon className="h-4 w-4 text-[#ef4444]" />
                      ) : (
                        <CheckCircle2 className="h-4 w-4 text-[#22c55e]" />
                      )}
                      <span className="text-xs font-mono text-[#8FB8FF]">{rec.id}</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <span
                        className={`text-xs font-bold ${
                          rec.verdict === "BLOCK" ? "text-[#ef4444]" : "text-[#22c55e]"
                        }`}
                      >
                        {rec.verdict}
                      </span>
                      <span className="text-xs text-[#7F8CA3]">{rec.timestamp}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Panel 4: Audit Depth */}
            <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                  <Fingerprint className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-[#F5F7FB]">Audit Depth</h3>
              </div>
              <div className="space-y-3">
                {[
                  { label: "Policy reason", value: "Trust score below threshold" },
                  { label: "Linked agent", value: "pr-reviewer-01" },
                  { label: "Cryptographic proof", value: "SHA-256 + Ed25519" },
                  { label: "Chain reference", value: "Base L2 · Block 24,891,003" },
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
                  icon: AlertTriangle,
                  text: "Investigate blocked or high-risk actions",
                },
                {
                  icon: FileCheck2,
                  text: "Produce evidence for compliance and incident review",
                },
                {
                  icon: Shield,
                  text: "Verify that records have not been altered",
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
              Audit Explorer is available to approved teams requiring full search and
              investigation capabilities.
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
