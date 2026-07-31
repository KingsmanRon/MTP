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
import { MobileMenu } from "@/components/mobile-menu";

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
    verdict: "PASS",
    timestamp: "2026-03-18  14:28 UTC",
    status: "Verified",
  },
  {
    id: "a1d7..b204",
    verdict: "PASS",
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
              <div className="text-xs text-muted-foreground">Audit Explorer</div>
            </div>
          </Link>
          <nav className="hidden items-center gap-6 text-sm md:flex">
            <Link href="/admin" className="text-muted-foreground transition hover:text-white">Console</Link>
            <Link href="/portal" className="text-muted-foreground transition hover:text-white">Portal</Link>
            <Link href="/verify" className="text-muted-foreground transition hover:text-white">Verify</Link>
            <Link href="/docs" className="text-muted-foreground transition hover:text-white">Docs</Link>
          </nav>
          <MobileMenu
            links={[
              { href: "/admin", label: "Console" },
              { href: "/portal", label: "Portal" },
              { href: "/verify", label: "Verify" },
              { href: "/docs", label: "Docs" },
            ]}
          />
        </div>
      </header>

      <AuthRedirectBanner dashboardPath="/audit/search" label="Audit Explorer" />

      <main className="relative">
        {/* Hero */}
        <section className="mx-auto max-w-4xl px-6 pb-12 pt-16 text-center lg:px-8 lg:pt-24">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-tileLine bg-tile/90 px-3 py-1.5 text-sm text-muted-foreground">
            <Search className="h-4 w-4 text-brandInk" />
            Inntris Audit Explorer
          </div>

          <h1 className="text-3xl font-semibold leading-tight tracking-tight md:text-5xl">
            Search the decision trail and{" "}
            <span className="text-primary">inspect cryptographic evidence</span>
          </h1>

          <p className="mx-auto mt-5 max-w-2xl text-lg leading-8 text-muted-foreground">
            Trace policy outcomes, inspect signed receipts, and review tamper-evident
            records across agent activity.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/#contact"
              className="rounded-lg bg-primary px-6 py-3 text-sm font-medium text-white transition-opacity hover:opacity-90"
            >
              Request Access
            </Link>
            <Link
              href="/verify"
              className="rounded-lg border border-tileLine bg-tile px-6 py-3 text-sm font-medium text-foreground transition hover:bg-card"
            >
              Verify a Live Receipt
            </Link>
          </div>
        </section>

        {/* Preview Panels */}
        <section className="mx-auto max-w-7xl px-6 pb-16 lg:px-8">
          <div className="grid gap-5 md:grid-cols-2">
            {/* Panel 1: Search and Filter */}
            <div className="rounded-[24px] border border-tileLine bg-tile p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-tileLine bg-card text-brandInk">
                  <Search className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-foreground">Search and Filter</h3>
              </div>
              <div className="space-y-3">
                {[
                  { label: "Receipt ID", value: "8f3a21c4-...-c91e" },
                  { label: "Agent ID", value: "agent-pr-reviewer-01" },
                  { label: "Outcome", value: "PASS / BLOCK / ESCALATE" },
                  { label: "Date range", value: "2026-03-12 — 2026-03-18" },
                ].map((row) => (
                  <div
                    key={row.label}
                    className="flex items-center justify-between rounded-xl border border-tileLine bg-card/70 px-4 py-3"
                  >
                    <span className="text-xs text-muted-foreground">{row.label}</span>
                    <span className="text-sm font-mono text-muted-foreground">{row.value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Panel 2: Evidence Timeline */}
            <div className="rounded-[24px] border border-tileLine bg-tile p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-tileLine bg-card text-brandInk">
                  <Clock className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-foreground">Evidence Timeline</h3>
              </div>
              <div className="relative space-y-4 pl-5">
                <div className="absolute left-[9px] top-1 bottom-1 w-px bg-[hsl(var(--tile-line))]" />
                {timelineSteps.map((step) => {
                  const Icon = step.icon;
                  return (
                    <div key={step.label} className="relative flex items-center gap-3">
                      <div className="relative z-10 flex h-5 w-5 items-center justify-center rounded-full border border-tileLine bg-tile">
                        <div className="h-2 w-2 rounded-full bg-primary" />
                      </div>
                      <div className="flex flex-1 items-center justify-between rounded-xl border border-tileLine bg-card/70 px-4 py-3">
                        <span className="text-sm text-foreground">{step.label}</span>
                        <Icon className="h-4 w-4 text-muted-foreground" />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Panel 3: Recent Records */}
            <div className="rounded-[24px] border border-tileLine bg-tile p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-tileLine bg-card text-brandInk">
                  <FileCheck2 className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-foreground">Recent Records</h3>
              </div>
              <div className="space-y-2">
                {previewRecords.map((rec) => (
                  <div
                    key={rec.id}
                    className="flex items-center justify-between rounded-xl border border-tileLine bg-card/70 px-4 py-3"
                  >
                    <div className="flex items-center gap-3">
                      {rec.verdict === "BLOCK" ? (
                        <XOctagon className="h-4 w-4 text-destructive" />
                      ) : (
                        <CheckCircle2 className="h-4 w-4 text-success" />
                      )}
                      <span className="text-xs font-mono text-brandInk">{rec.id}</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <span
                        className={`text-xs font-bold ${
                          rec.verdict === "BLOCK" ? "text-destructive" : "text-success"
                        }`}
                      >
                        {rec.verdict}
                      </span>
                      <span className="text-xs text-muted-foreground">{rec.timestamp}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Panel 4: Audit Depth */}
            <div className="rounded-[24px] border border-tileLine bg-tile p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-tileLine bg-card text-brandInk">
                  <Fingerprint className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-foreground">Audit Depth</h3>
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
                    className="flex items-center justify-between rounded-xl border border-tileLine bg-card/70 px-4 py-3"
                  >
                    <span className="text-xs text-muted-foreground">{row.label}</span>
                    <span className="text-sm font-mono text-muted-foreground">{row.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* What teams use this for */}
        <section className="mx-auto max-w-4xl px-6 pb-16 lg:px-8">
          <div className="rounded-[28px] border border-tileLine bg-tile p-8">
            <h2 className="mb-5 text-lg font-semibold tracking-tight text-foreground">
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
                    className="flex gap-3 rounded-2xl border border-tileLine bg-card/70 p-4"
                  >
                    <Icon className="mt-0.5 h-5 w-5 flex-shrink-0 text-brandInk" />
                    <p className="text-sm leading-6 text-muted-foreground">{item.text}</p>
                  </div>
                );
              })}
            </div>
            <p className="mt-6 text-sm text-muted-foreground">
              Audit Explorer is available to approved teams requiring full search and
              investigation capabilities.
            </p>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-tileLine">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-8 lg:px-8">
          <div className="flex items-center gap-2">
            <InntrisLogo className="h-5 w-5" />
            <span className="text-muted-foreground">Inntris Core</span>
          </div>
          <div className="flex items-center gap-6 text-muted-foreground">
            <Link href="/" className="text-sm transition-colors hover:text-white">Home</Link>
            <Link href="/docs" className="text-sm transition-colors hover:text-white">Docs</Link>
            <Link href="/verify" className="text-sm transition-colors hover:text-white">Verify</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
