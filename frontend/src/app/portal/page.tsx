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
import { AuthRedirectBanner } from "@/components/auth-redirect-banner";
import { MobileMenu } from "@/components/mobile-menu";

/* ------------------------------------------------------------------ */
/*  Page (Server Component — SSR public preview shell)                 */
/* ------------------------------------------------------------------ */

export default function PortalPreviewPage() {
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
              <div className="text-xs text-muted-foreground">Portal</div>
            </div>
          </Link>
          <nav className="hidden items-center gap-6 text-sm md:flex">
            <Link href="/admin" className="text-muted-foreground transition hover:text-foreground">Console</Link>
            <Link href="/audit" className="text-muted-foreground transition hover:text-foreground">Audit</Link>
            <Link href="/verify" className="text-muted-foreground transition hover:text-foreground">Verify</Link>
            <Link href="/docs" className="text-muted-foreground transition hover:text-foreground">Docs</Link>
          </nav>
          <MobileMenu
            links={[
              { href: "/admin", label: "Console" },
              { href: "/audit", label: "Audit" },
              { href: "/verify", label: "Verify" },
              { href: "/docs", label: "Docs" },
            ]}
          />
        </div>
      </header>

      <AuthRedirectBanner dashboardPath="/portal/dashboard" label="Portal" />

      <main className="relative">
        {/* Hero */}
        <section className="mx-auto max-w-4xl px-6 pb-12 pt-16 text-center lg:px-8 lg:pt-24">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-tileLine bg-tile/90 px-3 py-1.5 text-sm text-muted-foreground">
            <Bot className="h-4 w-4 text-brandInk" />
            Inntris Portal
          </div>

          <h1 className="text-3xl font-semibold leading-tight tracking-tight md:text-5xl">
            Inspect agent identity, decisions, and{" "}
            <span className="text-primary">trust status</span>
          </h1>

          <p className="mx-auto mt-5 max-w-2xl text-lg leading-8 text-muted-foreground">
            View registered agents, signed activity, trust scores, and decision records
            tied to each agent.
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
              See Live Verification
            </Link>
          </div>
        </section>

        {/* Preview Panels */}
        <section className="mx-auto max-w-7xl px-6 pb-16 lg:px-8">
          <div className="grid gap-5 md:grid-cols-2">
            {/* Panel 1: Agent Profile */}
            <div className="min-w-0 rounded-[24px] border border-tileLine bg-tile p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-tileLine bg-card text-brandInk">
                  <Fingerprint className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-foreground">Agent Profile</h3>
              </div>
              <div className="space-y-3">
                {[
                  { label: "Agent name", value: "pr-reviewer-01" },
                  { label: "Agent ID", value: "agt_8f3a21c4...c91e" },
                  { label: "Key status", value: "Valid", color: "text-success" },
                  { label: "Signature status", value: "Ed25519 active", color: "text-success" },
                ].map((row) => (
                  <div
                    key={row.label}
                    className="flex min-w-0 items-center justify-between gap-3 rounded-xl border border-tileLine bg-card px-4 py-3"
                  >
                    <span className="shrink-0 text-xs text-muted-foreground">{row.label}</span>
                    <span className={`truncate text-sm font-mono ${row.color ?? "text-muted-foreground"}`}>
                      {row.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Panel 2: Trust State */}
            <div className="min-w-0 rounded-[24px] border border-tileLine bg-tile p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-tileLine bg-card text-brandInk">
                  <Shield className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-foreground">Trust State</h3>
              </div>
              <div className="space-y-3">
                <div className="flex min-w-0 items-center justify-between gap-3 rounded-xl border border-tileLine bg-card px-4 py-3">
                  <span className="text-xs text-muted-foreground">Trust score</span>
                  <span className="text-lg font-bold text-success">
                    87<span className="text-sm text-muted-foreground">/100</span>
                  </span>
                </div>
                {[
                  { label: "Policy standing", value: "Good", color: "text-success" },
                  { label: "Last verified action", value: "14 min ago" },
                ].map((row) => (
                  <div
                    key={row.label}
                    className="flex min-w-0 items-center justify-between gap-3 rounded-xl border border-tileLine bg-card px-4 py-3"
                  >
                    <span className="shrink-0 text-xs text-muted-foreground">{row.label}</span>
                    <span className={`truncate text-sm font-mono ${row.color ?? "text-muted-foreground"}`}>
                      {row.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Panel 3: Recent Decisions */}
            <div className="min-w-0 rounded-[24px] border border-tileLine bg-tile p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-tileLine bg-card text-brandInk">
                  <Activity className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-foreground">Recent Decisions</h3>
              </div>
              <div className="space-y-2">
                {[
                  { verdict: "PASS", rule: "api_call", time: "14:32 UTC" },
                  { verdict: "BLOCK", rule: "data_export", time: "14:28 UTC" },
                  { verdict: "PASS", rule: "api_call", time: "14:21 UTC" },
                  { verdict: "ESCALATE", rule: "financial_transaction", time: "14:15 UTC" },
                ].map((dec, i) => (
                  <div
                    key={i}
                    className="flex min-w-0 items-center justify-between gap-3 rounded-xl border border-tileLine bg-card px-4 py-3"
                  >
                    <div className="flex items-center gap-3">
                      {dec.verdict === "BLOCK" ? (
                        <XOctagon className="h-4 w-4 text-destructive" />
                      ) : dec.verdict === "ESCALATE" ? (
                        <Clock className="h-4 w-4 text-warning" />
                      ) : (
                        <CheckCircle2 className="h-4 w-4 text-success" />
                      )}
                      <span
                        className={`text-xs font-bold ${
                          dec.verdict === "BLOCK"
                            ? "text-destructive"
                            : dec.verdict === "ESCALATE"
                            ? "text-warning"
                            : "text-success"
                        }`}
                      >
                        {dec.verdict}
                      </span>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className="text-xs font-mono text-muted-foreground">{dec.rule}</span>
                      <span className="text-xs text-muted-foreground">{dec.time}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Panel 4: Linked Workflows */}
            <div className="min-w-0 rounded-[24px] border border-tileLine bg-tile p-6">
              <div className="mb-5 flex items-center gap-2">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-tileLine bg-card text-brandInk">
                  <Link2 className="h-4 w-4" />
                </div>
                <h3 className="text-sm font-semibold text-foreground">Linked Workflows</h3>
              </div>
              <div className="space-y-3">
                {[
                  { label: "PR verification", value: "3 checks today" },
                  { label: "Tool execution checks", value: "12 actions" },
                  { label: "External API calls", value: "8 verified" },
                ].map((row) => (
                  <div
                    key={row.label}
                    className="flex min-w-0 items-center justify-between gap-3 rounded-xl border border-tileLine bg-card px-4 py-3"
                  >
                    <span className="shrink-0 text-xs text-muted-foreground">{row.label}</span>
                    <span className="truncate text-sm font-mono text-muted-foreground">{row.value}</span>
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
                    className="flex gap-3 rounded-2xl border border-tileLine bg-card/70 p-4"
                  >
                    <Icon className="mt-0.5 h-5 w-5 flex-shrink-0 text-brandInk" />
                    <p className="text-sm leading-6 text-muted-foreground">{item.text}</p>
                  </div>
                );
              })}
            </div>
            <p className="mt-6 text-sm text-muted-foreground">
              Portal access is available to approved teams managing registered Inntris
              agents.
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
            <Link href="/" className="text-sm transition-colors hover:text-foreground">Home</Link>
            <Link href="/docs" className="text-sm transition-colors hover:text-foreground">Docs</Link>
            <Link href="/verify" className="text-sm transition-colors hover:text-foreground">Verify</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
