import type { Metadata } from "next";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  CheckCircle2,
  ClipboardCheck,
  Code2,
  CreditCard,
  Database,
  FileCode2,
  GitBranch,
  KeyRound,
  LockKeyhole,
  ServerCog,
  ShieldCheck,
  Workflow,
} from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";
import { MobileMenu } from "@/components/mobile-menu";

export const metadata: Metadata = {
  title: "AI PR Protection for GitHub - Inntris",
  description:
    "Inntris adds a required GitHub Action check that PASS/BLOCKs AI-generated pull requests and creates a verification receipt for every decision.",
};

const protectedAreas = [
  { label: "auth", icon: LockKeyhole },
  { label: "payments", icon: CreditCard },
  { label: "secrets", icon: KeyRound },
  { label: "database migrations", icon: Database },
  { label: "infrastructure", icon: ServerCog },
  { label: "GitHub workflows", icon: Workflow },
  { label: "production branch", icon: GitBranch },
];

const demoSteps = [
  {
    title: "AI PR",
    body: "An AI coding agent opens a pull request against the production branch.",
  },
  {
    title: "Inntris required check",
    body: "The GitHub Action reads the changed files, policy, and optional Promptfoo risk evidence.",
  },
  {
    title: "PASS/BLOCK receipt",
    body: "Reviewers get a decision and verification evidence showing what happened and why.",
  },
];

const included = [
  "1 repo",
  "1 protected branch",
  "GitHub Action setup",
  "basic policy file",
  "PASS/BLOCK receipts",
  "monthly review summary",
  "setup included for first 3 design partners",
];

export default function AiPrProtectionPage() {
  return (
    <div className="min-h-screen bg-muted text-foreground">
      <header className="sticky top-0 z-20 border-b border-border/10 bg-muted/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-5 py-4 lg:px-8">
          <Link href="/" className="flex items-center gap-3" aria-label="Inntris home">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary">
              <InntrisLogo className="h-5 w-5" />
            </span>
            <span className="font-semibold">Inntris</span>
          </Link>
          <nav className="hidden items-center gap-6 text-sm text-muted-foreground md:flex">
            <a href="#problem" className="transition hover:text-foreground">Problem</a>
            <a href="#demo" className="transition hover:text-foreground">Demo</a>
            <a href="#pricing" className="transition hover:text-foreground">Pricing</a>
          </nav>
          <MobileMenu
            variant="light"
            links={[
              { href: "#problem", label: "Problem" },
              { href: "#demo", label: "Demo" },
              { href: "#pricing", label: "Pricing" },
            ]}
          />
        </div>
      </header>

      <main>
        <section className="mx-auto grid min-h-[calc(100vh-144px)] max-w-7xl items-center gap-6 border-b border-border/10 px-5 py-6 md:grid-cols-[1.08fr_0.72fr] lg:gap-10 lg:px-8 lg:py-12">
          <div className="min-w-0 max-w-3xl">
            <p className="mb-3 text-xs font-bold uppercase text-primary">
              AI PR Protection for GitHub
            </p>
            <h1 className="text-4xl font-semibold leading-[0.98] tracking-normal sm:text-5xl md:text-5xl lg:text-6xl xl:text-7xl">
              Stop AI-generated PRs reaching production without proof.
            </h1>
            <p className="mt-6 max-w-2xl text-lg leading-8 text-muted-foreground md:text-xl">
              Inntris adds a required GitHub Action check that PASS/BLOCKs AI-generated pull
              requests and creates a verification receipt for every decision.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <a
                href="mailto:founder@inntris.com?subject=Protect%20one%20repo%20with%20Inntris"
                className="inline-flex min-h-12 items-center justify-center rounded-md bg-primary px-5 text-sm font-semibold text-white transition hover:bg-brandDeep"
              >
                <ShieldCheck className="mr-2 h-4 w-4" />
                Protect one repo
              </a>
              <a
                href="#demo"
                className="inline-flex min-h-12 items-center justify-center rounded-md border border-border bg-white/50 px-5 text-sm font-semibold transition hover:bg-white"
              >
                <ClipboardCheck className="mr-2 h-4 w-4" />
                Watch 60-second demo
              </a>
            </div>
          </div>

          <aside className="min-w-0 rounded-lg border border-border bg-white p-4 shadow-[0_18px_42px_rgba(31,41,55,0.12)] sm:p-6">
            <div className="mb-4 flex items-center justify-between text-sm font-semibold text-muted-foreground sm:mb-6">
              <span className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-destructive shadow-[0_0_0_5px_rgba(180,35,24,0.12)]" />
                Inntris Verification
              </span>
              <span>pull_request -&gt; main</span>
            </div>
            <div className="mb-4 flex flex-wrap items-center justify-between gap-4 sm:mb-6">
              <span className="inline-flex min-h-12 min-w-28 items-center justify-center rounded-md bg-destructive px-4 text-lg font-black text-white">
                BLOCK
              </span>
              <span className="text-sm text-muted-foreground">AI coding agent</span>
            </div>
            <p className="border-t border-border pt-4 text-sm font-semibold leading-6 text-muted-foreground sm:hidden">
              AI-generated PR touched protected production-sensitive files.
            </p>
            <dl className="hidden space-y-4 sm:block">
              <div className="border-t border-border pt-4">
                <dt className="text-xs font-bold uppercase text-muted-foreground">Changed path</dt>
                <dd className="mt-1 break-words font-semibold">supabase/migrations/0012_update_rls.sql</dd>
              </div>
              <div className="border-t border-border pt-4">
                <dt className="text-xs font-bold uppercase text-muted-foreground">Policy reason</dt>
                <dd className="mt-1 font-semibold">
                  AI-generated PR touched protected production-sensitive files
                </dd>
              </div>
              <div className="border-t border-border pt-4">
                <dt className="text-xs font-bold uppercase text-muted-foreground">Receipt</dt>
                <dd className="mt-1 font-semibold text-primary">Verification evidence ready</dd>
              </div>
            </dl>
          </aside>
        </section>

        <section id="problem" className="mx-auto max-w-7xl px-5 pb-12 pt-5 lg:px-8 lg:pb-16 lg:pt-6">
          <div className="max-w-3xl">
            <p className="mb-3 text-xs font-bold uppercase text-primary">The problem</p>
            <h2 className="text-4xl font-semibold leading-tight md:text-5xl">
              CI can pass while the action still violates production policy.
            </h2>
          </div>
          <div className="mt-8 grid gap-4 md:grid-cols-3">
            {[
              {
                title: "Agents edit sensitive files",
                body: "AI coding agents can open PRs and edit production-sensitive files.",
                icon: Code2,
              },
              {
                title: "Build checks are not intent checks",
                body: "CI can pass even when the agent was not allowed to touch that surface.",
                icon: AlertTriangle,
              },
              {
                title: "Reviewers need proof",
                body: "Teams need evidence of what the agent attempted and why it was allowed or blocked.",
                icon: FileCode2,
              },
            ].map((item) => {
              const Icon = item.icon;
              return (
                <article key={item.title} className="rounded-lg border border-border bg-white p-6">
                  <Icon className="mb-5 h-6 w-6 text-warning" />
                  <h3 className="text-lg font-semibold">{item.title}</h3>
                  <p className="mt-2 leading-7 text-muted-foreground">{item.body}</p>
                </article>
              );
            })}
          </div>
        </section>

        <section id="demo" className="bg-accent">
          <div className="mx-auto max-w-7xl px-5 py-12 lg:px-8 lg:py-16">
            <div className="max-w-3xl">
              <p className="mb-3 text-xs font-bold uppercase text-primary">The demo</p>
              <h2 className="text-4xl font-semibold leading-tight md:text-5xl">
                AI PR -&gt; Inntris required check -&gt; PASS/BLOCK receipt
              </h2>
            </div>
            <div className="mt-8 grid gap-4 lg:grid-cols-[1fr_auto_1fr_auto_1fr] lg:items-stretch">
              {demoSteps.map((step, index) => (
                <div key={step.title} className="contents">
                  <article className="rounded-lg border border-border bg-white p-6">
                    <span className="mb-5 flex h-11 w-11 items-center justify-center rounded-md bg-primary text-sm font-black text-white">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <h3 className="text-lg font-semibold">{step.title}</h3>
                    <p className="mt-2 leading-7 text-muted-foreground">{step.body}</p>
                  </article>
                  {index < demoSteps.length - 1 && (
                    <div className="hidden items-center justify-center text-3xl font-black text-primary lg:flex">
                      <ArrowRight className="h-8 w-8" />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="mx-auto max-w-7xl px-5 py-12 lg:px-8 lg:py-16">
          <div className="max-w-3xl">
            <p className="mb-3 text-xs font-bold uppercase text-primary">What gets protected</p>
            <h2 className="text-4xl font-semibold leading-tight md:text-5xl">
              Start with the files buyers are nervous about.
            </h2>
          </div>
          <div className="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-7">
            {protectedAreas.map((area) => {
              const Icon = area.icon;
              return (
                <div key={area.label} className="min-h-24 rounded-lg border border-border bg-white p-4">
                  <Icon className="mb-3 h-5 w-5 text-primary" />
                  <p className="font-semibold">{area.label}</p>
                </div>
              );
            })}
          </div>
        </section>

        <section id="pricing" className="bg-white">
          <div className="mx-auto grid max-w-7xl gap-5 px-5 py-12 lg:grid-cols-[0.85fr_1fr] lg:px-8 lg:py-16">
            <div className="rounded-lg border border-border bg-white p-6">
              <p className="mb-2 text-xs font-bold uppercase text-primary">Starter</p>
              <p className="text-5xl font-black">$200</p>
              <p className="mt-2 font-semibold text-muted-foreground">per month per repo</p>
              <ul className="mt-6 space-y-3">
                {included.map((item) => (
                  <li key={item} className="flex gap-3 text-foreground">
                    <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-success" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="flex flex-col justify-center rounded-lg border border-border bg-white p-6">
              <p className="mb-3 text-xs font-bold uppercase text-primary">Trust-safe wording</p>
              <h2 className="text-3xl font-semibold leading-tight">
                Adds an AI-specific policy gate. Creates verification evidence. Supports review and audit.
              </h2>
              <div className="mt-6 grid gap-3 sm:grid-cols-2">
                <p className="flex gap-2 text-muted-foreground">
                  <BadgeCheck className="mt-0.5 h-5 w-5 shrink-0 text-success" />
                  Keep normal CI and code review.
                </p>
                <p className="flex gap-2 text-muted-foreground">
                  <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  Use it as evidence for review, audit, and production change control.
                </p>
              </div>
              <div className="mt-8 flex flex-wrap gap-3">
                <a
                  href="mailto:founder@inntris.com?subject=Protect%20one%20repo%20with%20Inntris"
                  className="inline-flex min-h-12 items-center justify-center rounded-md bg-primary px-5 text-sm font-semibold text-white transition hover:bg-brandDeep"
                >
                  Protect one repo
                </a>
                <a
                  href="#demo"
                  className="inline-flex min-h-12 items-center justify-center rounded-md border border-border px-5 text-sm font-semibold transition hover:bg-white"
                >
                  Watch 60-second demo
                </a>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
