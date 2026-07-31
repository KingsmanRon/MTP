import type { Metadata } from "next";
import Link from "next/link";
import {
  ArrowRight,
  CheckCircle2,
  FileCheck2,
  LockKeyhole,
  ShieldCheck,
  Timer,
} from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";
import { PilotRiskAssessment } from "@/components/pilot-risk-assessment";

export const metadata: Metadata = {
  title: "14-Day Agent Action Proof Pilot - Inntris",
  description:
    "Instrument one high-risk AI agent workflow with pre-execution policy enforcement and verifiable PASS/BLOCK receipts in 14 days.",
};

const deliverables = [
  "One high-risk agent workflow instrumented",
  "Agent identity and policy boundary configured",
  "PASS/BLOCK enforcement before execution",
  "Verifiable receipt for every decision",
  "Pilot report with risks found and rollout recommendation",
];

const phases = [
  {
    label: "Days 1-2",
    title: "Choose the action",
    body: "Map one risky production workflow, its execution boundary, and the team that owns the consequence.",
  },
  {
    label: "Days 3-7",
    title: "Enforce the policy",
    body: "Put Inntris in the decision path, bind the agent identity, and configure clear allow and block conditions.",
  },
  {
    label: "Days 8-14",
    title: "Prove the outcome",
    body: "Run real scenarios, verify receipts independently, and deliver the production rollout recommendation.",
  },
];

export default function PilotPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-accent/50 via-transparent to-transparent" />
      <header className="sticky top-0 z-20 border-b border-tileLine bg-background/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
          <Link href="/" className="flex items-center gap-3" aria-label="Inntris home">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-tileLine bg-tile">
              <InntrisLogo className="h-6 w-6" />
            </span>
            <span className="font-semibold">Inntris</span>
          </Link>
          <div className="flex items-center gap-4">
            <Link href="/verify" className="hidden text-sm text-muted-foreground hover:text-foreground sm:inline">
              View live receipt
            </Link>
            <a
              href="#assessment"
              className="rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white hover:opacity-90"
            >
              Qualify your workflow
            </a>
          </div>
        </div>
      </header>

      <main className="relative">
        <section className="mx-auto grid max-w-7xl gap-10 px-6 pb-20 pt-16 lg:grid-cols-[1.08fr_0.92fr] lg:px-8 lg:pb-28 lg:pt-24">
          <div className="max-w-3xl">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-primary/25 bg-primary/10 px-3 py-1.5 font-mono text-xs text-primary">
              <Timer className="h-3.5 w-3.5" />
              14-day Agent Action Proof Pilot
            </div>
            <h1 className="text-4xl font-semibold leading-[1.08] tracking-tight md:text-6xl">
              Control one high-risk agent action.{" "}
              <span className="text-primary">Prove every decision.</span>
            </h1>
            <p className="mt-6 max-w-2xl text-lg leading-8 text-muted-foreground">
              In 14 days, Inntris instruments one AI agent workflow with pre-execution policy
              enforcement and verifiable receipts for every allowed and blocked action.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <a
                href="#assessment"
                className="inline-flex items-center rounded-lg bg-primary px-5 py-3 text-sm font-medium text-white hover:opacity-90"
              >
                Find your pilot workflow
                <ArrowRight className="ml-2 h-4 w-4" />
              </a>
              <Link
                href="/verify/d8dd0902-4750-42d2-9516-92bf6362e815"
                className="rounded-lg border border-tileLine bg-tile px-5 py-3 text-sm font-medium hover:bg-card"
              >
                Inspect a live receipt
              </Link>
            </div>
            <p className="mt-5 text-sm text-muted-foreground">
              Design-partner pilots start at $5,000. One workflow, fixed scope, production
              rollout recommendation included.
            </p>
          </div>

          <aside className="rounded-[28px] border border-tileLine bg-tile p-6 shadow-2xl shadow-black/25 md:p-8">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brandInk">
              Definition of done
            </p>
            <h2 className="mt-3 text-2xl font-semibold">A workflow your team can control and audit.</h2>
            <ul className="mt-6 space-y-4">
              {deliverables.map((deliverable) => (
                <li key={deliverable} className="flex gap-3 text-sm leading-6 text-muted-foreground">
                  <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
                  {deliverable}
                </li>
              ))}
            </ul>
            <div className="mt-7 grid grid-cols-3 gap-3 border-t border-tileLine pt-6 text-center">
              <div>
                <p className="font-mono text-lg font-semibold">1</p>
                <p className="mt-1 text-xs text-muted-foreground">workflow</p>
              </div>
              <div>
                <p className="font-mono text-lg font-semibold">14</p>
                <p className="mt-1 text-xs text-muted-foreground">days</p>
              </div>
              <div>
                <p className="font-mono text-lg font-semibold">100%</p>
                <p className="mt-1 text-xs text-muted-foreground">decision receipts</p>
              </div>
            </div>
          </aside>
        </section>

        <section className="border-y border-tileLine bg-tile/55">
          <div className="mx-auto max-w-7xl px-6 py-16 lg:px-8">
            <div className="max-w-3xl">
              <p className="text-sm font-medium uppercase tracking-[0.18em] text-brandInk">
                The pilot path
              </p>
              <h2 className="mt-3 text-3xl font-semibold tracking-tight md:text-4xl">
                Enforce first. Authorize clearly. Prove afterward.
              </h2>
            </div>
            <div className="mt-10 grid gap-4 md:grid-cols-3">
              {phases.map((phase) => (
                <article key={phase.label} className="rounded-2xl border border-tileLine bg-background p-6">
                  <p className="font-mono text-xs text-primary">{phase.label}</p>
                  <h3 className="mt-4 text-xl font-semibold">{phase.title}</h3>
                  <p className="mt-3 text-sm leading-7 text-muted-foreground">{phase.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
          <div className="grid gap-5 md:grid-cols-3">
            {[
              {
                icon: LockKeyhole,
                title: "A real control boundary",
                body: "The agent must receive a PASS decision before the protected action executes.",
              },
              {
                icon: ShieldCheck,
                title: "A policy your team owns",
                body: "The pilot makes the allow, block, identity, and limit conditions explicit.",
              },
              {
                icon: FileCheck2,
                title: "Evidence others can verify",
                body: "Every decision produces a receipt that can be inspected without trusting a screenshot or mutable log.",
              },
            ].map((item) => {
              const Icon = item.icon;
              return (
                <article key={item.title} className="rounded-2xl border border-tileLine bg-tile p-6">
                  <Icon className="h-6 w-6 text-brandInk" />
                  <h3 className="mt-5 text-lg font-semibold">{item.title}</h3>
                  <p className="mt-2 text-sm leading-7 text-muted-foreground">{item.body}</p>
                </article>
              );
            })}
          </div>
        </section>

        <PilotRiskAssessment />
      </main>

      <footer className="border-t border-tileLine">
        <div className="mx-auto flex max-w-7xl flex-col justify-between gap-3 px-6 py-8 text-sm text-muted-foreground sm:flex-row lg:px-8">
          <span>Inntris Agent Action Proof Pilot</span>
          <a href="mailto:sales@inntris.com" className="text-brandInk hover:text-foreground">
            sales@inntris.com
          </a>
        </div>
      </footer>
    </div>
  );
}
