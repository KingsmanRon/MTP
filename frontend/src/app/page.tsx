import React from "react";
import Link from "next/link";
import { Shield, LayoutDashboard, Bot, SearchCheck, Globe, KeyRound, CheckCircle2, Lock, FileCheck2, ChevronRight } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import ContactSection from "@/components/contact-section";
const modules = [
  {
    icon: LayoutDashboard,
    title: "Admin Console",
    role: "For platform admins",
    body: "Manage organisations, agents, policies, API keys, and security alerts.",
    cta: "Open Console",
    href: "/admin",
  },
  {
    icon: Bot,
    title: "Agent Portal",
    role: "For developers and operators",
    body: "Issue credentials, test verification, and monitor agent trust state.",
    cta: "Open Portal",
    href: "/portal",
  },
  {
    icon: SearchCheck,
    title: "Audit Explorer",
    role: "For investigations and compliance",
    body: "Search verification decisions and inspect tamper-evident audit history.",
    cta: "Open Explorer",
    href: "/audit",
  },
  {
    icon: Globe,
    title: "Public Verify",
    role: "For customers, partners, and auditors",
    body: "Verify an agent's trust status and verification history externally.",
    cta: "Open Verifier",
    href: "/verify",
  },
];
const trustSignals = [
  {
    value: "Fail-closed",
    label: "Fail-closed by default",
  },
  {
    value: "Ed25519",
    label: "Ed25519-signed actions",
  },
  {
    value: "Base L2",
    label: "Base L2 anchored audit",
  },
  {
    value: "< 100 ms",
    label: "Sub-100 ms verification",
  },
];
const capabilities = [
  {
    icon: KeyRound,
    title: "Cryptographic identity",
    body: "Every agent signs actions with a verifiable identity. No key, no action.",
  },
  {
    icon: Lock,
    title: "Policy before execution",
    body: "Evaluate risky actions before they run, not after the fact.",
  },
  {
    icon: FileCheck2,
    title: "Tamper-evident audit",
    body: "Record approvals, blocks, and evidence in a verifiable audit trail.",
  },
];
export default function InntrisCoreDarkPreview() {
  return (
    <div className="min-h-screen bg-[#07111F] text-[#F5F7FB]">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(76,141,255,0.14),transparent_32%),radial-gradient(circle_at_80%_30%,rgba(143,184,255,0.08),transparent_24%)] pointer-events-none" />
      <header className="sticky top-0 z-20 border-b border-white/8 bg-[#07111F]/85 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#0D1728] shadow-[0_0_0_1px_rgba(255,255,255,0.02)]">
              <Shield className="h-5 w-5 text-[#8FB8FF]" />
            </div>
            <div>
              <div className="text-lg font-semibold tracking-tight">Inntris</div>
              <div className="text-xs text-[#7F8CA3]">Core control plane</div>
            </div>
          </div>
          <nav className="hidden items-center gap-8 text-[15px] text-[#C4CFDE] md:flex">
            <a className="transition hover:text-white" href="#overview">Overview</a>
            <a className="transition hover:text-white" href="#use-cases">Use Cases</a>
            <a className="transition hover:text-white" href="#modules">Modules</a>
            <a className="transition hover:text-white" href="#contact">Contact</a>
            <Link className="transition hover:text-white" href="/docs">Docs</Link>
          </nav>
          <div className="flex items-center gap-3">
            <Link href="/docs">
              <Button variant="outline" className="hidden border-[#22314D] bg-[#0D1728] text-[#F5F7FB] hover:bg-[#101C31] hover:text-white md:inline-flex">
                View documentation
              </Button>
            </Link>
            <Link href="/admin">
              <Button className="bg-[#4C8DFF] text-white hover:bg-[#6AA2FF]">
                Open Admin Console
              </Button>
            </Link>
          </div>
        </div>
      </header>
      <main className="relative">
        <section id="overview" className="mx-auto grid max-w-7xl gap-12 px-6 pb-20 pt-16 lg:grid-cols-[1.15fr_0.85fr] lg:px-8 lg:pb-28 lg:pt-20">
          <div className="max-w-3xl">
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-[#22314D] bg-[#0D1728]/90 px-3 py-1.5 text-sm text-[#AAB7CC]">
              <CheckCircle2 className="h-4 w-4 text-[#28C281]" />
              Verification infrastructure for production AI agents
            </div>
            <h1 className="max-w-3xl text-4xl font-semibold leading-tight tracking-tight md:text-6xl">
              Your AI agents are taking real actions.
              <br />
              <span className="text-[#4C8DFF]">Prove what they actually did.</span>
            </h1>
            <p className="mt-5 max-w-2xl text-lg leading-8 text-[#C4CFDE] md:text-xl">
              Cryptographic identity, policy enforcement, and tamper-evident audit for AI agents in production.
            </p>
            <p className="mt-4 max-w-2xl text-[15px] leading-7 text-[#AAB7CC]">
              Built for teams running agent workflows against code, data, APIs, and high-trust operations.
            </p>
            <div className="mt-8 mb-4 flex flex-wrap gap-3">
              <Link href="/docs">
                <Button size="lg" className="bg-[#4C8DFF] px-6 text-white hover:bg-[#6AA2FF]">
                  View Documentation
                </Button>
              </Link>
              <Link href="/verify">
                <Button
                  size="lg"
                  variant="outline"
                  className="border-[#22314D] bg-[#0D1728] px-6 text-[#F5F7FB] hover:bg-[#101C31] hover:text-white"
                >
                  See Live Verification
                </Button>
              </Link>
            </div>
          </div>
          <div className="relative">
            <div className="absolute -inset-4 rounded-[32px] bg-[radial-gradient(circle_at_top,rgba(76,141,255,0.18),transparent_38%)] blur-2xl" />
            <div className="relative overflow-hidden rounded-[28px] border border-[#22314D] bg-[#0D1728] shadow-2xl shadow-black/30">
              <div className="border-b border-white/8 px-5 py-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium text-[#F5F7FB]">Verification decision flow</div>
                    <div className="mt-1 text-xs text-[#7F8CA3]">Where Inntris sits in your stack</div>
                  </div>
                  <div className="rounded-full border border-[#22314D] bg-[#101C31] px-3 py-1 text-xs text-[#8FB8FF]">
                    live policy path
                  </div>
                </div>
              </div>
              <div className="space-y-4 p-5">
                {[
                  ["01", "Action requested", "Agent requests a code, data, API, or finance operation."],
                  ["02", "Policy evaluated", "Inntris checks permissions, risk, and execution context."],
                  ["03", "Decision signed", "Approved or blocked outcome is bound to the agent identity."],
                  ["04", "Proof recorded", "Evidence is written to the audit trail for later verification."],
                ].map(([step, title, body]) => (
                  <div key={step} className="flex gap-4 rounded-2xl border border-white/6 bg-[#101C31]/80 p-5">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[#4C8DFF]/15 text-sm font-semibold text-[#8FB8FF]">
                      {step}
                    </div>
                    <div>
                      <div className="text-sm font-medium text-[#F5F7FB]">{title}</div>
                      <div className="mt-1 text-[14px] leading-7 text-[#C4CFDE]">{body}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>
        <section id="modules" className="mx-auto max-w-7xl px-6 py-4 lg:px-8">
          <div className="mb-8">
            <div className="text-sm font-medium uppercase tracking-[0.18em] text-[#8FB8FF]">
              Product surface
            </div>
            <h2 className="mt-3 text-2xl font-semibold tracking-tight md:text-3xl">
              One control plane. Four modules.
            </h2>
          </div>
          <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
            {modules.map((item) => {
              const Icon = item.icon;
              return (
                <Card
                  key={item.title}
                  className="group rounded-[24px] border-[#22314D] bg-[#0D1728] shadow-none transition duration-200 hover:-translate-y-1 hover:border-[#35507A] hover:bg-[#101C31]"
                >
                  <CardContent className="p-6">
                    <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-2xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                      <Icon className="h-6 w-6" />
                    </div>
                    <h3 className="text-xl font-semibold tracking-tight text-[#F5F7FB]">{item.title}</h3>
                    <p className="mt-1.5 text-[11px] font-semibold uppercase tracking-[0.16em] text-[#6AA2FF]">{item.role}</p>
                    <p className="mt-3 min-h-[72px] text-[14px] leading-7 text-[#C4CFDE]">{item.body}</p>
                    <Link href={item.href} className="mt-5 inline-flex items-center gap-2 text-sm font-medium text-[#8FB8FF] transition group-hover:text-white">
                      {item.cta}
                      <ChevronRight className="h-4 w-4" />
                    </Link>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </section>
        <section id="trust" className="mx-auto max-w-7xl px-6 py-12 lg:px-8">
          <div className="grid gap-4 rounded-[28px] border border-[#22314D] bg-[#0D1728] p-6 md:grid-cols-2 xl:grid-cols-4 xl:p-8">
            {trustSignals.map((item) => (
              <div key={item.value} className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-5">
                <div className="text-3xl font-semibold tracking-tight text-[#F5F7FB]">{item.value}</div>
                <div className="mt-2 text-sm leading-6 text-[#AAB7CC]">{item.label}</div>
              </div>
            ))}
          </div>
        </section>
        <section id="use-cases" className="mx-auto max-w-7xl px-6 py-8 lg:px-8">
          <div className="mb-5">
            <div className="text-sm font-medium uppercase tracking-[0.18em] text-[#8FB8FF]">
              Use cases
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            {[
              "Pull request verification",
              "Sensitive data access",
              "API and tool execution",
              "Financial operations",
            ].map((useCase) => (
              <span
                key={useCase}
                className="rounded-full border border-[#22314D] bg-[#0D1728] px-4 py-2 text-sm text-[#AAB7CC]"
              >
                {useCase}
              </span>
            ))}
          </div>
        </section>
        <section id="product" className="mx-auto max-w-7xl px-6 pb-16 lg:px-8 lg:pb-24">
          <div className="rounded-[28px] border border-[#22314D] bg-[#0D1728] p-7 lg:p-10">
            <div className="text-sm font-medium uppercase tracking-[0.18em] text-[#8FB8FF]">Core capability</div>
            <h2 className="mt-3 text-2xl font-semibold tracking-tight md:text-3xl">
              Serious enough for a control plane, clear enough for daily use.
            </h2>
            <p className="mt-4 max-w-2xl text-base leading-7 text-[#AAB7CC]">
              Inntris combines cryptographic identity, policy checks before execution, and tamper-evident audit in one control plane.
            </p>
            <div className="mt-8 grid gap-4 md:grid-cols-3">
              {capabilities.map((item) => {
                const Icon = item.icon;
                return (
                  <div key={item.title} className="flex gap-4 rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
                    <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-[#22314D] bg-[#0D1728] text-[#8FB8FF]">
                      <Icon className="h-5 w-5" />
                    </div>
                    <div>
                      <div className="font-medium text-[#F5F7FB]">{item.title}</div>
                      <div className="mt-1 text-sm leading-6 text-[#AAB7CC]">{item.body}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </section>
        <ContactSection />
      </main>
    </div>
  );
}
