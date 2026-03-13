import React from "react";
import Link from "next/link";
import { Shield, LayoutDashboard, Bot, SearchCheck, Globe, KeyRound, Lock, FileCheck2, ChevronRight } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
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
            <a
              href="#contact"
              className="hidden rounded-md bg-[#28C281] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90 md:inline-flex"
            >
              Request Access
            </a>
          </div>
        </div>
      </header>
      <main className="relative">
        <section id="overview" className="mx-auto grid max-w-7xl gap-12 px-6 pb-20 pt-16 lg:grid-cols-[1.15fr_0.85fr] lg:px-8 lg:pb-28 lg:pt-20">
          <div className="max-w-3xl">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-[#28C281]/25 bg-[#28C281]/10 px-3 py-1.5 font-mono text-xs text-[#28C281]">
              <span className="h-1.5 w-1.5 rounded-full bg-[#28C281] animate-pulse" />
              Verification API live
            </div>
            <h1 className="max-w-3xl text-4xl font-semibold leading-[1.12] tracking-tight md:text-6xl mb-5">
              Your AI agents act.{" "}
              <span className="text-[#28C281]">Prove every decision.</span>
            </h1>
            <p className="text-base text-[#AAB7CC] mb-3 max-w-lg leading-relaxed">
              One control plane for agents running in production.
            </p>
            <ul className="flex flex-col gap-2 mb-8 max-w-lg">
              {[
                "Cryptographic identity — every agent signs every action",
                "Policy before execution — block risky operations before they run",
                "Tamper-evident audit — verifiable trail for compliance and investigation",
              ].map((item) => (
                <li
                  key={item}
                  className="text-sm text-[#AAB7CC] pl-4 relative leading-relaxed before:content-[''] before:absolute before:left-0 before:top-[9px] before:w-1.5 before:h-px before:bg-[#28C281]"
                >
                  {item}
                </li>
              ))}
            </ul>
            <div className="flex flex-wrap gap-3 mb-10">
              <a
                href="#contact"
                className="rounded-md bg-[#28C281] px-5 py-3 text-sm font-medium text-white transition-opacity hover:opacity-90"
              >
                Request Access
              </a>
              <Link
                href="/verify"
                className="rounded-md border border-[#22314D] bg-[#0D1728] px-5 py-3 text-sm font-medium text-[#F5F7FB] transition-colors hover:bg-[#101C31]"
              >
                See live verification →
              </Link>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 divide-x divide-[#22314D] border-t border-[#22314D] pt-7">
              {[
                { value: "<100ms", label: "Verification latency" },
                { value: "Ed25519", label: "Signing algorithm" },
                { value: "Base L2", label: "Audit anchor" },
                { value: "Fail-closed", label: "Default policy mode" },
              ].map(({ value, label }) => (
                <div key={label} className="px-5 first:pl-0">
                  <p className="text-lg font-semibold font-mono text-[#F5F7FB] mb-1">
                    {value}
                  </p>
                  <p className="text-[11px] uppercase tracking-widest text-[#AAB7CC]">
                    {label}
                  </p>
                </div>
              ))}
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
      <footer className="border-t border-[#22314D] bg-[#07111F]">
        <div className="mx-auto max-w-7xl px-6 py-10 lg:px-8">
          <div className="flex flex-col items-center gap-5">
            <div className="flex items-center gap-2.5">
              <Shield className="h-5 w-5 text-[#8FB8FF]" />
              <span className="text-sm font-semibold tracking-tight text-[#F5F7FB]">Inntris</span>
            </div>
            <p className="text-sm text-[#7F8CA3] text-center">
              Cryptographic verification for AI agents.
            </p>
            <div className="flex items-center gap-6 text-[#7F8CA3]">
              <a href="/docs" className="text-sm transition-colors hover:text-white">Docs</a>
              <a href="/verify" className="text-sm transition-colors hover:text-white">Verify</a>
              <a
                href="https://github.com/KingsmanRon/MTP"
                target="_blank"
                rel="noopener noreferrer"
                className="transition-colors hover:text-white"
              >
                <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
              </a>
            </div>
            <p className="text-xs text-[#7F8CA3]/60">
              &copy; 2025 Inntris INC
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
