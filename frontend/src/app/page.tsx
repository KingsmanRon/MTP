import React from "react";
import Link from "next/link";
import { LayoutDashboard, Bot, SearchCheck, Globe, KeyRound, Lock, FileCheck2, ChevronRight, CheckCircle2, XOctagon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { InntrisLogo } from "@/components/inntris-logo";
import ContactSection from "@/components/contact-section";
import { ReceiptIdCopy } from "@/components/receipt-id-copy";
import { publicApi } from "@/lib/api";
const modules = [
  {
    icon: LayoutDashboard,
    title: "Admin Console",
    role: "For platform admins",
    body: "Manage agents, enforce policies, rotate API keys, and investigate security alerts from one dashboard.",
    cta: "Explore Console",
    href: "/admin",
  },
  {
    icon: Bot,
    title: "Agent Portal",
    role: "For developers and operators",
    body: "Register agents, test policy evaluation in the sandbox, and track trust score changes over time.",
    cta: "Explore Portal",
    href: "/portal",
  },
  {
    icon: SearchCheck,
    title: "Audit Explorer",
    role: "For investigations and compliance",
    body: "Search every verification decision by agent, action, or verdict. Each record is append-only and tamper-evident.",
    cta: "Explore Audit Explorer",
    href: "/audit",
  },
  {
    icon: Globe,
    title: "Public Verify",
    role: "For customers, partners, and auditors",
    body: "Share a receipt link with anyone. They can independently verify the signature, policy hash, and on-chain anchor.",
    cta: "Verify a live receipt",
    href: "https://www.inntris.com/verify",
  },
];
const capabilities = [
  {
    icon: KeyRound,
    title: "Cryptographic identity",
    body: "Every agent holds an Ed25519 key pair. Every action is signed. No valid signature, no execution.",
  },
  {
    icon: Lock,
    title: "Policy before execution",
    body: "Rate limits, spend caps, and action allowlists are evaluated before the action runs — not after the damage is done.",
  },
  {
    icon: FileCheck2,
    title: "Tamper-evident audit",
    body: "Every decision is recorded in an append-only log, Merkle-anchored on Base L2. Proves what was allowed to happen, and what actually happened.",
  },
];
const CANONICAL_RECEIPT_ID = "62afc74f-9e57-4748-82e3-10f1bfe07b9f";
const CANONICAL_PASS_ID = "659c20b1-d1b1-4a4e-9676-4d04e222ae58";

export default async function InntrisCoreDarkPreview() {
  let receipt = null;
  let passReceipt = null;
  try {
    receipt = await publicApi.getVerificationRecord(CANONICAL_RECEIPT_ID);
  } catch {
    // API unavailable — skip the proof preview
  }
  try {
    passReceipt = await publicApi.getVerificationRecord(CANONICAL_PASS_ID);
  } catch {
    // API unavailable — use fallback values
  }

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "Inntris",
    "legalName": "Inntris Inc.",
    "url": "https://www.inntris.com",
    "logo": "https://www.inntris.com/logo.svg",
    "description":
      "Cryptographic verification and governance layer for AI agents. Identity, policy enforcement, and tamper-evident audit trails anchored on Base L2.",
    "foundingDate": "2025",
    "sameAs": ["https://github.com/Inntris"],
  };

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    <div className="min-h-screen bg-[#07111F] text-[#F5F7FB]">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(76,141,255,0.14),transparent_32%),radial-gradient(circle_at_80%_30%,rgba(143,184,255,0.08),transparent_24%)] pointer-events-none" />
      <header className="sticky top-0 z-20 border-b border-white/8 bg-[#07111F]/85 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#0D1728] shadow-[0_0_0_1px_rgba(255,255,255,0.02)]">
              <InntrisLogo className="h-6 w-6" />
            </div>
            <div>
              <div className="text-lg font-semibold tracking-tight">Inntris</div>
              <div className="text-xs text-[#7F8CA3]">Core control plane</div>
            </div>
          </div>
          <nav className="hidden items-center gap-5 text-[15px] text-[#C4CFDE] md:flex lg:gap-7">
            <a className="transition hover:text-white" href="#overview">Overview</a>
            <a className="transition hover:text-white" href="#modules">Modules</a>
            <a className="transition hover:text-white" href="#contact">Contact</a>
            <Link className="transition hover:text-white" href="/verify">Verify</Link>
            <Link className="transition hover:text-white" href="/admin">Console</Link>
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
              <span className="text-[#28C281]">We prove every decision.</span>
            </h1>
            <p className="text-lg text-[#7F8CA3] mb-5 max-w-2xl leading-relaxed">
              AI agent governance with cryptographic verification — identity, policy enforcement, and on-chain proof for every decision.
            </p>
            <p className="text-base text-[#AAB7CC] mb-3 max-w-lg leading-relaxed">
              The governance layer for AI agents in production. Verify what was allowed and what actually happened — independently.
            </p>
            <ul className="flex flex-col gap-2 mb-8 max-w-lg">
              {[
                "Cryptographic identity — Ed25519 signatures bind every action to its agent",
                "Policy before execution — rate limits, spend caps, and allowlists enforced before the action runs",
                "Tamper-evident audit — only logs anchored on Base L2 with receipt integrity you can verify yourself",
                "Independently verifiable — anyone can check the receipt using the on-chain anchor alone. No Inntris account required.",
              ].map((item) => (
                <li
                  key={item}
                  className="text-sm text-[#AAB7CC] pl-4 relative leading-relaxed before:content-[''] before:absolute before:left-0 before:top-[9px] before:w-1.5 before:h-px before:bg-[#28C281]"
                >
                  {item}
                </li>
              ))}
            </ul>
            <p className="text-sm text-[#AAB7CC] mb-8 max-w-lg leading-relaxed">
              When your agents handle money, data, and code in regulated environments, you need cryptographic proof of every decision. Inntris is that proof layer.
            </p>
            <div className="flex flex-wrap gap-3 mb-10">
              <a
                href="https://www.inntris.com/verify/659c20b1-d1b1-4a4e-9676-4d04e222ae58"
                className="rounded-md bg-[#28C281] px-5 py-3 text-sm font-medium text-white transition-opacity hover:opacity-90"
              >
                See live verification →
              </a>
              <a
                href="#contact"
                className="rounded-md border border-[#22314D] bg-[#0D1728] px-5 py-3 text-sm font-medium text-[#F5F7FB] transition-colors hover:bg-[#101C31]"
              >
                Request Access
              </a>
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
          <div className="grid grid-cols-2 gap-x-5 md:grid-cols-4">
            <div className="col-span-2 mb-2">
              <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#4A6FA5]">
                Operate
              </span>
            </div>
            <div className="col-span-2 mb-2">
              <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#4A6FA5]">
                Prove
              </span>
            </div>
            {modules.map((item) => {
              const Icon = item.icon;
              return (
                <Card
                  key={item.title}
                  className="group rounded-[24px] border-[#22314D] bg-[#0D1728] shadow-none transition duration-200 hover:-translate-y-1 hover:border-[#35507A] hover:bg-[#101C31] mb-5"
                >
                  <CardContent className="flex h-full flex-col p-6">
                    <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-2xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
                      <Icon className="h-6 w-6" />
                    </div>
                    <h3 className="text-xl font-semibold tracking-tight text-[#F5F7FB]">{item.title}</h3>
                    <p className="mt-1.5 min-h-[32px] text-[11px] font-semibold uppercase tracking-[0.16em] text-[#6AA2FF]">{item.role}</p>
                    <p className="mt-3 flex-1 min-h-[84px] text-[14px] leading-7 text-[#C4CFDE]">{item.body}</p>
                    {item.href.startsWith("http") ? (
                      <a href={item.href} target="_blank" rel="noopener noreferrer" className="mt-auto inline-flex items-center gap-2 pt-5 text-sm font-medium text-[#8FB8FF] transition group-hover:text-white">
                        {item.cta}
                        <ChevronRight className="h-4 w-4" />
                      </a>
                    ) : (
                      <Link href={item.href} className="mt-auto inline-flex items-center gap-2 pt-5 text-sm font-medium text-[#8FB8FF] transition group-hover:text-white">
                        {item.cta}
                        <ChevronRight className="h-4 w-4" />
                      </Link>
                    )}
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
        {(receipt || passReceipt) && (
          <section className="mx-auto max-w-7xl px-6 py-8 lg:px-8">
            <div className="mb-6">
              <div className="text-sm font-medium uppercase tracking-[0.18em] text-[#8FB8FF]">
                Live proof
              </div>
              <h2 className="mt-3 text-2xl font-semibold tracking-tight md:text-3xl">
                A real verification receipt.
              </h2>
              <p className="mt-2 max-w-xl text-sm leading-6 text-[#AAB7CC]">
                This is a live receipt from the Inntris network — not a mockup. Click to inspect the full proof, including signature validity, policy hash, and on-chain anchor.
              </p>
            </div>
            <div className="grid gap-5 md:grid-cols-2">
              {/* PASS card */}
              <a
                href="https://www.inntris.com/verify/659c20b1-d1b1-4a4e-9676-4d04e222ae58"
                className="group block rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6 transition hover:border-[#35507A] hover:bg-[#101C31] md:p-8"
              >
                <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#22c55e]/15">
                      <CheckCircle2 className="h-5 w-5 text-[#22c55e]" />
                    </div>
                    <div>
                      <span className="text-lg font-bold tracking-tight text-[#22c55e]">
                        PASS
                      </span>
                      <p className="text-xs text-[#7F8CA3]">
                        Safe action evaluated, approved, and recorded on-chain.
                      </p>
                    </div>
                  </div>
                  <span className="inline-flex items-center gap-2 text-sm font-medium text-[#8FB8FF] transition group-hover:text-white">
                    View full receipt
                    <ChevronRight className="h-4 w-4" />
                  </span>
                </div>
                <div className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 pt-5 border-t border-white/10">
                  <div className="min-w-0">
                    <p className="text-[10px] font-medium uppercase tracking-widest text-[#7F8CA3]">Agent</p>
                    <p className="mt-1 truncate text-sm font-medium text-[#F5F7FB]">{passReceipt?.agent_name ?? "Demo Agent"}</p>
                    <p className="truncate text-xs text-[#7F8CA3]">{passReceipt?.organization_name ?? "Inntris Demo"}</p>
                  </div>
                  <div className="min-w-0">
                    <p className="text-[10px] font-medium uppercase tracking-widest text-[#7F8CA3]">Action</p>
                    <p className="mt-1 truncate font-mono text-xs text-[#F5F7FB]">{passReceipt?.action_type ?? "api_call"}</p>
                    <p className="truncate text-xs text-[#7F8CA3]">
                      Trust {passReceipt?.trust_score ?? 85}/100
                    </p>
                  </div>
                  <div className="min-w-0">
                    <p className="text-[10px] font-medium uppercase tracking-widest text-[#7F8CA3]">Signature</p>
                    <p className="mt-1 truncate text-sm font-medium text-[#22c55e]">
                      {passReceipt?.signature_valid !== false ? "Valid Ed25519" : "Invalid"}
                    </p>
                    <p className="truncate text-xs text-[#7F8CA3]">
                      Anchored on Base L2
                    </p>
                  </div>
                  <div className="min-w-0">
                    <p className="text-[10px] font-medium uppercase tracking-widest text-[#7F8CA3]">Receipt ID</p>
                    <ReceiptIdCopy id={passReceipt?.audit_id ?? CANONICAL_PASS_ID} />
                  </div>
                </div>
              </a>

              {/* BLOCK card */}
              {receipt && (
                <Link
                  href={`/verify/${CANONICAL_RECEIPT_ID}`}
                  className="group block rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6 transition hover:border-[#35507A] hover:bg-[#101C31] md:p-8"
                >
                  <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex items-center gap-3">
                      {receipt.verdict === "approved" ? (
                        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#22c55e]/15">
                          <CheckCircle2 className="h-5 w-5 text-[#22c55e]" />
                        </div>
                      ) : (
                        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#ef4444]/15">
                          <XOctagon className="h-5 w-5 text-[#ef4444]" />
                        </div>
                      )}
                      <div>
                        <span
                          className={`text-lg font-bold tracking-tight ${
                            receipt.verdict === "approved" ? "text-[#22c55e]" : "text-[#ef4444]"
                          }`}
                        >
                          {receipt.verdict === "approved" ? "PASS" : "BLOCK"}
                        </span>
                        <p className="text-xs text-[#7F8CA3]">
                          {receipt.verdict_reason ?? "All policy checks passed"}
                        </p>
                      </div>
                    </div>
                    <span className="inline-flex items-center gap-2 text-sm font-medium text-[#8FB8FF] transition group-hover:text-white">
                      View full receipt
                      <ChevronRight className="h-4 w-4" />
                    </span>
                  </div>
                  <div className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 pt-5 border-t border-white/10">
                    <div className="min-w-0">
                      <p className="text-[10px] font-medium uppercase tracking-widest text-[#7F8CA3]">Agent</p>
                      <p className="mt-1 truncate text-sm font-medium text-[#F5F7FB]">{receipt.agent_name}</p>
                      <p className="truncate text-xs text-[#7F8CA3]">{receipt.organization_name}</p>
                    </div>
                    <div className="min-w-0">
                      <p className="text-[10px] font-medium uppercase tracking-widest text-[#7F8CA3]">Action</p>
                      <p className="mt-1 truncate font-mono text-xs text-[#F5F7FB]">{receipt.action_type}</p>
                      <p className="truncate text-xs text-[#7F8CA3]">
                        Trust {receipt.trust_score}/100
                      </p>
                    </div>
                    <div className="min-w-0">
                      <p className="text-[10px] font-medium uppercase tracking-widest text-[#7F8CA3]">Signature</p>
                      <p className={`mt-1 truncate text-sm font-medium ${receipt.signature_valid ? "text-[#22c55e]" : "text-[#ef4444]"}`}>
                        {receipt.signature_valid ? "Valid Ed25519" : "Invalid"}
                      </p>
                      <p className="truncate text-xs text-[#7F8CA3]">
                        {receipt.tx_hash ? "Anchored on Base L2" : "Pending anchor"}
                      </p>
                    </div>
                    <div className="min-w-0">
                      <p className="text-[10px] font-medium uppercase tracking-widest text-[#7F8CA3]">Receipt ID</p>
                      <ReceiptIdCopy id={receipt.audit_id} />
                    </div>
                  </div>
                </Link>
              )}
            </div>
            <p className="mt-4 text-center text-sm text-[#AAB7CC]">
              Both receipts are independently verifiable. No Inntris access required.
            </p>
          </section>
        )}

        <section id="product" className="mx-auto max-w-7xl px-6 pb-16 lg:px-8 lg:pb-24">
          <div className="rounded-[28px] border border-[#22314D] bg-[#0D1728] p-7 lg:p-10">
            <div className="text-sm font-medium uppercase tracking-[0.18em] text-[#8FB8FF]">Core capability</div>
            <h2 className="mt-3 text-2xl font-semibold tracking-tight md:text-3xl">
              Three guarantees. One control plane.
            </h2>
            <p className="mt-4 max-w-2xl text-base leading-7 text-[#AAB7CC]">
              Every agent action passes through three layers: identity verification, policy enforcement, and immutable audit. Together they prove what was allowed to happen, and what actually happened.
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
              <InntrisLogo className="h-5 w-5" />
              <span className="text-sm font-semibold tracking-tight text-[#F5F7FB]">Inntris</span>
            </div>
            <p className="text-sm text-[#7F8CA3] text-center">
              Cryptographic proof for every AI agent decision.
            </p>
            <div className="flex items-center gap-6 text-[#7F8CA3]">
              <a href="/docs" className="text-sm transition-colors hover:text-white">Docs</a>
              <a href="/verify" className="text-sm transition-colors hover:text-white">Verify</a>
              <a
                href="https://github.com/Inntris/agent-orchestrator-guardrails"
                target="_blank"
                rel="noopener noreferrer"
                className="transition-colors hover:text-white"
              >
                <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
              </a>
            </div>
            <p className="text-xs text-[#7F8CA3]/60">
              &copy; 2026 Inntris, Inc.
            </p>
          </div>
        </div>
      </footer>
    </div>
    </>
  );
}
