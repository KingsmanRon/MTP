import React from "react";
import Link from "next/link";
import { LayoutDashboard, Bot, SearchCheck, Globe, KeyRound, Lock, FileCheck2, ChevronRight, CheckCircle2, XOctagon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { InntrisLogo } from "@/components/inntris-logo";
import { MobileMenu } from "@/components/mobile-menu";
import ContactSection from "@/components/contact-section";
import { ReceiptIdCopy } from "@/components/receipt-id-copy";
import { LandingHash } from "@/components/landing-hash";
import { publicApi } from "@/lib/api";
import { verdictLabel, isPassVerdict, isEscalateVerdict } from "@/lib/verdict";
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
const CANONICAL_RECEIPT_ID = "3030c27c-87c4-4464-b4af-605fbe638e0e";
const CANONICAL_PASS_ID = "d8dd0902-4750-42d2-9516-92bf6362e815";

function formatReceiptTimestamp(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const diffMs = Date.now() - d.getTime();
  const sec = Math.round(diffMs / 1000);
  const min = Math.round(sec / 60);
  const hr = Math.round(min / 60);
  const day = Math.round(hr / 24);
  let relative: string;
  if (sec < 60) relative = "just now";
  else if (min < 60) relative = `${min} minute${min === 1 ? "" : "s"} ago`;
  else if (hr < 24) relative = `${hr} hour${hr === 1 ? "" : "s"} ago`;
  else relative = `${day} day${day === 1 ? "" : "s"} ago`;
  const pad = (n: number) => n.toString().padStart(2, "0");
  const absolute = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
  return `Generated ${relative} · ${absolute}`;
}

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
      "Pre-execution policy enforcement and verifiable evidence for high-risk AI agent actions.",
    "foundingDate": "2025",
  };

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    <LandingHash />
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
              <div className="text-xs text-[#7F8CA3]">Agent action proof</div>
            </div>
          </div>
          <nav className="hidden items-center gap-5 text-[15px] text-[#C4CFDE] md:flex lg:gap-7">
            <a className="transition hover:text-white" href="/#overview">Overview</a>
            <a className="transition hover:text-white" href="/#modules">Modules</a>
            <Link className="transition hover:text-white" href="/pilot">14-day Pilot</Link>
            <Link className="transition hover:text-white" href="/docs">Docs</Link>
            <Link className="transition hover:text-white" href="/verify">Verify</Link>
          </nav>
          <div className="flex items-center gap-3">
            <Link
              href="/pilot"
              className="hidden rounded-md bg-[#28C281] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90 md:inline-flex"
            >
              Scope a Pilot
            </Link>
            <MobileMenu
              links={[
                { href: "/#overview", label: "Overview" },
                { href: "/#modules", label: "Modules" },
                { href: "/pilot", label: "14-day Pilot" },
                { href: "/docs", label: "Docs" },
                { href: "/verify", label: "Verify" },
              ]}
              cta={{ href: "/pilot", label: "Scope a Pilot" }}
            />
          </div>
        </div>
      </header>
      <main className="relative">
        <section id="overview" className="scroll-mt-24 mx-auto grid max-w-7xl gap-12 px-6 pb-20 pt-6 lg:grid-cols-[1.15fr_0.85fr] lg:px-8 lg:pb-28">
          <div className="max-w-3xl">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-[#28C281]/25 bg-[#28C281]/10 px-3 py-1.5 font-mono text-xs text-[#28C281]">
              <span className="h-1.5 w-1.5 rounded-full bg-[#28C281] animate-pulse" />
              Verification API live
            </div>
            <h1 className="max-w-3xl text-4xl font-semibold leading-[1.12] tracking-tight md:text-6xl mb-5">
              Stop unchecked AI-generated PRs from reaching{" "}
              <span className="text-[#28C281]">protected branches.</span>
            </h1>
            <p className="text-lg text-[#7F8CA3] mb-5 max-w-2xl leading-relaxed">
              Inntris adds a required policy check for AI coding agents and creates a
              verification receipt for every PASS or BLOCK decision.
            </p>
            <p className="text-base text-[#AAB7CC] mb-3 max-w-lg leading-relaxed">
              CI tells you whether code builds. Inntris tells you whether an AI agent was
              allowed to make repo changes, edit CI/CD workflows, merge protected branches,
              or deploy.
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
              Start with one risky workflow. In 14 days, Inntris instruments its control
              boundary and produces receipts for every allowed and blocked action.
            </p>
            <div className="flex flex-wrap gap-3 mb-10">
              <Link
                href="/pilot"
                className="rounded-md bg-[#28C281] px-5 py-3 text-sm font-medium text-white transition-opacity hover:opacity-90"
              >
                Scope a 14-day pilot
              </Link>
              <a
                href="https://www.inntris.com/verify/d8dd0902-4750-42d2-9516-92bf6362e815"
                className="rounded-md border border-[#22314D] bg-[#0D1728] px-5 py-3 text-sm font-medium text-[#F5F7FB] transition-colors hover:bg-[#101C31]"
              >
                See live verification
              </a>
            </div>
            {/* Dividers only when all four stats share a row; stacked 2x2 on
                phones the divide-x borders land in odd places. */}
            <div className="grid grid-cols-2 gap-y-6 border-t border-[#22314D] pt-7 md:grid-cols-4 md:gap-y-0 md:divide-x md:divide-[#22314D]">
              {[
                { value: "<100ms", label: "Verification latency" },
                { value: "Ed25519", label: "Signing algorithm" },
                { value: "Base L2", label: "Audit anchor" },
                { value: "Fail-closed", label: "Default policy mode" },
              ].map(({ value, label }) => (
                <div key={label} className="pr-4 md:px-5 md:first:pl-0">
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
        <section id="modules" className="scroll-mt-24 mx-auto max-w-7xl px-6 py-4 lg:px-8">
          <div className="mb-8">
            <div className="text-sm font-medium uppercase tracking-[0.18em] text-[#8FB8FF]">
              Product surface
            </div>
            <h2 className="mt-3 text-2xl font-semibold tracking-tight md:text-3xl">
              One control plane. Four modules.
            </h2>
          </div>
          <div className="grid grid-cols-1 gap-x-5 sm:grid-cols-2 md:grid-cols-4">
            <div className="hidden sm:col-span-2 sm:mb-2 sm:block">
              <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#4A6FA5]">
                Operate
              </span>
            </div>
            <div className="hidden sm:col-span-2 sm:mb-2 sm:block">
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
        <section id="use-cases" className="scroll-mt-24 mx-auto max-w-7xl px-6 py-8 lg:px-8">
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
                Every receipt below is live, signed, anchored to Base L2, and independently verifiable. Click any receipt to inspect the full proof — signature, policy hash, and on-chain anchor.
              </p>
            </div>
            <div className="grid gap-5 md:grid-cols-2">
              {/* PASS card */}
              <a
                href="https://www.inntris.com/verify/d8dd0902-4750-42d2-9516-92bf6362e815"
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
                {formatReceiptTimestamp(passReceipt?.timestamp) && (
                  <p className="mt-4 text-[11px] text-[#7F8CA3]">
                    {formatReceiptTimestamp(passReceipt?.timestamp)}
                  </p>
                )}
              </a>

              {/* BLOCK card */}
              {receipt && (
                <Link
                  href={`/verify/${CANONICAL_RECEIPT_ID}`}
                  className="group block rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6 transition hover:border-[#35507A] hover:bg-[#101C31] md:p-8"
                >
                  <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex items-center gap-3">
                      {isPassVerdict(receipt.verdict) ? (
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
                            isPassVerdict(receipt.verdict)
                              ? "text-[#22c55e]"
                              : isEscalateVerdict(receipt.verdict)
                              ? "text-[#f59e0b]"
                              : "text-[#ef4444]"
                          }`}
                        >
                          {verdictLabel(receipt.verdict)}
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
                  {formatReceiptTimestamp(receipt.timestamp) && (
                    <p className="mt-4 text-[11px] text-[#7F8CA3]">
                      {formatReceiptTimestamp(receipt.timestamp)}
                    </p>
                  )}
                </Link>
              )}
            </div>
            <p className="mt-4 text-center text-sm text-[#AAB7CC]">
              Both receipts are independently verifiable. No Inntris access required.
            </p>
          </section>
        )}

        {/* ============================================================ */}
        {/*  What a public receipt proves                                */}
        {/* ============================================================ */}
        <section
          id="what-a-receipt-proves"
          aria-labelledby="what-a-receipt-proves-heading"
          className="scroll-mt-24 mx-auto max-w-7xl px-6 pb-4 lg:px-8"
        >
          <div className="rounded-[24px] border border-[#22314D] bg-[#0D1728] p-6 md:p-8">
            <h2
              id="what-a-receipt-proves-heading"
              className="text-lg font-semibold tracking-tight text-[#F5F7FB]"
            >
              What a public receipt proves
            </h2>
            <ul className="mt-4 grid gap-3 md:grid-cols-2">
              {[
                ["Which agent acted", "via Ed25519 signature validation"],
                ["What decision was made", "PASS, BLOCK, or ESCALATE"],
                ["Which policy bound the decision", "via policy hash"],
                ["That the record was anchored", "via Base L2 transaction proof"],
              ].map(([primary, secondary]) => (
                <li
                  key={primary}
                  className="flex items-start gap-3 rounded-xl border border-white/6 bg-[#101C31]/70 px-4 py-3"
                >
                  <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-[#28C281]" />
                  <p className="text-sm leading-6 text-[#C4CFDE]">
                    <span className="font-medium text-[#F5F7FB]">{primary}</span>
                    <span className="text-[#7F8CA3]"> — {secondary}</span>
                  </p>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section id="product" className="scroll-mt-24 mx-auto max-w-7xl px-6 pb-16 lg:px-8 lg:pb-24">
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
              Control and proof for high-risk AI agent actions.
            </p>
            <div className="flex items-center gap-6 text-[#7F8CA3]">
              <a href="/docs" className="text-sm transition-colors hover:text-white">Docs</a>
              <a href="/verify" className="text-sm transition-colors hover:text-white">Verify</a>
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
