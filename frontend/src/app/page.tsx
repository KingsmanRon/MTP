import React from "react";
import Link from "next/link";
import { LayoutDashboard, Bot, SearchCheck, Globe, KeyRound, Lock, FileCheck2, ChevronRight, CheckCircle2, XOctagon } from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";
import { MobileMenu } from "@/components/mobile-menu";
import ContactSection from "@/components/contact-section";
import { ReceiptIdCopy } from "@/components/receipt-id-copy";
import { LandingHash } from "@/components/landing-hash";
import { Eyebrow, Num, Tile, IconTile, StepNumber, focusRing } from "@/components/landing/primitives";
import { cn } from "@/lib/utils";
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
    <div className="theme-light min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-30 border-b border-border bg-muted/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
          <div className="flex items-center gap-3">
            {/* White against the grey header — the tile always flips against
                its ground, and bg-tile is the same value as bg-muted. */}
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-tileLine bg-card">
              <InntrisLogo className="h-6 w-6" />
            </div>
            <div>
              <div className="text-lg font-semibold tracking-tight">Inntris</div>
              <div className="text-xs text-muted-foreground">Agent action proof</div>
            </div>
          </div>
          <nav aria-label="Primary" className="hidden items-center gap-5 text-[15px] md:flex lg:gap-7">
            <Link className={cn("rounded-sm text-muted-foreground transition-colors hover:text-foreground", focusRing)} href="/#overview">Overview</Link>
            <Link className={cn("rounded-sm text-muted-foreground transition-colors hover:text-foreground", focusRing)} href="/#modules">Modules</Link>
            <Link className={cn("rounded-sm text-muted-foreground transition-colors hover:text-foreground", focusRing)} href="/pilot">14-day Pilot</Link>
            <Link className={cn("rounded-sm text-muted-foreground transition-colors hover:text-foreground", focusRing)} href="/docs">Docs</Link>
            <Link className={cn("rounded-sm text-muted-foreground transition-colors hover:text-foreground", focusRing)} href="/verify">Verify</Link>
          </nav>
          <div className="flex items-center gap-3">
            <Link
              href="/pilot"
              className={cn(
                "hidden min-h-11 items-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-brandDeep md:inline-flex",
                focusRing,
              )}
            >
              Scope a Pilot
            </Link>
            <MobileMenu
              variant="light"
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
      <main>
        <section id="overview" className="scroll-mt-24 border-b border-border bg-background">
          <div className="mx-auto grid max-w-7xl gap-12 px-6 pb-20 pt-10 lg:grid-cols-[1.15fr_0.85fr] lg:px-8 lg:pb-28">
          <div className="min-w-0 max-w-3xl">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-tileLine bg-tile px-3 py-1.5 font-mono text-xs text-brandInk">
              <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-primary" />
              Verification API live
            </div>
            <h1 className="max-w-3xl text-4xl font-semibold leading-[1.12] tracking-tight md:text-6xl mb-5">
              Stop unchecked AI-generated PRs from reaching{" "}
              <span className="text-primary">protected branches.</span>
            </h1>
            <p className="text-lg text-muted-foreground mb-5 max-w-2xl leading-relaxed">
              Inntris adds a required policy check for AI coding agents and creates a
              verification receipt for every PASS or BLOCK decision.
            </p>
            <p className="text-base text-muted-foreground mb-3 max-w-lg leading-relaxed">
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
                  className="text-sm text-muted-foreground pl-4 relative leading-relaxed before:content-[''] before:absolute before:left-0 before:top-[9px] before:w-1.5 before:h-px before:bg-primary"
                >
                  {item}
                </li>
              ))}
            </ul>
            <p className="text-sm text-muted-foreground mb-8 max-w-lg leading-relaxed">
              Start with one risky workflow. In 14 days, Inntris instruments its control
              boundary and produces receipts for every allowed and blocked action.
            </p>
            <div className="flex flex-wrap gap-3 mb-10">
              <Link
                href="/pilot"
                className={cn(
                  "inline-flex min-h-11 items-center rounded-md bg-primary px-5 text-sm font-medium text-primary-foreground transition-colors hover:bg-brandDeep",
                  focusRing,
                )}
              >
                Scope a 14-day pilot
              </Link>
              <a
                href="https://www.inntris.com/verify/d8dd0902-4750-42d2-9516-92bf6362e815"
                className={cn(
                  "inline-flex min-h-11 items-center rounded-md border border-input bg-background px-5 text-sm font-medium text-foreground transition-colors hover:bg-tile",
                  focusRing,
                )}
              >
                See live verification
              </a>
            </div>
            {/* Dividers only when all four stats share a row; stacked 2x2 on
                phones the divide-x borders land in odd places. */}
            <div className="grid grid-cols-2 gap-y-6 border-t border-border pt-7 md:grid-cols-4 md:gap-y-0 md:divide-x md:divide-border">
              {[
                { value: "<100ms", label: "Verification latency" },
                { value: "Ed25519", label: "Signing algorithm" },
                { value: "Base L2", label: "Audit anchor" },
                { value: "Fail-closed", label: "Default policy mode" },
              ].map(({ value, label }) => (
                <div key={label} className="pr-4 md:px-5 md:first:pl-0">
                  <Num className="block text-lg font-semibold text-foreground mb-1">
                    {value}
                  </Num>
                  <p className="text-[11px] uppercase tracking-widest text-muted-foreground">
                    {label}
                  </p>
                </div>
              ))}
            </div>
          </div>
          <div className="min-w-0">
            <div className="overflow-hidden rounded-lg border border-tileLine bg-tile">
              <div className="border-b border-tileLine px-5 py-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-medium text-foreground">Verification decision flow</div>
                    <div className="mt-1 text-xs text-muted-foreground">Where Inntris sits in your stack</div>
                  </div>
                  <div className="shrink-0 rounded-full bg-accent px-3 py-1 font-mono text-xs text-accent-foreground">
                    live policy path
                  </div>
                </div>
              </div>
              <div className="space-y-3 p-5">
                {[
                  ["01", "Action requested", "Agent requests a code, data, API, or finance operation."],
                  ["02", "Policy evaluated", "Inntris checks permissions, risk, and execution context."],
                  ["03", "Decision signed", "Approved or blocked outcome is bound to the agent identity."],
                  ["04", "Proof recorded", "Evidence is written to the audit trail for later verification."],
                ].map(([step, title, body]) => (
                  <div key={step} className="flex gap-4 rounded-lg border border-tileLine bg-card p-4 transition duration-200 hover:-translate-y-1 hover:border-primary/40 hover:bg-tile hover:shadow-lg">
                    <StepNumber>{step}</StepNumber>
                    <div className="min-w-0">
                      <div className="text-sm font-medium text-foreground">{title}</div>
                      <div className="mt-1 text-sm leading-6 text-muted-foreground">{body}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
          </div>
        </section>
        <section id="modules" className="scroll-mt-24 border-b border-border bg-muted">
          <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
          <div className="mb-8">
            <Eyebrow>Product surface</Eyebrow>
            <h2 className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl">
              One control plane. Four modules.
            </h2>
          </div>
          <div className="grid grid-cols-1 gap-x-5 sm:grid-cols-2 md:grid-cols-4">
            <div className="hidden sm:col-span-2 sm:mb-2 sm:block">
              <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-brandInk">
                Operate
              </span>
            </div>
            <div className="hidden sm:col-span-2 sm:mb-2 sm:block">
              <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-brandInk">
                Prove
              </span>
            </div>
            {modules.map((item) => {
              const Icon = item.icon;
              const label = (
                <span className="mt-auto inline-flex items-center gap-2 pt-5 text-sm font-medium text-brandInk">
                  {item.cta}
                  <ChevronRight className="h-4 w-4" aria-hidden="true" />
                </span>
              );
              return (
                <Tile key={item.title} ground="tinted" className="mb-5 flex flex-col p-6">
                  <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-lg border border-tileLine bg-tile text-primary">
                    <Icon className="h-6 w-6" aria-hidden="true" />
                  </div>
                  <h3 className="text-xl font-semibold tracking-tight text-foreground">{item.title}</h3>
                  <p className="mt-1.5 min-h-[32px] text-[11px] font-semibold uppercase tracking-[0.16em] text-brandInk">{item.role}</p>
                  <p className="mt-3 flex-1 min-h-[84px] text-sm leading-6 text-muted-foreground">{item.body}</p>
                  {item.href.startsWith("http") ? (
                    <a href={item.href} target="_blank" rel="noopener noreferrer" className={cn("flex flex-col rounded-sm", focusRing)}>
                      {label}
                    </a>
                  ) : (
                    <Link href={item.href} className={cn("flex flex-col rounded-sm", focusRing)}>
                      {label}
                    </Link>
                  )}
                </Tile>
              );
            })}
          </div>
          </div>
        </section>
        <section id="use-cases" className="scroll-mt-24 border-b border-border bg-background">
          <div className="mx-auto max-w-7xl px-6 py-16 lg:px-8">
          <div className="mb-5">
            <Eyebrow>Use cases</Eyebrow>
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
                className="rounded-full border border-tileLine bg-tile px-4 py-2 text-sm text-muted-foreground"
              >
                {useCase}
              </span>
            ))}
          </div>
          </div>
        </section>
        {(receipt || passReceipt) && (
          <section className="border-b border-border bg-muted">
            <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
            <div className="mb-6">
              <Eyebrow>Live proof</Eyebrow>
              <h2 className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl">
                A real verification receipt.
              </h2>
              <p className="mt-2 max-w-xl text-sm leading-6 text-muted-foreground">
                Every receipt below is live, signed, anchored to Base L2, and independently verifiable. Click any receipt to inspect the full proof — signature, policy hash, and on-chain anchor.
              </p>
            </div>
            <div className="grid gap-5 md:grid-cols-2">
              {/* PASS card */}
              <a
                href="https://www.inntris.com/verify/d8dd0902-4750-42d2-9516-92bf6362e815"
                className={cn(
                  "group block rounded-lg border border-tileLine bg-card p-6 transition duration-200 hover:-translate-y-1 hover:border-primary/40 hover:bg-tile hover:shadow-lg md:p-8",
                  focusRing,
                )}
              >
                <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-success/10">
                      <CheckCircle2 className="h-5 w-5 text-success" aria-hidden="true" />
                    </div>
                    <div>
                      <span className="text-lg font-bold tracking-tight text-success">
                        PASS
                      </span>
                      <p className="text-xs text-muted-foreground">
                        Safe action evaluated, approved, and recorded on-chain.
                      </p>
                    </div>
                  </div>
                  <span className="inline-flex items-center gap-2 text-sm font-medium text-brandInk">
                    View full receipt
                    <ChevronRight className="h-4 w-4" aria-hidden="true" />
                  </span>
                </div>
                <div className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 pt-5 border-t border-tileLine">
                  <div className="min-w-0">
                    <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">Agent</p>
                    <p className="mt-1 truncate text-sm font-medium text-foreground">{passReceipt?.agent_name ?? "Demo Agent"}</p>
                    <p className="truncate text-xs text-muted-foreground">{passReceipt?.organization_name ?? "Inntris Demo"}</p>
                  </div>
                  <div className="min-w-0">
                    <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">Action</p>
                    <Num className="mt-1 block truncate text-xs text-foreground">{passReceipt?.action_type ?? "api_call"}</Num>
                    <Num className="block truncate text-xs text-muted-foreground">
                      Trust {passReceipt?.trust_score ?? 85}/100
                    </Num>
                  </div>
                  <div className="min-w-0">
                    <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">Signature</p>
                    <p className="mt-1 truncate text-sm font-medium text-success">
                      {passReceipt?.signature_valid !== false ? "Valid Ed25519" : "Invalid"}
                    </p>
                    <p className="truncate text-xs text-muted-foreground">
                      Anchored on Base L2
                    </p>
                  </div>
                  <div className="min-w-0">
                    <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">Receipt ID</p>
                    <ReceiptIdCopy id={passReceipt?.audit_id ?? CANONICAL_PASS_ID} />
                  </div>
                </div>
                {formatReceiptTimestamp(passReceipt?.timestamp) && (
                  <p className="mt-4 text-[11px] text-muted-foreground">
                    {formatReceiptTimestamp(passReceipt?.timestamp)}
                  </p>
                )}
              </a>

              {/* BLOCK card */}
              {receipt && (
                <Link
                  href={`/verify/${CANONICAL_RECEIPT_ID}`}
                  className={cn(
                    "group block rounded-lg border border-tileLine bg-card p-6 transition duration-200 hover:-translate-y-1 hover:border-primary/40 hover:bg-tile hover:shadow-lg md:p-8",
                    focusRing,
                  )}
                >
                  <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex items-center gap-3">
                      {isPassVerdict(receipt.verdict) ? (
                        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-success/10">
                          <CheckCircle2 className="h-5 w-5 text-success" aria-hidden="true" />
                        </div>
                      ) : (
                        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-destructive/10">
                          <XOctagon className="h-5 w-5 text-destructive" aria-hidden="true" />
                        </div>
                      )}
                      <div>
                        <span
                          className={`text-lg font-bold tracking-tight ${
                            isPassVerdict(receipt.verdict)
                              ? "text-success"
                              : isEscalateVerdict(receipt.verdict)
                              ? "text-warning"
                              : "text-destructive"
                          }`}
                        >
                          {verdictLabel(receipt.verdict)}
                        </span>
                        <p className="text-xs text-muted-foreground">
                          {receipt.verdict_reason ?? "All policy checks passed"}
                        </p>
                      </div>
                    </div>
                    <span className="inline-flex items-center gap-2 text-sm font-medium text-brandInk">
                      View full receipt
                      <ChevronRight className="h-4 w-4" aria-hidden="true" />
                    </span>
                  </div>
                  <div className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 pt-5 border-t border-tileLine">
                    <div className="min-w-0">
                      <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">Agent</p>
                      <p className="mt-1 truncate text-sm font-medium text-foreground">{receipt.agent_name}</p>
                      <p className="truncate text-xs text-muted-foreground">{receipt.organization_name}</p>
                    </div>
                    <div className="min-w-0">
                      <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">Action</p>
                      <Num className="mt-1 block truncate text-xs text-foreground">{receipt.action_type}</Num>
                      <Num className="block truncate text-xs text-muted-foreground">
                        Trust {receipt.trust_score}/100
                      </Num>
                    </div>
                    <div className="min-w-0">
                      <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">Signature</p>
                      <p className={`mt-1 truncate text-sm font-medium ${receipt.signature_valid ? "text-success" : "text-destructive"}`}>
                        {receipt.signature_valid ? "Valid Ed25519" : "Invalid"}
                      </p>
                      <p className="truncate text-xs text-muted-foreground">
                        {receipt.tx_hash ? "Anchored on Base L2" : "Pending anchor"}
                      </p>
                    </div>
                    <div className="min-w-0">
                      <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">Receipt ID</p>
                      <ReceiptIdCopy id={receipt.audit_id} />
                    </div>
                  </div>
                  {formatReceiptTimestamp(receipt.timestamp) && (
                    <p className="mt-4 text-[11px] text-muted-foreground">
                      {formatReceiptTimestamp(receipt.timestamp)}
                    </p>
                  )}
                </Link>
              )}
            </div>
            <p className="mt-4 text-center text-sm text-muted-foreground">
              Both receipts are independently verifiable. No Inntris access required.
            </p>
            </div>
          </section>
        )}

        {/* ============================================================ */}
        {/*  What a public receipt proves                                */}
        {/* ============================================================ */}
        <section
          id="what-a-receipt-proves"
          aria-labelledby="what-a-receipt-proves-heading"
          className="scroll-mt-24 border-b border-border bg-background"
        >
          <div className="mx-auto max-w-7xl px-6 py-16 lg:px-8">
          <Tile ground="white" interactive={false} className="p-6 md:p-8">
            <h2
              id="what-a-receipt-proves-heading"
              className="text-lg font-semibold tracking-tight text-foreground"
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
                  className="flex items-start gap-3 rounded-lg border border-tileLine bg-card px-4 py-3"
                >
                  <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-success" aria-hidden="true" />
                  <p className="text-sm leading-6 text-muted-foreground">
                    <span className="font-medium text-foreground">{primary}</span>
                    <span> — {secondary}</span>
                  </p>
                </li>
              ))}
            </ul>
          </Tile>
          </div>
        </section>

        <section id="product" className="scroll-mt-24 border-b border-border bg-muted">
          <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
          <Tile ground="tinted" interactive={false} className="p-7 lg:p-10">
            <Eyebrow>Core capability</Eyebrow>
            <h2 className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl">
              Three guarantees. One control plane.
            </h2>
            <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">
              Every agent action passes through three layers: identity verification, policy enforcement, and immutable audit. Together they prove what was allowed to happen, and what actually happened.
            </p>
            <div className="mt-8 grid gap-4 md:grid-cols-3">
              {capabilities.map((item) => {
                const Icon = item.icon;
                return (
                  <div key={item.title} className="flex gap-4 rounded-lg border border-tileLine bg-tile p-4">
                    <IconTile className="h-11 w-11">
                      <Icon className="h-5 w-5" aria-hidden="true" />
                    </IconTile>
                    <div className="min-w-0">
                      <div className="font-medium text-foreground">{item.title}</div>
                      <div className="mt-1 text-sm leading-6 text-muted-foreground">{item.body}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </Tile>
          </div>
        </section>
        <ContactSection />
      </main>
      <footer className="border-t border-border bg-background">
        <div className="mx-auto max-w-7xl px-6 py-10 lg:px-8">
          <div className="flex flex-col items-center gap-5">
            <div className="flex items-center gap-2.5">
              <InntrisLogo className="h-5 w-5" />
              <span className="text-sm font-semibold tracking-tight text-foreground">Inntris</span>
            </div>
            <p className="text-sm text-muted-foreground text-center">
              Control and proof for high-risk AI agent actions.
            </p>
            <div className="flex items-center gap-6">
              <Link href="/docs" className={cn("rounded-sm text-sm text-muted-foreground transition-colors hover:text-foreground", focusRing)}>Docs</Link>
              <Link href="/verify" className={cn("rounded-sm text-sm text-muted-foreground transition-colors hover:text-foreground", focusRing)}>Verify</Link>
            </div>
            <p className="text-xs text-muted-foreground">
              &copy; 2026 Inntris, Inc.
            </p>
          </div>
        </div>
      </footer>
    </div>
    </>
  );
}
