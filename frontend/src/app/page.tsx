import React from "react";
import Link from "next/link";
import {
  LayoutDashboard,
  Bot,
  SearchCheck,
  Globe,
  ChevronRight,
  CheckCircle2,
} from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";
import { MobileMenu } from "@/components/mobile-menu";
import ContactSection from "@/components/contact-section";
import { LandingHash } from "@/components/landing-hash";
import { Eyebrow, Num, Tile, focusRing } from "@/components/landing/primitives";
import { Reveal, RevealGroup } from "@/components/landing/reveal";
import { ProtocolSection } from "@/components/landing/protocol-section";
import { WhyNowSection } from "@/components/landing/why-now-section";
import {
  LiveProofSection,
  loadLiveReceipts,
  blockedReceiptId,
} from "@/components/landing/live-proof-section";
import { VerificationSection } from "@/components/landing/verification-section";
import { BeyondPaymentsSection } from "@/components/landing/beyond-payments-section";
import { cn } from "@/lib/utils";

/**
 * The Inntris homepage.
 *
 * Payments-led throughout. Two boundaries are enforced in the copy and must
 * survive any future edit, because a reader following the public docs can
 * disprove them if they slip:
 *
 *  1. Inntris records the policy decision. The payment rail records that money
 *     moved. The page never claims Inntris proves settlement.
 *  2. The Base L2 anchor proves a Merkle root was recorded. Verifying a
 *     specific receipt additionally requires the pack, its inclusion proof and
 *     a pinned public key — so the page never says the anchor alone is enough.
 *
 * Verdict vocabularies differ between systems: platform receipts carry
 * PASS / BLOCK / ESCALATE, decision envelopes carry ALLOW / BLOCK /
 * REQUIRE_APPROVAL. Narrative copy here is plain English; the literal tokens
 * appear only on the artifact that emits them, labelled with its source. Do
 * not normalise one vocabulary into the other in the UI.
 */

const heroProofPoints = [
  {
    term: "Exact-action binding",
    detail:
      "The decision is tied to the amount, asset, recipient, purpose and relevant payment-protocol requirements.",
  },
  {
    term: "Policy before execution",
    detail:
      "Limits, approved recipients, cumulative spend and approval requirements are evaluated before the rail is called.",
  },
  {
    term: "Independent evidence",
    detail: "Signed receipts can be checked outside the system that produced them.",
  },
  {
    term: "Rail-independent control",
    detail: "Inntris does not hold funds, issue wallets or replace the payment provider.",
  },
];

const proofStrip = [
  { value: "Ed25519", label: "Decision and receipt signing" },
  { value: "Fail-closed", label: "Execution pattern" },
  { value: "Base L2", label: "Evidence-pack anchoring" },
  { value: "MIT", label: "Public x402 reference" },
];

const gapPoints = [
  {
    step: "01",
    title: "The credential is valid",
    body: "The agent has access to the payment API, wallet or card credential. Authentication has succeeded, but the exact payment has not yet been evaluated against organisational policy.",
  },
  {
    step: "02",
    title: "The decision is time-sensitive",
    body: "Limits, recipients, approval state and policy versions can change between an initial request and execution.",
  },
  {
    step: "03",
    title: "The consequences are immediate",
    body: "Once money moves, an after-the-fact log can explain the event. It cannot retroactively authorise it.",
  },
];

const controlPath = [
  {
    step: "01",
    title: "Agent proposes",
    body: "The agent submits the amount, asset, recipient, purpose and relevant protocol references.",
  },
  {
    step: "02",
    title: "Policy evaluates",
    body: "Inntris checks agent identity, action limits, cumulative spend, approved recipients, approval requirements and the current policy version.",
  },
  {
    step: "03",
    title: "Result is signed",
    body: "The approve, block or approval-required result is bound to the proposed action and recorded with cryptographic evidence.",
  },
  {
    step: "04",
    title: "Execution boundary enforces",
    body: "The integrated executor checks the result before calling the payment rail. A missing, invalid, expired or mismatched decision fails closed.",
  },
  {
    step: "05",
    title: "The rail settles",
    body: "The payment provider, facilitator, wallet or network remains responsible for execution and settlement.",
  },
];

const surfaces = [
  {
    icon: LayoutDashboard,
    title: "Admin Console",
    role: "For platform and security teams",
    body: "Manage agents, policies, credentials and approval boundaries from one place.",
    cta: "Explore Console",
    href: "/admin",
  },
  {
    icon: Bot,
    title: "Agent Portal",
    role: "For developers and operators",
    body: "Register agents, test policy evaluation in the sandbox and inspect policy outcomes.",
    cta: "Explore Portal",
    href: "/portal",
  },
  {
    icon: SearchCheck,
    title: "Audit Explorer",
    role: "For investigations and compliance",
    body: "Search verification records by agent, action, time and verdict, then inspect their integrity evidence.",
    cta: "Explore Audit Explorer",
    href: "/audit",
  },
  {
    icon: Globe,
    title: "Public Verify",
    role: "For customers, partners and auditors",
    body: "Share a receipt link so another party can inspect its signature, policy hash and anchor evidence.",
    cta: "Verify a receipt",
    href: "/verify",
  },
];

const pilotDeliverables = [
  "One agent-payment workflow mapped and instrumented",
  "Agent identity and policy boundary configured",
  "Approve, block and human-approval-required paths tested",
  "Fail-closed enforcement at the execution boundary",
  "Verifiable evidence for each policy result",
  "Pilot findings and production-rollout recommendation",
];

const navLinks = [
  { href: "/#payments", label: "Payments" },
  { href: "/#use-cases", label: "Use cases" },
  { href: "/#verify", label: "Verify" },
  { href: "/docs", label: "Docs" },
  { href: "/pilot", label: "14-day pilot" },
];

export default async function InntrisHomePage() {
  // One fetch for both canonical receipts. The hero deep link and the live
  // proof section read the same records, so they cannot disagree about which
  // receipt is the blocked one.
  const receipts = await loadLiveReceipts();
  const blockedId = blockedReceiptId(receipts);

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "Organization",
    name: "Inntris",
    legalName: "Inntris Inc.",
    url: "https://www.inntris.com",
    logo: "https://www.inntris.com/logo.svg",
    description:
      "Inntris evaluates the exact proposed agent payment against organisational policy before execution and produces signed evidence that can be independently verified.",
    foundingDate: "2025",
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
                <div className="text-xs text-muted-foreground">Agent payment authorisation</div>
              </div>
            </div>
            <nav
              aria-label="Primary"
              className="hidden items-center gap-5 text-[15px] md:flex lg:gap-7"
            >
              {navLinks.map((link) => (
                <Link
                  key={link.href}
                  className={cn(
                    "rounded-sm text-muted-foreground transition-colors hover:text-foreground",
                    focusRing,
                  )}
                  href={link.href}
                >
                  {link.label}
                </Link>
              ))}
            </nav>
            <div className="flex items-center gap-3">
              <Link
                href="/pilot"
                className={cn(
                  "hidden min-h-11 items-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-brandDeep md:inline-flex",
                  focusRing,
                )}
              >
                Scope a payment pilot
              </Link>
              <MobileMenu
                variant="light"
                links={navLinks}
                cta={{ href: "/pilot", label: "Scope a payment pilot" }}
              />
            </div>
          </div>
        </header>

        <main>
          {/* ══ 1 · Hero ═══════════════════════════════════════════════ */}
          <section
            id="overview"
            className="scroll-mt-24 bg-gradient-to-b from-accent/60 via-accent/10 to-background"
          >
            <div className="mx-auto grid max-w-7xl gap-12 px-6 pb-24 pt-14 lg:grid-cols-[1.1fr_0.9fr] lg:gap-16 lg:px-8">
              <RevealGroup className="min-w-0 max-w-3xl">
                <div className="mb-7 inline-flex items-center gap-2 rounded-full border border-primary/25 bg-card px-4 py-2 shadow-sm">
                  <span
                    aria-hidden="true"
                    className="live-dot h-1.5 w-1.5 rounded-full bg-primary text-primary"
                  />
                  <span className="text-sm text-brandInk">Agentic payment control</span>
                </div>
                {/* Two clauses, because the product has two halves: control
                    before execution, proof afterwards.

                    An earlier draft read "Prove every agent payment was
                    authorised before it settles." It blurred the boundary the
                    rest of the page draws. Inntris proves the policy decision;
                    it does not tie a specific settled transaction back to that
                    decision unless the rail's transaction reference is brought
                    into the evidence chain. "Before it settles" implied that
                    link. Do not reintroduce settlement into this headline
                    unless the product actually closes that loop. */}
                <h1 className="mb-5 max-w-3xl text-4xl font-semibold leading-[1.12] tracking-tight md:text-6xl">
                  Authorise every agent payment before execution.{" "}
                  <span className="text-primary">Prove every decision independently.</span>
                </h1>
                <p className="mb-5 max-w-2xl text-lg leading-relaxed text-muted-foreground">
                  Inntris evaluates the exact proposed payment against your organisation&rsquo;s
                  current policy before execution. It allows the payment, blocks it or requires
                  human approval — with signed evidence bound to the exact action.
                </p>
                <p className="mb-8 max-w-xl border-l-[3px] border-primary pl-4 text-base leading-relaxed text-foreground">
                  The payment rail records that money moved. Inntris records the policy decision
                  that allowed or prevented it.
                </p>
                <ul className="mb-8 flex max-w-xl flex-col gap-3.5">
                  {heroProofPoints.map(({ term, detail }) => (
                    <li key={term} className="flex gap-3.5">
                      <span
                        aria-hidden="true"
                        className="mt-3 h-0.5 w-3.5 shrink-0 rounded-full bg-primary"
                      />
                      <span className="text-[15px] leading-7 text-muted-foreground">
                        <span className="font-semibold text-foreground">{term}</span>
                        {" — "}
                        {detail}
                      </span>
                    </li>
                  ))}
                </ul>
                <div className="flex flex-wrap gap-3">
                  <Link
                    href="/pilot"
                    className={cn(
                      "inline-flex min-h-12 items-center rounded-xl bg-primary px-6 text-[15px] font-semibold text-primary-foreground shadow-sm transition-colors hover:bg-brandDeep",
                      focusRing,
                    )}
                  >
                    Scope a 14-day payment pilot
                  </Link>
                  <Link
                    href={`/verify/${blockedId}`}
                    className={cn(
                      "inline-flex min-h-12 items-center rounded-xl border border-tileLine bg-card px-6 text-[15px] font-semibold text-foreground shadow-sm transition-colors hover:bg-tile",
                      focusRing,
                    )}
                  >
                    Inspect a blocked payment
                  </Link>
                </div>
              </RevealGroup>

              <Reveal className="min-w-0" delay={160}>
                <div className="overflow-hidden rounded-2xl border border-tileLine bg-card shadow-sm">
                  <div className="px-6 pb-2 pt-6">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-lg font-semibold tracking-tight text-foreground">
                          Payment decision flow
                        </div>
                        {/* brandInk rather than muted-foreground. The muted
                            token is a 10%-saturation cool grey that reads as a
                            washed-out blue next to the chip and the numbered
                            tiles — neither clearly grey nor clearly blue. This
                            is a label, and blue labels are the page convention
                            (eyebrows, role captions, protocol status lines), so
                            it matches the chip beside it on purpose. The title
                            above stays near-black: blue headings would collide
                            with the blue reserved for interactive elements. */}
                        <div className="mt-1 font-mono text-sm text-brandInk">
                          Where Inntris sits before the rail
                        </div>
                      </div>
                      <span className="inline-flex shrink-0 items-center gap-2 rounded-full bg-accent px-3 py-1.5 font-mono text-xs text-accent-foreground">
                        <span
                          aria-hidden="true"
                          className="live-dot h-1.5 w-1.5 rounded-full bg-primary text-primary"
                        />
                        live policy path
                      </span>
                    </div>
                  </div>
                  <RevealGroup className="space-y-3 p-4">
                    {controlPath.slice(0, 4).map(({ step, title, body }) => (
                      <div
                        key={step}
                        className="flex gap-4 rounded-xl bg-tile p-5 transition duration-200 hover:translate-x-1 hover:bg-accent"
                      >
                        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary">
                          <Num className="text-xs font-semibold text-primary-foreground">{step}</Num>
                        </span>
                        <div className="min-w-0">
                          <div className="font-semibold text-foreground">{title}</div>
                          <div className="mt-1 text-[15px] leading-7 text-muted-foreground">
                            {body}
                          </div>
                        </div>
                      </div>
                    ))}
                  </RevealGroup>
                </div>
              </Reveal>
            </div>
          </section>

          {/* ── Proof strip ──────────────────────────────────────────── */}
          {/* No latency or throughput figure appears here. The x402 README
              explicitly disclaims production performance claims, and the site
              must not contradict its own repository in public. */}
          <section
            aria-label="Platform characteristics"
            className="border-t-2 border-primary bg-background"
          >
            <RevealGroup className="mx-auto grid max-w-7xl grid-cols-2 px-6 lg:grid-cols-4 lg:px-8">
              {proofStrip.map(({ value, label }, i) => (
                <div
                  key={label}
                  className={cn(
                    "py-9 pr-6",
                    // 2-up on phones: rule between the pair, rule above row two.
                    i % 2 === 1 && "border-l border-border pl-6",
                    i >= 2 && "border-t border-border",
                    // 4-up from lg: one rule before every cell but the first.
                    "lg:border-t-0",
                    i === 0 ? "lg:pl-0" : "lg:border-l lg:border-border lg:pl-8",
                  )}
                >
                  <Num className="block text-2xl font-semibold text-foreground md:text-3xl">
                    {value}
                  </Num>
                  <p className="mt-2 text-sm text-muted-foreground">{label}</p>
                </div>
              ))}
            </RevealGroup>
          </section>

          {/* ══ 2 · The payment-authority gap ══════════════════════════ */}
          <section
            id="problem"
            aria-labelledby="problem-heading"
            className="scroll-mt-24 border-b border-border bg-muted"
          >
            <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
              <Reveal className="max-w-3xl">
                <Eyebrow>The problem</Eyebrow>
                <h2
                  id="problem-heading"
                  className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl"
                >
                  A valid payment credential does not prove a valid payment decision.
                </h2>
                <p className="mt-4 text-base leading-7 text-muted-foreground">
                  An agent may authenticate correctly and still exceed a limit, pay an unapproved
                  recipient, reuse stale authority or act after company policy has changed.
                </p>
                <p className="mt-4 text-base leading-7 text-muted-foreground">
                  A settlement record proves that the rail processed the payment. It is not the same
                  as a portable record of the organisation&rsquo;s policy decision immediately
                  before execution.
                </p>
              </Reveal>

              <RevealGroup className="mt-8 grid gap-5 md:grid-cols-3">
                {gapPoints.map((point) => (
                  <Tile
                    key={point.step}
                    ground="tinted"
                    interactive={false}
                    className="flex flex-col p-6 md:p-7"
                  >
                    <Num className="text-sm font-semibold text-brandInk">{point.step}</Num>
                    <h3 className="mt-3 text-base font-semibold tracking-tight text-foreground">
                      {point.title}
                    </h3>
                    <p className="mt-3 text-sm leading-6 text-muted-foreground">{point.body}</p>
                  </Tile>
                ))}
              </RevealGroup>

              <Reveal className="mt-8">
                <p className="max-w-3xl text-base leading-7 text-muted-foreground">
                  Reconstructing authority after settlement is not the same as proving it before
                  settlement.
                </p>
              </Reveal>
            </div>
          </section>

          {/* ══ 3 · The control path ═══════════════════════════════════ */}
          <section
            id="payments"
            aria-labelledby="payments-heading"
            className="scroll-mt-24 border-b border-border bg-background"
          >
            <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
              <Reveal className="max-w-3xl">
                <Eyebrow>How Inntris works</Eyebrow>
                <h2
                  id="payments-heading"
                  className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl"
                >
                  One independent decision point before the payment rail.
                </h2>
                <p className="mt-4 text-base leading-7 text-muted-foreground">
                  Inntris sits between agent intent and the execution boundary. It evaluates the
                  exact proposed payment, records the result and provides evidence the executor can
                  check before allowing the rail to proceed.
                </p>
              </Reveal>

              <RevealGroup className="mt-8 space-y-3">
                {controlPath.map(({ step, title, body }) => (
                  <div
                    key={step}
                    className="flex gap-4 rounded-xl border border-tileLine bg-tile p-5 transition duration-200 hover:translate-x-1 hover:bg-accent md:p-6"
                  >
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary">
                      <Num className="text-xs font-semibold text-primary-foreground">{step}</Num>
                    </span>
                    <div className="min-w-0">
                      <div className="font-semibold text-foreground">{title}</div>
                      <div className="mt-1 text-[15px] leading-7 text-muted-foreground">{body}</div>
                    </div>
                  </div>
                ))}
              </RevealGroup>

              <Reveal className="mt-6">
                <div className="rounded-lg border-l-[3px] border-primary bg-muted px-5 py-4">
                  <p className="max-w-3xl text-sm leading-7 text-muted-foreground">
                    Inntris does not hold funds, issue payment credentials, sign payment
                    transactions or settle payments. It decides and proves; the payment rail
                    executes.
                  </p>
                </div>
              </Reveal>
            </div>
          </section>

          {/* ══ 4 · Public protocol references ═════════════════════════ */}
          <ProtocolSection />

          {/* ══ 5 · Why now ════════════════════════════════════════════ */}
          <WhyNowSection />

          {/* ══ 6 · Live payment proof ═════════════════════════════════ */}
          <LiveProofSection records={receipts} />

          {/* ══ 7 · Independent verification ═══════════════════════════ */}
          <VerificationSection />

          {/* ══ 8 · Beyond payments ════════════════════════════════════ */}
          <BeyondPaymentsSection />

          {/* ══ 9 · The platform ═══════════════════════════════════════ */}
          <section
            id="platform"
            aria-labelledby="platform-heading"
            className="scroll-mt-24 border-b border-border bg-background"
          >
            <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
              <Reveal className="mb-8 max-w-3xl">
                <Eyebrow>Operate and prove</Eyebrow>
                <h2
                  id="platform-heading"
                  className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl"
                >
                  One control layer. Four operating surfaces.
                </h2>
              </Reveal>
              <RevealGroup className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
                {surfaces.map((item) => {
                  const Icon = item.icon;
                  return (
                    <Link
                      key={item.title}
                      href={item.href}
                      className={cn(
                        "group flex flex-col rounded-lg border border-tileLine bg-tile p-6 transition duration-200 hover:-translate-y-1 hover:border-primary/40 hover:bg-card hover:shadow-lg",
                        focusRing,
                      )}
                    >
                      <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-lg border border-tileLine bg-card text-primary">
                        <Icon className="h-6 w-6" aria-hidden="true" />
                      </div>
                      <h3 className="text-xl font-semibold tracking-tight text-foreground">
                        {item.title}
                      </h3>
                      <p className="mt-1.5 min-h-[32px] text-[11px] font-semibold uppercase tracking-[0.16em] text-brandInk">
                        {item.role}
                      </p>
                      <p className="mt-3 flex-1 text-sm leading-6 text-muted-foreground">
                        {item.body}
                      </p>
                      <span className="mt-5 inline-flex items-center gap-2 text-sm font-medium text-brandInk">
                        {item.cta}
                        <ChevronRight
                          className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-1"
                          aria-hidden="true"
                        />
                      </span>
                    </Link>
                  );
                })}
              </RevealGroup>
            </div>
          </section>

          {/* ══ 10 · Independence ══════════════════════════════════════ */}
          <section
            id="independence"
            aria-labelledby="independence-heading"
            className="scroll-mt-24 border-b border-border bg-muted"
          >
            <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
              <Reveal className="max-w-3xl">
                <Eyebrow>Independent by design</Eyebrow>
                <h2
                  id="independence-heading"
                  className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl"
                >
                  The party executing a payment should not be the only party proving it was
                  authorised.
                </h2>
                <p className="mt-5 text-base leading-7 text-muted-foreground">
                  Payment rails provide settlement, fraud controls and network evidence. Model and
                  agent platforms provide execution environments. Identity systems establish who or
                  what is acting.
                </p>
                <p className="mt-4 text-base leading-7 text-muted-foreground">
                  Inntris adds the organisation&rsquo;s transaction-specific policy decision
                  immediately before execution and produces evidence that can travel beyond any one
                  platform.
                </p>
                <p className="mt-6 border-l-[3px] border-primary pl-5 text-base leading-7 text-foreground">
                  Rails and agent platforms will keep adding native controls, and should. What they
                  cannot produce is a neutral record of your policy decision that holds up outside
                  their own boundary. Inntris complements the rail, the model provider and the
                  identity stack — it is simply not one of them.
                </p>
              </Reveal>
            </div>
          </section>

          {/* ══ 11 · Published boundaries ══════════════════════════════ */}
          <section
            id="boundaries"
            aria-labelledby="boundaries-heading"
            className="scroll-mt-24 border-b border-border bg-background"
          >
            <div className="mx-auto max-w-7xl px-6 py-16 lg:px-8">
              <Reveal>
                <Tile ground="white" interactive={false} className="p-6 md:p-8">
                  <Eyebrow>Published boundaries</Eyebrow>
                  <p
                    id="boundaries-heading"
                    className="mt-4 max-w-3xl text-base leading-7 text-muted-foreground"
                  >
                    The public implementation is a reference architecture, not evidence of HSM
                    custody, distributed spend accounting or production performance. AP2 and A2A are
                    public reference packages rather than hosted production integrations. Review the
                    complete limitations in our technical documentation.
                  </p>
                  <Link
                    href="/security"
                    className={cn(
                      "mt-5 inline-flex items-center gap-2 rounded-sm text-sm font-medium text-brandInk",
                      focusRing,
                    )}
                  >
                    Full limitations
                    <ChevronRight className="h-4 w-4" aria-hidden="true" />
                  </Link>
                </Tile>
              </Reveal>
            </div>
          </section>

          {/* ══ 12 · Pilot CTA ═════════════════════════════════════════ */}
          <section
            id="pilot"
            aria-labelledby="pilot-heading"
            className="scroll-mt-24 border-b border-border bg-muted"
          >
            <div className="mx-auto grid max-w-7xl gap-10 px-6 py-20 lg:grid-cols-[1fr_1fr] lg:gap-16 lg:px-8">
              <Reveal className="min-w-0">
                <Eyebrow>Design-partner pilot</Eyebrow>
                <h2
                  id="pilot-heading"
                  className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl"
                >
                  Start with one agent payment workflow.
                </h2>
                <p className="mt-4 text-base leading-7 text-muted-foreground">
                  In 14 days, Inntris instruments one high-risk agent-payment workflow with a
                  defined policy boundary and verifiable evidence for approved and blocked actions.
                </p>
                <div className="mt-8 flex flex-wrap gap-3">
                  <Link
                    href="/pilot"
                    className={cn(
                      "inline-flex min-h-12 items-center rounded-xl bg-primary px-6 text-[15px] font-semibold text-primary-foreground shadow-sm transition-colors hover:bg-brandDeep",
                      focusRing,
                    )}
                  >
                    Scope a 14-day payment pilot
                  </Link>
                </div>
                <p className="mt-5 text-sm text-muted-foreground">
                  Fixed scope. One workflow. Clear production recommendation.
                </p>
              </Reveal>

              <Reveal className="min-w-0" delay={120}>
                <Tile ground="tinted" interactive={false} className="p-6 md:p-8">
                  <h3 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-brandInk">
                    Pilot deliverables
                  </h3>
                  <ul className="mt-5 space-y-3.5">
                    {pilotDeliverables.map((deliverable) => (
                      <li key={deliverable} className="flex gap-3 text-sm leading-6 text-muted-foreground">
                        <CheckCircle2
                          className="mt-0.5 h-5 w-5 shrink-0 text-primary"
                          aria-hidden="true"
                        />
                        {deliverable}
                      </li>
                    ))}
                  </ul>
                </Tile>
              </Reveal>
            </div>
          </section>

          {/* ══ 13 · Contact ═══════════════════════════════════════════ */}
          <ContactSection />
        </main>

        <footer className="border-t border-border bg-background">
          <div className="mx-auto max-w-7xl px-6 py-10 lg:px-8">
            <div className="flex flex-col items-center gap-5">
              <div className="flex items-center gap-2.5">
                <InntrisLogo className="h-5 w-5" />
                <span className="text-sm font-semibold tracking-tight text-foreground">Inntris</span>
              </div>
              <p className="text-center text-sm text-muted-foreground">
                Independent authorisation and verifiable evidence for agent actions. Payments first.
              </p>
              <nav aria-label="Footer" className="flex flex-wrap items-center justify-center gap-x-6 gap-y-3">
                {[
                  { href: "/#payments", label: "Payments" },
                  { href: "/#use-cases", label: "Use cases" },
                  { href: "/verify", label: "Verify" },
                  { href: "/docs", label: "Docs" },
                  { href: "/security", label: "Security" },
                  { href: "/#contact", label: "Contact" },
                ].map((link) => (
                  <Link
                    key={link.href}
                    href={link.href}
                    className={cn(
                      "rounded-sm text-sm text-muted-foreground transition-colors hover:text-foreground",
                      focusRing,
                    )}
                  >
                    {link.label}
                  </Link>
                ))}
              </nav>
              <p className="text-xs text-muted-foreground">&copy; 2026 Inntris, Inc.</p>
            </div>
          </div>
        </footer>
      </div>
    </>
  );
}
