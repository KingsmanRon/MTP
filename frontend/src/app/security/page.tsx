import type { Metadata } from "next";
import Link from "next/link";
import { ArrowUpRight, KeyRound, ShieldAlert } from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";
import { MobileMenu } from "@/components/mobile-menu";
import { Eyebrow, Num, Tile, focusRing } from "@/components/landing/primitives";
import { cn } from "@/lib/utils";

export const metadata: Metadata = {
  title: "Security and published boundaries — Inntris",
  description:
    "Signing keys, independent verification instructions, vulnerability reporting, and the complete list of what the public Inntris implementation does and does not prove.",
};

/**
 * `/security` is load-bearing rather than decorative. Four separate published
 * artifacts resolve here — the footer navigation, the homepage key-pinning
 * instructions, the published-boundaries link, and the evidence-pack
 * verifier's own README, which tells auditors to write to security@inntris.com
 * on any key discrepancy. If this page 404s, that instruction dead-ends at the
 * exact moment someone is deciding whether to trust the key registry.
 */

const KEY_REGISTRY_URL = "/.well-known/inntris-keys.txt";
const VERIFY_REPO = "https://github.com/Inntris/inntris-verify";
const ADAPTER_REPO = "https://github.com/Inntris/inntris-x402-policy-adapter";

const limitations = [
  {
    title: "Custody and recovery",
    body: "No HSM-grade key custody or disaster-recovery guarantees. The managed signer path is planned, not proven.",
  },
  {
    title: "Durable state",
    body: "The public reference implementation uses in-memory nonce, decision and approval stores. A production deployment requires a durable, atomic store shared across executors.",
  },
  {
    title: "Cumulative limits",
    body: "Reference cumulative spend tracking is not a distributed ledger and requires an atomic durable store in production.",
  },
  {
    title: "Follow-on packages",
    body: "The AP2 and A2A gates are reference implementations on main. They are not evidence of a deployed production service.",
  },
  {
    title: "Performance",
    body: "No production latency or throughput figures are claimed.",
  },
];

const navLinks = [
  { href: "/#payments", label: "Payments" },
  { href: "/#use-cases", label: "Use cases" },
  { href: "/verify", label: "Verify" },
  { href: "/docs", label: "Docs" },
  { href: "/pilot", label: "14-day pilot" },
];

export default function SecurityPage() {
  return (
    <div className="theme-light min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-30 border-b border-border bg-muted/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
          <Link href="/" className="flex items-center gap-3" aria-label="Inntris home">
            <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-tileLine bg-card">
              <InntrisLogo className="h-6 w-6" />
            </span>
            <span className="text-lg font-semibold tracking-tight">Inntris</span>
          </Link>
          <nav aria-label="Primary" className="hidden items-center gap-5 text-[15px] md:flex lg:gap-7">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className={cn("rounded-sm text-muted-foreground transition-colors hover:text-foreground", focusRing)}
              >
                {link.label}
              </Link>
            ))}
          </nav>
          <MobileMenu
            variant="light"
            links={navLinks}
            cta={{ href: "/pilot", label: "Scope a payment pilot" }}
          />
        </div>
      </header>

      <main>
        <section className="border-b border-border bg-gradient-to-b from-accent/60 via-accent/10 to-background">
          <div className="mx-auto max-w-4xl px-6 pb-16 pt-14 lg:px-8">
            <Eyebrow>Security</Eyebrow>
            <h1 className="mt-4 max-w-3xl text-3xl font-semibold leading-[1.14] tracking-tight md:text-5xl">
              Signing keys, reporting, and what the public implementation does not prove.
            </h1>
            <p className="mt-5 max-w-2xl text-lg leading-relaxed text-muted-foreground">
              Inntris asks you to verify its evidence rather than trust it. That only works if the
              key you check against, the way to report a problem, and the limits of the published
              claim are all in one place you can read without an account.
            </p>
          </div>
        </section>

        {/* ── Signing keys ─────────────────────────────────────────── */}
        <section id="keys" className="scroll-mt-24 border-b border-border bg-background">
          <div className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
            <Eyebrow>Signing keys</Eyebrow>
            <h2 className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl">
              Pin the key from one channel. Cross-check it against the other.
            </h2>
            <p className="mt-4 text-base leading-7 text-muted-foreground">
              A verifier is only as independent as the key it checks against. Without a pinned key,
              a valid signature proves the artifact is internally consistent — not that Inntris
              produced it.
            </p>

            <div className="mt-8 grid gap-5 md:grid-cols-2">
              <Tile ground="white" interactive={false} className="flex flex-col p-6">
                <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-lg border border-tileLine bg-card text-primary">
                  <KeyRound className="h-5 w-5" aria-hidden="true" />
                </div>
                <h3 className="text-lg font-semibold tracking-tight">Channel one — this site</h3>
                <p className="mt-2 flex-1 text-sm leading-6 text-muted-foreground">
                  The published key registry mirror, served from the Inntris domain.
                </p>
                <a
                  href={KEY_REGISTRY_URL}
                  className={cn(
                    "mt-4 inline-flex w-fit items-center gap-2 rounded-sm font-mono text-sm text-brandInk underline-offset-4 hover:underline",
                    focusRing,
                  )}
                >
                  inntris.com/.well-known/inntris-keys.txt
                </a>
              </Tile>

              <Tile ground="white" interactive={false} className="flex flex-col p-6">
                <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-lg border border-tileLine bg-card text-primary">
                  <KeyRound className="h-5 w-5" aria-hidden="true" />
                </div>
                <h3 className="text-lg font-semibold tracking-tight">Channel two — the verifier repo</h3>
                <p className="mt-2 flex-1 text-sm leading-6 text-muted-foreground">
                  <Num>KEYS.md</Num> and <Num>SHA256SUMS</Num> in the public verifier repository.
                </p>
                <a
                  href={`${VERIFY_REPO}/blob/main/KEYS.md`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={cn(
                    "mt-4 inline-flex w-fit items-center gap-2 rounded-sm font-mono text-sm text-brandInk underline-offset-4 hover:underline",
                    focusRing,
                  )}
                >
                  github.com/Inntris/inntris-verify
                  <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
                  <span className="sr-only"> (opens in a new tab)</span>
                </a>
              </Tile>
            </div>

            <div className="mt-6 rounded-lg border-l-[3px] border-primary bg-tile px-5 py-4">
              <p className="text-sm leading-7 text-muted-foreground">
                The two channels are controlled independently, so an attacker must compromise both
                to substitute a key. On any discrepancy between them, treat verification as failed
                and write to{" "}
                <a
                  href="mailto:security@inntris.com"
                  className={cn("rounded-sm font-mono text-brandInk underline-offset-4 hover:underline", focusRing)}
                >
                  security@inntris.com
                </a>
                .
              </p>
            </div>
          </div>
        </section>

        {/* ── Reporting ────────────────────────────────────────────── */}
        <section id="reporting" className="scroll-mt-24 border-b border-border bg-muted">
          <div className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
            <Eyebrow>Reporting</Eyebrow>
            <h2 className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl">
              Report a vulnerability or a key discrepancy.
            </h2>

            <Tile ground="tinted" interactive={false} className="mt-6 p-6 md:p-8">
              <div className="flex gap-4">
                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-tileLine bg-tile text-primary">
                  <ShieldAlert className="h-5 w-5" aria-hidden="true" />
                </div>
                <div className="min-w-0">
                  <a
                    href="mailto:security@inntris.com"
                    className={cn(
                      "rounded-sm font-mono text-base text-brandInk underline-offset-4 hover:underline",
                      focusRing,
                    )}
                  >
                    security@inntris.com
                  </a>
                  <ul className="mt-4 space-y-2.5 text-sm leading-6 text-muted-foreground">
                    <li className="flex gap-3">
                      <span aria-hidden="true" className="mt-3 h-0.5 w-3 shrink-0 rounded-full bg-primary" />
                      <span>
                        Please report privately first and give us a reasonable window to respond
                        before disclosing publicly.
                      </span>
                    </li>
                    <li className="flex gap-3">
                      <span aria-hidden="true" className="mt-3 h-0.5 w-3 shrink-0 rounded-full bg-primary" />
                      <span>
                        Include the artifact — a receipt ID, an evidence pack, or a decision
                        envelope — and the verifier output you saw.
                      </span>
                    </li>
                    <li className="flex gap-3">
                      <span aria-hidden="true" className="mt-3 h-0.5 w-3 shrink-0 rounded-full bg-primary" />
                      <span>
                        We acknowledge security reports within one business day.
                      </span>
                    </li>
                  </ul>
                </div>
              </div>
            </Tile>
          </div>
        </section>

        {/* ── Published boundaries ─────────────────────────────────── */}
        <section id="boundaries" className="scroll-mt-24 border-b border-border bg-background">
          <div className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
            <Eyebrow>Published boundaries</Eyebrow>
            <h2 className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl">
              What the public implementation is not evidence of.
            </h2>
            <p className="mt-4 text-base leading-7 text-muted-foreground">
              The public implementation is a reference architecture. Listing its limits is cheaper
              than having a reader find them, and the same list is published in the technical pilot
              document and the x402 repository so the three cannot drift apart quietly.
            </p>

            <ul className="mt-8 space-y-4">
              {limitations.map((item) => (
                <li
                  key={item.title}
                  className="rounded-lg border border-tileLine bg-tile px-5 py-4"
                >
                  <p className="font-medium text-foreground">{item.title}</p>
                  <p className="mt-1.5 text-sm leading-6 text-muted-foreground">{item.body}</p>
                </li>
              ))}
            </ul>
          </div>
        </section>

        {/* ── Verifiers ────────────────────────────────────────────── */}
        <section id="verifiers" className="scroll-mt-24 border-b border-border bg-muted">
          <div className="mx-auto max-w-4xl px-6 py-16 lg:px-8">
            <Eyebrow>Verifiers</Eyebrow>
            <h2 className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl">
              Two artifacts. Two verifiers. Neither substitutes for the other.
            </h2>
            <p className="mt-4 text-base leading-7 text-muted-foreground">
              The evidence-pack verifier does not verify decision envelopes. The decision verifier
              does not verify evidence packs. We do not claim otherwise.
            </p>

            <div className="mt-8 grid gap-5 md:grid-cols-2">
              {[
                {
                  name: "Evidence packs",
                  repo: "github.com/Inntris/inntris-verify",
                  href: VERIFY_REPO,
                  body: "Signed pack manifest, file hashes in both directions, receipt fingerprints, agent signatures and Merkle inclusion proofs. Python standard library only.",
                },
                {
                  name: "Payment decisions",
                  repo: "github.com/Inntris/inntris-x402-policy-adapter",
                  href: ADAPTER_REPO,
                  body: "Decision schema, fingerprint, Ed25519 signature, action hash and binding, expiry at a supplied execution time, policy version and payment-requirements binding. Offline by default.",
                },
              ].map((v) => (
                <a
                  key={v.name}
                  href={v.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={cn(
                    "group flex h-full flex-col rounded-lg border border-tileLine bg-card p-6 transition duration-200 hover:-translate-y-1 hover:border-primary/40 hover:shadow-lg",
                    focusRing,
                  )}
                >
                  <h3 className="text-lg font-semibold tracking-tight">{v.name}</h3>
                  <p className="mt-2 flex-1 text-sm leading-6 text-muted-foreground">{v.body}</p>
                  <Num className="mt-4 flex items-center gap-2 break-words text-sm text-brandInk">
                    {v.repo}
                    <ArrowUpRight
                      className="h-4 w-4 shrink-0 transition-transform duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5"
                      aria-hidden="true"
                    />
                    <span className="sr-only"> (opens in a new tab)</span>
                  </Num>
                </a>
              ))}
            </div>
          </div>
        </section>
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
            <p className="text-xs text-muted-foreground">&copy; 2026 Inntris, Inc.</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
