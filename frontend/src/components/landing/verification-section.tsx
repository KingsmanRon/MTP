import React from "react";
import { ArrowUpRight, KeyRound, FileArchive, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { Eyebrow, Num, focusRing } from "@/components/landing/primitives";
import { Reveal, RevealGroup } from "@/components/landing/reveal";
import { cn } from "@/lib/utils";

/**
 * Independent verification — the two public verifiers and the key-pinning
 * instruction that makes them worth anything.
 *
 * Two rules are load-bearing here and neither is decoration:
 *
 *  - The evidence-pack verifier and the decision verifier are different tools
 *    for different artifacts. Neither substitutes for the other, and the page
 *    says so rather than letting a reader assume one covers both.
 *  - Pinning is what turns "verify us" from a slogan into a procedure. The
 *    verifier itself prints a warning when the key is not pinned; the site
 *    should not be quieter about it than the tool is.
 */

const VERIFY_REPO = "https://github.com/Inntris/inntris-verify";
const ADAPTER_REPO = "https://github.com/Inntris/inntris-x402-policy-adapter";

const verifiers = [
  {
    icon: FileArchive,
    artifact: "Artifact 01 · Evidence pack",
    title: "Evidence packs",
    verifies:
      "the signed pack manifest, every file hash in both directions, receipt fingerprints, agent signatures and Merkle inclusion proofs. An optional check queries a Base mainnet RPC node chosen by the verifier.",
    properties: [
      "Python 3.10 or later",
      "Standard library only — nothing to install",
      "No Inntris endpoint, library or account required",
      "Single file, auditable in one sitting",
    ],
    cta: "Review the evidence-pack verifier",
    repo: "github.com/Inntris/inntris-verify",
    href: VERIFY_REPO,
  },
  {
    icon: ShieldCheck,
    artifact: "Artifact 02 · Decision envelope",
    title: "Payment decisions",
    verifies:
      "the decision schema, fingerprint, Ed25519 signature, action hash, action binding, expiry at a supplied execution time, policy version and payment-requirements binding.",
    properties: [
      "Offline by default",
      "No Inntris account required",
      "Makes no network request unless a key registry URL is supplied explicitly",
    ],
    cta: "Review the payment decision verifier",
    repo: "github.com/Inntris/inntris-x402-policy-adapter",
    href: ADAPTER_REPO,
  },
] as const;

export function VerificationSection() {
  return (
    <section
      id="verify"
      aria-labelledby="verify-heading"
      className="scroll-mt-24 border-b border-border bg-gradient-to-b from-accent/40 via-accent/5 to-background"
    >
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
        <Reveal className="max-w-3xl">
          <Eyebrow>Verify without trusting us</Eyebrow>
          <h2 id="verify-heading" className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl">
            Separate proof artifacts. Separate public verifiers.
          </h2>
          <p className="mt-4 text-base leading-7 text-muted-foreground">
            Verification that routes through the company producing the evidence is circular. Inntris
            publishes both verification paths outside the production service so it never has to.
          </p>
        </Reveal>

        <RevealGroup className="mt-8 grid gap-6 md:grid-cols-2">
          {verifiers.map((v) => {
            const Icon = v.icon;
            return (
              <a
                key={v.title}
                href={v.href}
                target="_blank"
                rel="noopener noreferrer"
                className={cn(
                  // These two cards used to be a matched pair of white
                  // rectangles on a near-white ground with a hairline that did
                  // not read — so a reader saw one block, not two artifacts.
                  // Elevation, an icon and a numbered artifact label give each
                  // card its own identity before any copy is read.
                  "group flex h-full flex-col rounded-xl border border-tileLine bg-card shadow-e2 transition duration-200",
                  "hover:-translate-y-1 hover:border-primary/50 hover:shadow-e3",
                  focusRing,
                )}
              >
                <div className="flex items-start gap-4 border-b border-tileLine p-6 md:p-8 md:pb-6">
                  <div
                    className="flex h-12 w-12 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-brandDeep text-primary-foreground shadow-e1"
                    aria-hidden="true"
                  >
                    <Icon className="h-6 w-6" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-brandInk">
                      {v.artifact}
                    </p>
                    <h3 className="mt-1 text-xl font-semibold tracking-tight text-foreground">
                      {v.title}
                    </h3>
                  </div>
                </div>

                <div className="flex flex-1 flex-col p-6 md:p-8 md:pt-6">
                  <p className="text-sm leading-6 text-muted-foreground">
                    <span className="font-semibold text-foreground">What it verifies:</span>{" "}
                    {v.verifies}
                  </p>

                  <p className="mt-6 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                    Properties
                  </p>
                  <ul className="mt-3 flex-1 space-y-2 border-t border-tileLine pt-3">
                    {v.properties.map((p) => (
                      <li key={p} className="flex gap-3 text-sm leading-6 text-muted-foreground">
                        <span
                          aria-hidden="true"
                          className="mt-2.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary"
                        />
                        <span>{p}</span>
                      </li>
                    ))}
                  </ul>

                  <span className="mt-6 inline-flex items-center gap-2 text-sm font-semibold text-brandInk">
                    {v.cta}
                    <ArrowUpRight
                      className="h-4 w-4 transition-transform duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5"
                      aria-hidden="true"
                    />
                    <span className="sr-only"> (opens in a new tab)</span>
                  </span>
                  {/* The repo string has no spaces, so it needs an explicit wrap
                      opportunity or it widens the grid track on a phone. */}
                  <Num className="mt-1.5 block break-words text-xs text-muted-foreground">
                    {v.repo}
                  </Num>
                </div>
              </a>
            );
          })}
        </RevealGroup>

        {/* ── Pin the key ──────────────────────────────────────────── */}
        <Reveal className="mt-6">
          <div className="rounded-xl border border-tileLine bg-card p-6 shadow-e2 md:p-8">
            <div className="flex flex-col gap-5 md:flex-row md:gap-7">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-brandDeep text-primary-foreground">
                <KeyRound className="h-5 w-5" aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <h3 className="text-lg font-semibold tracking-tight text-foreground">
                  A verifier is only as independent as the key it checks against.
                </h3>
                <p className="mt-3 text-sm leading-7 text-muted-foreground">
                  Signing keys are published in two independently controlled channels: the verifier
                  repository and{" "}
                  <a
                    href="/.well-known/inntris-keys.txt"
                    className={cn(
                      "rounded-sm font-mono text-brandInk underline-offset-4 hover:underline",
                      focusRing,
                    )}
                  >
                    inntris.com/.well-known/inntris-keys.txt
                  </a>
                  . Pin the key from one and cross-check it against the other. An attacker must
                  compromise both to substitute a key.
                </p>
                <p className="mt-3 text-sm leading-7 text-muted-foreground">
                  Without a pinned key, a signature proves the artifact is internally consistent —
                  not that Inntris produced it. On any discrepancy between the two channels, treat
                  verification as failed and contact{" "}
                  <a
                    href="mailto:sales@inntris.com"
                    className={cn(
                      "rounded-sm font-mono text-brandInk underline-offset-4 hover:underline",
                      focusRing,
                    )}
                  >
                    sales@inntris.com
                  </a>
                  .
                </p>
                <Link
                  href="/security"
                  className={cn(
                    "mt-4 inline-flex items-center gap-2 rounded-sm text-sm font-medium text-brandInk",
                    focusRing,
                  )}
                >
                  Key registry and reporting
                  <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
                </Link>
              </div>
            </div>
          </div>
        </Reveal>

        {/* ── The distinction we do not let a reader blur ───────────── */}
        <Reveal className="mt-6">
          <div className="rounded-lg border border-tileLine border-l-[3px] border-l-primary bg-tile px-5 py-4 shadow-e1">
            <p className="text-sm font-medium text-foreground">
              An evidence pack and a decision envelope are different artifacts with different
              verifiers.
            </p>
            <p className="mt-1.5 text-sm leading-7 text-muted-foreground">
              The evidence-pack verifier does not verify decision envelopes. The decision verifier
              does not verify evidence packs. Neither one substitutes for the other, and we do not
              claim otherwise.
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
