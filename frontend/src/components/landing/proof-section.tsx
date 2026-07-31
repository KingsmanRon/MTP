import React from "react";
import { ArrowUpRight } from "lucide-react";
import { Eyebrow, Num, focusRing } from "@/components/landing/primitives";
import { Reveal, RevealGroup } from "@/components/landing/reveal";
import { cn } from "@/lib/utils";

/**
 * Proof — the two public Inntris repositories.
 *
 * Everything in this section is static and public on purpose, so it links
 * straight out rather than proxying anything through the API. Each card's copy
 * is taken from that repository's own README, so it stays true if someone
 * clicks through.
 */

const repositories = [
  {
    name: "Inntris/inntris-verify",
    label: "Offline verifier",
    body: "The canonical, out-of-band publication channel for the verifier and its signing keys. verify_pack.py checks the Ed25519 signature, every file hash in both directions, every receipt fingerprint, and every Merkle inclusion proof. The copy here is byte-identical to the one embedded in every evidence pack, so you can audit it once and diff it against any pack you receive.",
    href: "https://github.com/Inntris/inntris-verify",
  },
  {
    name: "Inntris/inntris-x402-policy-adapter",
    label: "Reference implementation",
    body: "Inntris does not move money. It proves the exact payment was authorised by organisational policy before another system moves it. A rail-independent decision envelope and a fail-closed adapter for the official x402 TypeScript SDK, where blocked, expired, tampered, and replayed decisions never reach settlement.",
    href: "https://github.com/Inntris/inntris-x402-policy-adapter",
  },
] as const;

/** Announced only to screen readers — the arrow carries it visually. */
function NewTabHint() {
  return <span className="sr-only"> (opens in a new tab)</span>;
}

export function ProofSection() {
  return (
    /* The receipt section above is tinted and the one below is white, so a
       flat ground here would merge into one of its neighbours. The faint accent
       wash echoes the hero and gives the section its own edge. */
    <section
      id="proof"
      aria-labelledby="proof-heading"
      className="scroll-mt-24 border-b border-border bg-gradient-to-b from-accent/40 via-accent/5 to-background"
    >
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
        <Reveal className="max-w-3xl">
          <Eyebrow>Proof</Eyebrow>
          <h2
            id="proof-heading"
            className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl"
          >
            Verify it without us.
          </h2>
          <p className="mt-4 text-base leading-7 text-muted-foreground">
            Two public repositories, both independently checkable. The evidence
            pack verifier runs on stock Python with no network and no Inntris
            dependency — verification that routes through the vendor of the
            evidence is circular. The x402 adapter binds a signed policy decision
            to the exact proposed payment, and fails closed before settlement.
          </p>
        </Reveal>

        <RevealGroup className="mt-8 grid gap-5 md:grid-cols-2">
          {repositories.map((repo) => (
            <a
              key={repo.name}
              href={repo.href}
              target="_blank"
              rel="noopener noreferrer"
              className={cn(
                "group flex h-full flex-col rounded-lg border border-tileLine bg-tile p-6 transition duration-200 hover:-translate-y-1 hover:border-primary/40 hover:bg-card hover:shadow-lg md:p-8",
                focusRing,
              )}
            >
              <div className="flex items-start justify-between gap-3">
                <span className="text-[11px] font-semibold uppercase tracking-[0.16em] text-brandInk">
                  {repo.label}
                </span>
                <ArrowUpRight
                  className="h-4 w-4 shrink-0 text-muted-foreground transition-transform duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:text-brandInk"
                  aria-hidden="true"
                />
              </div>
              {/* The org/repo string has no spaces, so it needs an explicit
                  wrap opportunity or it widens the grid track on a phone. It
                  breaks at the hyphens first, and only mid-word if it must. */}
              <Num className="mt-3 block break-words text-base font-medium text-foreground">
                {repo.name}
              </Num>
              <p className="mt-3 flex-1 text-sm leading-6 text-muted-foreground">
                {repo.body}
              </p>
              <span className="mt-5 inline-flex items-center gap-2 text-sm font-medium text-brandInk">
                View on GitHub
                <ArrowUpRight
                  className="h-4 w-4 transition-transform duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5"
                  aria-hidden="true"
                />
                <NewTabHint />
              </span>
            </a>
          ))}
        </RevealGroup>
      </div>
    </section>
  );
}
