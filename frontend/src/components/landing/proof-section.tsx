import React from "react";
import { ArrowUpRight } from "lucide-react";
import { Eyebrow, Num, focusRing } from "@/components/landing/primitives";
import { Reveal, RevealGroup } from "@/components/landing/reveal";
import { cn } from "@/lib/utils";

/**
 * Proof — the two public repositories whose pull requests Inntris blocked.
 *
 * Everything in this section is static and public on purpose, so it links
 * straight out rather than proxying anything through the API.
 */

const repositories = [
  {
    name: "Inntris/agent-orchestrator-guardrails",
    label: "Live demo",
    body: "Action-level governance for AI agent pull requests. When an agent opens a PR, Inntris evaluates it against your policy, issues a signed PASS or BLOCK verdict, and anchors a cryptographic receipt on-chain.",
    href: "https://github.com/Inntris/agent-orchestrator-guardrails",
  },
  {
    name: "Inntris/inntris-verify",
    label: "GitHub Action",
    body: "The Action that evaluates each pull request, classifies changed paths by risk, and issues the verdict. Workflow files and policy definitions are sensitive by default.",
    href: "https://github.com/Inntris/inntris-verify",
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
            The governance layer blocked its own tooling.
          </h2>
          <p className="mt-4 text-base leading-7 text-muted-foreground">
            An AI agent opened two pull requests adding workflow files and policy
            definitions. Inntris evaluated each one, classified the changes as
            high-risk, and issued BLOCK verdicts before merge. Both PRs are
            permanently open and blocked — that&apos;s the product working, not a
            bug.
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
