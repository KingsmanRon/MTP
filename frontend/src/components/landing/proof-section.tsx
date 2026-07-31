import React from "react";
import { ArrowUpRight, XOctagon } from "lucide-react";
import { Eyebrow, Num, focusRing } from "@/components/landing/primitives";
import { Reveal, RevealGroup } from "@/components/landing/reveal";
import { cn } from "@/lib/utils";

/**
 * Proof — the two public repositories and the live receipts for the pull
 * requests Inntris blocked in them.
 *
 * Everything in this section is static and public on purpose: the receipts are
 * verifiable without an account, so the section links straight out rather than
 * proxying anything through the API.
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

const receipts = [
  {
    number: 1,
    title: "Add inntris-verify Action scaffold + demo workflow and policies",
    prHref: "https://github.com/Inntris/agent-orchestrator-guardrails/pull/1",
    verifyHref: "https://www.inntris.com/verify/2f41036e-cd54-4ec1-86e1-22f96cbc09aa",
  },
  {
    number: 2,
    title: "Add Inntris Verified GitHub Action, policies, docs and tests",
    prHref: "https://github.com/Inntris/agent-orchestrator-guardrails/pull/2",
    verifyHref: "https://www.inntris.com/verify/e8025672-096d-4c5c-b621-e3daeea4baa6",
  },
] as const;

/** Same treatment as the BLOCK verdict on the receipt cards above. */
function BlockChip() {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-destructive/20 bg-destructive/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-destructive">
      <XOctagon className="h-3.5 w-3.5" aria-hidden="true" />
      Block
    </span>
  );
}

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

        <Reveal className="mt-5 overflow-hidden rounded-lg border border-tileLine bg-tile">
          {/* Below md the table collapses to stacked rows — three columns in a
              phone-width viewport shreds the PR titles one word per line. The
              overflow container stays as a safety net above that. */}
          <div className="overflow-x-auto">
            <table className="block w-full border-collapse text-left md:table">
              <caption className="sr-only">
                Pull requests blocked by Inntris, with their public verification
                receipts
              </caption>
              <thead className="hidden md:table-header-group">
                <tr className="border-b border-tileLine">
                  <th
                    scope="col"
                    className="w-full px-5 py-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground"
                  >
                    PR
                  </th>
                  <th
                    scope="col"
                    className="whitespace-nowrap px-5 py-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground"
                  >
                    Verdict
                  </th>
                  <th
                    scope="col"
                    className="whitespace-nowrap px-5 py-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground"
                  >
                    Verify
                  </th>
                </tr>
              </thead>
              <RevealGroup as="tbody" className="block md:table-row-group">
                {receipts.map((receipt) => (
                  <tr
                    key={receipt.number}
                    className="block border-b border-tileLine px-5 py-5 align-top transition-colors duration-200 last:border-b-0 hover:bg-card md:table-row md:p-0"
                  >
                    <td className="block md:table-cell md:px-5 md:py-4">
                      <a
                        href={receipt.prHref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={cn("group block rounded-sm", focusRing)}
                      >
                        <Num className="block text-xs text-muted-foreground">
                          PR #{receipt.number}
                        </Num>
                        <span className="mt-1 block text-sm font-medium leading-6 text-foreground transition-colors group-hover:text-brandInk">
                          {receipt.title}
                          <ArrowUpRight
                            className="ml-1.5 inline h-3.5 w-3.5 align-[-1px] text-muted-foreground transition-transform duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:text-brandInk"
                            aria-hidden="true"
                          />
                          <NewTabHint />
                        </span>
                      </a>
                    </td>
                    <td className="mt-3 block md:mt-0 md:table-cell md:whitespace-nowrap md:px-5 md:py-4">
                      <BlockChip />
                    </td>
                    <td className="mt-3 block md:mt-0 md:table-cell md:whitespace-nowrap md:px-5 md:py-4">
                      <a
                        href={receipt.verifyHref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={cn(
                          "group inline-flex items-center gap-1.5 rounded-sm text-sm font-medium text-brandInk",
                          focusRing,
                        )}
                      >
                        View receipt
                        <ArrowUpRight
                          className="h-3.5 w-3.5 transition-transform duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5"
                          aria-hidden="true"
                        />
                        <NewTabHint />
                      </a>
                    </td>
                  </tr>
                ))}
              </RevealGroup>
            </table>
          </div>
        </Reveal>

        <Reveal>
          <p className="mt-4 max-w-2xl text-sm leading-6 text-muted-foreground">
            Signed with Ed25519. Anchored on Base L2. Publicly verifiable — no
            login, no repo access, no trust required.
          </p>
        </Reveal>
      </div>
    </section>
  );
}
