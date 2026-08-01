import React from "react";
import { GitBranch, Database, ServerCog, Webhook } from "lucide-react";
import { Eyebrow, Tile } from "@/components/landing/primitives";
import { Reveal, RevealGroup } from "@/components/landing/reveal";

/**
 * Beyond payments — the expansion story, deliberately compressed.
 *
 * One line per card, no protocol detail, no status labels. The asymmetry
 * against the payments protocol section is the positioning: if any card here
 * grows to match that section, the page has quietly reverted to being a
 * general-purpose governance platform.
 */

const useCases = [
  {
    icon: GitBranch,
    title: "Code and CI/CD",
    body: "Require a policy decision before repository changes, CI/CD edits, protected-branch merges or production deployments.",
  },
  {
    icon: Database,
    title: "Sensitive data",
    body: "Gate customer-data access, bulk exports, PII reads and cross-boundary transfers before the query or export runs.",
  },
  {
    icon: ServerCog,
    title: "Administration and infrastructure",
    body: "Control permission grants, production configuration, resource provisioning, key rotation and destructive operations.",
  },
  {
    icon: Webhook,
    title: "APIs, tools and communications",
    body: "Apply policy before external API calls, MCP tool execution, outbound emails and other actions that affect third-party systems.",
  },
] as const;

export function BeyondPaymentsSection() {
  return (
    <section
      id="use-cases"
      aria-labelledby="use-cases-heading"
      className="scroll-mt-24 border-b border-border bg-muted"
    >
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
        <Reveal className="max-w-3xl">
          <Eyebrow>Additional use cases</Eyebrow>
          <h2
            id="use-cases-heading"
            className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl"
          >
            Payments first. Every consequential agent action next.
          </h2>
          <p className="mt-4 text-base leading-7 text-muted-foreground">
            Payments are the first product because errors are immediate, financial and difficult to
            reverse. The same pre-execution policy model can govern other actions an organisation
            should not allow an agent to take unchecked.
          </p>
        </Reveal>

        <RevealGroup className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {useCases.map((item) => {
            const Icon = item.icon;
            return (
              <Tile key={item.title} ground="tinted" interactive={false} className="flex flex-col p-5">
                <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg border border-tileLine bg-tile text-primary">
                  <Icon className="h-5 w-5" aria-hidden="true" />
                </div>
                <h3 className="text-base font-semibold tracking-tight text-foreground">
                  {item.title}
                </h3>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">{item.body}</p>
              </Tile>
            );
          })}
        </RevealGroup>

        <Reveal className="mt-8">
          <p className="max-w-3xl text-base leading-7 text-muted-foreground">
            Start with agent spend. Expand along the organisation&rsquo;s risk surface using the same
            agent identity, policy model and evidence layer.
          </p>
        </Reveal>
      </div>
    </section>
  );
}
