import Link from "next/link";
import {
  Bot,
  CheckCircle2,
  ChevronRight,
  Globe,
  LayoutDashboard,
  SearchCheck,
  XOctagon,
} from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";
import {
  CodePanel,
  Eyebrow,
  Num,
  PrimaryButton,
  SecondaryButton,
  SectionHeading,
  Tile,
  focusRing,
} from "./primitives";
import {
  APPROVED_PAYLOAD,
  BLOCKED_PAYLOAD,
  CANONICAL_BLOCK_RECEIPT_ID,
  LIVE_PASS_RECEIPT_URL,
  PUBLIC_VERIFY_URL,
  SALES_EMAIL,
} from "./content";
import { cn } from "@/lib/utils";

/* ── 8. Product — the two payloads ──────────────────────────────── */

export function ProductPayloads() {
  return (
    <section id="product" className="scroll-mt-24 border-b border-border bg-muted">
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8 lg:py-24">
        <SectionHeading
          eyebrow="The receipt"
          title="Two outcomes. Both recorded, both signed."
          lede="POST /verify returns an approval token or it does not. Either way the decision is written to the audit log before the response leaves the server."
        />

        <div className="mt-12 grid gap-5 lg:grid-cols-2">
          <div className="min-w-0">
            <CodePanel
              filename="200 OK — approved"
              badge={
                <span className="inline-flex items-center gap-1.5 rounded-md bg-success/15 px-2.5 py-1 font-mono text-xs font-semibold text-success">
                  <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                  APPROVED
                </span>
              }
            >
              {APPROVED_PAYLOAD}
            </CodePanel>
            <a
              href={LIVE_PASS_RECEIPT_URL}
              target="_blank"
              rel="noopener noreferrer"
              className={cn(
                "mt-3 inline-flex items-center gap-1.5 rounded-sm text-sm font-medium text-brandInk hover:text-brandDeep",
                focusRing,
              )}
            >
              Inspect a live approved receipt
              <ChevronRight className="h-4 w-4" aria-hidden="true" />
            </a>
          </div>

          <div className="min-w-0">
            <CodePanel
              filename="403 Forbidden — blocked"
              badge={
                <span className="inline-flex items-center gap-1.5 rounded-md bg-destructive/15 px-2.5 py-1 font-mono text-xs font-semibold text-destructive">
                  <XOctagon className="h-3.5 w-3.5" aria-hidden="true" />
                  BLOCKED
                </span>
              }
            >
              {BLOCKED_PAYLOAD}
            </CodePanel>
            <Link
              href={`/verify/${CANONICAL_BLOCK_RECEIPT_ID}`}
              className={cn(
                "mt-3 inline-flex items-center gap-1.5 rounded-sm text-sm font-medium text-brandInk hover:text-brandDeep",
                focusRing,
              )}
            >
              Inspect a live blocked receipt
              <ChevronRight className="h-4 w-4" aria-hidden="true" />
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ── 10. Modules ────────────────────────────────────────────────── */

const MODULES = [
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
    href: PUBLIC_VERIFY_URL,
  },
];

export function Modules() {
  return (
    <section
      id="modules"
      className="scroll-mt-24 border-b border-border bg-background"
    >
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8 lg:py-24">
        <SectionHeading
          eyebrow="Product surface"
          title="One control plane. Four modules."
        />

        <div className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {MODULES.map((item) => {
            const Icon = item.icon;
            const external = item.href.startsWith("http");
            const label = (
              <span className="mt-auto inline-flex items-center gap-1.5 pt-5 text-sm font-medium text-brandInk">
                {item.cta}
                <ChevronRight className="h-4 w-4" aria-hidden="true" />
              </span>
            );
            return (
              <Tile key={item.title} ground="white" className="flex flex-col p-6">
                <span className="flex h-11 w-11 items-center justify-center rounded-lg border border-tileLine bg-card text-primary">
                  <Icon className="h-5 w-5" aria-hidden="true" />
                </span>
                <h3 className="mt-5 text-lg font-semibold tracking-tight text-foreground">
                  {item.title}
                </h3>
                <p className="mt-1.5 text-[11px] font-semibold uppercase tracking-[0.14em] text-brandInk">
                  {item.role}
                </p>
                <p className="mt-3 flex-1 text-sm leading-6 text-muted-foreground">
                  {item.body}
                </p>
                {external ? (
                  <a
                    href={item.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={cn("flex flex-col rounded-sm", focusRing)}
                  >
                    {label}
                  </a>
                ) : (
                  <Link
                    href={item.href}
                    className={cn("flex flex-col rounded-sm", focusRing)}
                  >
                    {label}
                  </Link>
                )}
              </Tile>
            );
          })}
        </div>
      </div>
    </section>
  );
}

/* ── 11. Trust stack ────────────────────────────────────────────── */

const TRUST_STACK = [
  {
    title: "Signed at the source",
    body: "Each decision is signed with the server's Ed25519 key. The signature covers the agent, the action hash, the verdict, and the timestamp.",
  },
  {
    title: "Hashed into a tree",
    body: "Audit rows are SHA-256 hashed and bundled into a keccak256 Merkle tree, so a single root commits to every record in the batch.",
  },
  {
    title: "Anchored on Base",
    body: "The root is written to the AnchorRegistry contract on Base Mainnet, chain 8453. Re-anchoring an edited log would produce a different root.",
  },
  {
    title: "Checked by anyone",
    body: "A receipt carries its Merkle path. Verification needs the public anchor and the record — not an Inntris account, and not our cooperation.",
  },
];

export function TrustStack() {
  return (
    <section
      id="trust"
      className="scroll-mt-24 border-b border-border bg-muted"
    >
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8 lg:py-24">
        <SectionHeading
          eyebrow="Trust stack"
          title="Why the receipt survives us."
          lede="The proof chain is built so that a customer can validate a decision even if Inntris is unreachable, uncooperative, or gone."
        />

        <div className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {TRUST_STACK.map((item, i) => (
            <Tile key={item.title} ground="tinted" className="p-6">
              <Num className="text-xs font-semibold text-brandInk">
                {String(i + 1).padStart(2, "0")}
              </Num>
              <h3 className="mt-3 text-lg font-semibold tracking-tight text-foreground">
                {item.title}
              </h3>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">
                {item.body}
              </p>
            </Tile>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── 12. Statement block ────────────────────────────────────────── */

export function StatementBlock() {
  return (
    <section
      aria-label="Positioning"
      className="bg-gradient-to-br from-primary to-vault"
    >
      <div className="mx-auto max-w-4xl px-6 py-20 text-center lg:px-8 lg:py-28">
        <p className="text-2xl font-semibold leading-[1.35] tracking-tight text-primary-foreground md:text-3xl md:leading-[1.35]">
          Inntris provides a verification layer for teams that need signed
          decisions, policy enforcement, and tamper-evident audit trails for AI
          agent actions.
        </p>
      </div>
    </section>
  );
}

/* ── 13. Specs ──────────────────────────────────────────────────── */

const SPECS: Array<[string, string]> = [
  ["Agent signing", "Ed25519, per-agent key pair"],
  ["Decision token", "HMAC-SHA256, 5-minute TTL"],
  ["Audit hashing", "SHA-256 per record"],
  ["Anchor tree", "keccak256 Merkle root"],
  ["Anchor chain", "Base Mainnet, chain 8453"],
  ["Verification latency", "<100ms"],
  ["Default policy mode", "Fail-closed"],
  ["New agent trust score", "50 / 100"],
  ["Deploy / merge threshold", "80 / 100"],
  ["Admin action threshold", "70 / 100"],
  ["Integration surface", "MCP server, REST /verify"],
  ["Request tracing", "X-Request-ID on every response"],
];

export function Specs() {
  return (
    <section id="specs" className="scroll-mt-24 border-b border-border bg-background">
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8 lg:py-24">
        <SectionHeading eyebrow="Specifications" title="The numbers behind it." />

        <div className="mt-12 overflow-x-auto rounded-lg border border-tileLine">
          <table className="w-full min-w-[36rem] border-collapse text-left">
            <caption className="sr-only">
              Inntris platform specifications
            </caption>
            <thead>
              <tr className="bg-tile">
                <th
                  scope="col"
                  className="px-5 py-3 text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground"
                >
                  Property
                </th>
                <th
                  scope="col"
                  className="px-5 py-3 text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground"
                >
                  Value
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-tileLine">
              {SPECS.map(([property, value]) => (
                <tr key={property} className="bg-card">
                  <th
                    scope="row"
                    className="px-5 py-3 text-sm font-medium text-foreground"
                  >
                    {property}
                  </th>
                  <td className="px-5 py-3">
                    <Num className="text-sm text-muted-foreground">{value}</Num>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

/* ── 14. Design partners ────────────────────────────────────────── */

const PARTNER_CARDS = [
  {
    title: "What you bring",
    items: [
      "One agent workflow that already touches code, data, or money",
      "A protected branch, a spend cap, or an export path worth gating",
      "An engineer who can wire the MCP config and own the policy file",
    ],
  },
  {
    title: "What you get",
    items: [
      "Integration and policy setup, included for the first three partners",
      "PASS and BLOCK receipts for every decision on the instrumented path",
      "A monthly review summary, and direct input on what gets built next",
    ],
  },
];

export function DesignPartners() {
  return (
    <section
      id="design-partners"
      className="scroll-mt-24 border-b border-border bg-muted"
    >
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8 lg:py-24">
        <SectionHeading
          eyebrow="Design partners"
          title="We are taking on a small number of partners."
          lede="Start with one risky workflow. In 14 days, Inntris instruments its control boundary and produces receipts for every allowed and blocked action."
        />

        <div className="mt-12 grid gap-5 lg:grid-cols-2">
          {PARTNER_CARDS.map((card) => (
            <Tile key={card.title} ground="tinted" className="p-6 lg:p-8">
              <h3 className="text-lg font-semibold tracking-tight text-foreground">
                {card.title}
              </h3>
              <ul className="mt-4 flex flex-col gap-3">
                {card.items.map((item) => (
                  <li key={item} className="flex gap-3">
                    <span
                      aria-hidden="true"
                      className="mt-2.5 h-px w-3 shrink-0 bg-primary"
                    />
                    <span className="text-sm leading-6 text-muted-foreground">
                      {item}
                    </span>
                  </li>
                ))}
              </ul>
            </Tile>
          ))}
        </div>

        <Tile
          ground="tinted"
          interactive={false}
          className="mt-5 flex flex-col gap-6 p-6 sm:flex-row sm:items-center sm:justify-between lg:p-8"
        >
          <div className="min-w-0">
            <h3 className="text-lg font-semibold tracking-tight text-foreground">
              Talk to the team
            </h3>
            <p className="mt-2 max-w-xl text-sm leading-6 text-muted-foreground">
              For design partner discussions, platform reviews, and production agent
              deployments, contact us directly. We respond within 24 hours.
            </p>
          </div>
          <a
            href={`mailto:${SALES_EMAIL}`}
            className={cn(
              "shrink-0 rounded-sm font-mono text-sm text-brandInk underline-offset-4 hover:underline",
              focusRing,
            )}
          >
            {SALES_EMAIL}
          </a>
        </Tile>
      </div>
    </section>
  );
}

/* ── 15. Final CTA + footer ─────────────────────────────────────── */

export function FinalCta() {
  return (
    <section className="border-b border-border bg-background">
      <div className="mx-auto max-w-4xl px-6 py-20 text-center lg:px-8 lg:py-24">
        <Eyebrow className="inline-block text-left">Get started</Eyebrow>
        <h2 className="mt-4 text-3xl font-semibold leading-tight tracking-tight text-foreground md:text-4xl">
          Instrument one workflow. Keep the receipts.
        </h2>
        <p className="mx-auto mt-4 max-w-2xl text-base leading-8 text-muted-foreground md:text-lg">
          Fourteen days from the first config block to a control boundary your team
          owns and an audit trail anyone can check.
        </p>
        <div className="mt-9 flex flex-wrap justify-center gap-3">
          <PrimaryButton href="/pilot">Apply for Early Access</PrimaryButton>
          <SecondaryButton href="/docs">Read the docs</SecondaryButton>
        </div>
      </div>
    </section>
  );
}

export function SiteFooter() {
  return (
    <footer className="bg-background">
      <div className="mx-auto flex max-w-7xl flex-col items-center gap-5 px-6 py-12 lg:px-8">
        <div className="flex items-center gap-2.5">
          <InntrisLogo className="h-5 w-5" />
          <span className="text-sm font-semibold tracking-tight text-foreground">
            Inntris
          </span>
        </div>
        <p className="text-center text-sm text-muted-foreground">
          Control and proof for high-risk AI agent actions.
        </p>
        <nav aria-label="Footer" className="flex items-center gap-6">
          <Link
            href="/docs"
            className={cn(
              "rounded-sm text-sm text-muted-foreground transition-colors hover:text-foreground",
              focusRing,
            )}
          >
            Docs
          </Link>
          <Link
            href="/verify"
            className={cn(
              "rounded-sm text-sm text-muted-foreground transition-colors hover:text-foreground",
              focusRing,
            )}
          >
            Verify
          </Link>
          <a
            href={`mailto:${SALES_EMAIL}`}
            className={cn(
              "rounded-sm text-sm text-muted-foreground transition-colors hover:text-foreground",
              focusRing,
            )}
          >
            Contact
          </a>
        </nav>
        <p className="text-xs text-muted-foreground">&copy; 2026 Inntris, Inc.</p>
      </div>
    </footer>
  );
}
