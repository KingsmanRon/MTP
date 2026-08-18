import React from "react";
import { Eyebrow, Num, Tile } from "@/components/landing/primitives";
import { Reveal, RevealGroup } from "@/components/landing/reveal";

/**
 * Agent payment protocols — one organisational policy layer across x402, AP2
 * and A2A.
 *
 * Each card carries an explicit status label. The reference packages are
 * reference packages, and saying so here is cheaper than having a reader work
 * it out from the repository and conclude the rest of the page is padded too.
 */

const protocols = [
  {
    name: "x402",
    headline: "Exact-payment authorisation",
    body: "The decision binds the proposed payment to the x402 payment requirements it answers. Changing the amount, recipient or payment challenge changes the binding and causes the guard to refuse settlement.",
    status: "Public MIT Phase 1 reference implementation",
  },
  {
    name: "AP2",
    headline: "Verified mandate, current company policy",
    body: "The reference gate verifies the merchant checkout and open mandate constraints, then applies the organisation's current policy. A valid protocol mandate cannot override a company-policy block or approval requirement.",
    status: "Public follow-on reference package",
  },
  {
    name: "A2A",
    headline: "Settlement finality before delegation",
    body: "The reference gate binds the payment to the A2A task and requires a verified approval plus confirmed settlement finality before one delegated execution can proceed.",
    status: "Public follow-on reference package",
  },
] as const;

export function ProtocolSection() {
  return (
    <section
      id="protocols"
      aria-labelledby="protocols-heading"
      className="scroll-mt-24 border-b border-border bg-muted"
    >
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
        <Reveal className="max-w-3xl">
          <Eyebrow>Agent payment protocols</Eyebrow>
          <h2
            id="protocols-heading"
            className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl"
          >
            One organisational policy layer across emerging agent-payment protocols.
          </h2>
          <p className="mt-4 text-base leading-7 text-muted-foreground">
            Inntris publishes reference implementations built against pinned official protocol SDKs
            and types. The x402 adapter also validates payment objects using the official runtime
            schemas.
          </p>
        </Reveal>

        <RevealGroup className="mt-8 grid gap-5 md:grid-cols-3">
          {protocols.map((protocol) => (
            <Tile
              key={protocol.name}
              ground="tinted"
              interactive={false}
              className="flex flex-col p-6 md:p-7"
            >
              <Num className="text-lg font-semibold text-foreground">{protocol.name}</Num>
              <h3 className="mt-3 text-base font-semibold tracking-tight text-foreground">
                {protocol.headline}
              </h3>
              <p className="mt-3 flex-1 text-sm leading-6 text-muted-foreground">{protocol.body}</p>
              <p className="mt-5 border-t border-tileLine pt-4 text-[11px] font-semibold uppercase tracking-[0.14em] text-brandInk">
                {protocol.status}
              </p>
            </Tile>
          ))}
        </RevealGroup>

        {/* Human approval — the callout that stops a stale "yes" from settling. */}
        <Reveal className="mt-6">
          <Tile ground="tinted" interactive={false} className="p-6 md:p-8">
            <h3 className="text-lg font-semibold tracking-tight text-foreground">
              An approval does not rewrite an old decision.
            </h3>
            <p className="mt-3 max-w-3xl text-sm leading-7 text-muted-foreground">
              A human-approval-required result remains immutable and cannot reach settlement. When
              the human responds, Inntris re-evaluates the action against the policy that is current
              at that moment and issues a new signed result that supersedes the original.
            </p>
            <p className="mt-3 max-w-3xl text-sm leading-7 text-muted-foreground">
              A stale human &ldquo;yes&rdquo; cannot override a limit or policy that has since
              changed. A refusal produces a signed block with a recorded reason, and resolution is
              single-use.
            </p>
          </Tile>
        </Reveal>

        {/* The literal tokens, each attributed to the artifact that actually
            emits it.

            This block previously said the envelope tokens were "the literal
            values in the signed artifact" without naming which artifact — on
            the same page as receipt cards rendering PASS. A reader who took up
            the "check it yourself" invitation landed straight on a value the
            homepage appeared to deny existed.

            Two systems, two vocabularies, and neither is normalised into the
            other in the UI. Platform receipts carry a `verdict` field that is
            hashed into the receipt fingerprint and signed, so its wire values
            cannot be renamed for presentation — see lib/verdict.ts. */}
        <Reveal className="mt-6">
          <div className="rounded-lg border-l-[3px] border-primary bg-tile px-5 py-4">
            <p className="text-sm font-medium text-foreground">
              Verdict names, and where each one appears
            </p>
            <p className="mt-1.5 text-sm leading-7 text-muted-foreground">
              The x402 policy adapter emits decision envelopes carrying{" "}
              <Num className="text-foreground">ALLOW</Num>,{" "}
              <Num className="text-foreground">BLOCK</Num> and{" "}
              <Num className="text-foreground">REQUIRE_APPROVAL</Num>. Inntris platform receipts
              are a different artifact: they record a signed{" "}
              <Num className="text-foreground">verdict</Num> field, shown on the public verifier as{" "}
              <Num className="text-foreground">PASS</Num>,{" "}
              <Num className="text-foreground">BLOCK</Num> or{" "}
              <Num className="text-foreground">ESCALATE</Num>.
            </p>
            <p className="mt-3 text-sm leading-7 text-muted-foreground">
              The two vocabularies are not interchangeable and neither is rewritten to match the
              other. A receipt shows the value its own signed record contains, because that value
              is part of what the fingerprint covers.
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
