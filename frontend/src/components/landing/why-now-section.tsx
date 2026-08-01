import React from "react";
import { Eyebrow, focusRing } from "@/components/landing/primitives";
import { Reveal } from "@/components/landing/reveal";
import { cn } from "@/lib/utils";

/**
 * Why now — the market shift, with every named technology linked to a primary
 * source in the body text.
 *
 * Inline links rather than a footnote of bare URLs: a long block of raw links
 * reads as defensive, inline citation reads as ordinary. Every company named
 * in the body appears in the source line below it — if a claim about someone
 * else's product is added here, its source is added at the same time.
 *
 * Claims verified 31 July 2026. Where a primary source pins an exact date it
 * is stated; where only secondary reporting gives a day, the month is used.
 */

const SOURCES = {
  x402: "https://x402.org/",
  ap2: "https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol",
  ap2Fido:
    "https://blog.google/products-and-platforms/platforms/google-pay/agent-payments-protocol-fido-alliance/",
  visa: "https://developer.visa.com/capabilities/trusted-agent-protocol",
  mastercard:
    "https://www.mastercard.com/us/en/news-and-trends/stories/2026/verifiable-intent.html",
  acp: "https://www.agenticcommerce.dev/",
} as const;

function Source({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={cn(
        "rounded-sm font-medium text-brandInk underline decoration-primary/30 underline-offset-4 transition-colors hover:decoration-primary",
        focusRing,
      )}
    >
      {children}
    </a>
  );
}

export function WhyNowSection() {
  return (
    <section
      id="why-now"
      aria-labelledby="why-now-heading"
      className="scroll-mt-24 border-b border-border bg-background"
    >
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
        <Reveal className="max-w-3xl">
          <Eyebrow>The market shift</Eyebrow>
          <h2
            id="why-now-heading"
            className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl"
          >
            Agent payments are becoming a protocol layer.
          </h2>
        </Reveal>

        <Reveal className="mt-6 max-w-3xl space-y-5 text-base leading-8 text-muted-foreground">
          <p>
            <Source href={SOURCES.x402}>x402</Source> activates HTTP 402 for programmatic,
            machine-to-machine payments, including payments initiated by AI agents.
          </p>
          <p>
            Google launched the{" "}
            <Source href={SOURCES.ap2}>Agent Payments Protocol</Source> in September 2025 as an
            open, payment-agnostic framework that uses cryptographically signed mandates to
            represent a user&rsquo;s instructions and an agent&rsquo;s authority to transact. Google{" "}
            <Source href={SOURCES.ap2Fido}>donated AP2 to the FIDO Alliance</Source> in April 2026
            and released AP2 version 0.2 with support for autonomous, human-not-present
            transactions.
          </p>
          <p>
            <Source href={SOURCES.visa}>Visa</Source> and{" "}
            <Source href={SOURCES.mastercard}>Mastercard</Source> are introducing payment
            infrastructure for recognised agents, tokenised credentials, user consent, spending
            conditions and agent-initiated transactions.
          </p>
          <p>
            OpenAI and Stripe released the{" "}
            <Source href={SOURCES.acp}>Agentic Commerce Protocol</Source> as an open standard in
            September 2025, defining how an agent completes checkout against a merchant it does not
            own — while the merchant remains merchant of record and retains responsibility for
            accepting, processing and fulfilling the order.
          </p>
          <p>
            As agent-payment execution becomes easier and more standardised, enterprises still need
            their own portable answer to one question:
          </p>
        </Reveal>

        <Reveal className="mt-6 max-w-3xl">
          <p className="border-l-[3px] border-primary pl-5 text-xl font-semibold leading-9 tracking-tight text-foreground md:text-2xl">
            Was this exact payment authorised under our current organisational policy?
          </p>
        </Reveal>

        <Reveal className="mt-8 max-w-3xl">
          <p className="text-base leading-8 text-muted-foreground">
            Inntris is designed to provide that answer across agents, execution environments and
            payment rails.
          </p>
          <p className="mt-6 border-t border-border pt-5 text-xs leading-6 text-muted-foreground">
            Sources: x402 documentation; Google AP2 announcement, 16 September 2025; Google and FIDO
            Alliance AP2 v0.2 announcement, April 2026; Visa Intelligent Commerce and Trusted Agent
            Protocol; Mastercard Verifiable Intent and Agent Pay for Machines; OpenAI and Stripe
            Agentic Commerce Protocol, 29 September 2025. Verified 31 July 2026.
          </p>
        </Reveal>
      </div>
    </section>
  );
}
