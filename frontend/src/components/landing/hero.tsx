import { ArrowRight, ShieldCheck } from "lucide-react";
import {
  Eyebrow,
  Num,
  PrimaryButton,
  SecondaryButton,
  StepNumber,
} from "./primitives";
import { LIVE_PASS_RECEIPT_URL } from "./content";

const BULLETS = [
  "Cryptographic identity — Ed25519 signatures bind every action to its agent",
  "Policy before execution — rate limits, spend caps, and allowlists enforced before the action runs",
  "Tamper-evident audit — logs anchored on Base L2 with receipt integrity you can verify yourself",
];

const DECISION_STEPS: Array<[string, string, string]> = [
  ["01", "Action requested", "Agent requests a code, data, API, or finance operation."],
  ["02", "Policy evaluated", "Inntris checks permissions, risk, and execution context."],
  ["03", "Decision signed", "Approved or blocked outcome is bound to the agent identity."],
  ["04", "Proof recorded", "Evidence is written to the audit trail for later verification."],
];

export function Hero() {
  return (
    <section
      id="overview"
      className="scroll-mt-24 border-b border-border bg-background"
    >
      <div className="mx-auto grid max-w-7xl gap-12 px-6 py-16 lg:grid-cols-[1.1fr_0.9fr] lg:gap-16 lg:px-8 lg:py-24">
        <div className="min-w-0">
          <div className="inline-flex items-center gap-2 rounded-full border border-tileLine bg-tile px-3 py-1.5">
            <span
              aria-hidden="true"
              className="h-1.5 w-1.5 rounded-full bg-primary"
            />
            <span className="font-mono text-xs text-brandInk">
              Verification API live
            </span>
          </div>

          <h1 className="mt-6 text-4xl font-semibold leading-[1.1] tracking-tight text-foreground md:text-6xl">
            Stop unchecked AI-generated PRs from reaching{" "}
            <span className="text-primary">protected branches.</span>
          </h1>

          <p className="mt-6 max-w-2xl text-lg leading-8 text-muted-foreground">
            Inntris adds a required policy check for AI coding agents and creates a
            verification receipt for every PASS or BLOCK decision.
          </p>

          <ul className="mt-8 flex max-w-xl flex-col gap-3">
            {BULLETS.map((bullet) => (
              <li key={bullet} className="flex gap-3">
                <span
                  aria-hidden="true"
                  className="mt-2.5 h-px w-3 shrink-0 bg-primary"
                />
                <span className="text-sm leading-6 text-muted-foreground">
                  {bullet}
                </span>
              </li>
            ))}
          </ul>

          <div className="mt-9 flex flex-wrap gap-3">
            <PrimaryButton href="/pilot">
              Scope a 14-day pilot
              <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </PrimaryButton>
            <SecondaryButton href={LIVE_PASS_RECEIPT_URL} external>
              <ShieldCheck className="h-4 w-4" aria-hidden="true" />
              See live verification
            </SecondaryButton>
          </div>
        </div>

        <div className="min-w-0">
          <div className="overflow-hidden rounded-lg border border-tileLine bg-tile">
            <div className="flex items-center justify-between gap-3 border-b border-tileLine px-5 py-4">
              <div>
                <p className="text-sm font-medium text-foreground">
                  Verification decision flow
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  Where Inntris sits in your stack
                </p>
              </div>
              <span className="shrink-0 rounded-full bg-accent px-3 py-1 font-mono text-xs text-accent-foreground">
                live policy path
              </span>
            </div>
            <div className="flex flex-col gap-3 p-5">
              {DECISION_STEPS.map(([step, title, body]) => (
                <div
                  key={step}
                  className="flex gap-4 rounded-lg border border-tileLine bg-card p-4 transition duration-200 hover:-translate-y-1 hover:border-primary/40 hover:bg-tile hover:shadow-lg"
                >
                  <StepNumber>{step}</StepNumber>
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground">{title}</p>
                    <p className="mt-1 text-sm leading-6 text-muted-foreground">
                      {body}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

const STATS: Array<{ value: string; label: string }> = [
  { value: "<100ms", label: "Verification latency" },
  { value: "Ed25519", label: "Signing algorithm" },
  { value: "Base L2", label: "Audit anchor" },
  { value: "Fail-closed", label: "Default policy mode" },
];

export function StatStrip() {
  return (
    <section
      aria-label="Platform characteristics"
      className="border-b border-border bg-background"
    >
      <div className="mx-auto grid max-w-7xl grid-cols-2 gap-px px-6 lg:grid-cols-4 lg:px-8">
        {STATS.map((stat) => (
          <div key={stat.label} className="border-t-2 border-primary py-8 pr-6">
            <Num className="block text-2xl font-semibold text-foreground">
              {stat.value}
            </Num>
            <p className="mt-2 text-[11px] uppercase tracking-[0.14em] text-muted-foreground">
              {stat.label}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}
