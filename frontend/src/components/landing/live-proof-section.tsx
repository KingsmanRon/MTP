import React from "react";
import Link from "next/link";
import { ChevronRight, CheckCircle2, XOctagon, AlertTriangle } from "lucide-react";
import { Eyebrow, Num, Tile, focusRing } from "@/components/landing/primitives";
import { Reveal, RevealGroup } from "@/components/landing/reveal";
import { cn, formatUtcTimestamp } from "@/lib/utils";
import { publicApi, type PublicVerificationRecord } from "@/lib/api";
import { verdictLabel, isPassVerdict, isEscalateVerdict } from "@/lib/verdict";
import { CANONICAL_RECEIPT_IDS } from "@/lib/canonical-receipts";

/**
 * Payment proof — one allowed request and one blocked request, rendered from
 * the platform records themselves rather than from copy.
 *
 * The section does not call these receipts "live". They are real signed
 * records, but they are generated on demand rather than continuously, and a
 * heading that overclaims freshness on the one artifact meant to establish
 * trust is the worst possible place to overclaim.
 *
 * Three rules hold this section together:
 *
 *  1. Nothing about a card is hardcoded to a receipt ID. Which card leads,
 *     which badge it carries and which CTA it offers are all derived from the
 *     fetched verdict, so regenerating the receipts against a new policy
 *     version means editing `CANONICAL_RECEIPT_IDS` and nothing else. The blocked
 *     receipt leads because it is the more interesting artifact.
 *  2. The verdict tokens shown here — PASS / BLOCK / ESCALATE — are the
 *     platform receipt's own vocabulary, mapped in lib/verdict.ts from the
 *     signed wire values (approved / blocked / rate_limited). Decision
 *     envelopes are a separate artifact and use ALLOW / BLOCK /
 *     REQUIRE_APPROVAL. Do not normalise one into the other in the UI; display
 *     what the artifact actually contains.
 *  3. No trust score. An unpublished scoring methodology sitting beside a
 *     cryptographic signature weakens the claim it sits next to. It stays
 *     inside the Console.
 *
 * These are evidence-pack artifacts, verified by `verify_pack.py`. They are
 * not decision envelopes — the verification section carries that distinction.
 */

const receiptProofs = [
  "The agent request was cryptographically signed.",
  "The policy verdict and reason were recorded.",
  "The receipt is protected by its fingerprint and policy hash.",
  "The receipt was included in a Merkle batch anchored to Base L2.",
];

/**
 * The recorded time of a receipt, in UTC, absolute.
 *
 * This used to lead with a relative form — "Generated 27 days ago · 2026-07-22
 * 15:43 UTC" — which grows without bound. On an evidence artifact the absolute
 * time is the fact; the relative form is decoration that decays, and on the
 * flagship proof it eventually reads as abandonment rather than authority. It
 * is gone rather than demoted.
 */
export function formatReceiptTimestamp(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return `Recorded ${formatUtcTimestamp(d)}`;
}

async function loadReceipt(id: string): Promise<PublicVerificationRecord | null> {
  try {
    return await publicApi.getVerificationRecord(id);
  } catch {
    // API unavailable — the card is dropped rather than faked.
    return null;
  }
}

/**
 * Fetch the canonical receipts once per render. The page loads these and
 * passes them down, so the hero's deep link and this section agree on which
 * receipt is the blocked one without paying for the round trip twice.
 */
export async function loadLiveReceipts(): Promise<PublicVerificationRecord[]> {
  const loaded = await Promise.all(CANONICAL_RECEIPT_IDS.map(loadReceipt));
  return loaded.filter((r): r is PublicVerificationRecord => r !== null);
}

/** The blocked receipt the hero CTA deep-links to. */
export function blockedReceiptId(records: PublicVerificationRecord[]): string {
  const blocked = records.find((r) => !isPassVerdict(r.verdict));
  return blocked?.audit_id ?? CANONICAL_RECEIPT_IDS[0];
}

function ReceiptCard({ record }: { record: PublicVerificationRecord }) {
  const pass = isPassVerdict(record.verdict);
  const escalate = isEscalateVerdict(record.verdict);
  const Icon = pass ? CheckCircle2 : escalate ? AlertTriangle : XOctagon;

  return (
    <Link
      href={`/verify/${record.audit_id}`}
      className={cn(
        "group block rounded-lg border border-tileLine bg-card p-6 transition duration-200 hover:-translate-y-1 hover:border-primary/40 hover:bg-tile hover:shadow-lg md:p-8",
        focusRing,
      )}
    >
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div
            className={cn(
              "flex h-10 w-10 shrink-0 items-center justify-center rounded-full",
              pass ? "bg-success/10" : escalate ? "bg-warning/10" : "bg-destructive/10",
            )}
          >
            <Icon
              className={cn(
                "h-5 w-5",
                pass ? "text-success" : escalate ? "text-warning" : "text-destructive",
              )}
              aria-hidden="true"
            />
          </div>
          <div className="min-w-0">
            <span
              className={cn(
                "text-lg font-bold tracking-tight",
                pass ? "text-success" : escalate ? "text-warning" : "text-destructive",
              )}
            >
              {verdictLabel(record.verdict)}
            </span>
            <p className="text-xs text-muted-foreground">
              {record.verdict_reason ??
                (pass
                  ? "The proposed payment passed the configured policy checks."
                  : "The payment request was stopped by the configured policy.")}
            </p>
          </div>
        </div>
        <span className="inline-flex shrink-0 items-center gap-2 text-sm font-medium text-brandInk">
          {pass ? "Inspect approved receipt" : "Inspect blocked receipt"}
          <ChevronRight
            className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-1"
            aria-hidden="true"
          />
        </span>
      </div>

      <p className="mt-4 text-sm leading-6 text-muted-foreground">
        {pass
          ? "The receipt records the agent, action, policy result and cryptographic proof."
          : "The payment request was blocked and the receipt records the verdict and policy reason."}
      </p>

      <div className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 border-t border-tileLine pt-5">
        <div className="min-w-0">
          <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">
            Agent
          </p>
          <p className="mt-1 truncate text-sm font-medium text-foreground">{record.agent_name}</p>
          <p className="truncate text-xs text-muted-foreground">{record.organization_name}</p>
        </div>
        <div className="min-w-0">
          <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">
            Action
          </p>
          <Num className="mt-1 block truncate text-xs text-foreground">{record.action_type}</Num>
        </div>
        <div className="min-w-0">
          <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">
            Signature
          </p>
          <p
            className={cn(
              "mt-1 truncate text-sm font-medium",
              record.signature_valid ? "text-success" : "text-destructive",
            )}
          >
            {record.signature_valid ? "Valid Ed25519" : "Invalid"}
          </p>
          <p className="truncate text-xs text-muted-foreground">
            {record.tx_hash ? "Anchored on Base L2" : "Pending anchor"}
          </p>
        </div>
        <div className="min-w-0">
          <p className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">
            Receipt ID
          </p>
          <Num className="mt-1 block truncate text-xs text-muted-foreground">
            {record.audit_id}
          </Num>
        </div>
      </div>

      {formatReceiptTimestamp(record.timestamp) && (
        <p className="mt-4 text-[11px] text-muted-foreground">
          {formatReceiptTimestamp(record.timestamp)}
        </p>
      )}
    </Link>
  );
}

export function LiveProofSection({ records }: { records: PublicVerificationRecord[] }) {
  if (records.length === 0) return null;

  // Blocked receipts lead. Stable sort keeps the configured order within a
  // group, so two receipts of the same verdict do not swap between builds.
  const ordered = [...records].sort(
    (a, b) => Number(isPassVerdict(a.verdict)) - Number(isPassVerdict(b.verdict)),
  );

  return (
    <section
      id="live-proof"
      aria-labelledby="live-proof-heading"
      className="scroll-mt-24 border-b border-border bg-muted"
    >
      <div className="mx-auto max-w-7xl px-6 py-20 lg:px-8">
        <Reveal className="max-w-3xl">
          <Eyebrow>Signed platform records</Eyebrow>
          <h2
            id="live-proof-heading"
            className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl"
          >
            One allowed request. One blocked request.
          </h2>
          <p className="mt-4 text-base leading-7 text-muted-foreground">
            Both receipts are signed platform records for financial-transaction requests, produced
            by the same path a production request takes. Each shows the policy decision applied
            before the proposed action was allowed or blocked, and each can be verified
            independently.
          </p>
        </Reveal>

        <RevealGroup className="mt-8 grid gap-5 md:grid-cols-2">
          {ordered.map((record) => (
            <ReceiptCard key={record.audit_id} record={record} />
          ))}
        </RevealGroup>

        <Reveal className="mt-6">
          <Tile ground="tinted" interactive={false} className="p-6 md:p-8">
            <h3 className="text-lg font-semibold tracking-tight text-foreground">
              What the receipt proves
            </h3>
            <ul className="mt-4 grid gap-3 md:grid-cols-2">
              {receiptProofs.map((proof) => (
                <li
                  key={proof}
                  className="flex items-start gap-3 rounded-lg border border-tileLine bg-tile px-4 py-3"
                >
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden="true" />
                  <p className="text-sm leading-6 text-muted-foreground">{proof}</p>
                </li>
              ))}
            </ul>
            {/* The boundary the homepage used to cross. Inntris records the
                policy decision, not the execution outcome. */}
            <p className="mt-5 border-t border-tileLine pt-4 text-sm leading-7 text-muted-foreground">
              The receipt proves the recorded Inntris decision. Settlement confirmation remains the
              responsibility of the external payment rail.
            </p>
          </Tile>
        </Reveal>
      </div>
    </section>
  );
}
