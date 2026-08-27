import React from "react";
import Link from "next/link";
import { ChevronRight, CheckCircle2, XOctagon, AlertTriangle } from "lucide-react";
import { Eyebrow, Num, Tile, focusRing } from "@/components/landing/primitives";
import { Reveal, RevealGroup } from "@/components/landing/reveal";
import { cn } from "@/lib/utils";
import { publicApi, type PublicVerificationRecord } from "@/lib/api";
import { verdictLabel, isPassVerdict, isEscalateVerdict } from "@/lib/verdict";
import { CANONICAL_RECEIPT_IDS } from "@/lib/canonical-receipts";

/**
 * Live payment proof — one allowed request and one blocked request, rendered
 * from the live platform records rather than from copy.
 *
 * Three rules hold this section together:
 *
 *  1. Nothing about a card is hardcoded to a receipt ID. Which card leads,
 *     which badge it carries and which CTA it offers are all derived from the
 *     fetched verdict, so regenerating the receipts against a new policy
 *     version means editing `CANONICAL_RECEIPT_IDS` and nothing else. The blocked
 *     receipt leads because it is the more interesting artifact.
 *  2. The verdict tokens shown here — PASS / BLOCK / ESCALATE — are the
 *     platform receipt's own vocabulary. Decision envelopes use ALLOW / BLOCK /
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

export function formatReceiptTimestamp(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const diffMs = Date.now() - d.getTime();
  const sec = Math.round(diffMs / 1000);
  const min = Math.round(sec / 60);
  const hr = Math.round(min / 60);
  const day = Math.round(hr / 24);
  let relative: string;
  if (sec < 60) relative = "just now";
  else if (min < 60) relative = `${min} minute${min === 1 ? "" : "s"} ago`;
  else if (hr < 24) relative = `${hr} hour${hr === 1 ? "" : "s"} ago`;
  else relative = `${day} day${day === 1 ? "" : "s"} ago`;
  const pad = (n: number) => n.toString().padStart(2, "0");
  const absolute = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
  return `Generated ${relative} · ${absolute}`;
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

  // One verdict, one colour, applied to every part of the card that carries
  // the verdict — rail, header band, icon, label and hover edge. A reader
  // should be able to tell the two cards apart from across the room, before
  // reading a single word.
  const tone = pass
    ? {
        rail: "bg-success",
        band: "border-success-line bg-success-surface",
        ink: "text-success-ink",
        chip: "border-success-line bg-card",
        edge: "hover:border-success/60",
      }
    : escalate
      ? {
          rail: "bg-warning",
          band: "border-warning-line bg-warning-surface",
          ink: "text-warning-ink",
          chip: "border-warning-line bg-card",
          edge: "hover:border-warning/60",
        }
      : {
          rail: "bg-destructive",
          band: "border-destructive-line bg-destructive-surface",
          ink: "text-destructive-ink",
          chip: "border-destructive-line bg-card",
          edge: "hover:border-destructive/60",
        };

  return (
    <Link
      href={`/verify/${record.audit_id}`}
      className={cn(
        // The card stays white on hover and gains elevation instead of
        // swapping ground: `bg-tile` is the same value as the section's
        // `bg-muted`, so the old hover made the card sink into the page.
        "group block overflow-hidden rounded-xl border border-tileLine bg-card shadow-e2 transition duration-200",
        "hover:-translate-y-1 hover:shadow-e3",
        tone.edge,
        focusRing,
      )}
    >
      {/* Verdict rail. 4px of saturated colour along the top edge is the
          cheapest possible way to make two outcomes scannable at a glance. */}
      <div className={cn("h-1 w-full", tone.rail)} aria-hidden="true" />

      {/* Verdict band — a labelled tinted region, not coloured text adrift
          on the card ground. */}
      <div
        className={cn(
          "flex flex-col gap-4 border-b px-6 py-5 sm:flex-row sm:items-center sm:justify-between md:px-8",
          tone.band,
        )}
      >
        <div className="flex items-center gap-3">
          <div
            className={cn(
              "flex h-11 w-11 shrink-0 items-center justify-center rounded-full border",
              tone.chip,
            )}
          >
            <Icon className={cn("h-5 w-5", tone.ink)} aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <span
              className={cn(
                "text-xl font-bold uppercase tracking-tight",
                tone.ink,
              )}
            >
              {verdictLabel(record.verdict)}
            </span>
            <p className="text-xs leading-5 text-foreground/75">
              {record.verdict_reason ??
                (pass
                  ? "The proposed payment passed the configured policy checks."
                  : "The payment request was stopped by the configured policy.")}
            </p>
          </div>
        </div>
        <span className={cn("inline-flex shrink-0 items-center gap-2 text-sm font-semibold", tone.ink)}>
          {pass ? "Inspect approved receipt" : "Inspect blocked receipt"}
          <ChevronRight
            className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-1"
            aria-hidden="true"
          />
        </span>
      </div>

      <div className="p-6 md:p-8">
        <p className="text-sm leading-6 text-muted-foreground">
          {pass
            ? "The receipt records the agent, action, policy result and cryptographic proof."
            : "The payment request was blocked and the receipt records the verdict and policy reason."}
        </p>

        <div className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 border-t border-tileLine pt-5">
          <div className="min-w-0">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              Agent
            </p>
            <p className="mt-1 truncate text-sm font-medium text-foreground">{record.agent_name}</p>
            <p className="truncate text-xs text-muted-foreground">{record.organization_name}</p>
          </div>
          <div className="min-w-0">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              Action
            </p>
            <Num className="mt-1 block truncate text-xs text-foreground">{record.action_type}</Num>
          </div>
          <div className="min-w-0">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              Signature
            </p>
            <p
              className={cn(
                "mt-1 truncate text-sm font-medium",
                record.signature_valid ? "text-success-ink" : "text-destructive-ink",
              )}
            >
              {record.signature_valid ? "Valid Ed25519" : "Invalid"}
            </p>
            <p className="truncate text-xs text-muted-foreground">
              {record.tx_hash ? "Anchored on Base L2" : "Pending anchor"}
            </p>
          </div>
          <div className="min-w-0">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
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
      </div>
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
          <Eyebrow>Live verification receipts</Eyebrow>
          <h2
            id="live-proof-heading"
            className="mt-4 text-2xl font-semibold tracking-tight md:text-3xl"
          >
            One allowed request. One blocked request.
          </h2>
          <p className="mt-4 text-base leading-7 text-muted-foreground">
            Both receipts are live, signed platform records for financial-transaction requests. Each
            shows the policy decision applied before the proposed action was allowed or blocked.
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
