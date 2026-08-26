"use client";

import Link from "next/link";
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { formatDateTime, copyToClipboard } from "@/lib/utils";
import type { PublicVerificationRecord } from "@/lib/api";
import {
  CheckCircle2,
  XOctagon,
  Copy,
  Check,
  ExternalLink,
  Clock,
  AlertTriangle,
  Fingerprint,
  FileCheck2,
  Link2,
  ShieldCheck,
} from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";
import { verdictLabel, isPassVerdict, isEscalateVerdict } from "@/lib/verdict";
import {
  signatureCheckStatus,
  policyHashCheckStatus,
  anchorCheckStatus,
  isSupportedSchemaVersion,
  checkStatusUiLabel,
  computeReceiptFingerprint,
  deriveIntegrityStatus,
  type CheckStatus,
} from "@/lib/proof-state";

const blockNumberFormatter = new Intl.NumberFormat("en-GB");

function actionBadgeColor(action: string) {
  const map: Record<string, string> = {
    financial_transaction: "border-warning/30 bg-warning/10 text-warning",
    email_send: "border-primary/30 bg-primary/10 text-primary",
    data_export: "border-primary/30 bg-primary/10 text-primary",
    admin_action: "border-destructive/30 bg-destructive/10 text-destructive",
    api_call: "border-primary/30 bg-primary/10 text-brandInk",
  };
  return map[action] ?? "border-[hsl(var(--muted-foreground))]/30 bg-[hsl(var(--muted-foreground))]/10 text-muted-foreground";
}

function truncateHash(hash: string, chars = 10) {
  if (hash.length <= chars * 2 + 3) return hash;
  return `${hash.slice(0, chars)}...${hash.slice(-chars)}`;
}

/* ------------------------------------------------------------------ */
/*  Proof check types                                                  */
/* ------------------------------------------------------------------ */

function checkStatusColor(s: CheckStatus) {
  switch (s) {
    case "verified": return "text-success";
    case "pending": return "text-warning";
    case "failed": return "text-destructive";
    case "not_applicable": return "text-muted-foreground";
  }
}

function CheckIcon({ status }: { status: CheckStatus }) {
  switch (status) {
    case "verified":
      return <CheckCircle2 className="h-5 w-5 text-success" />;
    case "pending":
      return <Clock className="h-5 w-5 text-warning" />;
    case "failed":
      return <XOctagon className="h-5 w-5 text-destructive" />;
    case "not_applicable":
      return <ShieldCheck className="h-5 w-5 text-muted-foreground" />;
  }
}

/* ------------------------------------------------------------------ */
/*  CopyableHash                                                       */
/* ------------------------------------------------------------------ */

function CopyableHash({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await copyToClipboard(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="flex items-center gap-2">
      <code className="text-sm font-mono text-brandInk break-all">
        {label ?? value}
      </code>
      <button
        onClick={handleCopy}
        className="flex-shrink-0 rounded p-1 transition-[transform,background-color] duration-100 ease-out hover:bg-tile active:scale-[0.88] active:bg-tile motion-reduce:transition-none motion-reduce:active:scale-100"
        title="Copy to clipboard"
      >
        {copied ? (
          <Check className="h-3.5 w-3.5 text-primary" />
        ) : (
          <Copy className="h-3.5 w-3.5 text-muted-foreground" />
        )}
      </button>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Header                                                            */
/* ------------------------------------------------------------------ */

function Header({ onCopy, copied }: { onCopy: () => void; copied: boolean }) {
  return (
    <header className="sticky top-0 z-20 border-b border-tileLine/60 bg-background/75 backdrop-blur-xl backdrop-saturate-150 supports-[backdrop-filter]:bg-background/70">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
        <Link href="/" className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-tileLine bg-tile">
            <InntrisLogo className="h-6 w-6" />
          </div>
          <div>
            <div className="text-lg font-semibold tracking-tight text-foreground">Inntris</div>
            <div className="text-xs text-muted-foreground">Verification receipt</div>
          </div>
        </Link>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={onCopy}
            className="border-tileLine bg-tile text-foreground hover:bg-card hover:text-foreground"
          >
            {copied ? (
              <Check className="h-4 w-4 mr-2 text-primary" />
            ) : (
              <Copy className="h-4 w-4 mr-2" />
            )}
            {copied ? "Copied!" : "Share"}
          </Button>
          <Link href="/verify">
            <Button
              variant="outline"
              size="sm"
              className="hidden border-tileLine bg-tile text-foreground hover:bg-card hover:text-foreground md:inline-flex"
            >
              Verify another
            </Button>
          </Link>
        </div>
      </div>
    </header>
  );
}

/* ------------------------------------------------------------------ */
/*  Not Found view                                                    */
/* ------------------------------------------------------------------ */

export function VerifyRecordNotFound() {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await copyToClipboard(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="absolute inset-0 bg-gradient-to-b from-accent/50 via-transparent to-transparent pointer-events-none" />
      <Header onCopy={handleCopy} copied={copied} />
      <main className="relative mx-auto max-w-lg px-6 py-20 text-center">
        <div className="rounded-[28px] border border-tileLine bg-tile p-10">
          <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-full bg-destructive/15">
            <XOctagon className="h-8 w-8 text-destructive" />
          </div>
          <h1 className="text-2xl font-bold mb-2">Record not found</h1>
          <p className="text-muted-foreground mb-8">
            No verification record matches this ID or transaction hash. Check the value and try again.
          </p>
          <Link href="/verify">
            <Button className="bg-primary text-white hover:bg-brandInk">
              Back to verifier
            </Button>
          </Link>
        </div>
      </main>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Proof completeness checks                                          */
/* ------------------------------------------------------------------ */

function ProofCompletenessChecks({ record }: { record: PublicVerificationRecord }) {
  const [integrityStatus, setIntegrityStatus] = useState<CheckStatus>("pending");
  const [fingerprintMatches, setFingerprintMatches] = useState<boolean | null>(null);

  useEffect(() => {
    if (!isSupportedSchemaVersion(record.schema_version)) {
      setFingerprintMatches(false);
      setIntegrityStatus("failed");
      return;
    }

    computeReceiptFingerprint(record).then((computed) => {
      const frontendMatch = computed === record.receipt_fingerprint;
      const nextSignatureCheck = signatureCheckStatus(record.signature_valid);
      const nextPolicyHashCheck = policyHashCheckStatus(record.policy_hash);
      const nextAnchorCheck = anchorCheckStatus(
        record.tx_hash,
        record.block_number,
        record.integrity_status,
      );
      setFingerprintMatches(frontendMatch);
      setIntegrityStatus(
        deriveIntegrityStatus(
          nextSignatureCheck,
          nextPolicyHashCheck,
          nextAnchorCheck,
          frontendMatch,
          record.integrity_status,
        ),
      );
    }).catch(() => {
      setFingerprintMatches(false);
      setIntegrityStatus("failed");
    });
  }, [record]);

  // Pure deterministic checks (see lib/proof-state.ts).
  const signatureCheck: CheckStatus = signatureCheckStatus(record.signature_valid);
  const policyHashCheck: CheckStatus = policyHashCheckStatus(record.policy_hash);
  const anchorCheck: CheckStatus = anchorCheckStatus(
    record.tx_hash,
    record.block_number,
    record.integrity_status,
  );
  const anchorLabel: string =
    record.integrity_status === "sandbox"
      ? "Sandbox — not anchored on-chain"
      : anchorCheck === "failed"
      ? "Anchor proof failed"
      : anchorCheck === "verified"
      ? "Confirmed on-chain"
      : record.tx_hash != null
      ? "Transaction submitted"
      : "Awaiting anchoring";
  const integrityLabel: string =
    fingerprintMatches === false
      ? "Fingerprint mismatch; receipt may be tampered"
      : record.integrity_status === "sandbox"
      ? "Sandbox receipt; signed & verifiable, not anchored"
      : record.integrity_status === "failed"
      ? "Anchor proof failed; receipt fingerprint still matches"
      : integrityStatus === "verified"
      ? "Fingerprint matches; receipt is intact"
      : integrityStatus === "pending"
      ? "Fingerprint matches; awaiting anchoring"
      : "Verifying integrity...";

  // Schema version gate
  if (!isSupportedSchemaVersion(record.schema_version)) {
    return (
      <section className="mt-5 rounded-[28px] border border-warning/20 bg-warning/5 p-6 text-center">
        <AlertTriangle className="mx-auto h-8 w-8 text-warning mb-3" />
        <p className="text-sm text-warning">
          Unsupported schema version: {record.schema_version ?? "unknown"}
        </p>
      </section>
    );
  }

  const checks: { label: string; status: CheckStatus; sublabel: string }[] = [
    {
      label: "Ed25519 signature",
      status: signatureCheck,
      sublabel: signatureCheck === "verified" ? "Cryptographic signature valid" : "Signature verification failed",
    },
    {
      label: "Policy hash",
      status: policyHashCheck,
      sublabel:
        policyHashCheck === "verified"
          ? "Policy file hash bound to record"
          : policyHashCheck === "not_applicable"
          ? "Receipt does not bind a policy"
          : "Policy hash present but did not validate",
    },
    {
      label: "On-chain anchor",
      status: record.integrity_status === "sandbox" ? "not_applicable" : anchorCheck,
      sublabel: anchorLabel,
    },
    {
      label: "Receipt integrity",
      status: record.integrity_status === "sandbox" ? "not_applicable" : integrityStatus,
      sublabel: integrityLabel,
    },
  ];

  return (
    <section className="mt-5 rounded-[28px] border border-tileLine bg-tile p-6 md:p-8">
      <div className="flex items-center gap-3 mb-5">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-tileLine bg-card text-brandInk">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <h3 className="text-lg font-semibold">Proof completeness</h3>
          <p className="text-xs text-muted-foreground">
            Independent verification of receipt integrity
          </p>
        </div>
      </div>

      {record.integrity_status === "sandbox" && (
        <div className="mb-5 rounded-2xl border border-warning/30 bg-warning/10 px-4 py-3 text-sm text-warning">
          Sandbox receipt — this decision is cryptographically signed and
          independently verifiable, but is not anchored on-chain.
        </div>
      )}

      <div className="space-y-3">
        {checks.map((check) => (
          <div
            key={check.label}
            className="flex items-center gap-4 rounded-2xl border border-tileLine bg-card/70 p-4"
          >
            <CheckIcon status={check.status} />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-foreground">{check.label}</p>
              <p className="text-xs text-muted-foreground">{check.sublabel}</p>
            </div>
            <span className={`text-xs font-bold ${checkStatusColor(check.status)}`}>
              {checkStatusUiLabel(check.status)}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

const VERIFY_ACTION_REPO = "https://github.com/Inntris/inntris-verify";

/* ------------------------------------------------------------------ */
/*  Main record view                                                  */
/* ------------------------------------------------------------------ */

export function VerifyRecordView({ record }: { record: PublicVerificationRecord }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await copyToClipboard(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isPass = isPassVerdict(record.verdict);
  const isEscalate = isEscalateVerdict(record.verdict);

  // The headline already states the reason. Repeating it verbatim under
  // "Violations" reads as a rendering fault rather than as emphasis, so the
  // list carries only what the headline has not already said.
  const additionalViolations = record.violations.filter(
    (v) => v.trim() !== (record.verdict_reason ?? "").trim()
  );
  const baseScanDomain = "https://basescan.org";
  const baseScanUrl = record.tx_hash
    ? `${baseScanDomain}/tx/${record.tx_hash}`
    : null;

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="absolute inset-0 bg-gradient-to-b from-accent/50 via-transparent to-transparent pointer-events-none" />

      <Header onCopy={handleCopy} copied={copied} />

      <main className="relative mx-auto max-w-3xl px-6 py-12 lg:px-8">
        {/* ============================================================ */}
        {/* 1. VerdictHero                                               */}
        {/* ============================================================ */}
        <section
          className={`rounded-t-[28px] border border-b-0 p-8 text-center ${
            isPass
              ? "border-success/20 bg-gradient-to-b from-success/10 to-tile"
              : isEscalate
              ? "border-warning/20 bg-gradient-to-b from-warning/10 to-tile"
              : "border-destructive/20 bg-gradient-to-b from-destructive/10 to-tile"
          }`}
        >
          {/* Icon */}
          <div className="flex items-center justify-center mb-5">
            {isPass ? (
              <div className="flex h-20 w-20 items-center justify-center rounded-full bg-success/15 ring-4 ring-success/10">
                <CheckCircle2 className="h-10 w-10 text-success" />
              </div>
            ) : isEscalate ? (
              <div className="flex h-20 w-20 items-center justify-center rounded-full bg-warning/15 ring-4 ring-warning/10">
                <AlertTriangle className="h-10 w-10 text-warning" />
              </div>
            ) : (
              <div className="flex h-20 w-20 items-center justify-center rounded-full bg-destructive/15 ring-4 ring-destructive/10">
                <XOctagon className="h-10 w-10 text-destructive" />
              </div>
            )}
          </div>

          {/* Verdict text */}
          <h1
            className={`text-4xl font-bold tracking-[-0.03em] leading-[1.05] mb-2 ${
              isPass ? "text-success" : isEscalate ? "text-warning" : "text-destructive"
            }`}
          >
            {verdictLabel(record.verdict)}
          </h1>
          <p className="mx-auto mb-4 max-w-[52ch] break-words leading-relaxed text-muted-foreground">
            {record.verdict_reason ?? (isPass ? "All policy checks passed" : "Policy violation detected")}
          </p>

          {/* Badges */}
          <div className="flex flex-wrap items-center justify-center gap-2">
            <span
              className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium font-mono tracking-[0.02em] ${actionBadgeColor(
                record.action_type
              )}`}
            >
              {record.action_type}
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-tileLine bg-card px-3 py-1 text-xs text-muted-foreground">
              <Clock className="h-3 w-3" />
              {formatDateTime(record.timestamp)}
            </span>
          </div>
        </section>

        {/* ============================================================ */}
        {/* 2. DetailsGrid — Agent card + Policy Decision card           */}
        {/* ============================================================ */}
        <section className="border border-t-0 border-tileLine bg-tile p-6 md:p-8">
          <div className="grid gap-5 md:grid-cols-2">
            {/* Agent card */}
            <div className="rounded-2xl border border-tileLine bg-card/70 p-5">
              <div className="flex items-center gap-2 mb-4">
                <Fingerprint className="h-4 w-4 text-brandInk" />
                <span className="text-sm font-semibold text-foreground">Agent</span>
              </div>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-muted-foreground">Name</p>
                  <p className="text-sm font-medium">{record.agent_name}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Organization</p>
                  <p className="text-sm font-medium">{record.organization_name}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Agent ID</p>
                  <CopyableHash value={record.agent_id} />
                </div>
              </div>
            </div>

            {/* Policy Decision card */}
            <div className="rounded-2xl border border-tileLine bg-card/70 p-5">
              <div className="flex items-center gap-2 mb-4">
                <FileCheck2 className="h-4 w-4 text-brandInk" />
                <span className="text-sm font-semibold text-foreground">Policy decision</span>
              </div>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-muted-foreground">Verdict</p>
                  <span
                    className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-bold ${
                      isPass
                        ? "border-success/30 bg-success/10 text-success"
                        : isEscalate
                        ? "border-warning/30 bg-warning/10 text-warning"
                        : "border-destructive/30 bg-destructive/10 text-destructive"
                    }`}
                  >
                    {verdictLabel(record.verdict)}
                  </span>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Risk level</p>
                  <p className="text-sm font-medium">
                    {record.risk_level ? (
                      <span
                        className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium ${
                          record.risk_level === "critical"
                            ? "border-destructive/30 bg-destructive/10 text-destructive"
                            : record.risk_level === "high"
                            ? "border-warning/30 bg-warning/10 text-warning"
                            : "border-[hsl(var(--muted-foreground))]/30 bg-[hsl(var(--muted-foreground))]/10 text-muted-foreground"
                        }`}
                      >
                        {record.risk_level}
                      </span>
                    ) : (
                      <span className="text-sm font-normal text-muted-foreground">
                        Not assessed
                      </span>
                    )}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Signature</p>
                  <span
                    className={`inline-flex items-center gap-1 text-sm font-medium ${
                      record.signature_valid ? "text-success" : "text-destructive"
                    }`}
                  >
                    {record.signature_valid ? (
                      <>
                        <CheckCircle2 className="h-3.5 w-3.5" /> Valid Ed25519
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="h-3.5 w-3.5" /> Invalid
                      </>
                    )}
                  </span>
                </div>
                {additionalViolations.length > 0 && (
                  <div>
                    <p className="text-xs tracking-[0.01em] text-muted-foreground mb-1.5">
                      {record.verdict_reason ? "Further violations" : "Violations"}
                    </p>
                    <ul className="space-y-1">
                      {additionalViolations.map((v, i) => (
                        <li
                          key={i}
                          className="flex items-start gap-2 text-sm leading-relaxed text-destructive"
                        >
                          <XOctagon className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
                          <span className="break-words">{v}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        {/* ============================================================ */}
        {/* 3. OnChainProof                                              */}
        {/* ============================================================ */}
        <section className="rounded-b-[28px] border border-t-0 border-tileLine bg-tile p-6 md:p-8">
          <div className="flex items-center gap-3 mb-5">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-tileLine bg-card text-brandInk">
              <Link2 className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-lg font-semibold">On-chain proof</h3>
              <p className="text-xs text-muted-foreground">
                {record.tx_hash
                  ? "Anchored to Base L2 via Merkle tree"
                  : "Awaiting the next Base L2 anchor batch"}
              </p>
            </div>
          </div>

          <div className="space-y-3">
            {/* tx_hash */}
            <div className="rounded-2xl border border-tileLine bg-card/70 p-4">
              <p className="text-xs text-muted-foreground mb-1">Transaction hash</p>
              {record.tx_hash ? (
                <div className="flex items-center justify-between gap-3">
                  <CopyableHash value={record.tx_hash} />
                  {baseScanUrl && (
                    <a
                      href={baseScanUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex-shrink-0"
                    >
                      <Button
                        size="sm"
                        variant="outline"
                        className="border-tileLine bg-tile text-brandInk hover:bg-card hover:text-foreground"
                      >
                        <ExternalLink className="h-3.5 w-3.5 mr-1.5" />
                        BaseScan
                      </Button>
                    </a>
                  )}
                </div>
              ) : (
                <p className="text-sm font-mono text-muted-foreground">Pending anchoring…</p>
              )}
            </div>

            {/* merkle_root */}
            <div className="rounded-2xl border border-tileLine bg-card/70 p-4">
              <p className="text-xs text-muted-foreground mb-1">Merkle root</p>
              <code className="text-sm font-mono text-brandInk break-all">
                {record.merkle_root ?? "Pending…"}
              </code>
              {record.merkle_root && record.merkle_root === record.action_hash && (
                <p className="mt-2 text-xs text-muted-foreground">
                  This batch contains a single action, so the Merkle root is that
                  action&rsquo;s hash. Larger batches produce a distinct root.
                </p>
              )}
            </div>

            {/* action_hash */}
            <div className="rounded-2xl border border-tileLine bg-card/70 p-4">
              <p className="text-xs text-muted-foreground mb-1">Action hash (SHA-256)</p>
              <CopyableHash value={record.action_hash} />
            </div>

            {/* policy_hash */}
            <div className="rounded-2xl border border-tileLine bg-card/70 p-4">
              <p className="text-xs text-muted-foreground mb-1">Policy hash (SHA-256)</p>
              {record.policy_hash ? (
                <CopyableHash value={record.policy_hash} />
              ) : (
                <span className="text-sm font-mono text-muted-foreground">Not applicable</span>
              )}
            </div>

            {/* Grid: block, chain, anchored */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div className="rounded-2xl border border-tileLine bg-card/70 p-4">
                <p className="text-xs text-muted-foreground mb-1">Block</p>
                <p className="text-sm font-mono text-foreground">
                  {record.block_number == null
                    ? "Pending"
                    : blockNumberFormatter.format(record.block_number)}
                </p>
              </div>
              <div className="rounded-2xl border border-tileLine bg-card/70 p-4">
                <p className="text-xs text-muted-foreground mb-1">Chain</p>
                <p className="text-sm font-mono text-foreground">
                  Base Mainnet ({record.chain_id})
                </p>
              </div>
              <div className="rounded-2xl border border-tileLine bg-card/70 p-4">
                <p className="text-xs text-muted-foreground mb-1">Anchored</p>
                <p className="text-sm font-mono text-foreground">
                  {record.anchored_at ? formatDateTime(record.anchored_at) : "Pending"}
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Trust score is deliberately absent from this public page. The
            scoring methodology is unpublished, and an unpublished score sitting
            beside a cryptographic signature weakens the claim it sits next to —
            a reader cannot check it, so it reads as the soft part of an
            otherwise checkable artifact. It stays inside the Console, where the
            operator who configured the policy has the context to read it. */}

        {/* ============================================================ */}
        {/* 4. ProofCompletenessChecks                                   */}
        {/* ============================================================ */}
        <ProofCompletenessChecks record={record} />

        {/* ============================================================ */}
        {/* 5. ConversionCTA                                             */}
        {/* ============================================================ */}
        <section className="mt-8 rounded-[28px] border border-primary/20 bg-gradient-to-b from-primary/8 to-tile p-8 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">
            Want PR protection for AI agent changes?
          </h2>
          <p className="mx-auto mt-3 max-w-md text-base leading-7 text-muted-foreground">
            View the GitHub Actions example for PR protection. It shows how{" "}
            <a
              href={VERIFY_ACTION_REPO}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-baseline gap-1 font-mono text-brandInk underline decoration-brandInk/40 decoration-1 underline-offset-2 transition-colors duration-100 ease-out hover:decoration-brandInk focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brandInk"
            >
              inntris-verify
              <ExternalLink className="h-3 w-3 shrink-0 self-center" aria-hidden="true" />
              <span className="sr-only"> (opens GitHub in a new tab)</span>
            </a>{" "}
            runs as a required status check and records a PASS or BLOCK receipt.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Link href="/ai-pr-protection">
              <Button
                variant="outline"
                className="border-tileLine bg-tile text-foreground hover:bg-card hover:text-foreground"
              >
                Learn more
              </Button>
            </Link>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-tileLine mt-12">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-8 lg:px-8">
          <div className="flex items-center gap-2">
            <InntrisLogo className="h-5 w-5" />
            <span className="text-muted-foreground">Inntris Core</span>
          </div>
          <p className="text-sm text-muted-foreground">
            Cryptographic verification for AI agents
          </p>
        </div>
      </footer>
    </div>
  );
}
