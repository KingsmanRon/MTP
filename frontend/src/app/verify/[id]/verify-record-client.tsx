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
  ChevronRight,
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
  type CheckStatus,
} from "@/lib/proof-state";

function actionBadgeColor(action: string) {
  const map: Record<string, string> = {
    financial_transaction: "border-[#f59e0b]/30 bg-[#f59e0b]/10 text-[#f59e0b]",
    email_send: "border-[#8b5cf6]/30 bg-[#8b5cf6]/10 text-[#8b5cf6]",
    data_export: "border-[#ec4899]/30 bg-[#ec4899]/10 text-[#ec4899]",
    admin_action: "border-[#ef4444]/30 bg-[#ef4444]/10 text-[#ef4444]",
    api_call: "border-[#4C8DFF]/30 bg-[#4C8DFF]/10 text-[#8FB8FF]",
  };
  return map[action] ?? "border-[#7F8CA3]/30 bg-[#7F8CA3]/10 text-[#AAB7CC]";
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
    case "verified": return "text-[#22c55e]";
    case "pending": return "text-[#f59e0b]";
    case "failed": return "text-[#ef4444]";
    case "not_applicable": return "text-[#7F8CA3]";
  }
}

function CheckIcon({ status }: { status: CheckStatus }) {
  switch (status) {
    case "verified":
      return <CheckCircle2 className="h-5 w-5 text-[#22c55e]" />;
    case "pending":
      return <Clock className="h-5 w-5 text-[#f59e0b]" />;
    case "failed":
      return <XOctagon className="h-5 w-5 text-[#ef4444]" />;
    case "not_applicable":
      return <ShieldCheck className="h-5 w-5 text-[#7F8CA3]" />;
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
      <code className="text-sm font-mono text-[#8FB8FF] break-all">
        {label ?? value}
      </code>
      <button
        onClick={handleCopy}
        className="flex-shrink-0 p-1 rounded hover:bg-white/5 transition-colors"
        title="Copy to clipboard"
      >
        {copied ? (
          <Check className="h-3.5 w-3.5 text-[#28C281]" />
        ) : (
          <Copy className="h-3.5 w-3.5 text-[#7F8CA3]" />
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
    <header className="sticky top-0 z-20 border-b border-white/8 bg-[#07111F]/85 backdrop-blur">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
        <Link href="/" className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#0D1728] shadow-[0_0_0_1px_rgba(255,255,255,0.02)]">
            <InntrisLogo className="h-6 w-6" />
          </div>
          <div>
            <div className="text-lg font-semibold tracking-tight text-[#F5F7FB]">Inntris</div>
            <div className="text-xs text-[#7F8CA3]">Verification receipt</div>
          </div>
        </Link>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={onCopy}
            className="border-[#22314D] bg-[#0D1728] text-[#F5F7FB] hover:bg-[#101C31] hover:text-white"
          >
            {copied ? (
              <Check className="h-4 w-4 mr-2 text-[#28C281]" />
            ) : (
              <Copy className="h-4 w-4 mr-2" />
            )}
            {copied ? "Copied!" : "Share"}
          </Button>
          <Link href="/verify">
            <Button
              variant="outline"
              size="sm"
              className="hidden border-[#22314D] bg-[#0D1728] text-[#F5F7FB] hover:bg-[#101C31] hover:text-white md:inline-flex"
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
    <div className="min-h-screen bg-[#07111F] text-[#F5F7FB]">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(76,141,255,0.14),transparent_32%)] pointer-events-none" />
      <Header onCopy={handleCopy} copied={copied} />
      <main className="relative mx-auto max-w-lg px-6 py-20 text-center">
        <div className="rounded-[28px] border border-[#22314D] bg-[#0D1728] p-10">
          <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-full bg-[#ef4444]/15">
            <XOctagon className="h-8 w-8 text-[#ef4444]" />
          </div>
          <h1 className="text-2xl font-bold mb-2">Record not found</h1>
          <p className="text-[#AAB7CC] mb-8">
            No verification record matches this ID or transaction hash. Check the value and try again.
          </p>
          <Link href="/verify">
            <Button className="bg-[#4C8DFF] text-white hover:bg-[#6AA2FF]">
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

  useEffect(() => {
    if (!isSupportedSchemaVersion(record.schema_version)) {
      setIntegrityStatus("failed");
      return;
    }

    computeReceiptFingerprint(record).then((computed) => {
      const frontendMatch = computed === record.receipt_fingerprint;
      if (!frontendMatch || record.integrity_status === "failed") {
        setIntegrityStatus("failed");
      } else {
        setIntegrityStatus("verified");
      }
    }).catch(() => {
      setIntegrityStatus("failed");
    });
  }, [record]);

  // Pure deterministic checks (see lib/proof-state.ts).
  const signatureCheck: CheckStatus = signatureCheckStatus(record.signature_valid);
  const policyHashCheck: CheckStatus = policyHashCheckStatus(record.policy_hash);
  const anchorCheck: CheckStatus = anchorCheckStatus(record.tx_hash, record.block_number);
  const anchorLabel: string =
    anchorCheck === "verified"
      ? "Confirmed on-chain"
      : record.tx_hash != null
      ? "Transaction submitted"
      : "Awaiting anchoring";

  // Schema version gate
  if (!isSupportedSchemaVersion(record.schema_version)) {
    return (
      <section className="mt-5 rounded-[28px] border border-[#f59e0b]/20 bg-[#f59e0b]/5 p-6 text-center">
        <AlertTriangle className="mx-auto h-8 w-8 text-[#f59e0b] mb-3" />
        <p className="text-sm text-[#f59e0b]">
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
      status: anchorCheck,
      sublabel: anchorLabel,
    },
    {
      label: "Receipt integrity",
      status: integrityStatus,
      sublabel: integrityStatus === "verified"
        ? "Fingerprint matches — receipt is intact"
        : integrityStatus === "failed"
        ? "Fingerprint mismatch — receipt may be tampered"
        : "Verifying integrity…",
    },
  ];

  return (
    <section className="mt-5 rounded-[28px] border border-[#22314D] bg-[#0D1728] p-6 md:p-8">
      <div className="flex items-center gap-3 mb-5">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <h3 className="text-lg font-semibold">Proof completeness</h3>
          <p className="text-xs text-[#7F8CA3]">
            Independent verification of receipt integrity
          </p>
        </div>
      </div>

      <div className="space-y-3">
        {checks.map((check) => (
          <div
            key={check.label}
            className="flex items-center gap-4 rounded-2xl border border-white/6 bg-[#101C31]/70 p-4"
          >
            <CheckIcon status={check.status} />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-[#F5F7FB]">{check.label}</p>
              <p className="text-xs text-[#7F8CA3]">{check.sublabel}</p>
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
  const baseScanDomain = "https://basescan.org";
  const baseScanUrl = record.tx_hash
    ? `${baseScanDomain}/tx/${record.tx_hash}`
    : null;

  return (
    <div className="min-h-screen bg-[#07111F] text-[#F5F7FB]">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(76,141,255,0.14),transparent_32%),radial-gradient(circle_at_80%_30%,rgba(143,184,255,0.08),transparent_24%)] pointer-events-none" />

      <Header onCopy={handleCopy} copied={copied} />

      <main className="relative mx-auto max-w-3xl px-6 py-12 lg:px-8">
        {/* ============================================================ */}
        {/* 1. VerdictHero                                               */}
        {/* ============================================================ */}
        <section
          className={`rounded-t-[28px] border border-b-0 p-8 text-center ${
            isPass
              ? "border-[#22c55e]/20 bg-gradient-to-b from-[#22c55e]/10 to-[#0D1728]"
              : isEscalate
              ? "border-[#f59e0b]/20 bg-gradient-to-b from-[#f59e0b]/10 to-[#0D1728]"
              : "border-[#ef4444]/20 bg-gradient-to-b from-[#ef4444]/10 to-[#0D1728]"
          }`}
        >
          {/* Icon */}
          <div className="flex items-center justify-center mb-5">
            {isPass ? (
              <div className="flex h-20 w-20 items-center justify-center rounded-full bg-[#22c55e]/15 ring-4 ring-[#22c55e]/10">
                <CheckCircle2 className="h-10 w-10 text-[#22c55e]" />
              </div>
            ) : isEscalate ? (
              <div className="flex h-20 w-20 items-center justify-center rounded-full bg-[#f59e0b]/15 ring-4 ring-[#f59e0b]/10">
                <AlertTriangle className="h-10 w-10 text-[#f59e0b]" />
              </div>
            ) : (
              <div className="flex h-20 w-20 items-center justify-center rounded-full bg-[#ef4444]/15 ring-4 ring-[#ef4444]/10">
                <XOctagon className="h-10 w-10 text-[#ef4444]" />
              </div>
            )}
          </div>

          {/* Verdict text */}
          <h1
            className={`text-4xl font-bold tracking-tight mb-2 ${
              isPass ? "text-[#22c55e]" : isEscalate ? "text-[#f59e0b]" : "text-[#ef4444]"
            }`}
          >
            {verdictLabel(record.verdict)}
          </h1>
          <p className="text-[#AAB7CC] mb-4">
            {record.verdict_reason ?? (isPass ? "All policy checks passed" : "Policy violation detected")}
          </p>

          {/* Badges */}
          <div className="flex flex-wrap items-center justify-center gap-2">
            <span
              className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium font-mono ${actionBadgeColor(
                record.action_type
              )}`}
            >
              {record.action_type}
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-[#101C31] px-3 py-1 text-xs text-[#AAB7CC]">
              <Clock className="h-3 w-3" />
              {formatDateTime(record.timestamp)}
            </span>
          </div>
        </section>

        {/* ============================================================ */}
        {/* 2. DetailsGrid — Agent card + Policy Decision card           */}
        {/* ============================================================ */}
        <section className="border border-t-0 border-[#22314D] bg-[#0D1728] p-6 md:p-8">
          <div className="grid gap-5 md:grid-cols-2">
            {/* Agent card */}
            <div className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-5">
              <div className="flex items-center gap-2 mb-4">
                <Fingerprint className="h-4 w-4 text-[#8FB8FF]" />
                <span className="text-sm font-semibold text-[#F5F7FB]">Agent</span>
              </div>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-[#7F8CA3]">Name</p>
                  <p className="text-sm font-medium">{record.agent_name}</p>
                </div>
                <div>
                  <p className="text-xs text-[#7F8CA3]">Organization</p>
                  <p className="text-sm font-medium">{record.organization_name}</p>
                </div>
                <div>
                  <p className="text-xs text-[#7F8CA3]">Agent ID</p>
                  <CopyableHash value={record.agent_id} />
                </div>
              </div>
            </div>

            {/* Policy Decision card */}
            <div className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-5">
              <div className="flex items-center gap-2 mb-4">
                <FileCheck2 className="h-4 w-4 text-[#8FB8FF]" />
                <span className="text-sm font-semibold text-[#F5F7FB]">Policy decision</span>
              </div>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-[#7F8CA3]">Verdict</p>
                  <span
                    className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-bold ${
                      isPass
                        ? "border-[#22c55e]/30 bg-[#22c55e]/10 text-[#22c55e]"
                        : isEscalate
                        ? "border-[#f59e0b]/30 bg-[#f59e0b]/10 text-[#f59e0b]"
                        : "border-[#ef4444]/30 bg-[#ef4444]/10 text-[#ef4444]"
                    }`}
                  >
                    {verdictLabel(record.verdict)}
                  </span>
                </div>
                <div>
                  <p className="text-xs text-[#7F8CA3]">Risk level</p>
                  <p className="text-sm font-medium">
                    {record.risk_level ? (
                      <span
                        className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium ${
                          record.risk_level === "critical"
                            ? "border-[#ef4444]/30 bg-[#ef4444]/10 text-[#ef4444]"
                            : record.risk_level === "high"
                            ? "border-[#f59e0b]/30 bg-[#f59e0b]/10 text-[#f59e0b]"
                            : "border-[#7F8CA3]/30 bg-[#7F8CA3]/10 text-[#AAB7CC]"
                        }`}
                      >
                        {record.risk_level}
                      </span>
                    ) : (
                      <span className="text-[#7F8CA3]">—</span>
                    )}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-[#7F8CA3]">Signature</p>
                  <span
                    className={`inline-flex items-center gap-1 text-sm font-medium ${
                      record.signature_valid ? "text-[#22c55e]" : "text-[#ef4444]"
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
                {record.violations.length > 0 && (
                  <div>
                    <p className="text-xs text-[#7F8CA3] mb-1.5">Violations</p>
                    <ul className="space-y-1">
                      {record.violations.map((v, i) => (
                        <li
                          key={i}
                          className="flex items-start gap-2 text-sm text-[#ef4444]"
                        >
                          <XOctagon className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
                          {v}
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
        <section className="rounded-b-[28px] border border-t-0 border-[#22314D] bg-[#0D1728] p-6 md:p-8">
          <div className="flex items-center gap-3 mb-5">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#22314D] bg-[#101C31] text-[#8FB8FF]">
              <Link2 className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-lg font-semibold">On-chain proof</h3>
              <p className="text-xs text-[#7F8CA3]">
                Anchored to Base L2 via Merkle tree
              </p>
            </div>
          </div>

          <div className="space-y-3">
            {/* tx_hash */}
            <div className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
              <p className="text-xs text-[#7F8CA3] mb-1">Transaction hash</p>
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
                        className="border-[#22314D] bg-[#0D1728] text-[#8FB8FF] hover:bg-[#101C31] hover:text-white"
                      >
                        <ExternalLink className="h-3.5 w-3.5 mr-1.5" />
                        BaseScan
                      </Button>
                    </a>
                  )}
                </div>
              ) : (
                <p className="text-sm font-mono text-[#7F8CA3]">Pending anchoring…</p>
              )}
            </div>

            {/* merkle_root */}
            <div className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
              <p className="text-xs text-[#7F8CA3] mb-1">Merkle root</p>
              <code className="text-sm font-mono text-[#8FB8FF] break-all">
                {record.merkle_root ?? "Pending…"}
              </code>
            </div>

            {/* action_hash */}
            <div className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
              <p className="text-xs text-[#7F8CA3] mb-1">Action hash (SHA-256)</p>
              <CopyableHash value={record.action_hash} />
            </div>

            {/* policy_hash */}
            <div className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
              <p className="text-xs text-[#7F8CA3] mb-1">Policy hash (SHA-256)</p>
              {record.policy_hash ? (
                <CopyableHash value={record.policy_hash} />
              ) : (
                <span className="text-sm font-mono text-[#7F8CA3]">Not applicable</span>
              )}
            </div>

            {/* Grid: block, chain, anchored */}
            <div className="grid grid-cols-3 gap-3">
              <div className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
                <p className="text-xs text-[#7F8CA3] mb-1">Block</p>
                <p className="text-sm font-mono text-[#F5F7FB]">
                  {record.block_number?.toLocaleString() ?? "—"}
                </p>
              </div>
              <div className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
                <p className="text-xs text-[#7F8CA3] mb-1">Chain</p>
                <p className="text-sm font-mono text-[#F5F7FB]">
                  {record.chain_id === 84532 ? "Base Sepolia (Testnet)" : "Base Mainnet"} ({record.chain_id})
                </p>
              </div>
              <div className="rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
                <p className="text-xs text-[#7F8CA3] mb-1">Anchored</p>
                <p className="text-sm font-mono text-[#F5F7FB]">
                  {record.anchored_at ? formatDateTime(record.anchored_at) : "Pending"}
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* ============================================================ */}
        {/* 3b. Trust score (advisory)                                   */}
        {/* ============================================================ */}
        <section className="mt-3 rounded-2xl border border-white/6 bg-[#101C31]/70 p-4">
          <p className="text-xs text-[#7F8CA3] mb-1">Trust score (advisory)</p>
          <p
            className={`text-sm font-medium ${
              record.trust_score >= 70
                ? "text-[#22c55e]"
                : record.trust_score >= 40
                ? "text-[#f59e0b]"
                : "text-[#ef4444]"
            }`}
          >
            {record.trust_score}
            <span className="text-xs text-[#7F8CA3]">/100</span>
          </p>
        </section>

        {/* ============================================================ */}
        {/* 4. ProofCompletenessChecks                                   */}
        {/* ============================================================ */}
        <ProofCompletenessChecks record={record} />

        {/* ============================================================ */}
        {/* 5. ConversionCTA                                             */}
        {/* ============================================================ */}
        <section className="mt-8 rounded-[28px] border border-[#4C8DFF]/20 bg-gradient-to-b from-[#4C8DFF]/8 to-[#0D1728] p-8 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">
            Want this for your AI agent PRs?
          </h2>
          <p className="mx-auto mt-3 max-w-md text-base leading-7 text-[#AAB7CC]">
            Add{" "}
            <code className="font-mono text-[#8FB8FF]">inntris-verify</code>{" "}
            as a required status check. Every agent PR gets a cryptographic
            receipt anchored on Base L2.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <a
              href="https://github.com/Inntris/agent-orchestrator-guardrails"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Button className="bg-[#4C8DFF] px-6 text-white hover:bg-[#6AA2FF]">
                Install GitHub Action
                <ChevronRight className="ml-1 h-4 w-4" />
              </Button>
            </a>
            <Link href="/">
              <Button
                variant="outline"
                className="border-[#22314D] bg-[#0D1728] text-[#F5F7FB] hover:bg-[#101C31] hover:text-white"
              >
                Learn more
              </Button>
            </Link>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/8 mt-12">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-8 lg:px-8">
          <div className="flex items-center gap-2">
            <InntrisLogo className="h-5 w-5" />
            <span className="text-[#7F8CA3]">Inntris Core</span>
          </div>
          <p className="text-sm text-[#7F8CA3]">
            Cryptographic verification for AI agents
          </p>
        </div>
      </footer>
    </div>
  );
}
