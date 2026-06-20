"use client";

import { useParams } from "next/navigation";
import { AdminShell } from "@/components/admin/admin-shell";
import { useAdminFetch } from "@/lib/admin/use-admin-fetch";
import { mapAuditDetail, mapAuditProof } from "@/lib/admin/mappers";
import type { MappedAuditDetail, MappedAuditProof } from "@/lib/admin/types";
import { AdminErrorState } from "@/components/admin/error-state";
import { AdminEmptyState } from "@/components/admin/empty-state";
import { AdminVerdictBadge } from "@/components/admin/verdict-badge";
import { PrGuardEvidence, isPrGuardRecord } from "@/components/admin/pr-guard-evidence";
import { CopyableMonoValue } from "@/components/admin/copyable-mono-value";
import { VerifyLinkCopy } from "@/components/admin/verify-link-copy";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  ArrowLeft,
  FileText,
  Shield,
  Link2,
  CheckCircle,
  AlertTriangle,
  Minus,
  ExternalLink,
} from "lucide-react";
import Link from "next/link";
import { formatDateTime } from "@/lib/utils";

function AuditDetailContent({ logId }: { logId: string }) {
  const {
    data: record,
    loading: recordLoading,
    error: recordError,
    refetch: refetchRecord,
  } = useAdminFetch<MappedAuditDetail | null>(
    `/api/admin/audit/${logId}`,
    { transform: (raw) => mapAuditDetail(raw) }
  );

  const {
    data: proof,
    loading: proofLoading,
    error: proofError,
  } = useAdminFetch<MappedAuditProof>(
    `/api/admin/audit/${logId}/proof`,
    { transform: (raw) => mapAuditProof(raw) }
  );

  // A 501 from the proof endpoint is expected during rollout
  const proofPending = proofError?.includes("501") || proofError?.includes("Not Implemented");

  if (recordError) {
    return (
      <div className="space-y-6">
        <BackLink />
        <AdminErrorState
          message="Failed to load audit record"
          detail={recordError}
          onRetry={refetchRecord}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <BackLink />

      {recordLoading ? (
        <div className="space-y-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-40 animate-pulse rounded-xl bg-[#0D1728]" />
          ))}
        </div>
      ) : record ? (
        <>
          {/* SECTION 1 — Record */}
          <Card className="border-[#22314D] bg-[#0D1728]">
            <CardHeader>
              <CardTitle className="text-base text-[#F5F7FB]">Record</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <DetailField label="Audit ID">
                  <CopyableMonoValue value={record.id} full />
                </DetailField>
                {record.agent_id && (
                  <DetailField label="Agent ID">
                    <CopyableMonoValue value={record.agent_id} />
                  </DetailField>
                )}
                <DetailField label="Timestamp">
                  <span className="font-mono text-xs text-[#AAB7CC]">
                    {record.timestamp ? formatDateTime(record.timestamp) : "—"}
                  </span>
                </DetailField>
                <DetailField label="Verdict">
                  {record.verdict ? (
                    <AdminVerdictBadge verdict={record.verdict} />
                  ) : (
                    <span className="text-xs text-[#7F8CA3]">—</span>
                  )}
                </DetailField>
              </div>
            </CardContent>
          </Card>

          {/* SECTION 1b — AI PR Guard evidence (only for guard records) */}
          {isPrGuardRecord(record) && (
            <Card className="border-[#22314D] bg-[#0D1728]">
              <CardHeader>
                <CardTitle className="text-base text-[#F5F7FB]">AI PR Guard</CardTitle>
              </CardHeader>
              <CardContent>
                <PrGuardEvidence record={record} />
              </CardContent>
            </Card>
          )}

          {/* SECTION 2 — Action payload */}
          <Card className="border-[#22314D] bg-[#0D1728]">
            <CardHeader>
              <CardTitle className="text-base text-[#F5F7FB]">
                Action Payload
              </CardTitle>
            </CardHeader>
            <CardContent>
              {record.payload ? (
                <pre className="overflow-x-auto rounded-lg bg-[#101C31] p-4 font-mono text-xs leading-relaxed text-[#AAB7CC]">
                  {JSON.stringify(record.payload, null, 2)}
                </pre>
              ) : (
                <AdminEmptyState
                  icon={FileText}
                  message="No payload recorded"
                />
              )}
            </CardContent>
          </Card>

          {/* SECTION 3 — Policy evaluation */}
          <Card className="border-[#22314D] bg-[#0D1728]">
            <CardHeader>
              <CardTitle className="text-base text-[#F5F7FB]">
                Policy Evaluation
              </CardTitle>
            </CardHeader>
            <CardContent>
              <PolicySection record={record} />
            </CardContent>
          </Card>

          {/* SECTION 4 — Cryptographic proof */}
          <Card className="border-[#22314D] bg-[#0D1728]">
            <CardHeader>
              <CardTitle className="text-base text-[#F5F7FB]">
                Cryptographic Proof
              </CardTitle>
            </CardHeader>
            <CardContent>
              {proofLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <div key={i} className="h-8 animate-pulse rounded-lg bg-[#101C31]" />
                  ))}
                </div>
              ) : proofPending || proofError ? (
                <div className="flex items-center gap-3 rounded-lg border border-[#22314D] bg-[#101C31] p-4">
                  <Link2 className="h-5 w-5 text-[#7F8CA3]" />
                  <p className="text-sm text-[#7F8CA3]">
                    Proof anchoring in progress or not yet available
                  </p>
                </div>
              ) : proof ? (
                <ProofSection proof={proof} />
              ) : (
                <div className="flex items-center gap-3 rounded-lg border border-[#22314D] bg-[#101C31] p-4">
                  <Link2 className="h-5 w-5 text-[#7F8CA3]" />
                  <p className="text-sm text-[#7F8CA3]">
                    Proof anchoring in progress or not yet available
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Footer — verify link */}
          <div className="flex items-center justify-between rounded-xl border border-[#22314D] bg-[#0D1728] p-4">
            <span className="text-sm text-[#7F8CA3]">Public verification receipt</span>
            <VerifyLinkCopy auditId={record.id} />
          </div>
        </>
      ) : (
        <AdminEmptyState icon={FileText} message="Audit record not found" />
      )}
    </div>
  );
}

function PolicySection({ record }: { record: MappedAuditDetail }) {
  const hasPolicyData =
    record.policy_rule_triggered !== undefined ||
    record.risk_level !== undefined ||
    (record.violations && record.violations.length > 0);

  if (hasPolicyData) {
    return (
      <div className="space-y-3">
        {record.policy_rule_triggered && (
          <div className="flex items-center justify-between rounded-lg border border-[#22314D] bg-[#101C31] px-4 py-3">
            <span className="text-xs text-[#7F8CA3]">Rule Triggered</span>
            <span className="font-mono text-xs text-[#AAB7CC]">
              {record.policy_rule_triggered}
            </span>
          </div>
        )}
        {record.risk_level && (
          <div className="flex items-center justify-between rounded-lg border border-[#22314D] bg-[#101C31] px-4 py-3">
            <span className="text-xs text-[#7F8CA3]">Risk Level</span>
            <span className="font-mono text-xs text-[#AAB7CC]">
              {record.risk_level}
            </span>
          </div>
        )}
        {record.violations && record.violations.length > 0 && (
          <div className="rounded-lg border border-[#22314D] bg-[#101C31] px-4 py-3">
            <span className="mb-2 block text-xs text-[#7F8CA3]">Violations</span>
            <div className="flex flex-wrap gap-2">
              {record.violations.map((v, i) => (
                <span
                  key={i}
                  className="rounded-md border border-red-500/20 bg-red-500/5 px-2 py-1 font-mono text-xs text-red-400"
                >
                  {v}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  // No policy data
  if (record.verdict === "blocked" || record.verdict === "rate_limited") {
    return (
      <AdminErrorState
        message="Policy evaluation data unavailable"
        detail="The agent action was blocked but the rule that triggered the verdict could not be retrieved."
      />
    );
  }

  if (record.verdict === "approved") {
    return (
      <AdminEmptyState icon={Shield} message="No policy violations recorded" />
    );
  }

  return (
    <AdminEmptyState icon={Shield} message="No policy evaluation data available" />
  );
}

function ProofSection({ proof }: { proof: MappedAuditProof }) {
  const hasAnyProof = proof.tx_hash || proof.merkle_root || proof.leaf;

  if (!hasAnyProof) {
    return (
      <div className="flex items-center gap-3 rounded-lg border border-[#22314D] bg-[#101C31] p-4">
        <Link2 className="h-5 w-5 text-[#7F8CA3]" />
        <p className="text-sm text-[#7F8CA3]">
          Proof anchoring in progress or not yet available
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {proof.tx_hash && (
        <div className="flex items-center justify-between rounded-lg border border-[#22314D] bg-[#101C31] px-4 py-3">
          <span className="text-xs text-[#7F8CA3]">Transaction Hash</span>
          <CopyableMonoValue value={proof.tx_hash} />
        </div>
      )}
      {proof.merkle_root && (
        <div className="flex items-center justify-between rounded-lg border border-[#22314D] bg-[#101C31] px-4 py-3">
          <span className="text-xs text-[#7F8CA3]">Merkle Root</span>
          <CopyableMonoValue value={proof.merkle_root} />
        </div>
      )}
      {proof.block_number !== undefined && proof.block_number !== null && (
        <div className="flex items-center justify-between rounded-lg border border-[#22314D] bg-[#101C31] px-4 py-3">
          <span className="text-xs text-[#7F8CA3]">Block Number</span>
          <span className="font-mono text-xs text-[#AAB7CC]">{proof.block_number}</span>
        </div>
      )}
      {proof.basescan_url && (
        <div className="flex items-center justify-between rounded-lg border border-[#22314D] bg-[#101C31] px-4 py-3">
          <span className="text-xs text-[#7F8CA3]">On-chain</span>
          <a
            href={proof.basescan_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-[#8FB8FF] hover:underline"
          >
            View on BaseScan
            <ExternalLink className="h-3 w-3" />
          </a>
        </div>
      )}
      <div className="flex items-center justify-between rounded-lg border border-[#22314D] bg-[#101C31] px-4 py-3">
        <span className="text-xs text-[#7F8CA3]">Signature Valid</span>
        {proof.signature_valid === true ? (
          <CheckCircle className="h-4 w-4 text-green-400" />
        ) : proof.signature_valid === false ? (
          <AlertTriangle className="h-4 w-4 text-amber-400" />
        ) : (
          <Minus className="h-4 w-4 text-[#7F8CA3]" />
        )}
      </div>
    </div>
  );
}

function DetailField({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <p className="mb-1 text-xs text-[#7F8CA3]">{label}</p>
      {children}
    </div>
  );
}

function BackLink() {
  return (
    <Link
      href="/admin/audit"
      className="inline-flex items-center gap-1 text-sm text-[#8FB8FF] hover:underline"
    >
      <ArrowLeft className="h-3 w-3" />
      Back to Audit Log
    </Link>
  );
}

export default function AuditDetailPage() {
  const { log_id } = useParams<{ log_id: string }>();
  return (
    <AdminShell>
      <AuditDetailContent logId={log_id} />
    </AdminShell>
  );
}
