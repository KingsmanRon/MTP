import type { Metadata } from "next";
import { publicApi } from "@/lib/api";
import { VerifyRecordView, VerifyRecordNotFound } from "./verify-record-client";

/* ------------------------------------------------------------------ */
/*  Server-side data fetching                                         */
/* ------------------------------------------------------------------ */

async function fetchRecord(id: string) {
  try {
    return await publicApi.getVerificationRecord(id);
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/*  Dynamic metadata / Open Graph                                     */
/* ------------------------------------------------------------------ */

function verdictLabel(v: string) {
  return v === "approved" ? "PASS" : "BLOCK";
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}): Promise<Metadata> {
  const { id } = await params;
  const record = await fetchRecord(id);

  if (!record) {
    return {
      title: "Record not found — Inntris Public Verifier",
      description:
        "No verification record matches this ID or transaction hash. The record may have been removed or the link may be incorrect.",
      openGraph: {
        title: "Record not found — Inntris Public Verifier",
        description:
          "No verification record matches this ID or transaction hash.",
        type: "website",
        siteName: "Inntris",
      },
      twitter: {
        card: "summary",
        title: "Record not found — Inntris Public Verifier",
        description:
          "No verification record matches this ID or transaction hash.",
      },
    };
  }

  const verdict = verdictLabel(record.verdict);
  const sigStatus = record.signature_valid ? "Signature valid" : "Signature invalid";
  const chainStatus = record.tx_hash ? "Anchored on Base L2" : "Pending anchor";
  const title = `${verdict} — ${record.agent_name} · ${record.action_type} — Inntris Verification`;
  const description = `Verdict: ${verdict}. Agent: ${record.agent_name} (${record.organization_name}). Action: ${record.action_type}. Trust score: ${record.trust_score}/100. ${sigStatus}. ${chainStatus}. Receipt: ${id.slice(0, 8)}…`;

  return {
    title,
    description,
    openGraph: {
      title,
      description,
      type: "website",
      siteName: "Inntris",
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
    },
  };
}

/* ------------------------------------------------------------------ */
/*  Page (Server Component)                                           */
/* ------------------------------------------------------------------ */

export default async function VerifyRecordPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const record = await fetchRecord(id);

  if (!record) {
    return <VerifyRecordNotFound />;
  }

  return <VerifyRecordView record={record} />;
}
