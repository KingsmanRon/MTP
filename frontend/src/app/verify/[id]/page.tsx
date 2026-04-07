import type { Metadata } from "next";
import { publicApi } from "@/lib/api";
import { verdictLabel } from "@/lib/verdict";
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
  const chainLabel = record.chain_id === 84532 ? "Base Sepolia (Testnet)" : "Base Mainnet";
  const chainStatus = record.tx_hash ? `Anchored on ${chainLabel}` : "Pending anchor";
  const title = `Verification Receipt ${id.slice(0, 8)}… — Inntris`;
  const description = `Independently verify this AI agent action. Cryptographic signature, policy hash, and on-chain anchor checked in real time. ${verdict} — ${record.agent_name}, ${record.action_type}. ${sigStatus}. ${chainStatus}.`;

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
