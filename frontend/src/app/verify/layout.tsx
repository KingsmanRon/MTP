import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Verify — Inntris | AI Agent Verification Receipts",
  description:
    "Independently verify AI agent actions. Check Ed25519 signatures, policy hash binding, on-chain Merkle root anchoring, and receipt integrity — no Inntris account required.",
  openGraph: {
    title: "Verify — Inntris | AI Agent Verification Receipts",
    description:
      "Independently verify AI agent actions. Check Ed25519 signatures, policy hash binding, on-chain Merkle root anchoring, and receipt integrity — no Inntris account required.",
    type: "website",
    siteName: "Inntris",
  },
  twitter: {
    card: "summary",
    title: "Verify — Inntris | AI Agent Verification Receipts",
    description:
      "Independently verify AI agent actions. Check Ed25519 signatures, policy hash binding, on-chain Merkle root anchoring, and receipt integrity — no Inntris account required.",
  },
  robots: { index: true, follow: true },
};

export default function VerifyLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
