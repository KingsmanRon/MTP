import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Inntris Public Verifier — Verify a decision. See the proof.",
  description:
    "Check the policy decision, verification details, and on-chain audit trail of any Inntris verification record.",
  openGraph: {
    title: "Inntris Public Verifier — Verify a decision. See the proof.",
    description:
      "Check the policy decision, verification details, and on-chain audit trail of any Inntris verification record.",
    type: "website",
    siteName: "Inntris",
  },
  twitter: {
    card: "summary",
    title: "Inntris Public Verifier — Verify a decision. See the proof.",
    description:
      "Check the policy decision, verification details, and on-chain audit trail of any Inntris verification record.",
  },
  robots: { index: true, follow: true },
};

export default function VerifyLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
