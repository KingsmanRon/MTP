import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Inntris Audit Explorer — Search the decision trail",
  description:
    "Trace policy outcomes, inspect signed receipts, and review tamper-evident records across agent activity.",
  openGraph: {
    title: "Inntris Audit Explorer — Search the decision trail",
    description:
      "Trace policy outcomes, inspect signed receipts, and review tamper-evident records across agent activity.",
    type: "website",
    siteName: "Inntris",
  },
  twitter: {
    card: "summary",
    title: "Inntris Audit Explorer — Search the decision trail",
    description:
      "Trace policy outcomes, inspect signed receipts, and review tamper-evident records across agent activity.",
  },
};

export default function AuditLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
