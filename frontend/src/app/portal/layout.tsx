import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Inntris Portal — Inspect agent identity and trust status",
  description:
    "View registered agents, signed activity, trust status, and decision records tied to each agent.",
  openGraph: {
    title: "Inntris Portal — Inspect agent identity and trust status",
    description:
      "View registered agents, signed activity, trust status, and decision records tied to each agent.",
    type: "website",
    siteName: "Inntris",
  },
  twitter: {
    card: "summary",
    title: "Inntris Portal — Inspect agent identity and trust status",
    description:
      "View registered agents, signed activity, trust status, and decision records tied to each agent.",
  },
};

export default function PortalLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
