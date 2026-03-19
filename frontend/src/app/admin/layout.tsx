import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Inntris Console — Control agent policy before execution",
  description:
    "Define enforcement rules, manage trust thresholds, and control how agent actions are evaluated before they run.",
  openGraph: {
    title: "Inntris Console — Control agent policy before execution",
    description:
      "Define enforcement rules, manage trust thresholds, and control how agent actions are evaluated before they run.",
    type: "website",
    siteName: "Inntris",
  },
  twitter: {
    card: "summary",
    title: "Inntris Console — Control agent policy before execution",
    description:
      "Define enforcement rules, manage trust thresholds, and control how agent actions are evaluated before they run.",
  },
};

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
