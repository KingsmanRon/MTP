import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Inntris Admin",
  description: "Inntris administration console — manage agents, review audit records, and monitor operations.",
  robots: { index: false, follow: false },
};

export default function AdminRootLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
