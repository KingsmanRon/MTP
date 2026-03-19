import { DashboardLayout } from "@/components/layout/dashboard-layout";

export default function PortalAppLayout({ children }: { children: React.ReactNode }) {
  return <DashboardLayout variant="portal">{children}</DashboardLayout>;
}
