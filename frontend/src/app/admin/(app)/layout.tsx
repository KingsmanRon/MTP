import { DashboardLayout } from "@/components/layout/dashboard-layout";

export default function AdminAppLayout({ children }: { children: React.ReactNode }) {
  return <DashboardLayout variant="admin">{children}</DashboardLayout>;
}
