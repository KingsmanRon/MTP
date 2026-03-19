import { DashboardLayout } from "@/components/layout/dashboard-layout";

export default function AuditAppLayout({ children }: { children: React.ReactNode }) {
  return <DashboardLayout variant="audit">{children}</DashboardLayout>;
}
