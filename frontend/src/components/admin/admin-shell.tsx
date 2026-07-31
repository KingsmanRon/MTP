"use client";

import { useAdminSession } from "@/lib/admin/use-admin-session";
import { AdminNav } from "./admin-nav";
import { Loader2 } from "lucide-react";

/**
 * Authenticated admin shell. Wraps all /admin/* pages except /admin/login.
 * Checks session validity and shows loading state during check.
 */
export function AdminShell({ children }: { children: React.ReactNode }) {
  const state = useAdminSession();

  if (state === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (state === "unauthenticated") {
    // Redirect is handled by the hook; show nothing while navigating
    return null;
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <AdminNav />
      <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">{children}</main>
    </div>
  );
}
