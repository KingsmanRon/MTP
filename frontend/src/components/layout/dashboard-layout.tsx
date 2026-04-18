"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Sidebar } from "./sidebar";
import { useTheme } from "next-themes";
import { Sun, Moon, LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";

interface DashboardLayoutProps {
  children: React.ReactNode;
  variant: "admin" | "portal" | "audit";
}

export function DashboardLayout({ children, variant }: DashboardLayoutProps) {
  const router = useRouter();
  const { theme, setTheme } = useTheme();
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);

  // Check for session on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/admin/session", { cache: "no-store" });
        if (cancelled) return;
        if (res.ok) {
          setIsAuthenticated(true);
        } else {
          router.push("/login");
        }
      } catch {
        if (!cancelled) router.push("/login");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [router]);

  const handleLogout = async () => {
    try {
      await fetch("/api/admin/session", { method: "DELETE", cache: "no-store" });
    } catch {
      // ignore — client-side cleanup still runs
    }
    try {
      localStorage.removeItem("onboarding_dismissed");
      localStorage.removeItem("portal_agent_id");
    } catch {
      // localStorage may be unavailable (SSR / privacy mode)
    }
    router.push("/login");
  };

  // Show nothing while checking auth
  if (isAuthenticated === null) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-background">
      <Sidebar variant={variant} />
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="h-14 border-b bg-card flex items-center justify-between px-6">
          <div />
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              title="Toggle theme"
            >
              <Sun className="h-4 w-4 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
              <Moon className="absolute h-4 w-4 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
              <span className="sr-only">Toggle theme</span>
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={handleLogout}
              title="Sign out"
            >
              <LogOut className="h-4 w-4" />
              <span className="sr-only">Sign out</span>
            </Button>
          </div>
        </header>
        {/* Main content */}
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}
