"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { LayoutDashboard, Bot, FileSearch, LogOut } from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";
import { cn } from "@/lib/utils";
import { useState } from "react";

const navItems = [
  { href: "/admin", label: "Dashboard", icon: LayoutDashboard },
  { href: "/admin/agents", label: "Agents", icon: Bot },
  { href: "/admin/audit", label: "Audit Log", icon: FileSearch },
] as const;

export function AdminNav() {
  const pathname = usePathname();
  const router = useRouter();
  const [signingOut, setSigningOut] = useState(false);

  const handleSignOut = async () => {
    setSigningOut(true);
    try {
      await fetch("/api/admin/session", { method: "DELETE" });
    } finally {
      router.push("/admin/login");
    }
  };

  return (
    <nav className="flex h-16 items-center justify-between border-b border-tileLine bg-background/95 px-4 backdrop-blur sm:px-6">
      <div className="flex items-center gap-3 sm:gap-8">
        {/* Brand */}
        <Link href="/admin" className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-tileLine bg-tile">
            <InntrisLogo className="h-5 w-5" />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-semibold text-foreground">Inntris</div>
            <div className="text-[10px] text-muted-foreground">Admin</div>
          </div>
        </Link>

        {/* Navigation links */}
        <div className="flex items-center gap-1">
          {navItems.map(({ href, label, icon: Icon }) => {
            const isActive =
              href === "/admin"
                ? pathname === "/admin"
                : pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                title={label}
                className={cn(
                  "flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors",
                  isActive
                    ? "bg-tile text-foreground"
                    : "text-muted-foreground hover:bg-tile hover:text-muted-foreground"
                )}
              >
                <Icon className="h-4 w-4 shrink-0" />
                {/* Icon-only below sm so the bar fits a phone screen */}
                <span className="hidden sm:inline">{label}</span>
                <span className="sr-only sm:hidden">{label}</span>
              </Link>
            );
          })}
        </div>
      </div>

      {/* Sign out */}
      <button
        onClick={handleSignOut}
        disabled={signingOut}
        title="Sign Out"
        className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-tile hover:text-muted-foreground disabled:opacity-50"
      >
        <LogOut className="h-4 w-4 shrink-0" />
        <span className="hidden sm:inline">Sign Out</span>
        <span className="sr-only sm:hidden">Sign Out</span>
      </button>
    </nav>
  );
}
