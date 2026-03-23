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
    <nav className="flex h-16 items-center justify-between border-b border-[#22314D] bg-[#07111F]/95 px-6 backdrop-blur">
      <div className="flex items-center gap-8">
        {/* Brand */}
        <Link href="/admin" className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#22314D] bg-[#0D1728]">
            <InntrisLogo className="h-5 w-5" />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-semibold text-[#F5F7FB]">Inntris</div>
            <div className="text-[10px] text-[#7F8CA3]">Admin</div>
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
                className={cn(
                  "flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors",
                  isActive
                    ? "bg-[#1A2744] text-[#F5F7FB]"
                    : "text-[#7F8CA3] hover:bg-[#0D1728] hover:text-[#C4CFDE]"
                )}
              >
                <Icon className="h-4 w-4" />
                {label}
              </Link>
            );
          })}
        </div>
      </div>

      {/* Sign out */}
      <button
        onClick={handleSignOut}
        disabled={signingOut}
        className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-[#7F8CA3] transition-colors hover:bg-[#0D1728] hover:text-[#C4CFDE] disabled:opacity-50"
      >
        <LogOut className="h-4 w-4" />
        Sign Out
      </button>
    </nav>
  );
}
