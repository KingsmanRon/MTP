"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  Bot,
  AlertTriangle,
  Key,
  FileSearch,
  Settings,
  ChevronLeft,
  Menu,
  CheckCircle2,
} from "lucide-react";
import { InntrisLogo } from "@/components/inntris-logo";
import { useState } from "react";

interface SidebarProps {
  variant: "admin" | "portal" | "audit";
  /** Set when rendered inside the mobile drawer: closes the drawer on link click. */
  onNavigate?: () => void;
}

const navItems = {
  admin: [
    { href: "/admin/dashboard", icon: LayoutDashboard, label: "Dashboard" },
    { href: "/admin/agents", icon: Bot, label: "Agents" },
    { href: "/admin/alerts", icon: AlertTriangle, label: "Alerts" },
    { href: "/admin/api-keys", icon: Key, label: "API Keys" },
    { href: "/admin/settings", icon: Settings, label: "Settings" },
  ],
  portal: [
    { href: "/portal/dashboard", icon: LayoutDashboard, label: "Dashboard" },
    { href: "/portal/credentials", icon: Key, label: "Credentials" },
    { href: "/portal/playground", icon: Bot, label: "Playground" },
    { href: "/portal/logs", icon: FileSearch, label: "Activity Logs" },
  ],
  audit: [
    { href: "/audit/search", icon: FileSearch, label: "Search" },
    { href: "/audit/verify", icon: CheckCircle2, label: "Verify" },
    { href: "/audit/exports", icon: Key, label: "Exports" },
  ],
};

const titles = {
  admin: "Admin Console",
  portal: "Agent Portal",
  audit: "Audit Explorer",
};

export function Sidebar({ variant, onNavigate }: SidebarProps) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const items = navItems[variant];
  const title = titles[variant];
  // Inside the mobile drawer the backdrop handles closing, so the
  // collapse toggle would only waste tap space.
  const collapsible = !onNavigate;

  return (
    <aside
      className={cn(
        "flex flex-col h-full border-r bg-card transition-all duration-300",
        collapsed ? "w-16" : "w-64"
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b">
        {!collapsed && (
          <Link href="/" onClick={onNavigate} className="flex items-center gap-2">
            <InntrisLogo className="h-6 w-6" />
            <span className="font-semibold">Inntris</span>
          </Link>
        )}
        {collapsible && (
          <button
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="p-2 rounded-md hover:bg-muted transition"
          >
            {collapsed ? <Menu className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </button>
        )}
      </div>

      {/* Title */}
      {!collapsed && (
        <div className="px-4 py-3 border-b">
          <h2 className="text-sm font-medium text-muted-foreground">{title}</h2>
        </div>
      )}

      {/* Navigation */}
      <nav className="flex-1 p-2 space-y-1 overflow-y-auto">
        {items.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              onClick={onNavigate}
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
                isActive
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              )}
            >
              <item.icon className="h-4 w-4 flex-shrink-0" />
              {!collapsed && <span>{item.label}</span>}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t">
        {!collapsed && (
          <p className="text-xs text-muted-foreground">Inntris Core</p>
        )}
      </div>
    </aside>
  );
}
