"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ChevronRight } from "lucide-react";

interface AuthRedirectBannerProps {
  dashboardPath: string;
  label: string;
}

export function AuthRedirectBanner({ dashboardPath, label }: AuthRedirectBannerProps) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const key = localStorage.getItem("inntris_api_key");
    setIsAuthenticated(!!key);
  }, []);

  if (!isAuthenticated) return null;

  return (
    <div className="relative z-10 border-b border-[#28C281]/20 bg-[#28C281]/10">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3 lg:px-8">
        <p className="text-sm text-[#28C281]">
          You&apos;re signed in. Go to your {label}.
        </p>
        <Link
          href={dashboardPath}
          className="inline-flex items-center gap-1 rounded-lg bg-[#28C281] px-4 py-1.5 text-sm font-medium text-white transition-opacity hover:opacity-90"
        >
          Open {label}
          <ChevronRight className="h-4 w-4" />
        </Link>
      </div>
    </div>
  );
}
