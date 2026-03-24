"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

type SessionState = "loading" | "authenticated" | "unauthenticated";

/**
 * Client-side hook to check admin session validity.
 * Redirects to /admin/login if not authenticated.
 */
export function useAdminSession() {
  const router = useRouter();
  const [state, setState] = useState<SessionState>("loading");

  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        const res = await fetch("/api/admin/session");
        if (cancelled) return;
        if (res.ok) {
          setState("authenticated");
        } else {
          setState("unauthenticated");
          router.replace("/admin/login");
        }
      } catch {
        if (cancelled) return;
        setState("unauthenticated");
        router.replace("/admin/login");
      }
    }

    check();
    return () => { cancelled = true; };
  }, [router]);

  return state;
}
