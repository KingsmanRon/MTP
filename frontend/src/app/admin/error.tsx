"use client";

import { useEffect } from "react";
import Link from "next/link";
import { AlertTriangle, RefreshCw, ArrowLeft } from "lucide-react";

/**
 * Error boundary for all /admin/* routes.
 *
 * Without this, any error thrown while rendering an admin page bubbles to the
 * Next.js root handler and produces a bare white "Application error: a
 * client-side exception has occurred" screen. This keeps failures inside the
 * admin shell's look and gives the user a way to recover.
 */
export default function AdminError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Surface the error in the console for debugging.
    console.error("Admin route error:", error);
  }, [error]);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-6 text-center text-foreground">
      <div className="mb-4 rounded-full bg-red-500/10 p-4">
        <AlertTriangle className="h-8 w-8 text-red-400" />
      </div>
      <h1 className="mb-1 text-lg font-semibold">Something went wrong</h1>
      <p className="mb-6 max-w-md text-sm text-muted-foreground">
        This page hit an unexpected error and couldn&apos;t be displayed. You
        can try again or head back to the dashboard.
      </p>
      <div className="flex items-center gap-3">
        <button
          onClick={reset}
          className="inline-flex items-center gap-2 rounded-lg border border-tileLine bg-card px-4 py-2 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <RefreshCw className="h-4 w-4" />
          Try again
        </button>
        <Link
          href="/admin"
          className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm text-brandInk hover:underline"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to dashboard
        </Link>
      </div>
    </div>
  );
}
