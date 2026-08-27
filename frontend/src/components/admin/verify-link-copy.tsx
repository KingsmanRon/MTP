"use client";

import { useState } from "react";
import { Check, Copy, ExternalLink } from "lucide-react";
import Link from "next/link";

export function VerifyLinkCopy({ auditId }: { auditId: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    const url = `${window.location.origin}/verify/${auditId}`;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may not be available
    }
  };

  return (
    <div className="flex items-center gap-3">
      <Link
        href={`/verify/${auditId}`}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-1.5 text-sm text-brandInk hover:underline"
      >
        Open public receipt
        <ExternalLink className="h-3.5 w-3.5" />
      </Link>
      <button
        onClick={handleCopy}
        className="inline-flex items-center gap-1.5 rounded-md border border-tileLine bg-card px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground"
      >
        {copied ? (
          <>
            <Check className="h-3 w-3 text-success-ink" />
            Copied
          </>
        ) : (
          <>
            <Copy className="h-3 w-3" />
            Copy verify link
          </>
        )}
      </button>
    </div>
  );
}
