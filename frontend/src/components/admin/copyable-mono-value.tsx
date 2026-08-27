"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { truncateHash, copyToClipboard } from "@/lib/utils";

export function CopyableMonoValue({
  value,
  truncateStart = 8,
  truncateEnd = 6,
  full = false,
}: {
  value: string;
  truncateStart?: number;
  truncateEnd?: number;
  full?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    const ok = await copyToClipboard(value);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  const display = full ? value : truncateHash(value, truncateStart, truncateEnd);

  return (
    <button
      onClick={handleCopy}
      className="group inline-flex items-center gap-1 font-mono text-xs text-muted-foreground transition-colors hover:text-foreground"
      title={value}
    >
      <span>{display}</span>
      {copied ? (
        <Check className="h-3 w-3 text-success-ink" />
      ) : (
        <Copy className="h-3 w-3 opacity-0 group-hover:opacity-100" />
      )}
    </button>
  );
}
