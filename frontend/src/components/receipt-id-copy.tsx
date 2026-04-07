"use client";

import { useState, type MouseEvent } from "react";

export function ReceiptIdCopy({ id }: { id: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async (e: MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(id);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard API unavailable — title attribute still exposes the full ID
    }
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      title={copied ? "Copied!" : `Click to copy: ${id}`}
      aria-label={copied ? "Receipt ID copied" : "Copy receipt ID"}
      className="group mt-1 block w-full truncate rounded text-left font-mono text-xs text-[#8FB8FF] transition-colors hover:text-teal-400 focus:outline-none focus:ring-1 focus:ring-teal-400/50"
    >
      <span className="inline-block max-w-full truncate align-bottom">
        {copied ? "✓ Copied" : id}
      </span>
    </button>
  );
}
