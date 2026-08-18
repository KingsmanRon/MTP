import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Merge Tailwind CSS classes with clsx
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Format a date for display
 */
export function formatDate(date: Date | string | null | undefined): string {
  if (!date) return "N/A";
  const d = typeof date === "string" ? new Date(date) : date;
  return d.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/**
 * Format a date with time
 */
export function formatDateTime(date: Date | string | null | undefined): string {
  if (!date) return "N/A";
  const d = typeof date === "string" ? new Date(date) : date;
  return d.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/**
 * Absolute UTC timestamp, for evidence surfaces.
 *
 * `formatDateTime` renders in the reader's own locale and timezone, which is
 * the right choice for a console but the wrong one for an artifact two parties
 * are meant to agree about. Receipts state the time in UTC, spelled out, with
 * no relative form that decays as the receipt ages.
 *
 * e.g. "22 July 2026, 15:43 UTC"
 */
export function formatUtcTimestamp(date: Date | string | null | undefined): string {
  if (!date) return "N/A";
  const d = typeof date === "string" ? new Date(date) : date;
  if (Number.isNaN(d.getTime())) return "N/A";
  const day = d.getUTCDate();
  const month = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
  ][d.getUTCMonth()];
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${day} ${month} ${d.getUTCFullYear()}, ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

/**
 * Format a relative time (e.g., "5 minutes ago")
 */
export function formatRelative(date: Date | string | null | undefined): string {
  if (!date) return "Never";
  const d = typeof date === "string" ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSecs < 60) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return formatDate(d);
}

/**
 * Format a number as currency
 */
export function formatCurrency(amount: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(amount);
}

/**
 * Format a large number with abbreviations
 */
export function formatNumber(num: number): string {
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(1)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}K`;
  return num.toString();
}

/**
 * Truncate a string with ellipsis
 */
export function truncate(str: string, length: number): string {
  if (str.length <= length) return str;
  return str.slice(0, length) + "...";
}

/**
 * Truncate a hash for display (e.g., "0x1234...abcd")
 */
export function truncateHash(hash: string, startLen = 6, endLen = 4): string {
  if (hash.length <= startLen + endLen) return hash;
  return `${hash.slice(0, startLen)}...${hash.slice(-endLen)}`;
}

/**
 * Get trust score color
 */
export function getTrustScoreColor(score: number): string {
  if (score >= 70) return "text-[#22c55e]";
  if (score >= 40) return "text-[#f59e0b]";
  return "text-[#ef4444]";
}

/**
 * Get trust score background color
 */
export function getTrustScoreBgColor(score: number): string {
  if (score >= 70) return "bg-[#22c55e]/10";
  if (score >= 40) return "bg-[#f59e0b]/10";
  return "bg-[#ef4444]/10";
}

/**
 * Get verdict color
 */
export function getVerdictColor(verdict: string): string {
  switch (verdict.toLowerCase()) {
    case "approved":
      return "text-green-500";
    case "blocked":
      return "text-red-500";
    case "rate_limited":
      return "text-yellow-500";
    case "signature_invalid":
      return "text-red-600";
    default:
      return "text-muted-foreground";
  }
}

/**
 * Get verdict badge styles
 */
export function getVerdictBadgeStyles(verdict: string): string {
  switch (verdict.toLowerCase()) {
    case "approved":
      return "bg-green-500/20 text-green-400 border-green-500/30";
    case "blocked":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "rate_limited":
      return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "signature_invalid":
      return "bg-red-600/20 text-red-400 border-red-600/30";
    default:
      return "bg-muted text-muted-foreground border-border";
  }
}

/**
 * Copy text to clipboard
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
