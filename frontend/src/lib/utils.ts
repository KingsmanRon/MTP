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
  if (score >= 70) return "text-success-ink";
  if (score >= 40) return "text-warning-ink";
  return "text-destructive-ink";
}

/**
 * Get trust score background color
 */
export function getTrustScoreBgColor(score: number): string {
  if (score >= 70) return "bg-success-surface";
  if (score >= 40) return "bg-warning-surface";
  return "bg-destructive-surface";
}

/**
 * Get verdict color.
 *
 * Returns the status *ink* token, not a raw palette shade. The app renders
 * light by default, and the palette shades these used to return were tuned
 * for a dark ground and measured as low as 1.92:1 on white, well under the
 * 4.5:1 AA floor. Every ink token clears AA on both grounds.
 */
export function getVerdictColor(verdict: string): string {
  switch (verdict.toLowerCase()) {
    case "approved":
      return "text-success-ink";
    case "blocked":
    case "signature_invalid":
      return "text-destructive-ink";
    case "rate_limited":
      return "text-warning-ink";
    default:
      return "text-muted-foreground";
  }
}

/**
 * Get verdict badge styles.
 *
 * Surface + line + ink, so the chip reads as a tinted region with a defined
 * edge rather than coloured text floating on the card ground.
 */
export function getVerdictBadgeStyles(verdict: string): string {
  switch (verdict.toLowerCase()) {
    case "approved":
      return "bg-success-surface text-success-ink border-success-line";
    case "blocked":
    case "signature_invalid":
      return "bg-destructive-surface text-destructive-ink border-destructive-line";
    case "rate_limited":
      return "bg-warning-surface text-warning-ink border-warning-line";
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
