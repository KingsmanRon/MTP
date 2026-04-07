/**
 * Canonical presentation-layer mapping from backend verdict enums to UI labels.
 *
 * Backend enums (do not change): "approved" | "blocked" | "rate_limited" | "signature_invalid"
 * Canonical UI labels: "PASS" | "BLOCK" | "ESCALATE"
 *
 * Mapping:
 *   approved          -> PASS
 *   blocked           -> BLOCK
 *   rate_limited      -> ESCALATE
 *   signature_invalid -> BLOCK
 *
 * Anything unknown falls back to BLOCK (fail-closed presentation).
 */
export type BackendVerdict =
  | "approved"
  | "blocked"
  | "rate_limited"
  | "signature_invalid";

export type UiVerdict = "PASS" | "BLOCK" | "ESCALATE";

export function verdictLabel(v: string): UiVerdict {
  switch (v) {
    case "approved":
      return "PASS";
    case "rate_limited":
      return "ESCALATE";
    case "blocked":
    case "signature_invalid":
      return "BLOCK";
    default:
      return "BLOCK";
  }
}

export function isPassVerdict(v: string): boolean {
  return v === "approved";
}

export function isEscalateVerdict(v: string): boolean {
  return v === "rate_limited";
}
