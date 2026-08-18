/**
 * The single owner of every verdict display string in the UI.
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
 *
 * Two label sets, one module. `verdictLabel` is the public receipt vocabulary
 * a partner or auditor sees. `verdictLongLabel` is the console's descriptive
 * form, for operators reading a table of their own decisions. They lived in
 * three separate files before — this file, components/verdict-badge.tsx and
 * components/admin/verdict-badge.tsx — which is how a site ends up asserting
 * one vocabulary in its copy and rendering another on the artifact.
 *
 * None of these strings appear in the signed record. The wire value is the
 * `verdict` field, it is hashed into the receipt fingerprint, and it is not
 * renameable for presentation. Decision envelopes emitted by the x402 policy
 * adapter are a separate artifact with a separate vocabulary (ALLOW / BLOCK /
 * REQUIRE_APPROVAL) and are never normalised into these.
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

/**
 * Descriptive verdict label for the Console, where the reader is the operator
 * who configured the policy rather than a third party checking a receipt.
 * Unknown values are echoed rather than guessed at.
 */
export function verdictLongLabel(v: string): string {
  switch (v) {
    case "approved":
      return "Approved";
    case "blocked":
      return "Blocked";
    case "rate_limited":
      return "Rate limited";
    case "signature_invalid":
      return "Invalid signature";
    default:
      return v;
  }
}
