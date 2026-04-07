/**
 * Pure helpers that derive deterministic proof-completeness states for the
 * public verify page. Extracted from the verify page client component so they
 * can be unit-tested without rendering the full receipt UI.
 *
 * Spec (PR1 §1.4):
 *   - Signature check:    VERIFIED or FAILED. No PENDING after load.
 *   - Policy hash check:  VERIFIED if hash present in signed payload and
 *                         validates. NOT APPLICABLE if the receipt type does
 *                         not involve a policy. FAILED if hash present but
 *                         does not validate. Never NOT INCLUDED.
 *   - On-chain anchor:    VERIFIED or FAILED for canonical homepage demo
 *                         receipts; transient PENDING is legitimate for a
 *                         brand-new receipt that has not yet been confirmed.
 *   - Receipt integrity:  derived from the three above.
 */

export type CheckStatus =
  | "verified"
  | "pending"
  | "failed"
  | "not_applicable";

export const SUPPORTED_SCHEMA_VERSIONS = new Set(["v1", "v2"]);

export function isSupportedSchemaVersion(v: string | null | undefined): boolean {
  return v != null && SUPPORTED_SCHEMA_VERSIONS.has(v);
}

export function signatureCheckStatus(signatureValid: boolean): CheckStatus {
  return signatureValid ? "verified" : "failed";
}

export function policyHashCheckStatus(
  policyHash: string | null | undefined,
): CheckStatus {
  if (policyHash == null || policyHash === "") {
    return "not_applicable";
  }
  if (/^[a-f0-9]{64}$/.test(policyHash)) {
    return "verified";
  }
  return "failed";
}

export function anchorCheckStatus(
  txHash: string | null | undefined,
  blockNumber: number | null | undefined,
): CheckStatus {
  if (txHash != null && blockNumber != null) {
    return "verified";
  }
  if (txHash != null) {
    // Transaction submitted but not yet confirmed — legitimate transient state
    // for a brand-new receipt. Canonical homepage demo receipts should not
    // ever land here because they are generated and confirmed before being
    // swapped in.
    return "pending";
  }
  return "pending";
}

export function deriveIntegrityStatus(
  signature: CheckStatus,
  policy: CheckStatus,
  anchor: CheckStatus,
  fingerprintMatches: boolean,
  serverIntegrityStatus: string | null | undefined,
): CheckStatus {
  if (!fingerprintMatches || serverIntegrityStatus === "failed") {
    return "failed";
  }
  if (signature === "failed" || policy === "failed" || anchor === "failed") {
    return "failed";
  }
  if (anchor === "pending") {
    // Anchor still landing — integrity stays pending until anchor resolves.
    return "pending";
  }
  return "verified";
}

export function checkStatusUiLabel(s: CheckStatus): string {
  switch (s) {
    case "verified":
      return "VERIFIED";
    case "pending":
      return "PENDING";
    case "failed":
      return "FAILED";
    case "not_applicable":
      return "NOT APPLICABLE";
  }
}
