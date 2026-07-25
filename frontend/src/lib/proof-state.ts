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
 *
 * The receipt fingerprint helpers (`canonicalFingerprintPayload`,
 * `canonicalStringify`, `computeReceiptFingerprint`) live here too so they
 * can be locked in by tests. The exact bytes hashed here MUST match the
 * canonical wire form produced by the backend in `api/main.py`.
 */

export type CheckStatus =
  | "verified"
  | "pending"
  | "failed"
  | "not_applicable";

export const SUPPORTED_SCHEMA_VERSIONS = new Set(["v1", "v2", "v3"]);

export function isSupportedSchemaVersion(v: string | null | undefined): boolean {
  return v != null && SUPPORTED_SCHEMA_VERSIONS.has(v);
}

export function signatureCheckStatus(signatureValid: boolean): CheckStatus {
  return signatureValid ? "verified" : "failed";
}

export function effectiveControlsHashCheckStatus(
  effectiveControlsHash: string | null | undefined,
): CheckStatus {
  if (effectiveControlsHash == null || effectiveControlsHash === "") {
    return "not_applicable";
  }
  if (/^[a-f0-9]{64}$/.test(effectiveControlsHash)) {
    return "verified";
  }
  return "failed";
}

export function anchorCheckStatus(
  txHash: string | null | undefined,
  blockNumber: number | null | undefined,
  serverIntegrityStatus?: string | null,
): CheckStatus {
  if (serverIntegrityStatus === "failed") {
    return "failed";
  }
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

/* ------------------------------------------------------------------ */
/*  Canonical fingerprint — MUST stay byte-for-byte in sync with      */
/*  api/main.py `canonical_wire_timestamp` + fingerprint_payload.     */
/* ------------------------------------------------------------------ */

/** Shape of the record fields required for fingerprint computation. */
export interface FingerprintableRecord {
  action_hash: string;
  action_type: string;
  agent_id: string;
  audit_id: string;
  effective_controls_hash: string | null;
  timestamp: string;
  verdict: string;
}

/**
 * Build the canonical fingerprint payload from a verification record. The
 * field set and names are part of the receipt schema contract — do not
 * reorder, rename, add, or remove fields without bumping the schema.
 */
export function canonicalFingerprintPayload(
  record: FingerprintableRecord,
): Record<string, string | null> {
  return {
    action_hash: record.action_hash,
    action_type: record.action_type,
    agent_id: record.agent_id,
    audit_id: record.audit_id,
    effective_controls_hash: record.effective_controls_hash,
    timestamp: record.timestamp,
    verdict: record.verdict,
  };
}

/**
 * Deterministic JSON encoding: keys sorted lexicographically, no whitespace.
 * Must match Python's `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
 */
export function canonicalStringify(obj: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = obj[key];
  }
  return JSON.stringify(sorted);
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * SHA-256 over the canonical fingerprint payload of a receipt.
 *
 * The hash input is exactly:
 *   canonicalStringify(canonicalFingerprintPayload(record))
 *
 * The backend computes the identical bytes in `api/main.py`. The timestamp
 * field must already be in the canonical wire form used by pydantic v2
 * (UTC suffix `Z`, not `+00:00`); we trust the wire value as received.
 */
export async function computeReceiptFingerprint(
  record: FingerprintableRecord,
): Promise<string> {
  const canonical = canonicalStringify(canonicalFingerprintPayload(record));
  const encoded = new TextEncoder().encode(canonical);
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
  return bytesToHex(new Uint8Array(hashBuffer));
}
