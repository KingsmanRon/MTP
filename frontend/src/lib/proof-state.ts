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
  | "computing"
  | "pending"
  | "failed"
  | "not_applicable";

/**
 * Anchoring cadence published on the site. Used to tell a reader looking at a
 * genuinely un-anchored receipt what is being waited on and for how long,
 * rather than showing them a bare PENDING.
 */
export const ANCHOR_CADENCE_MINUTES = 10;

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
  if (anchor === "computing") {
    return "computing";
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
    case "computing":
      return "CHECKING";
    case "pending":
      return "PENDING";
    case "failed":
      return "FAILED";
    case "not_applicable":
      return "NOT APPLICABLE";
  }
}

/* ------------------------------------------------------------------ */
/*  Detail strings                                                    */
/*                                                                    */
/*  The panel used to hold two rows that could contradict each other: */
/*  "On-chain anchor — Confirmed on-chain — VERIFIED" sat next to     */
/*  "Receipt integrity — Fingerprint matches; awaiting anchoring —    */
/*  PENDING" on the same receipt. Two causes, both fixed here.        */
/*                                                                    */
/*  1. The integrity row started life as useState("pending") and was  */
/*     only corrected once an async fingerprint digest resolved. The  */
/*     anchor row derives synchronously from the record, so the       */
/*     server-rendered HTML and the first client paint always         */
/*     disagreed. "computing" is now a state of its own.              */
/*  2. The pending detail string was hardcoded. It claimed the        */
/*     fingerprint matched before it had been computed, and claimed   */
/*     the receipt was awaiting anchoring while the block number was  */
/*     on screen. The string is now derived from the same anchor      */
/*     status the anchor row renders, so the two cannot disagree.     */
/* ------------------------------------------------------------------ */

export function anchorDetailLabel(
  anchor: CheckStatus,
  txHash: string | null | undefined,
): string {
  switch (anchor) {
    case "not_applicable":
      return "Sandbox receipt — not anchored on-chain";
    case "failed":
      return "Anchor proof failed";
    case "verified":
      return "Confirmed on-chain";
    case "computing":
      return "Reading anchor state";
    case "pending":
      return txHash != null
        ? `Transaction submitted, awaiting confirmation (usually within ${ANCHOR_CADENCE_MINUTES} minutes)`
        : `Awaiting the next anchoring batch (published every ${ANCHOR_CADENCE_MINUTES} minutes)`;
  }
}

/**
 * The integrity row's detail string.
 *
 * Takes the anchor status rather than re-deriving it, which is what makes the
 * "anchor confirmed AND awaiting anchoring" pair unrepresentable: the only
 * branch that can mention anchoring is guarded on `anchor === "pending"`.
 * `proof-state.test.ts` asserts this exhaustively.
 */
export function integrityDetailLabel(
  integrity: CheckStatus,
  anchor: CheckStatus,
  fingerprintMatches: boolean | null,
  serverIntegrityStatus?: string | null,
): string {
  if (fingerprintMatches === false) {
    return "Fingerprint does not match; receipt may have been altered";
  }
  if (integrity === "computing" || fingerprintMatches == null) {
    return "Recomputing the receipt fingerprint in your browser";
  }
  if (integrity === "not_applicable" || serverIntegrityStatus === "sandbox") {
    return "Sandbox receipt; signed and independently verifiable, not anchored";
  }
  if (integrity === "failed") {
    return serverIntegrityStatus === "failed"
      ? "Anchor proof failed; the receipt fingerprint itself still matches"
      : "Fingerprint matches, but another proof check did not pass";
  }
  if (integrity === "verified") {
    return "Fingerprint matches record";
  }
  // integrity === "pending". Anchoring is the only thing that holds integrity
  // in this state, and it can only be reached while the anchor is pending.
  if (anchor === "pending") {
    return `Fingerprint matches; anchor confirmation expected within ${ANCHOR_CADENCE_MINUTES} minutes`;
  }
  return "Fingerprint matches; completing remaining checks";
}

/* ------------------------------------------------------------------ */
/*  Panel rollup                                                      */
/* ------------------------------------------------------------------ */

export interface ProofRollup {
  /** Checks that carry a pass/fail meaning for this receipt. */
  total: number;
  verified: number;
  notApplicable: number;
  /** Worst individual state, which is what the panel badge shows. */
  status: CheckStatus;
  label: string;
}

/**
 * Derive the panel's headline state from the individual checks so a reader is
 * not left adjudicating a mixed panel. Never hardcoded: a check that is not
 * applicable to this receipt type is excluded from the denominator rather than
 * counted as a failure.
 */
export function proofRollup(statuses: CheckStatus[]): ProofRollup {
  const notApplicable = statuses.filter((s) => s === "not_applicable").length;
  const scored = statuses.filter((s) => s !== "not_applicable");
  const verified = scored.filter((s) => s === "verified").length;
  const failed = scored.filter((s) => s === "failed").length;
  const pending = scored.filter((s) => s === "pending").length;
  const computing = scored.filter((s) => s === "computing").length;
  const total = scored.length;

  const suffix = notApplicable > 0 ? ` · ${notApplicable} not applicable` : "";
  const counted = `${verified} of ${total} checks verified`;

  if (failed > 0) {
    return {
      total,
      verified,
      notApplicable,
      status: "failed",
      label: `${counted} · ${failed} failed${suffix}`,
    };
  }
  if (computing > 0) {
    return {
      total,
      verified,
      notApplicable,
      status: "computing",
      label: `Checking ${total} proof${total === 1 ? "" : "s"}${suffix}`,
    };
  }
  if (pending > 0) {
    return {
      total,
      verified,
      notApplicable,
      status: "pending",
      label: `${counted} · ${pending} pending${suffix}`,
    };
  }
  return {
    total,
    verified,
    notApplicable,
    status: total === 0 ? "not_applicable" : "verified",
    label: `${counted}${suffix}`,
  };
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
  policy_hash: string | null;
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
    policy_hash: record.policy_hash,
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
