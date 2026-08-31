import type { MappedAuditLog } from "./types";

export type AdminAnchorDisplayState =
  | "awaiting_batch"
  | "pending"
  | "submitted"
  | "anchored";

/**
 * Derive the admin list's display state from persisted anchor evidence.
 *
 * A transaction hash alone only proves that a transaction identity exists; it
 * does not prove inclusion in a confirmed block. Treat the row as Anchored only
 * once both the transaction hash and block number are present.
 */
export function getAdminAnchorDisplayState(
  log: Pick<MappedAuditLog, "merkle_root_id" | "transaction_hash" | "block_number">
): AdminAnchorDisplayState {
  if (log.transaction_hash && log.block_number != null) return "anchored";
  if (log.transaction_hash) return "submitted";
  if (log.merkle_root_id) return "pending";
  return "awaiting_batch";
}
