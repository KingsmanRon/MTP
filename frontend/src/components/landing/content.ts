/**
 * Landing page content and the route targets it links to.
 *
 * Receipt IDs and the verify URLs are carried over unchanged from the previous
 * page.tsx — they point at real, anchored receipts.
 */

export const CANONICAL_BLOCK_RECEIPT_ID = "3030c27c-87c4-4464-b4af-605fbe638e0e";
export const CANONICAL_PASS_RECEIPT_ID = "d8dd0902-4750-42d2-9516-92bf6362e815";

export const LIVE_PASS_RECEIPT_URL =
  "https://www.inntris.com/verify/d8dd0902-4750-42d2-9516-92bf6362e815";
export const PUBLIC_VERIFY_URL = "https://www.inntris.com/verify";
export const SALES_EMAIL = "sales@inntris.com";

/** Section 6 — the MCP client config, verbatim from the repository README. */
export const MCP_CONFIG = `{
  "mcpServers": {
    "inntris-guard": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "env": {
        "INNTRIS_API_URL": "https://api.inntris.com",
        "INNTRIS_AGENT_ID": "<your-agent-id>",
        "INNTRIS_PRIVATE_KEY_B64": "<agent-ed25519-seed-b64>"
      }
    }
  }
}`;

/** Section 8 — response shapes returned by POST /verify. */
export const APPROVED_PAYLOAD = `{
  "verdict": "approved",
  "verdict_reason": "All verification checks passed",
  "approval_token": "base64_token",
  "trust_score": 85,
  "audit_id": "uuid",
  "timestamp": "2024-01-15T10:30:01Z",
  "limits_remaining": {
    "daily_limit_usd": "500.00",
    "daily_spent_usd": "99.99",
    "daily_remaining_usd": "400.01"
  }
}`;

export const BLOCKED_PAYLOAD = `{
  "detail": "Daily spending limit exceeded",
  "verdict": "blocked",
  "audit_id": "uuid",
  "timestamp": "2024-01-15T10:30:01Z"
}`;
