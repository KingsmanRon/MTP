# Inntris × Mastra AI Integration Spec

**Date:** 2026-04-14
**Author:** inntris-integration-architect
**Target:** Mastra AI (https://github.com/mastra-ai/mastra)
**Scout Score:** 14/15

---

## 1. EXECUTIVE SUMMARY (5 lines)

**Target:** Mastra AI — TypeScript agent framework, YC W25, 23k+ GitHub stars, 300k+ weekly npm.
**Agent surface:** Autonomous agents with tool calling, MCP support, and workflow orchestration.
**Specific risk:** No cryptographic attestation of tool calls — agents take consequential actions
(payments, data exports, API calls) with no tamper-evident proof of what happened.
**Inntris hook:** Wrap `createTool`'s `execute` function with Ed25519 signing + policy enforcement.
**Proof:** BLOCKED verdict on a malicious financial transaction, with audit_id and verify URL.

---

## 2. PREREQ CHECK

| Capability | Required? | Status in KingsmanRon/MTP main |
|---|---|---|
| `POST /verify` endpoint | Yes | PRESENT (api/main.py:810-1058) |
| Ed25519 signature verification | Yes | PRESENT (api/crypto.py:121-177) |
| Policy engine (pre-execution) | Yes | PRESENT (api/policy.py:42-299) |
| Nonce/replay protection | Yes | PRESENT (Redis-backed, 600s TTL) |
| Public verify endpoint | Yes | PRESENT (`GET /public/verify/{audit_id}`) |
| Merkle anchoring pipeline | Yes | PRESENT (workers/anchor_worker.py) |
| `POST /public/register` | Yes | PRESENT (api/main.py:410-478) |
| Receipt canonicalization | Yes | PRESENT (docs/RECEIPT_CANONICALIZATION.md) |

**PREREQ STATUS: PASS** — All required capabilities exist in main.

---

## 3. KECCAK ALIGNMENT DRY-RUN

**Leaf encoding used by Inntris:**

```python
# workers/anchor_worker.py:105-179
# Leaf = bytes.fromhex(action_hash)  where action_hash is SHA-256 hex
# Internal nodes = keccak256(left_bytes + right_bytes) via Web3.keccak()
```

**AnchorRegistry.sol verification:**

```solidity
// contracts/AnchorRegistry.sol
function verifyProof(
    bytes32 merkleRoot,
    bytes32 leaf,
    bytes32[] calldata proof,
    uint8[] calldata positions
) external view returns (bool valid) {
    bytes32 computedHash = leaf;
    for (uint256 i = 0; i < proof.length; i++) {
        if (positions[i] == 0) {
            computedHash = keccak256(abi.encodePacked(proof[i], computedHash));
        } else {
            computedHash = keccak256(abi.encodePacked(computedHash, proof[i]));
        }
    }
    return _batches[computedHash].batchId != 0;
}
```

**Alignment check:**
- Off-chain: `Web3.keccak(left + right)` → keccak256 of raw byte concatenation
- On-chain: `keccak256(abi.encodePacked(left, right))` → identical operation
- Leaf: SHA-256 hex → `bytes.fromhex()` → 32 bytes → `bytes32` in Solidity

**Status: ALIGNED.** No SHA-256/keccak256 confusion. Leaf encoding matches byte-for-byte.

---

## 4. ARCHITECTURE DIFF

### Their current agent tool call path:

```
Mastra Agent
  └─ agent.generate() / agent.stream()
       └─ LLM returns tool_call decision
            └─ makeCoreTool() wraps tool with observability + approval
                 └─ tool.execute(input, context)   ← TOOL RUNS HERE
                      └─ result returned to agent loop
                           └─ LLM receives result, continues
```

**Key files:**
- Agent class: `packages/core/src/agent/agent.ts`
- Tool creation: `packages/core/src/tools/tool.ts` — `createTool()` function
- Tool wrapping: `makeCoreTool()` in agent.ts — adds `runId`, `threadId`, `requireApproval`
- Input/Output processors: `__runInputProcessors()`, `__runOutputProcessors()`

### The same path with Inntris inserted:

```
Mastra Agent
  └─ agent.generate() / agent.stream()
       └─ LLM returns tool_call decision
            └─ makeCoreTool() wraps tool
                 └─ withInntris(tool) wrapper   ← INNTRIS INSERTED HERE
                      ├─ PRE: POST /verify → policy check + Ed25519 sign
                      │   └─ If BLOCKED → throw, tool NEVER executes
                      │   └─ If APPROVED → continue
                      ├─ tool.execute(input, context)   ← ORIGINAL TOOL RUNS
                      └─ POST: Log approval_token + audit_id for anchoring
                           └─ result returned to agent loop
```

**Exactly one insertion point:** The `execute` function inside `createTool()`.

---

## 5. INTEGRATION POINTS TABLE

| File | Function | Change | Ed25519 Signed? | Anchored? |
|---|---|---|---|---|
| `@inntris/mastra/src/withInntris.ts` | `withInntris(tool, config)` | Wraps createTool execute with policy + signing | Yes | Yes (via /verify) |
| `@inntris/mastra/src/inntris-client.ts` | `InntrisClient` | HTTP client for Inntris verify endpoint | N/A | N/A |
| `@inntris/mastra/src/crypto.ts` | `signAction()` | Ed25519 signing in TypeScript (tweetnacl) | Yes | N/A |
| `@inntris/mastra/src/canonical.ts` | `computeActionHash()` | SHA-256 canonical JSON, matching api/crypto.py | N/A | N/A |
| `@inntris/mastra/src/types.ts` | TypeScript interfaces | Request/response types matching api/models.py | N/A | N/A |
| Target's `src/mastra/tools/*.ts` | Any `createTool()` call | Wrap with `withInntris()` — one-line change | Yes | Yes |

---

## 6. REFERENCE IMPLEMENTATION

### 6.1 Package structure: `@inntris/mastra`

```
@inntris/mastra/
├── src/
│   ├── index.ts              # Public API exports
│   ├── withInntris.ts        # Core wrapper function
│   ├── inntris-client.ts     # HTTP client for /verify
│   ├── crypto.ts             # Ed25519 + SHA-256 canonical hashing
│   ├── canonical.ts          # Canonical JSON serialization
│   └── types.ts              # TypeScript interfaces
├── package.json
├── tsconfig.json
└── README.md
```

### 6.2 Core wrapper: `withInntris.ts`

```typescript
import { createTool, type Tool } from "@mastra/core/tools";
import { InntrisClient } from "./inntris-client";
import { signAction, computeActionHash, generateNonce } from "./crypto";
import type { InntrisConfig, VerifyResponse } from "./types";

/**
 * Wraps a Mastra tool with Inntris cryptographic attestation.
 * Policy enforcement happens BEFORE tool execution (fail-closed).
 */
export function withInntris<TIn, TOut>(
  tool: Tool<TIn, TOut>,
  config: InntrisConfig,
): Tool<TIn, TOut> {
  const client = new InntrisClient(config.apiUrl);
  const originalExecute = tool.execute;

  return createTool({
    id: tool.id,
    description: tool.description,
    inputSchema: tool.inputSchema,
    outputSchema: tool.outputSchema,

    execute: async (input: TIn, context) => {
      const nonce = generateNonce();
      const timestamp = new Date().toISOString().replace("+00:00", "Z");

      // 1. Compute action hash (matches api/crypto.py exactly)
      const actionHash = computeActionHash(
        config.agentId,
        tool.id,           // action_type = tool id
        input as Record<string, unknown>,
        nonce,
        timestamp,
      );

      // 2. Sign with Ed25519 (INNTRIS_SIGNING_KEY from env)
      const signature = signAction(config.signingKey, actionHash);

      // 3. PRE-EXECUTION: Call Inntris verify endpoint
      let verifyResponse: VerifyResponse;
      try {
        verifyResponse = await client.verify({
          agent_id: config.agentId,
          action_type: tool.id,
          payload: input as Record<string, unknown>,
          signature,
          nonce,
          timestamp,
          policy_hash: config.policyHash ?? null,
        });
      } catch (err) {
        // FAIL-CLOSED: If Inntris is unreachable, block the tool call
        throw new Error(
          `[Inntris] Verify endpoint unreachable — tool call BLOCKED (fail-closed). ` +
          `Tool: ${tool.id}. Error: ${(err as Error).message}`,
        );
      }

      // 4. Check verdict BEFORE execution
      if (verifyResponse.verdict !== "APPROVED") {
        throw new Error(
          `[Inntris] Tool call BLOCKED. Verdict: ${verifyResponse.verdict}. ` +
          `Reason: ${verifyResponse.verdict_reason}. ` +
          `Audit: ${verifyResponse.audit_id}. ` +
          `Verify: ${config.apiUrl}/public/verify/${verifyResponse.audit_id}`,
        );
      }

      // 5. APPROVED — execute the original tool
      const result = await originalExecute(input, context);

      // 6. POST-EXECUTION: Log attestation metadata (non-blocking)
      console.info(
        `[Inntris] Tool "${tool.id}" APPROVED. ` +
        `audit_id=${verifyResponse.audit_id} ` +
        `trust_score=${verifyResponse.trust_score} ` +
        `verify=${config.apiUrl}/public/verify/${verifyResponse.audit_id}`,
      );

      return result;
    },
  });
}
```

### 6.3 Ed25519 signing: `crypto.ts`

```typescript
import nacl from "tweetnacl";
import { createHash, randomUUID } from "crypto";

/**
 * Compute SHA-256 of canonical JSON.
 * MUST match api/crypto.py:compute_payload_hash() exactly:
 *   json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
 */
export function computePayloadHash(payload: Record<string, unknown>): string {
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  // Re-serialize with sorted keys to match Python's sort_keys=True
  const sorted = sortKeysDeep(payload);
  const canonicalStr = JSON.stringify(sorted);
  return createHash("sha256").update(canonicalStr, "utf-8").digest("hex");
}

/**
 * Deep sort object keys lexicographically to match Python sort_keys=True.
 */
function sortKeysDeep(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(sortKeysDeep);
  if (typeof obj === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((obj as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return obj;
}

/**
 * Compute action hash matching api/crypto.py:compute_action_hash().
 */
export function computeActionHash(
  agentId: string,
  actionType: string,
  payload: Record<string, unknown>,
  nonce: string,
  timestamp: string,
): string {
  const signingData = {
    agent_id: agentId,
    action_type: actionType,
    payload_hash: computePayloadHash(payload),
    nonce: nonce,
    timestamp: timestamp,
  };
  return computePayloadHash(signingData);
}

/**
 * Sign an action hash with Ed25519.
 * signingKey: 64-byte secret key (seed + public) as Uint8Array or base64.
 */
export function signAction(signingKey: Uint8Array | string, actionHash: string): string {
  const keyBytes = typeof signingKey === "string"
    ? Buffer.from(signingKey, "base64")
    : signingKey;
  const hashBytes = Buffer.from(actionHash, "hex");
  const signed = nacl.sign.detached(hashBytes, keyBytes);
  return Buffer.from(signed).toString("base64");
}

/**
 * Generate a cryptographically random nonce (UUID v4).
 */
export function generateNonce(): string {
  return randomUUID();
}
```

### 6.4 HTTP client: `inntris-client.ts`

```typescript
import type { VerifyRequest, VerifyResponse } from "./types";

export class InntrisClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async verify(request: VerifyRequest): Promise<VerifyResponse> {
    const response = await fetch(`${this.baseUrl}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(
        `Inntris /verify returned ${response.status}: ${body}`,
      );
    }

    return response.json() as Promise<VerifyResponse>;
  }
}
```

### 6.5 Types: `types.ts`

```typescript
export interface InntrisConfig {
  /** Inntris API base URL (e.g., "https://inntris.com") */
  apiUrl: string;
  /** Registered agent UUID */
  agentId: string;
  /** Ed25519 signing key (64-byte base64 or Uint8Array) */
  signingKey: Uint8Array | string;
  /** Optional SHA-256 hash of policy file (v2) */
  policyHash?: string;
}

export interface VerifyRequest {
  agent_id: string;
  action_type: string;
  payload: Record<string, unknown>;
  signature: string;
  nonce: string;
  timestamp: string;
  policy_hash: string | null;
}

export type ActionVerdict = "APPROVED" | "BLOCKED" | "RATE_LIMITED" | "SIGNATURE_INVALID";

export interface VerifyResponse {
  verdict: ActionVerdict;
  verdict_reason: string | null;
  approval_token: string | null;
  trust_score: number;
  audit_id: string;
  timestamp: string;
  limits_remaining: Record<string, number> | null;
}
```

---

## 7. THE BLOCKED-VERDICT DEMO

### Setup

```typescript
// demo.ts — Run this against the Mastra agent
import { Agent } from "@mastra/core/agent";
import { createTool } from "@mastra/core/tools";
import { z } from "zod";
import { withInntris } from "@inntris/mastra";

// 1. Define a financial transaction tool
const paymentTool = createTool({
  id: "financial_transaction",
  description: "Process a payment",
  inputSchema: z.object({
    amount: z.number(),
    currency: z.string(),
    recipient: z.string(),
  }),
  outputSchema: z.object({
    status: z.string(),
    txId: z.string(),
  }),
  execute: async (input) => {
    // Simulated payment — this should NEVER execute for blocked calls
    return { status: "completed", txId: "tx_" + Date.now() };
  },
});

// 2. Wrap with Inntris (one-line change)
const attestedPaymentTool = withInntris(paymentTool, {
  apiUrl: process.env.INNTRIS_API_URL!,      // https://inntris.com
  agentId: process.env.INNTRIS_AGENT_ID!,     // From POST /public/register
  signingKey: process.env.INNTRIS_SIGNING_KEY!, // Ed25519 64-byte base64
});

// 3. Create Mastra agent with the attested tool
const agent = new Agent({
  name: "payment-agent",
  instructions: "You process payments when asked.",
  model: { provider: "ANTHROPIC", name: "claude-sonnet-4-20250514" },
  tools: { financial_transaction: attestedPaymentTool },
});

// 4. Trigger a malicious tool call (exceeds per-action limit)
const result = await agent.generate(
  "Send $999,999 to account evil_corp_offshore",
);
// Expected: [Inntris] Tool call BLOCKED. Verdict: BLOCKED.
//           Reason: PER_ACTION_LIMIT_EXCEEDED.
//           Audit: <uuid>
//           Verify: https://inntris.com/public/verify/<uuid>
```

### Expected dashboard state

```
POST /verify → 200 OK
{
  "verdict": "BLOCKED",
  "verdict_reason": "Per-action spending limit exceeded: $999999.00 > $100.00",
  "audit_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "trust_score": 49,
  "approval_token": null
}
```

### Verification command (target engineer runs this)

```bash
# After running the demo, verify the blocked action is publicly auditable:
curl -s https://inntris.com/public/verify/<AUDIT_ID> | jq .

# Expected output:
# {
#   "audit_id": "...",
#   "verdict": "BLOCKED",
#   "action_type": "financial_transaction",
#   "signature_valid": true,
#   "integrity_status": "pending_anchor",
#   "agent_name": "payment-agent",
#   ...
# }
```

---

## 8. ROLLOUT PLAN

### Phase 1: Shadow Mode (log only)
- Wrap tools with `withInntris()` but set agent `per_action_limit_usd` very high
- All tool calls get signed and logged, none get blocked
- Monitor: verify endpoint latency, false positive rate, signing correctness
- **Duration:** 1 week
- **Success:** 100% of tool calls appear in Inntris dashboard with valid signatures
- **Breakage:** P99 latency increase >200ms per tool call → investigate

### Phase 2: Enforce (block + alert)
- Lower spending limits to production values
- Enable policy enforcement (blocks on limit/trust violations)
- Alert on blocks via existing Mastra logging or webhook
- **Duration:** 1 week
- **Success:** Blocked calls match expected policy violations, zero false positives
- **Breakage:** False positive rate >1% → revert to shadow, tune policy

### Phase 3: Full (block + anchor)
- Merkle anchoring pipeline active (workers/anchor_worker.py)
- Verify URL returns `integrity_status: "verified"` with `tx_hash` and `block_number`
- BaseScan link verifiable by third party
- **Duration:** Ongoing
- **Success:** Every tool call has a publicly verifiable, on-chain anchored receipt
- **Rollback:** Set agent status to `suspended` via `PATCH /admin/agents/{id}/status`

---

## 9. THE CONVERSATION OPENER

> Your Mastra agents execute tool calls — payments, API calls, data exports — but
> there's no cryptographic proof of what they did or which policy governed the
> decision. I built a working PoC that wraps any `createTool` with Ed25519 signing
> and on-chain anchoring — here's the branch: `inntris-integration`.
>
> What's the right insertion point in your agent loop for pre-execution policy hooks?

---

## PACKAGING

- (a) Fork of mastra-ai/mastra with branch `inntris-integration`
- (b) README: 90-second walkthrough at `@inntris/mastra/README.md`
- (c) GitHub Action: `inntris-verify` wired into CI
- (d) **Standalone value:** Even without Inntris adoption, the wrapper pattern adds
      pre-execution policy enforcement to any Mastra tool — a security improvement
      their enterprise users need regardless.
