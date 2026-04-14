# PoC Review: Inntris × Mastra AI Integration

**Date:** 2026-04-14
**Reviewer:** inntris-poc-reviewer
**Spec:** docs/INTEGRATION_SPEC_MASTRA_2026-04-14.md
**Author:** inntris-integration-architect

---

## VERDICT: FIX

## ONE-LINE JUSTIFICATION

The TypeScript canonical JSON serializer will produce different hashes than
Python for any payload containing floats, breaking signature verification in
production — the demo works by accident because it uses integers.

---

## BLOCKING ISSUES

### 1. Float serialization mismatch between TypeScript and Python

- **What**: `computePayloadHash()` in `crypto.ts` uses `JSON.stringify()` which
  formats floats differently than Python's `json.dumps()`. Example:
  `{ amount: 100.0 }` → Python: `{"amount":100.0}` → JS: `{"amount":100}`.
  Different canonical string → different SHA-256 → signature verification fails
  at `POST /verify`.
- **Where**: Section 6.3, `crypto.ts`, `computePayloadHash()` function
- **Why it matters**: Threat model item 4 (works in demo, fails in real traffic).
  Any Mastra tool whose input contains a float (payment amounts, scores, rates)
  will fail signature verification in production. The demo uses integer `999999`
  and passes by coincidence.
- **Fix**: Add a float normalization step to the TypeScript serializer. Either:
  (a) Force all numbers through `Number.prototype.toFixed()` to match Python's
  repr, or (b) Adopt RFC 8785 (JCS) in both Python and TypeScript for strict
  deterministic serialization (the Python code already recommends this in a
  comment at `api/crypto.py:67`), or (c) Document that payloads MUST use integer
  cents (not float dollars) and validate this at the wrapper level.
  Option (c) is fastest. Option (b) is correct long-term.

### 2. Dead code in computePayloadHash

- **What**: The first line `const canonical = JSON.stringify(payload, Object.keys(payload).sort());`
  computes a value that is never used. The actual hash is computed from
  `canonicalStr` on the third line. This creates confusion about which
  serialization is authoritative.
- **Where**: Section 6.3, `crypto.ts`, lines 1-4 of `computePayloadHash()`
- **Why it matters**: Threat model item 1 (obvious bug in 60 seconds). A target
  engineer reading this code will immediately question whether the hash is
  computed correctly. Two competing serialization approaches in 4 lines signals
  "this was not tested."
- **Fix**: Remove the dead first line entirely. Keep only the `sortKeysDeep` +
  `JSON.stringify` path.

### 3. No retry logic before fail-closed block

- **What**: The `withInntris` wrapper throws immediately on any network error
  from `/verify`. In production, transient DNS failures, TCP timeouts, and TLS
  handshake failures are common. A single transient failure blocks the tool call
  permanently.
- **Where**: Section 6.2, `withInntris.ts`, the `catch` block around `client.verify()`
- **Why it matters**: Threat model item 4 (works in demo, breaks in real traffic).
  Mastra agents in production may hit Inntris through a proxy, VPN, or cloud
  network with intermittent connectivity. Zero retries means every blip blocks
  a tool call.
- **Fix**: Add 1-2 retries with exponential backoff (200ms, 400ms) before the
  fail-closed throw. Keep the final behavior as fail-closed (BLOCK), but give
  transient errors a chance to resolve. Example:
  ```typescript
  const MAX_RETRIES = 2;
  const BASE_DELAY_MS = 200;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      verifyResponse = await client.verify(request);
      break;
    } catch (err) {
      if (attempt === MAX_RETRIES) throw new Error("...(fail-closed)...");
      await new Promise(r => setTimeout(r, BASE_DELAY_MS * 2 ** attempt));
    }
  }
  ```

### 4. Standalone value claim is unsupported by code

- **What**: Section PACKAGING(d) claims "the PoC is GENUINELY USEFUL STANDALONE
  — it improves their security even if they never adopt Inntris." But the
  `withInntris` wrapper calls Inntris's API on every tool execution. Without
  Inntris running, every tool call is blocked (fail-closed on unreachable API).
  The wrapper has zero standalone value.
- **Where**: Section PACKAGING(d), last line
- **Why it matters**: Threat model item 3 ("this is theater"). A target CTO's
  staff engineer will immediately see that the "standalone" claim is false.
  This undermines trust in the entire spec.
- **Fix**: Either (a) ship a local-only mode that logs signed actions to a local
  SQLite database without requiring the Inntris API (genuine standalone value),
  or (b) remove the standalone claim and be honest: "This PoC requires Inntris
  to function. The value proposition is independent verification and on-chain
  anchoring, not local-only security." Option (b) is honest and faster.

---

## NON-BLOCKING NOTES

### 1. Latency impact unaddressed

The spec doesn't discuss the latency impact of a synchronous HTTP call to
`/verify` before every tool execution. A staff engineer will ask "what's
the P99?" before reading anything else. Add a one-line note: expected
50-200ms per tool call, with optional async audit mode for non-critical
tools (sign + verify in background, don't block execution).

### 2. `ensure_ascii` discrepancy

Python's `compute_payload_hash` uses `ensure_ascii=False` (crypto.py:78).
The receipt canonicalization doc says `ensure_ascii` is NOT set for the
fingerprint payload (line 45-46). These are different code paths with
different serialization behavior. The TypeScript code doesn't address this
distinction. For ASCII-only payloads this doesn't matter, but if a Mastra
tool payload contains Unicode (e.g., recipient names in non-Latin scripts),
the hashes may diverge. Document the constraint or normalize.

### 3. Mastra's `makeCoreTool` wrapper ordering

The spec assumes `withInntris` wraps the tool BEFORE `makeCoreTool` wraps it.
But in practice, the Mastra Agent class calls `makeCoreTool` internally when
building the tool set. The architect should verify that wrapping at the
`createTool` level (before agent registration) means the Inntris check runs
inside `makeCoreTool`'s wrapper, not outside it. If `makeCoreTool` catches
and swallows the BLOCKED error, policy enforcement is bypassed.

---

## IF SHIP AFTER FIXES: THE GO/NO-GO CHECKLIST

Once the 4 blocking issues above are fixed, Ronald must verify:

1. **Cross-language hash test**: Run the same payload through both Python
   `compute_payload_hash()` and TypeScript `computePayloadHash()` with a
   payload containing floats, Unicode, and nested objects. Hashes must match
   byte-for-byte. Use the test vectors from
   `tests/fixtures/canonicalization/vectors.json`.

2. **Fail-closed test**: Kill the Inntris API process, then trigger a tool call
   through the Mastra agent. Verify the tool NEVER executes and the error
   message says "fail-closed."

3. **Blocked-verdict test**: Run the demo with a payload that exceeds
   `per_action_limit_usd`. Verify the tool's `execute` function never runs
   (add a console.log inside it and check it doesn't appear).

4. **Verify URL test**: After a blocked call, open the verify URL in a browser.
   Confirm the public receipt shows `verdict: "BLOCKED"`, `signature_valid: true`,
   and `integrity_status` is either `"pending_anchor"` or `"verified"`.

5. **Mastra version pin**: Confirm the spec targets a specific Mastra version
   (the `@mastra/core` package version) and that `createTool`'s API hasn't
   changed in the latest release. Check the changelog for breaking changes to
   the tool execution pipeline.
