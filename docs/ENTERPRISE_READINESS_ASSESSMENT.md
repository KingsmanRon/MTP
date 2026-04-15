# Enterprise Readiness Assessment

**Assessed against**: `docs/INNTRIS_ENTERPRISE_READINESS_V2.md`
**Date**: 2026-04-15
**Branch**: `claude/review-enterprise-readiness-lPKU8`

---

## Executive Summary

The repository is **substantially complete** against the V2 spec. PR1 (the load-bearing credibility work — receipt schema, signing path, verify page proof logic, and live demo receipt IDs) appears fully shipped. PR2 (cosmetic consistency) is **mostly complete** with a handful of residual issues in the portal preview, docs presentation labels, the `verdict-badge` component, and two markdown files that still reference the old contact address.

| Area | Status | Remaining Work |
|------|--------|----------------|
| PR1 — Receipt schema v2 | **DONE** | None |
| PR1 — policy_hash in signed payload | **DONE** | None |
| PR1 — Fresh mainnet receipts | **DONE** | None |
| PR1 — Verify page proof logic | **DONE** | None |
| PR1 — Canonical receipt ID swap | **DONE** | None |
| PR1 — Tests | **DONE** | None |
| PR1 — INNTRIS_CONTEXT.md update | **DONE** | None |
| PR2 — Verdict labels | **PARTIAL** | 3 issues remain (see below) |
| PR2 — Contact address | **PARTIAL** | 2 files remain (see below) |
| PR2 — "What a public receipt proves" block | **DONE** | None |
| PR2 — Homepage proof copy | **DONE** | None |
| PR2 — Trust score demotion | **DONE** | None |
| PR2 — Docs copy edits | **DONE** | None |
| PR2 — Portal & audit preview language | **PARTIAL** | Portal uses "Permit" (see below) |
| PR2 — Tests | **DONE** | None |

---

## PR1 — Load-Bearing Credibility Work

### 1.1 Pre-flight Checks — COMPLETE

All four pre-flight items from the spec have been resolved and documented:

1. **Verify page data flow** — Fully traced. `policy_hash` flows from API response through `PublicVerificationRecord` → `proof-state.ts` → `verify-record-client.tsx`. The `policyHashCheckStatus()` function at `frontend/src/lib/proof-state.ts:39-49` returns `"not_applicable"` (never `"not_included"`) when the field is null/empty, `"verified"` for valid 64-char hex, and `"failed"` otherwise.

2. **Current PASS receipt signed payload** — `policy_hash` is now part of the signed payload for v2 receipts. The canonical fingerprint includes it at `frontend/src/lib/proof-state.ts:122-134` and `api/main.py` (fingerprint_payload construction). The canonical demo receipts are v2 with `policy_hash = b5e687b5bd9878f561f8050e994fbd8632fec823503fa4bd8c047a3e3b14f686` per `docs/INNTRIS_CONTEXT.md:44`.

3. **PENDING root cause** — Documented in `docs/INNTRIS_CONTEXT.md:51-61`. Root cause: the legacy verify page treated `not_applicable` as `not_included` in the policy-hash slot, rendering "Policy hash (SHA-256): Not included". The frontend display layer never expressed a non-applicable state distinct from missing-but-required. Fixed by introducing the explicit `not_applicable` proof check and v2 schema version bump.

4. **BLOCK receipt parity** — Both PASS and BLOCK canonical receipts use the same v2 schema, both have `policy_hash` in the signed payload, both are anchored to Base mainnet (chain 8453). Parity confirmed.

### 1.2 Receipt Schema Change — COMPLETE

- `policy_hash` is a first-class field: `database/schemas.sql:146` defines `policy_hash CHAR(64)`.
- Migration exists: `database/migrations/003_add_policy_hash.sql`.
- Schema versioning: `api/main.py:676-688` — v2 if `policy_hash` is non-null, v1 otherwise.
- Frontend schema validation: `frontend/public/schema/receipt/v1.json:106-109` defines v1/v2 enum.
- `SUPPORTED_SCHEMA_VERSIONS` at `frontend/src/lib/proof-state.ts:29` includes both `"v1"` and `"v2"`.
- Canonical JSON includes `policy_hash`: `frontend/src/lib/proof-state.ts:130` and matching backend logic.
- Canonicalization rules documented in `docs/RECEIPT_CANONICALIZATION.md`.

### 1.3 Fresh Mainnet Receipts — COMPLETE

Per `docs/INNTRIS_CONTEXT.md:40-47`:
```
CANONICAL_PASS_ID    = d8dd0902-4750-42d2-9516-92bf6362e815
CANONICAL_RECEIPT_ID = 3030c27c-87c4-4464-b4af-605fbe638e0e
Demo policy hash     = b5e687b5bd9878f561f8050e994fbd8632fec823503fa4bd8c047a3e3b14f686
Anchored             = Base mainnet (chain 8453), block 44,401,999,
                       tx 0x3f86eea4328d00fbd968181f5f188aee95dea65ea690273f229534edd68ecd84
```

Both receipts generated under v2 schema on Base mainnet. Script exists at `scripts/generate_mainnet_receipts.py`.

### 1.4 Verify Page Proof Logic — COMPLETE

The four proof checks at `frontend/src/app/verify/[id]/verify-record-client.tsx:237-267` resolve deterministically:

| Check | Implementation | Renders |
|-------|---------------|---------|
| Ed25519 signature | `signatureCheckStatus()` at `proof-state.ts:35-37` | VERIFIED or FAILED |
| Policy hash | `policyHashCheckStatus()` at `proof-state.ts:39-49` | VERIFIED, NOT APPLICABLE, or FAILED. Never NOT INCLUDED. |
| On-chain anchor | `anchorCheckStatus()` at `proof-state.ts:51-66` | VERIFIED, PENDING (transient), or PENDING (no tx) |
| Receipt integrity | `deriveIntegrityStatus()` at `proof-state.ts:68-86` + async fingerprint check at `verify-record-client.tsx:202-211` | VERIFIED, FAILED, or PENDING (brief loading) |

Trust score is correctly demoted to advisory line at `verify-record-client.tsx:589-605`, labeled "(advisory)" and visually below the four proof checks.

### 1.5 Live Demo Receipt ID Swap — COMPLETE

`frontend/src/app/page.tsx:61-62`:
```javascript
const CANONICAL_RECEIPT_ID = "3030c27c-87c4-4464-b4af-605fbe638e0e";
const CANONICAL_PASS_ID = "d8dd0902-4750-42d2-9516-92bf6362e815";
```

Hardcoded URLs updated:
- Line 182: `https://www.inntris.com/verify/d8dd0902-4750-42d2-9516-92bf6362e815`
- Line 336: same URL on the PASS card

Both match the IDs in `docs/INNTRIS_CONTEXT.md`.

### 1.6 Tests for PR1 — COMPLETE

| Test | File | Status |
|------|------|--------|
| Receipt schema round-trip & fingerprint | `tests/test_receipt_fingerprint.py` (v1 and v2 vectors) | Present |
| Verify page proof-state logic | `frontend/src/lib/__tests__/proof-state.test.ts` (191 lines) | Present |
| Policy hash display (never NOT INCLUDED) | `proof-state.test.ts:54-61` | Present |
| Schema version support | `proof-state.test.ts:14-26` | Present |
| Canonicalization cross-language parity | `tests/fixtures/canonicalization/` (vectors.json, verify_node.js, verify_python.py) | Present |

### Context Update (INNTRIS_CONTEXT.md) — COMPLETE

`docs/INNTRIS_CONTEXT.md` contains all required post-PR1 updates:
- New receipt schema version and `policy_hash` rule (lines 28-37)
- New mainnet canonical receipt IDs (lines 42-47)
- Mainnet migration confirmation: "Regenerated on mainnet under schema v2. Mainnet migration fully complete." (line 49)
- Root cause of prior PENDING integrity state (lines 51-61)

---

## PR2 — Cosmetic Consistency Work

### 2.1 Verdict Labels — PARTIAL (3 issues remain)

**What's done:**
- Core mapping function: `frontend/src/lib/verdict.ts:23-35` — correctly maps `approved→PASS`, `blocked→BLOCK`, `rate_limited→ESCALATE`, `signature_invalid→BLOCK`.
- Test coverage: `frontend/src/lib/__tests__/verdict.test.ts` — all four mappings tested.
- Homepage: Uses `verdictLabel()` throughout (`page.tsx:419`, etc.).
- Public verify page: Uses `verdictLabel()` throughout (`verify-record-client.tsx:365`, `432`).
- Audit Explorer preview: Uses `"PASS"` and `"BLOCK"` correctly (`audit/page.tsx`).

**What's NOT done:**

1. **Portal preview** (`frontend/src/app/portal/page.tsx:155-158`): Uses `"Permit"` instead of `"PASS"`:
   ```tsx
   { verdict: "Permit", rule: "api_call", time: "14:32 UTC" },
   { verdict: "Permit", rule: "api_call", time: "14:21 UTC" },
   ```
   The conditional rendering logic at lines 165-181 also checks against `"Block"` and `"Escalate"` (title case) rather than the canonical uppercase `"PASS"`, `"BLOCK"`, `"ESCALATE"`.

2. **`verdict-badge.tsx` component** (`frontend/src/components/verdict-badge.tsx:18-23`): Uses human-readable labels that don't match canonical UI vocabulary:
   ```tsx
   approved: "Approved",       // spec says PASS
   blocked: "Blocked",         // spec says BLOCK
   rate_limited: "Rate Limited", // spec says ESCALATE
   signature_invalid: "Invalid Signature", // spec says BLOCK
   ```
   This component is used in admin-facing surfaces. The spec says "Do not change backend enums" but "Map at the presentation boundary only" — the component label layer IS the presentation boundary.

3. **Docs page outcome cards** (`frontend/src/app/docs/page.tsx:281-283`): Uses backend-facing labels in a presentation context:
   ```tsx
   { label: "APPROVED", desc: "Action verified & logged", ... },
   { label: "BLOCKED", desc: "Policy violation", ... },
   { label: "RATE LIMITED", desc: "Too many requests", ... },
   ```
   The spec (2.1) says to apply canonical labels across "docs presentation examples" and adds: "In docs, where a JSON example reflects the raw backend contract, keep the raw field truthful and add a one-line note nearby." The JSON example at docs/page.tsx:315 uses `"verdict": "approved"` which is correct (raw backend), but the visual outcome cards at line 281 are a presentation surface and should use `PASS`, `BLOCK`, `ESCALATE`.

### 2.2 Buyer Contact Address — PARTIAL (2 files remain)

**What's done:**
- Contact section component (`frontend/src/components/contact-section.tsx`): Uses `sales@inntris.com` throughout (lines 419, 466, 470, 502, 506).
- Supporting line present (lines 498-508): "For design partner discussions, platform reviews, and production agent deployments, contact sales@inntris.com."
- `applications@inntris.com` does NOT appear in any buyer-facing frontend surface.
- Test coverage: `frontend/src/components/__tests__/contact-section.test.tsx` — validates `sales@inntris.com` present and `applications@inntris.com` absent.

**What's NOT done:**

1. **README.md:468**: `Commercial licensing: applications@inntris.com`
2. **README.md:482**: `- **Contact**: applications@inntris.com`
3. **DEPLOYMENT_GUIDE.md:219**: `Contact **applications@inntris.com** to request repository access.`

These are not buyer-facing frontend surfaces, but they are the first files a technical evaluator reads. A buyer doing due diligence will see conflicting contact addresses.

### 2.3 "What a Public Receipt Proves" Block — COMPLETE

Present at `frontend/src/app/page.tsx:472-507`. Correctly renders:
- "Which agent acted — via Ed25519 signature validation"
- "What decision was made — PASS, BLOCK, or ESCALATE"
- "Which policy bound the decision — via policy hash"
- "That the record was anchored — via Base L2 transaction proof"

Matches spec exactly. Positioned below the live proof section, above the core capability section — under the 20-second comprehension bar.

### 2.4 Homepage Proof Copy — COMPLETE

Reviewed all homepage copy. Key claims are supported by the linked live receipts:
- "We prove every decision" — supported by live receipts with verified signatures, policy hashes, and on-chain anchors.
- "Independently verifiable — anyone can check the receipt using the on-chain anchor alone" — supported by BaseScan link in verify page.
- "Ed25519 signatures bind every action to its agent" — signature check shows VERIFIED.
- "Receipt integrity you can verify yourself" — fingerprint verification runs client-side.

No overstated claims found.

### 2.5 Trust Score Demotion — COMPLETE

| Surface | Treatment | Status |
|---------|-----------|--------|
| Homepage receipt cards | `Trust {score}/100` as small sub-line under Action (page.tsx:368, 441) | Advisory, not headline |
| Public verify page | Labeled "(advisory)" at verify-record-client.tsx:592, rendered as small section below proof checks (line 591) | Correctly secondary |
| Portal preview | `87/100` in Trust State panel (portal/page.tsx:122-127) | Present but doesn't outrank identity/decisions/verification |

### 2.6 Docs Copy Edits — COMPLETE

**"VISA network" line**: NOT present in live docs page (`frontend/src/app/docs/page.tsx`). Replacement copy is present at line 354: "Inntris provides a verification layer for teams that need signed decisions, policy enforcement, and tamper-evident audit trails for AI agent actions."

**"Optional on-premise" line**: NOT present in live docs page. Replacement copy is present at line 359: "Deployment and security requirements are reviewed with each team during evaluation."

**Test coverage**: `frontend/src/app/docs/__tests__/credibility.test.tsx` — tests that both old lines are absent and both new lines are present.

### 2.7 Portal and Audit Preview Language — PARTIAL

| Surface | Status | Detail |
|---------|--------|--------|
| Audit Explorer preview | **COMPLIANT** | Uses `"PASS"` and `"BLOCK"` (not `"PERMIT"`) |
| Portal recent decisions | **NON-COMPLIANT** | Uses `"Permit"` instead of `"PASS"` at `portal/page.tsx:155,157` |

### 2.8 Tests for PR2 — COMPLETE

| Test | File | Status |
|------|------|--------|
| Verdict label mapping | `frontend/src/lib/__tests__/verdict.test.ts` | Present — tests all 4 mappings |
| Contact regression | `frontend/src/components/__tests__/contact-section.test.tsx` | Present — validates sales@ present, applications@ absent |
| Docs credibility regression | `frontend/src/app/docs/__tests__/credibility.test.tsx` | Present — validates VISA line absent, on-premise line absent, replacements present |

---

## Remaining Issues — Punch List

### Must Fix (spec violations)

| # | File | Line(s) | Issue | Spec Section |
|---|------|---------|-------|-------------|
| 1 | `frontend/src/app/portal/page.tsx` | 155, 157 | `"Permit"` should be `"PASS"` | 2.1, 2.7 |
| 2 | `frontend/src/app/portal/page.tsx` | 158 | `"Escalate"` should be `"ESCALATE"` (uppercase) | 2.1, 2.7 |
| 3 | `frontend/src/app/portal/page.tsx` | 156 | `"Block"` should be `"BLOCK"` (uppercase) | 2.1, 2.7 |
| 4 | `frontend/src/app/portal/page.tsx` | 165-181 | Conditional checks use title-case (`"Block"`, `"Escalate"`) — must match new uppercase values | 2.1 |
| 5 | `frontend/src/app/docs/page.tsx` | 281-283 | Outcome cards use `"APPROVED"`, `"BLOCKED"`, `"RATE LIMITED"` — should use `"PASS"`, `"BLOCK"`, `"ESCALATE"` | 2.1 |
| 6 | `frontend/src/components/verdict-badge.tsx` | 18-23 | Labels use `"Approved"`, `"Blocked"`, `"Rate Limited"` instead of `"PASS"`, `"BLOCK"`, `"ESCALATE"` | 2.1 |

### Should Fix (consistency, not spec-breaking for buyer-facing surfaces)

| # | File | Line(s) | Issue | Spec Section |
|---|------|---------|-------|-------------|
| 7 | `README.md` | 468, 482 | `applications@inntris.com` should be `sales@inntris.com` | 2.2 |
| 8 | `DEPLOYMENT_GUIDE.md` | 219 | `applications@inntris.com` should be `sales@inntris.com` | 2.2 |

### Edge Case / Judgment Call

| # | File | Line(s) | Issue | Notes |
|---|------|---------|-------|-------|
| 9 | `frontend/src/app/docs/page.tsx` | 315 | JSON example shows `"verdict": "approved"` | Per spec 2.1: keep raw backend truthful in JSON, add a note nearby: "The UI presents `approved` as `PASS`." — note is currently absent. |

---

## Non-Negotiable Compliance Check

| Rule | Status |
|------|--------|
| No new dependencies added | **COMPLIANT** |
| No site redesign | **COMPLIANT** |
| No unrelated refactoring | **COMPLIANT** |
| No brand colour / layout / navigation changes | **COMPLIANT** |
| No retroactive policy_hash on existing receipts | **COMPLIANT** — v1 receipts remain v1 |
| No unsigned sidecar policy_hash | **COMPLIANT** — policy_hash is inside signed payload |
| Existing test stack used | **COMPLIANT** — Jest for frontend, pytest for backend |

---

## Validation Pass

| Check | Tool | Expected |
|-------|------|----------|
| Install | `npm install` (frontend) / `pip install` | Should pass |
| Typecheck | `npx tsc --noEmit` | Should pass (no type errors observed in reviewed code) |
| Lint | ESLint via Next.js | Should pass |
| Unit tests | `npx jest` (frontend) / `pytest` (backend) | Should pass — tests aligned with implementation |
| Build | `npm run build` | Should pass |
| Smoke tests | `tests/smoke_test.sh` | Requires live API |

---

## Bottom Line

**PR1 is fully shipped.** The receipt schema change, mainnet receipts, verify page proof logic, canonical ID swap, tests, and context update are all in place and consistent.

**PR2 is ~90% complete.** The core changes (verdict mapping function, contact section, docs copy, "What a public receipt proves" block, trust score demotion, audit preview, and all three test suites) are done. The remaining items are:

- 6 verdict label violations across portal preview, docs outcome cards, and verdict-badge component
- 3 contact address references in README.md and DEPLOYMENT_GUIDE.md
- 1 missing annotation on the docs JSON example

These are all straightforward find-and-replace fixes with no architectural implications.
