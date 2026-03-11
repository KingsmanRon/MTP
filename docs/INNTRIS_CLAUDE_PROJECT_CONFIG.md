# Claude Code Instructions: Build `/verify` Public Page
## Repo: `https://github.com/KingsmanRon/MTP` (branch: `main`)

---

## ⚠️ Scope — Read This First

**You are working exclusively in `KingsmanRon/MTP`.** This is the full
Inntris application — FastAPI backend on Railway, Next.js frontend on Vercel.

There is a second GitHub organisation (`github.com/Inntris`) that contains
the `inntris-verify` GitHub Action and demo wiring. **You do not have access
to that repo and must not attempt to clone, reference, or modify it.**
It is documented below purely so you understand the data contract — the
shape of verification payloads that the action sends to the MTP backend.
Use it to inform the API and UI only.

---

## Context: What Inntris Is

Inntris is a runtime verification and cryptographic audit layer for AI agents.
It anchors tamper-proof audit logs to Base L2 blockchain via PublicNode RPC.

The `/verify` page is the **most important growth surface in the product.**
When someone installs the `inntris-verify` GitHub Action on their repo, every
PR gets a cryptographic receipt. That receipt links to this page. It is the
public billboard that converts viewers into signups.

**Brand rules (non-negotiable):**
- Default theme: **dark navy**. Always. Never light mode as default.
- Fonts: `Outfit` (headings/UI) + `IBM Plex Mono` (hashes, code, technical values)
- Green (`#22c55e`) for PASS/VERIFIED verdicts
- Red (`#ef4444`) for BLOCK/FLAGGED verdicts
- Domain: `inntris.com` (NOT .io)

---

## Context: What the `inntris-verify` Action Does (read-only reference)

The `inntris-verify` GitHub Action (in the inaccessible `Inntris` org) runs
on PR events and calls the MTP backend. Here is the full contract so you
can match the backend and UI to it exactly.

### What the action sends to MTP

```
POST {INNTRIS_API_URL}/admin/test-verify
Headers: X-API-Key: {INNTRIS_API_KEY}
```

The action analyzes the PR diff against a repo policy file (`.inntris.yml`)
and promotes the action type based on findings:
- `admin_action` — sensitive path violations (`.github/workflows/`, `scripts/`, `packages/`)
- `data_export` — secret-only violations detected
- `api_call` — no sensitive violations found

**Sensitive paths monitored:** `.github/workflows/`, `scripts/`, `packages/`
**Dependency files monitored:** `package.json`, lockfiles
**Secret detection:** enabled, critical severity

### What the action expects back from MTP

A JSON response with a `verdict` field: `"PASS"` or `"BLOCK"`.

The action handles these backend responses:
- `404` → agent not found, surfaces config guidance
- `500+` → classified as backend crash
- Missing `verdict` field → surfaces as error
- Non-JSON response → surfaces as error

### Action configuration (injected via GitHub secrets)

```
INNTRIS_API_URL     — Railway backend base URL
INNTRIS_API_KEY     — API key (X-API-Key header)
INNTRIS_AGENT_ID    — Agent UUID to verify against
fail_on_block: true
fail_on_api_error: true
```

### Demo branches (context only — do not modify)

- `block-demo-pr` → full integration commit `4c2a776` → expected: BLOCK
- `pass-demo-pr` → docs-only commit `dd96231` → expected: PASS
- Safe PASS file: `docs/pass-demo-change.md` (no sensitive paths)

---

## Step 0 — Do This Before Anything Else

The admin console at `inntris-frontend.vercel.app/admin` is currently
rendering in **light mode** by default. Fix this first, before building
the verify page.

**Find the theme provider in the MTP Next.js frontend and set:**
```tsx
// Most likely next-themes — find in _app.tsx or layout.tsx
<ThemeProvider defaultTheme="dark" enableSystem={false}>
```

This is a one-line fix. Every demo screenshot and outreach link must
show dark navy.

---

## Step 1 — Explore MTP Before Writing Any Code

```bash
# Understand the repo structure
ls -la
cat README.md

# Backend
find . -name "*.py" | grep -v __pycache__ | head -40
grep -r "verify" --include="*.py" -rn | grep -i "route\|router\|get\|post" | head -20

# Frontend
find . -name "layout.tsx" -o -name "_app.tsx" | head -5
find . -path "*/app/*/page.tsx" | head -20
find . -name "tailwind.config*" | head -3

# Fonts — confirm Outfit and IBM Plex Mono are already imported
grep -r "Outfit\|IBM_Plex_Mono\|ibm-plex-mono" --include="*.tsx" --include="*.ts" -l

# Env vars
cat .env.local 2>/dev/null || echo "no .env.local"
```

Map what exists before creating anything.

---

## Step 2 — Check if the Public Verify Endpoint Exists

```bash
grep -r "verify" --include="*.py" -rn | grep -v "test_verify\|admin" | head -20
```

### If it EXISTS: note the exact path and response schema. Match the frontend to it.
### If it DOES NOT EXIST: build the backend endpoint first (spec below), then frontend.

---

## Backend Spec

### New public endpoint

```python
# Public read endpoint — NO auth required
# Add to the appropriate router in MTP

@router.get(
    "/verify/{verification_id}",
    response_model=PublicVerificationRecord,
    tags=["public"]
)
async def get_public_verification(
    verification_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Public endpoint — no auth required.
    Returns one verification record by ID or txhash.
    Only exposes whitelisted public fields.
    """
    record = await verification_service.get_by_id_or_txhash(db, verification_id)
    if not record:
        raise HTTPException(status_code=404, detail="Verification not found")
    return record


@router.get(
    "/verify",
    response_model=PublicVerificationRecord,
    tags=["public"]
)
async def get_public_verification_by_tx(
    tx: str = Query(..., description="Base L2 transaction hash"),
    db: AsyncSession = Depends(get_db)
):
    """Lookup by txhash: /verify?tx=0x..."""
    record = await verification_service.get_by_id_or_txhash(db, tx)
    if not record:
        raise HTTPException(status_code=404, detail="Verification not found")
    return record
```

### Public response model

Create a **separate** Pydantic model. Do NOT reuse the internal model.

```python
class PublicVerificationRecord(BaseModel):
    id: str
    agent_id: str
    agent_name: str
    action_type: str          # "admin_action" | "data_export" | "api_call"
    verdict: Literal["PASS", "BLOCK"]
    risk_level: Optional[str] # "low" | "medium" | "high" | "critical"
    violations: List[dict]    # [{file, rule, description}]
    timestamp: datetime
    tx_hash: Optional[str]    # Base L2 txhash
    merkle_root: Optional[str]
    block_number: Optional[int]
    chain: str = "base"
    trust_score: Optional[int]  # 0-100
    org_name: Optional[str]

    class Config:
        from_attributes = True
```

**Never expose:** `api_key`, agent secrets, org billing data, admin metadata.

---

## Step 3 — Build the Frontend `/verify` Page

### Route
```
app/verify/[id]/page.tsx      ← primary route (server component)
app/verify/page.tsx           ← /verify with no ID → redirect to inntris.com
```

### Data fetching

```typescript
export const revalidate = 60

async function getVerification(id: string): Promise<VerificationRecord | null> {
  try {
    const res = await fetch(
      `${process.env.NEXT_PUBLIC_API_URL}/api/v1/verify/${id}`,
      { next: { revalidate: 60 } }
    )
    if (!res.ok) return null
    return res.json()
  } catch {
    return null
  }
}
```

Confirm `NEXT_PUBLIC_API_URL` is set in `.env.local` and in Vercel env vars,
pointing to the Railway backend URL.

### TypeScript interface

```typescript
// types/verification.ts
export interface VerificationRecord {
  id: string
  agent_id: string
  agent_name: string
  action_type: string
  verdict: 'PASS' | 'BLOCK'
  risk_level: 'low' | 'medium' | 'high' | 'critical' | null
  violations: Array<{
    file?: string
    rule?: string
    description?: string
  }>
  timestamp: string
  tx_hash: string | null
  merkle_root: string | null
  block_number: number | null
  chain: string
  trust_score: number | null
  org_name?: string
}
```

---

## UI Layout

```
┌──────────────────────────────────────────────────────────┐
│  HEADER                                                  │
│  [Inntris logo — top left]    [inntris.com — top right]  │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  VERDICT HERO  (centred, full-width card)                │
│  ┌────────────────────────────────────────────────────┐  │
│  │  [✓ animated — green]  OR  [✗ animated — red]      │  │
│  │                                                    │  │
│  │  VERIFIED — PASSED         BLOCKED                 │  │
│  │  [action_type — mono badge]                        │  │
│  │  [timestamp]                                       │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  DETAILS  (2-col desktop / 1-col mobile)                 │
│  ┌─────────────────────┐  ┌─────────────────────────┐   │
│  │ Agent               │  │ Policy Decision         │   │
│  │ [agent_name]        │  │ Verdict: [badge]        │   │
│  │ [agent_id — mono]   │  │ Risk:    [badge]        │   │
│  │ Trust: 85/100       │  │ Violations: [list]      │   │
│  └─────────────────────┘  └─────────────────────────┘   │
│                                                          │
│  ON-CHAIN PROOF  (dark card, monospace)                  │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Transaction Hash  [0x1234...abcd]  [copy] [↗]     │  │
│  │ Merkle Root       [0xabcd...1234]  [copy]          │  │
│  │ Block Number      [number]                         │  │
│  │ Chain             Base L2                          │  │
│  │ Anchored          [human-readable timestamp]       │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  CONVERSION CTA                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ "Want this for your AI agent PRs?"                 │  │
│  │ [Install inntris-verify →]   [View Docs →]         │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  FOOTER: "Powered by Inntris · inntris.com"              │
└──────────────────────────────────────────────────────────┘
```

---

## Component Breakdown

### `VerdictHero`
- Animated glow border: green (PASS) or red (BLOCK)
- Entrance animation: scale-in for ✓, brief shake for ✗
- Verdict text in `Outfit` bold, large
- `action_type` in `IBM Plex Mono` pill badge
- All animations complete within 600ms

### `DetailsGrid`
- Two-column responsive grid
- **Agent card:** name, truncated `agent_id` with copy, trust score as
  circular progress (match existing admin console style from the codebase)
- **Policy Decision card:** verdict badge, risk level colour-coded badge,
  violations list — file paths in `IBM Plex Mono`

### `OnChainProof`
- Slightly lighter navy than page background
- Each row: small-caps grey label + `IBM Plex Mono` white value
- Hash display: `first8chars...last6chars` — full hash on hover + in clipboard
- `tx_hash`: external link to `https://basescan.org/tx/{tx_hash}` (new tab)
- Green dot "verified on-chain" indicator in card top-right

### `HashDisplay` (reusable)
```typescript
// components/verify/HashDisplay.tsx
// Props: hash: string, label: string, externalUrl?: string
// Renders: truncated hash + copy button + optional external link icon
const truncate = (h: string) => `${h.slice(0, 8)}...${h.slice(-6)}`
```

### `ConversionCTA`
- Natural continuation — not a jarring ad break
- Headline: `"Want this for your AI agent PRs?"`
- Sub-copy: `"Add inntris-verify to any repo in 2 minutes. Every agent PR gets a cryptographic receipt."`
- Primary: `"Install GitHub Action"` → GitHub Marketplace listing
- Secondary: `"View Docs"` → `/docs`

---

## States to Handle

```typescript
// 1. Loading        — skeleton placeholders matching layout, no spinner
// 2. PASS record    — full layout, green hero
// 3. BLOCK record   — full layout, red hero, violations list visible
// 4. Not found      — clean 404 message + link back to inntris.com
// 5. Network error  — error message + retry button
// 6. No ID (/verify)— redirect to inntris.com
```

---

## Open Graph Meta Tags (Required)

This page is linked from GitHub PR status checks and shared on social.

```typescript
export async function generateMetadata({
  params
}: {
  params: { id: string }
}): Promise<Metadata> {
  const record = await getVerification(params.id)
  if (!record) return { title: 'Verification Not Found — Inntris' }
  const icon = record.verdict === 'PASS' ? '✓' : '✗'
  return {
    title: `${icon} ${record.action_type} — Inntris Verified`,
    description: `Agent "${record.agent_name}" · ${record.action_type} · Verdict: ${record.verdict}. Anchored on Base L2.`,
    openGraph: {
      title: `Inntris Verification — ${record.verdict}`,
      description: `${record.agent_name} · ${record.action_type} · ${record.verdict}`,
      url: `https://inntris.com/verify/${params.id}`,
      siteName: 'Inntris',
    }
  }
}
```

---

## Files to Create or Modify in MTP

```
# Frontend
app/
  verify/
    [id]/
      page.tsx            ← server component, main page
      loading.tsx         ← skeleton state
      not-found.tsx       ← 404 state
    page.tsx              ← redirect to inntris.com

components/
  verify/
    VerdictHero.tsx
    DetailsGrid.tsx
    OnChainProof.tsx
    ConversionCTA.tsx
    HashDisplay.tsx

types/
  verification.ts

# Backend (only if public endpoint doesn't already exist)
routers/
  public.py               ← or add to existing appropriate router
schemas/
  public_verification.py  ← PublicVerificationRecord model
```

---

## Hard Rules

- Work only in `KingsmanRon/MTP` — never reference `github.com/Inntris`
- No auth on the `/verify` page — public and read-only
- Separate public Pydantic model — never reuse internal model
- PublicNode only for blockchain — never Base's official RPC
- Never expose `api_key`, secrets, billing data, or admin fields publicly
- Dark navy default always — no light mode as default on any page
- Outfit + IBM Plex Mono only — no Inter, Roboto, Arial
- No cookie banners or tracking on this page
- Single record per page — no pagination

---

## Acceptance Criteria

- [ ] Dark mode is the default across all pages — no light flash
- [ ] `/verify/[id]` renders correctly for a valid PASS record
- [ ] `/verify/[id]` renders correctly for a valid BLOCK record with violations
- [ ] `/verify/[id]` shows clean 404 state for unknown IDs
- [ ] `tx_hash` links to `basescan.org` in a new tab
- [ ] Copy buttons work for `tx_hash` and `merkle_root`
- [ ] Fully responsive (mobile / tablet / desktop)
- [ ] Open Graph meta tags present and correct
- [ ] No auth required to load the page
- [ ] Conversion CTA present, links to GitHub Action install
- [ ] Skeleton loading state — no blank flash
- [ ] All entrance animations complete within 600ms
- [ ] Outfit for UI text, IBM Plex Mono for all hashes and technical values
- [ ] Public API response contains only whitelisted fields

---

*Generated by Inntris engineering — 2026-03-10*
*Commit as `docs/verify-page-spec.md` in `KingsmanRon/MTP`*
