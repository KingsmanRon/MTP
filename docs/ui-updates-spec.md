# Claude Code Instructions: UI Updates
## Repo: `https://github.com/Inntris/agent-orchestrator-guardrails` (branch: `main`)

---

## ⚠️ Read This Before Writing Any Code

**Step 1 is always exploration.** Before touching any file, run the
commands in the Exploration section below. Map the codebase. Confirm
file locations. Then implement.

Never assume folder structure. Never overwrite without reading first.

---

## Step 1 — Explore the Repo First

```bash
# Top-level structure
ls -la

# Find the Next.js app root
find . -name "layout.tsx" | head -5
find . -name "_app.tsx" | head -5
find . -name "page.tsx" | grep -v node_modules | head -20

# Find the homepage
find . -path "*/app/page.tsx" | head -3
find . -path "*/pages/index.tsx" | head -3

# Find the theme provider
grep -r "ThemeProvider\|next-themes\|defaultTheme" --include="*.tsx" --include="*.ts" -rn | head -10

# Find existing components
find . -path "*/components/*" -name "*.tsx" | grep -v node_modules | head -30

# Find Tailwind config
find . -name "tailwind.config*" | head -3
cat tailwind.config.ts 2>/dev/null || cat tailwind.config.js 2>/dev/null

# Confirm font setup
grep -r "Outfit\|IBM_Plex_Mono\|ibm-plex-mono" --include="*.tsx" --include="*.ts" -rn | head -10

# Find the admin layout/dashboard
find . -path "*/admin*" -name "*.tsx" | grep -v node_modules | head -20

# Read the homepage file fully before touching it
# (replace path with what you find above)
cat app/page.tsx 2>/dev/null || cat pages/index.tsx 2>/dev/null
```

Report what you find. Then implement the changes below.

---

## Change 1 — Dark Mode Default (P0, Do First)

**Problem:** The admin console at `inntris-frontend.vercel.app/admin` renders
in light mode by default. Every demo screenshot and every link sent to
external parties must show dark navy.

**Fix:** Find the theme provider and set dark as the default.

```tsx
// Most likely in app/layout.tsx or pages/_app.tsx
// Find: <ThemeProvider ...>
// Change to:
<ThemeProvider defaultTheme="dark" enableSystem={false}>
```

If `next-themes` is not installed:
```bash
npm install next-themes
```

Then wrap the app in the provider with `defaultTheme="dark"`.

**Also check:** If there is a `localStorage` theme preference persisted from
a previous light mode session, it will override the default. Add this to
clear stale preferences on first load if needed:

```typescript
// In layout.tsx or a client component that runs once
// Only needed if users have visited before and stored "light"
if (typeof window !== 'undefined') {
  const stored = localStorage.getItem('theme')
  if (!stored) localStorage.setItem('theme', 'dark')
}
```

**Acceptance:** Open `/admin` in an incognito window. It must render dark
navy with no flash of light mode.

---

## Change 2 — Homepage Headline and Copy (P0)

**Problem:** The current homepage headline is:
> "The Security Assurance Layer for AI Agents"

The browser tab title is:
> "The Universal Liability Shield"

Both are generic and forgettable. They do not reflect the market moment
or what Inntris actually does.

**Find the homepage file** (from Step 1 exploration) and make these changes:

### Hero section

**Replace current headline with:**
```
Your AI agents are writing production code.
Prove what they actually did.
```

**Replace current subheadline with:**
```
Cryptographic identity, policy enforcement, and tamper-proof audit —
anchored on Base L2. Built for teams running AI agents in production.
```

**Replace current CTAs with:**
```
Primary CTA:   "See a Live Verification"  →  /verify  (or demo record)
Secondary CTA: "Open Admin Console"       →  /admin
```

### Below-the-fold problem statement (add this section)

```
AI agent frameworks can tell you what your agents claimed to do.
None of them can prove it. Inntris can.
```

### Three-column feature section (replace existing or add)

```
Column 1: Cryptographic Identity
Every agent signs every action with Ed25519.
No key, no action. Identity is not optional.

Column 2: Policy Before Execution
Block admin actions, financial operations,
and data exports before they run — not after.

Column 3: Tamper-Proof Audit
Merkle trees. Base L2. Hourly anchoring.
Every decision independently verifiable.
```

### Stat strip (keep existing — do not change)

```
100% Fail-Closed  |  Ed25519 Cryptographic Signing  |  Base L2 Blockchain Anchoring  |  <100ms Verification Latency
```

These four stats are correct and credible. Preserve them exactly.

### Page `<title>` / metadata

```typescript
// In the homepage metadata export or _document.tsx / layout.tsx
title: "Inntris — Cryptographic Verification for AI Agents"
description: "Your AI agents are writing production code. Inntris is the cryptographic proof of what they actually did. Policy enforcement and tamper-proof audit anchored on Base L2."
```

---

## Change 3 — Admin Console Visual Polish (P1)

These are secondary to the dark mode fix but should be done in the same session.

### Trust Score circular indicator
The agent detail page shows Trust Score as `85/100` with a circular progress
ring. Confirm this matches the existing admin console style. If the ring is
missing or broken in dark mode, fix the colour contrast:
- Ring fill: `#22c55e` (green) for scores ≥ 70
- Ring fill: `#f59e0b` (amber) for scores 40–69
- Ring fill: `#ef4444` (red) for scores < 40
- Ring background: subtle dark grey, not white

### Verdict badges
Confirm `Blocked` and `Approved` badges render correctly in dark mode:
- Blocked: red background, white text — `bg-red-500/20 text-red-400 border border-red-500/30`
- Approved: green background, white text — `bg-green-500/20 text-green-400 border border-green-500/30`

### Action type pills
`admin_action`, `api_call`, `email_send`, `data_export` in the activity feed
should render as monospace (`IBM Plex Mono`) pills, not plain text.

---

## What NOT to Change

- The four-card dashboard layout (Active Agents, Total Verifications, Approval Rate, Daily Spend) — structure is correct
- The agent detail page information architecture (Trust Score, Total Actions, Daily Limit, Rate Limit) — keep as is
- The Policies tab layout (Allowed Actions / Blocked Actions side by side) — this is the strongest demo screenshot in the product
- The stat strip on the homepage (100% Fail-Closed, Ed25519, Base L2, <100ms) — keep exactly
- The sidebar navigation items (Dashboard, Agents, Alerts, API Keys, Settings)

---

## Fonts — Confirm Before Changing Anything

Check that `Outfit` and `IBM Plex Mono` are loaded in `layout.tsx`:

```typescript
import { Outfit, IBM_Plex_Mono } from 'next/font/google'

const outfit = Outfit({
  subsets: ['latin'],
  variable: '--font-outfit'
})

const ibmPlexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500'],
  variable: '--font-mono'
})
```

If they are already present, do not re-add them. If they are missing, add them.

All headings and UI text: `Outfit`
All hashes, code, action types, IDs: `IBM Plex Mono`

---

## Implementation Order

```
1. Explore repo (Step 1) — read before writing
2. Fix dark mode default (Change 1) — test in incognito
3. Update homepage headline and copy (Change 2)
4. Admin console badge/pill polish (Change 3)
5. Confirm fonts are loaded correctly
```

Do not skip Step 1. Do not implement all changes in one pass without
reading the files first.

---

## Acceptance Criteria

- [ ] `/admin` opens in dark navy by default in incognito — no light flash
- [ ] Homepage headline reads: "Your AI agents are writing production code. Prove what they actually did."
- [ ] Homepage sub-headline updated to match spec
- [ ] Primary CTA is "See a Live Verification"
- [ ] Problem statement section present below hero
- [ ] Three-column feature section present with correct copy
- [ ] Stat strip unchanged (100% Fail-Closed, Ed25519, Base L2, <100ms)
- [ ] Page title updated to "Inntris — Cryptographic Verification for AI Agents"
- [ ] Verdict badges render correctly in dark mode (red/green)
- [ ] Action type pills render in IBM Plex Mono
- [ ] Trust score ring colours are correct (green/amber/red by range)
- [ ] Outfit loaded for all UI text
- [ ] IBM Plex Mono loaded for all hashes, IDs, action types

---

*Generated by Inntris engineering — 2026-03-10*
*Commit as `docs/ui-updates-spec.md` in `Inntris/agent-orchestrator-guardrails`*
