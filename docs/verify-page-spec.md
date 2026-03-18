# INNTRIS_CONTEXT.md
## Last updated: 2026-03-17
## Status: VERIFY PAGE LIVE — LANDING PAGE PRODUCTION READY — OUTREACH READY

---

## What Inntris Is

Runtime verification and cryptographic audit layer for AI agents.

NOT prompt guardrails. NOT observability. NOT logging.

Inntris is a **Policy Decision Point (PDP) + evidence system**:
- Enforces policy BEFORE agent actions execute
- Issues Ed25519 keypairs per agent (cryptographic identity)
- Records every decision in a tamper-evident audit trail
- Anchors Merkle trees hourly to Base L2 via PublicNode RPC
- Produces publicly verifiable, shareable receipts for every action

**One-sentence pitch:**
"AI agents are writing your production code. Inntris is the cryptographic proof of what they actually did."

**Live at:** https://inntris.com
**Backend:** https://inntris-api.up.railway.app
**Domain:** inntris.com (DNS pointed to Vercel — DONE)

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Backend | FastAPI (Python) | Railway, auto-deploys from master |
| Database | PostgreSQL + Redis | Railway |
| Blockchain | Base L2 (chain_id: 84532) | PublicNode RPC — NEVER Base official RPC |
| Frontend | Next.js | Vercel, dark navy, Outfit + IBM Plex Mono |
| Repo | github.com/Inntris/agent-orchestrator-guardrails | main branch: master |
| GitHub Action | github.com/Inntris/agent-orchestrator-guardrails | inntris-verify |

---

## Critical Technical Rules (never violate)

1. **RPC provider is PublicNode** — Base's official RPC blocks cloud IPs
2. **keccak256 in Solidity** must match Python side exactly
3. **All endpoints require auth** except `/public/verify/{record_id}` and `/verify` frontend route
4. **Gas costs sponsored by Inntris** — partners never manage ETH
5. **Nonce replay protection** must be present on all verification calls
6. **Railway watches master branch** — feature branches do NOT auto-deploy

---

## Database Schema (Supabase / PostgreSQL)

### audit_logs
| Column | Type | Notes |
|---|---|---|
| id | uuid | Primary key — used in /verify/[id] URLs |
| agent_id | uuid | FK → agents.id |
| timestamp | timestamptz | NOT created_at |
| action_type | varchar | e.g. admin_action, data_export, api_call |
| action_hash | varchar | |
| payload | jsonb | Contains risk_level, violations array |
| verdict | action_verdict | blocked / approved |
| verdict_reason | text | Human-readable block reason |
| signature | bytea | Ed25519 signature |
| signature_valid | bool | |
| trust_score_at_time | int4 | |
| merkle_root_id | uuid | FK → merkle_proofs.id (nullable) |
| merkle_leaf_index | int4 | Position in Merkle tree |

### agents
| Column | Type | Notes |
|---|---|---|
| id | uuid | Primary key |
| org_id | uuid | FK → organizations.id |
| name | varchar | |
| public_key | bytea | Ed25519 public key |
| public_key_fingerprint | varchar | |
| trust_score | int4 | 0–100 |
| status | agent_status | active / suspended / revoked |
| daily_limit_usd | numeric | |
| per_action_limit_usd | numeric | |
| total_actions_count | int8 | |
| total_blocked_count | int8 | |

### merkle_proofs
| Column | Type | Notes |
|---|---|---|
| id | uuid | Primary key — linked from audit_logs.merkle_root_id |
| root_hash | varchar | Merkle root (NOT merkle_root) |
| transaction_hash | varchar | On-chain txhash (NOT tx_hash) |
| block_number | int8 | |
| chain_id | int4 | 84532 = Base L2 |
| leaf_hashes | ARRAY | Audit log hashes in this batch |
| status | varchar | confirmed / pending |
| start_timestamp | timestamptz | |
| end_timestamp | timestamptz | |
| log_count | int4 | Number of audit logs in this proof |
| contract_address | varchar | |
| gas_used | int8 | |

**Important:** merkle_proofs is a BATCH table. Join via `audit_logs.merkle_root_id = merkle_proofs.id`.
There is no `audit_log_id` column on merkle_proofs.

### Other tables
- **organizations** — org name, billing_tier, daily/monthly limits
- **api_keys** — key_hash, scopes, is_active
- **policy_rules** — org/agent-level rules, conditions (jsonb), action_on_match
- **security_alerts** — alert_type, severity, audit_log_ids array
- **rate_limit_windows** — per-agent request and amount tracking

---

## Demo Agent (Production Data)

```
Agent Name:        Demo Agent
Agent ID:          db34c4c8-3a21-43f4-ac0d-7e0fa131d251
Organisation:      Inntris Demo
Status:            active
Trust Score:       85/100
Public Key FP:     ac7d68004ddef43882c71fbaecda54ac53c1360a0d536e80f6beb932eab14dfb
Daily Limit:       $10,000.00
Per-Action Limit:  $1,000.00
Rate Limit:        60/min
```

### Demo Verification Records

**Record 1 — BLOCK (primary outreach receipt)**
```
audit_log_id:      2f41036e-cd54-4ec1-86e1-22f96cbc09aa
verdict:           blocked
action_type:       admin_action
risk_level:        critical
timestamp:         2026-03-09 21:21:12 UTC
transaction_hash:  0x517853a7400bffc3446fc73711a0cee2f45c82fc1b89d37e76aa3797eb951a77
root_hash:         e56891f1de39aca50725f0e36ee4b1c4fe1c50966f69a1b368e1d691c2466149
block_number:      38662386
chain_id:          84532 (Base L2)
status:            confirmed
```

**Record 2 — BLOCK**
```
audit_log_id:      e8025672-096d-4c5c-b621-e3daeea4baa6
verdict:           blocked
action_type:       admin_action
risk_level:        critical
timestamp:         2026-03-09 18:55:21 UTC
transaction_hash:  0xca57a135cd37739d2c009a416536df7bd8697085d65fb91c66c87e962f45fb43
root_hash:         38e8a206ce373cb8f5f19e1dfd8c45b25a9ae7cdb5e9fd49609ea76291d51e43
block_number:      38658778
chain_id:          84532 (Base L2)
status:            confirmed
```

### Shareable Links (ready for outreach)
```
Verify page:  https://inntris.com/verify/2f41036e-cd54-4ec1-86e1-22f96cbc09aa
BaseScan:     https://basescan.org/tx/0x517853a7400bffc3446fc73711a0cee2f45c82fc1b89d37e76aa3797eb951a77
```

---

## Backend API

### Public Endpoints (no auth required)
```
GET /public/verify/{record_id}   — fetch by UUID
GET /public/verify?tx={txhash}   — fetch by transaction hash (0x-prefixed, 66 chars)
```

Returns `PublicVerificationRecord` — whitelisted fields only, never exposes api_key or secrets.

### Authenticated Endpoints (X-API-Key header required)
```
POST /admin/test-verify          — used by inntris-verify GitHub Action
GET  /agents                     — list agents
GET  /agents/{id}                — agent detail
GET  /audit                      — audit log search
```

### inntris-verify GitHub Action Contract
```
Endpoint:    POST {INNTRIS_API_URL}/admin/test-verify
Auth:        X-API-Key header
Action types:
  admin_action  → sensitive paths: .github/workflows/, scripts/, packages/
  data_export   → secret-only
  api_call      → all other changes
Response:    { verdict: "PASS" | "BLOCK" }
```

---

## Frontend Routes

| Route | Access | Description |
|---|---|---|
| / | Public | Homepage — product overview |
| /verify | Public | Search by record ID or txhash |
| /verify/[id] | Public | Single verification receipt |
| /admin | Auth | Admin console |
| /portal | Auth | Agent portal |
| /audit | Auth | Audit explorer |
| /docs | Public | Documentation |

---

## UI / Design System

```
Background:   #07111F
Surface:      #0D1728
Card:         #101C31
Border:       #22314D
Accent:       #4C8DFF
Accent hover: #6AA2FF
Text primary: #F5F7FB
Text body:    #C4CFDE
Text muted:   #AAB7CC
Text dimmed:  #7F8CA3
Green:        #28C281
Red:          via Tailwind red-500

Fonts:
  font-sans → var(--font-outfit) → Outfit (Google Fonts)
  font-mono → var(--font-mono)  → IBM Plex Mono (Google Fonts)
  Wired in tailwind.config.ts theme.extend.fontFamily

Border radius: rounded-[24px] cards, rounded-[28px] panels
```

---

## Current Product State (2026-03-17)

### COMPLETED ✓
- Dark navy homepage — correct copy, structure, fonts
- Outfit + IBM Plex Mono rendering (font-sans mapped to var(--font-outfit))
- All nav and button links wired correctly
- Verification decision flow panel in hero
- Four module cards with role labels, destination-led CTAs
- Use cases row, core capabilities section
- Public `/verify` landing page with search input
- `/verify/[id]` receipt page — full spec (VerdictHero, DetailsGrid, OnChainProof, CTA)
- Backend public endpoint `GET /public/verify/{record_id}`
- `PublicVerificationRecord` Pydantic model (safe whitelisted fields)
- Two BLOCK records anchored on Base L2, status: confirmed, publicly verifiable
- Railway correctly watching master branch
- **Landing page production readiness** (2026-03-14):
  - Nav: removed "View documentation" + "Open Admin Console", added green "Request Access" CTA
  - Hero: status chip ("Verification API live"), rewritten H1 + bullet list, green primary CTA
  - Trust stats bar moved into hero section (below CTAs)
  - Contact form: two qualifying dropdowns (agent framework, risk surface)
  - Footer added to landing page (was missing)
- **Docs page production readiness** (2026-03-14):
  - Hero rewritten (runtime verification language)
  - "Who We Are" → "What Inntris Is" (product-accurate framing)
  - Removed unverifiable claims (court-admissible, World Bank, SOC 2 compliant)
  - Added Verification Receipt section with real field names
  - Added "Start Here" section with GitHub Action CTA
  - Fixed all GitHub links: Inntris/agent-orchestrator-guardrails → Inntris/agent-orchestrator-guardrails
  - Centered, polished footer
- **Custom NN logo** (2026-03-17):
  - `InntrisLogo` component renders `<img src="/logo.svg">` from public/
  - Replacing Shield icon in all branding: landing nav + footer, verify pages,
    docs header + footer, login, admin/portal/audit sidebar
  - SVG favicon reference in layout.tsx metadata
  - To update the logo everywhere: replace `frontend/public/logo.svg`
- **README.md** — taglines updated, false claims removed

### PENDING
- Auth / login flow for external demos
  (unauthenticated visitors hitting /admin have no clear path in)
- PASS record on demo agent (only BLOCK records exist)
- ~~inntris.com domain pointed to Vercel production~~ — DONE (2026-03-17)
- Composio outreach — UNBLOCKED as of 2026-03-11
- INNTRIS_CONTEXT.md update after each session
- Mobile nav (hamburger menu) — landing page nav links hidden on mobile with no fallback
- Social proof strip — intentionally removed, add when real partner logos approved

---

## GitHub Repos

### Inntris/agent-orchestrator-guardrails (main application)
- **master** — production, Railway auto-deploys backend from here
- Vercel auto-deploys frontend from master
- Feature branch workflow: branch → build → preview → merge to master
- Never commit directly to master for significant changes

### Inntris/agent-orchestrator-guardrails (GitHub Action)
- Contains `inntris-verify` GitHub Action
- Demo branches: `block-demo-pr` (commit 4c2a776 — BLOCK), `pass-demo-pr` (commit dd96231 — PASS)
- Claude Code does NOT have access to this repo

---

## Market Position

### Primary Target: Composio
- Karan Vaidya (co-founder, a16z-backed): 30 agents, 175 PRs, 44K lines TypeScript in 12 days
- Zero cryptographic accountability on any of it
- Inntris already intercepted PRs from ComposioHQ/agent-orchestrator
- Outreach unblocked — verify page live with real on-chain receipts

### OWASP / NIST Alignment (use in all enterprise sales)
- LLM08 Excessive Agency → Inntris enforces before execution
- LLM07 Insecure Plugin Design → Inntris verifies at tool boundaries
- LLM05 Supply Chain Vulnerabilities → PR governance wedge
- NIST AI RMF: Govern, Map, Measure, Manage — Inntris maps to all four

### Unicorn Thesis
Every AI agent framework (Composio, LangChain, Cursor, Lovable, Manus) produces unverified
agent actions. Inntris is the accountability protocol beneath all of them.
Comparable to Wiz ($32B) — same enterprise security infrastructure motion.
At 24× ARR multiple: $1B valuation requires ~$41.7M ARR.

---

## Pricing

| Tier | Price | Notes |
|---|---|---|
| Free | $0 | 50 verifications/mo |
| Starter | $49/mo | 500 verifications |
| Team | $249/mo | Unlimited, RBAC, webhooks |
| Enterprise | $2,500–$10K/mo | SLA, dedicated anchor, SOC 2 |
| Platform API | $0.002/verification | Volume metered — unicorn lever |

---

## Model Selection

- **Opus 4.6** — codebase exploration, spec implementation, architecture, security, complex debugging
- **Sonnet 4.6** — boilerplate, isolated components, known error fixes, copy changes

---

## North Star Metric

Verified agent actions per month (on-chain). Everything else is downstream.
