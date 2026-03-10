# INNTRIS_CONTEXT.md
> Living project context document. Paste this at the start of every new Claude session.
> Last updated: 2026-03-10
> Maintained by: Ronald Maduna (Founder & CEO)

---

## 🏢 What Inntris Is

**Inntris** is a runtime verification and cryptographic audit layer for AI agents.
It provides identity, accountability, and tamper-proof logging for autonomous agent actions — targeting the gap between what AI agents *claim* to do and what they *actually* do.

- **Domain:** inntris.com (NOT .io) — hosted on Vercel
- **GitHub:** KingsmanRon/Inntris
- **Stage:** Post-audit production deployment, active go-to-market pivot

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python) |
| Database | PostgreSQL |
| Cache / Queue | Redis |
| Blockchain | Base L2 (Ethereum L2) — anchoring audit logs |
| Frontend | Next.js — dark navy aesthetic, scroll-triggered animations |
| Fonts | Outfit + IBM Plex Mono |
| Hosting (backend) | Railway |
| Hosting (frontend) | Vercel |
| RPC Provider | PublicNode (Base's official RPC blocks cloud IPs — this was a hard-won fix) |

---

## ✅ What Has Been Completed

### Security Audit & Fixes (Feb 2026)
A comprehensive code audit identified and resolved 17 critical issues across the codebase:
- [ x ] Bypassed policy engine — fixed
- [ x ] Broken nonce replay protection — fixed
- [ x ] SHA-256 / keccak256 cryptographic mismatch between Python Merkle trees and Solidity contracts — fixed
- [ x ] Hardcoded secrets — removed
- [ x ] Wide-open CORS — locked down
- [ x ] Missing auth on endpoints — added
- [ x ] Full fix packages delivered across 17 files

### Production Deployment
- [ x ] FastAPI backend live on Railway
- [ x ] PostgreSQL + Redis provisioned
- [ x ] Blockchain anchoring to Base L2 operational (via PublicNode)
- [ x ] Frontend live on Vercel (dark navy, Outfit + IBM Plex Mono)
- [ x ] Scroll-triggered animations implemented

### Marketing Site Audit
- [ x ] SDK → MCP-native integration language updated
- [ x ] Compliance claims refined: SOX, MiFID II, GDPR (accurate, not overstated)

### Outreach (Mar 2026)
- [ x ] 15 companies contacted (see Outreach Status below)
- [ x ] 2 responses received (Ismail Pelaseyed @ Superagent, John McGovern @ AuthMind)
- [ x ] LinkedIn content strategy active (runtime verification framing, not product pitches)

### GitHub Action Plan
- [ x ] 10-phase implementation plan created (`INNTRIS_GITHUB_ACTION_PLAN.md`)
- [ x ] MVP policies defined: sensitive paths, dependency changes, secret detection
- [ x ] Integration with Railway API via `/admin/test-verify` planned
- [ x ] Demo repo structure defined
- [ x ] Tiered blockchain cost strategy: Base Sepolia testnet for demos; Inntris sponsors all gas

---

## 🔄 Current Strategic Pivot

**From:** Broad outreach to AI companies
**To:** Product-led GitHub Action (`inntris-verify`)

### The Trigger
Composio publicly released a 30-agent, 175-PR autonomous orchestrator — a perfect showcase of the exact problem Inntris solves: unverified autonomous agent PRs with no runtime accountability layer.

### The Product
`inntris-verify` GitHub Action:
- Adds an **"Inntris Verified"** required check to agent PRs
- Triggered on any PR from an AI agent
- Calls Railway API `/admin/test-verify` to verify agent identity + action integrity
- Anchors cryptographic proof to Base L2
- Partners never manage ETH — Inntris sponsors all gas costs

### Why This Works
- Zero-friction adoption (one YAML line in CI/CD)
- Immediate visible value (required check on every agent PR)
- Creates network effect (every verified repo is a reference customer)
- Composio's 175-PR showcase = perfect public demo target

---

## 📬 Outreach Status

| Company | Contact | Status |
|---------|---------|--------|
| Superagent | Ismail Pelaseyed | ✅ Responded — warm signal |
| AuthMind | John McGovern | ✅ Responded — warm signal |
| Dust | Stanislas Polu | ⏳ No response |
| Parloa | Stefan Ostwald | ⏳ No response |
| PolyAI | Nikola Mrkšić | ⏳ No response |
| Anchor Browser | — | ⏳ No response |
| Port.io | — | ⏳ No response |
| Paid AI | — | ⏳ No response |
| Jack & Jill AI | — | ⏳ No response |
| Composio | Karan Vaidya / Dor Dankner / Zohar Einy | ⏳ No response — KEY TARGET |
| CrewAI | João Moura | ⏳ No response |
| Quantexa | — | ⏳ No response |
| H Company (Runner H) | — | ⏳ No response |
| Operant AI | — | ⏳ No response |
| Langflow | — | ⏳ No response |

---

## 🚧 Pending / Next Steps

### Immediate (This Week)
- [ ] Implement `inntris-verify` GitHub Action — Phase 1 of 10 (MVP: sensitive path policy)
- [ ] Build demo repo showing the Action on a mock agent PR workflow
- [ ] Re-engage Composio using the GitHub Action as the hook (not a pitch, a demo)
- [ ] Follow up with Ismail (Superagent) and John (AuthMind) — convert warm signals to pilots

### Short Term
- [ ] Complete all 10 phases of `INNTRIS_GITHUB_ACTION_PLAN.md`
- [ ] Write LinkedIn post using Composio's 175-PR story as the hook
- [ ] Create "Inntris Verified" badge/shield for GitHub READMEs
- [ ] Build onboarding flow for new GitHub Action users
- [ ] Define pricing for GitHub Action tiers (free / paid / enterprise)

### Medium Term
- [ ] Self-hosted enterprise licensing model — identified as the correct long-term GTM
- [ ] MCP-native SDK integration for platforms beyond GitHub
- [ ] Expand outreach to second-wave targets based on GitHub Action traction

---

## ⚠️ Key Technical Decisions & Reasoning

| Decision | Reasoning |
|----------|-----------|
| Base L2 for blockchain anchoring | Low gas costs, EVM-compatible, sufficient decentralization for audit proofs |
| PublicNode as RPC provider | Base's official RPC endpoint blocks cloud IPs. PublicNode was the solution. Do NOT switch back. |
| Railway for backend | Simple deployment, good DX, supports FastAPI + PostgreSQL + Redis natively |
| Vercel for frontend | Next.js native, best performance for the dark navy / animation-heavy UI |
| MCP-native positioning | "Runtime Layer" that complements agent platforms — not a competitor |
| Gas cost sponsorship | Partners should never manage ETH. Inntris absorbing gas removes the biggest adoption blocker |
| Sonnet 4.6 (no Extended Thinking) for Claude work | Token efficiency. Use Extended Thinking only for hard architectural decisions. |

---

## 🔴 Unresolved Issues

1. **Composio non-response** — The highest-value target hasn't replied. The GitHub Action pivot is designed to change this: lead with a working demo of their own orchestrator, not a pitch.

2. **13 of 15 outreach targets silent** — Current hypothesis: email outreach to founders is too noisy. GitHub Action creates inbound pull instead of push.

3. **Weekly Claude usage limits** — Managed via: new conversations per task, Sonnet 4.6 default, Extended Thinking off by default, direct API for automation.

4. **Enterprise licensing model not yet defined** — Self-hosted is the right long-term play but pricing tiers, license terms, and sales motion not yet documented.

5. **Gas cost sustainability** — Sponsoring all gas costs is the right move for adoption, but needs a cost model for when volume scales. Not urgent yet.

---

## 📁 Key Files & References

| File | Purpose |
|------|---------|
| `INNTRIS_GITHUB_ACTION_PLAN.md` | 10-phase implementation plan for `inntris-verify` |
| `INNTRIS_CONTEXT.md` (this file) | Living project state — update at end of every session |
| `/admin/test-verify` | Railway API endpoint used by the GitHub Action |
| `inntris.com` | Marketing site — Vercel hosted |

---

## 🧠 How to Use This File

**At the start of every Claude session:**
```
"Here is my current Inntris context: [paste this file]
Today's task: [one specific thing]"
```

**At the end of every Claude session:**
Ask Claude: *"Update INNTRIS_CONTEXT.md to reflect what we completed today and adjust the pending tasks."*

---
*This file is the single source of truth for Inntris project state.*
*Keep it ruthlessly up to date. An outdated context file wastes tokens and time.*
