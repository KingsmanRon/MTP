# INNTRIS_CONTEXT.md
_Last updated: 2026-03-10 — 12-Week execution plan integrated from docx, product reality grounded, ACV targets set, operating rhythm added_

---

## What Inntris Is

Runtime verification and cryptographic audit layer for AI agents.
Targets the gap between what AI agents **claim** to do and what they **actually** do.
Product is post-audit and live in production.

**Core value prop:** Identity, accountability, and tamper-proof logging for autonomous AI agent actions — anchored on-chain, verifiable by anyone.

**This is NOT prompt guardrails. It is a Policy Decision Point (PDP) + evidence system.**
The correct mental model: a PDP that applications call for a decision, and a Policy Enforcement Point (PEP) that actually blocks/permits execution. Inntris is the PDP. Every integration (GitHub Action, MCP server, API hook) is a PEP.

### Four Core Product Capabilities (from inntris.com — verified)

1. **Cryptographic identity** — every agent gets an Ed25519 keypair; actions are signed; the agent must prove identity before acting.
2. **Policy enforcement** — per-agent spending limits, rate controls, and action restrictions enforced **before execution**, not audited after. Allow/deny per action type: `api_call`, `email_send`, `data_export`, `financial_transaction`, `admin_action`.
3. **Tamper-evident audit** — verification decisions are logged and batched into Merkle trees anchored **hourly** to Base L2 to prove records existed and were not altered.
4. **MCP-native integration** — "one config line", "sub-100ms overhead", via `npx inntris-guard` server config.

### Live Product Evidence (from Railway/Admin Console screenshots)

- Live API deployment with `/admin/agents`, `/admin/alerts`, `/admin/audit/search`, `/admin/usage` endpoints
- Admin console models agent as first-class identity with: trust score, daily spend limit, per-action cap, rate limit (req/min), explicit allow/deny of action types
- Audit log view ties attempted action to verdict ("Blocked") with risk level and violations metadata
- Confirmed: `admin_action` blocked with `risk_level: "critical"` in payload

### OWASP LLM Top 10 Alignment (use this language in all enterprise sales)

- **LLM08 Excessive Agency** — unchecked autonomy to take actions → Inntris enforces before execution
- **LLM07 Insecure Plugin Design** — unsafe tool/plugin interfaces → Inntris verifies at tool boundaries
- **LLM05 Supply Chain Vulnerabilities** — compromised workflows → PR governance wedge directly addresses this

### NIST AI RMF Alignment

NIST's AI Risk Management Framework organises activities into **Govern, Map, Measure, Manage**.
Inntris maps directly to all four functions. Use this language in enterprise security questionnaires and compliance conversations.
Reference: https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=936225

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Backend | FastAPI (Python) | Hosted on Railway |
| Database | PostgreSQL + Redis | Hosted on Railway |
| Blockchain | Base L2 | Anchoring via PublicNode RPC |
| RPC Provider | PublicNode | NOT Base official RPC — it blocks cloud IPs |
| Frontend | Next.js | Hosted on Vercel, dark navy aesthetic |
| Fonts | Outfit + IBM Plex Mono | Brand standard |
| GitHub | KingsmanRon/Inntris | Main repo |
| Domain | inntris.com | NOT .io |

---

## Critical Technical Rules

1. **RPC = PublicNode only** — never suggest Base's official RPC
2. **Hashing = keccak256** — must match between Solidity and Python exactly
3. **All endpoints require auth** — no open endpoints, ever
4. **Gas is Inntris-sponsored** — partners never manage ETH
5. **Nonce replay protection** — required on all verification calls

---

## Primary Growth Lever: `inntris-verify` GitHub Action

The most important current deliverable. A required status check on AI agent pull requests that:

- Runs on every PR
- Hashes the agent's claimed actions
- Anchors to Base L2 via PublicNode
- Returns PASS or BLOCK with on-chain receipt
- Displays "Inntris Verified ✓" badge on the PR

**Lock-in mechanic:** Once set as a required status check, teams cannot merge without it. Every verified PR is immutable compliance evidence — switching cost compounds with scale.

**Flywheel:**
```
Agent opens PR
  → inntris-verify runs as required check
  → "Inntris Verified ✓" badge appears on PR
  → Reviewer clicks badge
  → Lands on shareable audit page at inntris.com
  → "Want this for your repo?" → signup
  → New org installs inntris-verify
  → Repeat
```

---

## Market Catalyst: Composio / Karan Vaidya

**The post (published ~6 days ago):**
> "Just Replaced 30 engineers with 30 agents to build an entire codebase in 12 days.
> 44K lines of TypeScript. 175 PRs opened. 1,500+ tests written. All CI failures self-corrected."
> — Karan Vaidya, Co-founder Composio (a16z-backed)
> https://www.linkedin.com/feed/update/urn:li:ugcPost:7434643803002765312/

**Why this matters for Inntris:**
175 agent-generated PRs with zero cryptographic accountability. This is the canonical proof that the market has moved and the problem Inntris solves is now real, urgent, and happening at scale inside a16z-backed companies.

**Demo already built:**
- `Inntris/testing` repo has a working PASS/BLOCK demo against agent-generated PRs
- `block-demo-pr` → points to full integration commit `4c2a776` (BLOCK path)
- `pass-demo-pr` → recreated from clean base `fd4603d`, docs-only commit `dd96231` (PASS path)
- Based on https://github.com/ComposioHQ/agent-orchestrator

**This is not a test — it's a live proof of concept with receipts.**

---

## Outreach Priority: Composio (48-hour deadline)

**Target:** Karan Vaidya, Co-founder Composio
**Hook:** We already verified one of your agent's PRs. Here's the on-chain record.

**Draft message:**
```
Subject: We verified one of your agent's PRs cryptographically

Karan — you just posted about 175 agent PRs in 12 days.
We intercepted one via our GitHub Action and anchored its 
audit trail to Base L2 in 4 seconds.

Here's the on-chain record: [txhash]
Here's the PASS/BLOCK demo: [link to Inntris org]

If your agents are writing production code, 
your customers need to know what they actually did.

10 minutes?
```

---

## The Unicorn Thesis

**Inntris is not a tool. It is infrastructure.**

Every AI agent framework that exists — Composio, LangChain, AutoGPT, CrewAI, Devin, Manus, Cursor, Lovable, GitHub Copilot — produces unverified, unaccountable agent actions at scale. None of them have a cryptographic audit layer. None of them can answer: *"Prove what your agent actually did."*

Inntris is the accountability protocol that sits beneath all of them. That is a different category of company entirely.

**Comparables and what they tell us:**

| Company | What they did | $100M ARR | Peak/Current |
|---|---|---|---|
| Lovable | UI layer for AI-generated apps | 8 months | ~$100M ARR |
| Manus AI | General AI agent platform | 8 months | ~$100M ARR |
| Cursor (Anysphere) | AI coding assistant | 12 months | $500M ARR |
| Wiz | Cloud security infrastructure | 18 months | $500M+ ARR → $32B acq. |
| Deel | Global HR/payroll infrastructure | 20 months | $1B+ revenue run-rate |

**Where Inntris sits:** Closest to Wiz — security/compliance infrastructure with a bottoms-up viral loop. Wiz was acquired for $32B. That is the ceiling here, not $1B.

**Why this could be faster than all of them:**
- The problem didn't exist at scale 18 months ago. It is acute right now.
- The viral loop (badge → audit page → signup) is already built into the product mechanic.
- Regulatory tailwind is arriving: EU AI Act, emerging US AI governance, SOC 2 auditors are already asking.
- Every AI agent platform is a potential distribution partner, not a competitor.
- Network effects: every on-chain verification makes the ledger more valuable.

**The volume math:**

```
GitHub alone: ~1M AI-assisted PRs/month today, growing exponentially
Add Cursor, Lovable, Manus, Composio, Devin agent activity...
Conservative 2027 estimate: 500M agent actions/month across the ecosystem

At $0.002/verification (volume tier):
500M × $0.002 = $1M MRR = $12M ARR from volume alone

At 10% ecosystem penetration:
$120M ARR — achieved without a single enterprise contract
```

This is why the pricing model must include a **per-verification volume tier** alongside seats.

---

## Revised ARR Milestone Map (Unicorn Path)

```
$0 → $100K ARR    :  Composio + 3 anchor partners, viral loop live     (90 days)
$100K → $1M ARR   :  GitHub Action in 500+ repos, Stripe flowing        (6 months)
$1M → $10M ARR    :  Platform partnerships (Composio, LangChain native) (9 months)
$10M → $50M ARR   :  Enterprise compliance mandates, EU AI Act angle    (12 months)
$50M → $100M ARR  :  Volume pricing at ecosystem scale, API tier        (18 months)
$100M+ ARR        :  Acquisition conversations or Series B at $1B+ val  (24 months)
```

**The target is $100M ARR in 18 months or less. This is achievable. Here is why:**
Cursor did it selling to individual developers. Inntris sells to every team running AI agents AND to every AI agent platform as infrastructure. The TAM is larger and the enterprise contract sizes are bigger.

---

## Pricing Model (Revised for Unicorn Scale)

| Tier | Price | Who | Inclusions |
|---|---|---|---|
| Free | $0/mo | Individual devs | 50 verifications/mo, public badge, read-only audit page |
| Starter | $49/mo | Small teams | 500 verifications, private audit log, webhook |
| Team | $249/mo | Engineering teams | Unlimited, RBAC, webhook exports, compliance export |
| Enterprise | $2,500–$10K/mo | Orgs with AI agents in prod | SLA, dedicated anchor wallet, SOC 2 reports, SSO |
| Platform API | Volume pricing | AI agent platforms (Composio etc.) | Per-verification at scale, white-label option |
| **Volume** | **$0.002/verification** | **High-throughput orgs** | **Pure metered billing, no seat limit** |

**Free tier purpose:** Badge distribution. Every badge is a billboard. Every billboard is a pipeline event.

**Platform API is the unicorn lever.** If Composio, LangChain, or any major agent framework builds Inntris in natively and bills their users for verifications, Inntris earns on every agent action in their ecosystem without direct sales.

---

## Enterprise Moat: Compliance Angle

SOC 2 / ISO 27001 auditors are beginning to ask: *"How do you control your AI agents?"*
Current industry answer: silence.
Inntris answer: tamper-proof, on-chain, exportable audit trail.

**EU AI Act (in force 2025–2026):** High-risk AI systems require audit trails and human oversight documentation. Inntris is the cheapest, fastest path to compliance for any company deploying AI agents in the EU.

**Planned deliverable:** One-click Compliance Export — signed PDF of all verified agent actions in a given audit window. $500/report standalone or included in Enterprise tier.

**The Wiz parallel:** Wiz won cloud security by making it frictionless to see your entire cloud attack surface. Inntris wins AI agent accountability by making it frictionless to prove what every agent did. Same motion, bigger market, better timing.

---

## 12-Week Execution Plan (Active Cycle — Start: 2026-03-10)

### The Single Lag Goal

**By end of Week 12: $3M contracted ARR run-rate** (signed subscription contracts).
- Conservative floor: $0.3M
- Moderate target: $1.0M
- **Aggressive target (the goal): $3.0M**

The Composio proof accelerates conversion speed — the aggressive scenario is the correct target, not the moderate one.

### ACV Targets (Enterprise Motion)

Cannot unicorn on small ACVs without Lovable-scale user volume (2.3M users). Inntris is enterprise infrastructure.

| ACV | Customers needed for $1M ARR | Customers needed for $3M ARR |
|---|---|---|
| $50K | 20 | 60 |
| $100K | 10 | 30 |
| $250K | 4 | 12 |

**Target: $100K–$250K ACV. Wiz's motion — high-value customers from day one.**

### Valuation Math (Unicorn Path)

Bessemer Cloud 100 benchmarks (2025): ~20× average revenue multiple, ~24× for AI companies.

- At 24× ARR: $1B valuation requires ~$41.7M ARR
- At 20× ARR: $1B valuation requires ~$50M ARR

The 12-week goal is not $41M ARR. It is building the **credible slope** that makes investors believe you get there. $3M ARR at Week 12 with strong growth trajectory and referenceable enterprise customers is the fundraise trigger.

### Weekly Lead Measures (Scored Every Friday — Target ≥85% Execution)

| Measure | Definition | Weekly Target |
|---|---|---|
| **A** | Qualified enterprise discovery calls | 12/wk (Weeks 1–6), 8/wk (Weeks 7–12) |
| **B** | Qualified demos delivered | 6–10/wk (Weeks 2–10) |
| **C** | Pilots started (enforcement + audit on) | 2/wk (Weeks 3–8) |
| **D** | Proof events produced (customer-validated blocked/approved decisions) | 10/wk by Week 6, 20/wk by Week 10 |
| **E** | Commercial steps advanced (proposal sent / procurement / paid pilot signed) | 3/wk from Week 5 |

**Execution score = (Completed planned actions ÷ Planned actions) × 100. Target: ≥85% average.**

### Week-by-Week Plan

| Week | Focus | Key Deliverables | Success Criteria |
|---|---|---|---|
| **1** | Baseline + positioning | ICP doc (2–3 segments), proof-event template, metrics dashboard, OWASP/NIST security one-pager | 50-account target list, 12 discovery calls booked, scorecard live |
| **2** | Pipeline launch | Demo script, design partner agreement, ROI hypothesis sheet | 12 discovery calls held, 6 demos, 3 pilot candidates qualified |
| **3** | First pilots live | 2 pilots started, evidence export v1 (JSON + signer + timestamps), incident diary template | 2 pilots live, ≥5 proof events, p95 latency measured |
| **4** | Proof events weekly | Customer-validated "risk prevented" narratives, approval mode if missing, fail-closed behaviour documented | ≥10 proof events, customer signs off on "prevented incident" statement |
| **5** | First paid motions | Pricing v1 (2 tiers + enterprise), proposal template, security questionnaire pack | ≥3 commercial steps, first paid contract in flight |
| **6** | Repeatable onboarding | 30-min onboarding runbook, trust score explainer, 2 more pilots started | 4 pilots active, time-to-first-proof <7 days |
| **7** | Conversions accelerate | First closed-won deal, expansion packaging v1, public sanitised case study | ≥$100K contracted ARR cumulative, 1 case study ready |
| **8** | Playbook formation | Tightened qualification rubric, partner channel motion (Composio, LangChain communities), investor metric definitions | Pipeline quality improves, ≥5 partner calls |
| **9** | Compliance narrative | NIST AI RMF alignment matrix, incident response and audit log retention options, SIEM export if demanded | Security review cycle time drops, buyers accept evidence model |
| **10** | Fundraise assets | Investor deck v1, metrics pack, customer references list, valuation narrative anchored to Bessemer/Wiz/Cursor benchmarks | Investor materials complete, target investor list built |
| **11** | Investor meetings | 5+ investor calls while still selling, 2 more closes, formalised sales stages | ≥5 investor meetings, ≥2 deals in legal/procurement |
| **12** | Cycle close | Signed contracts, retrospective, next-cycle plan | Contracted ARR at target, execution score ≥85% average |

### Fundraising Milestones (Investor-Facing Checkpoints)

**By Week 4:**
- 2 pilots live
- ≥10 proof events produced
- Evidence export demonstrated
- p95 latency and fail-closed behaviour measured

**By Week 8:**
- First paid contract signed (or paid pilot at minimum)
- 3–5 pilots active
- Repeatable onboarding playbook
- Security narrative aligned to OWASP LLM08/07/05 and NIST language

**By Week 12:**
- Contracted ARR run-rate at $3M target
- Documented sales stage funnel with conversion metrics
- 2 referenceable customers
- Category story: "verification layer for agent actions" + "PR governance wedge"

---

## Weekly Operating Rhythm

### Every Week — Non-Negotiable

| Cadence | When | Duration | Purpose |
|---|---|---|---|
| Weekly planning | Sunday PM / Monday AM | 45 min | Review last score, time-block week's highest-leverage tactics |
| Exec WAM | Monday | 20 min | Metrics-first accountability: results → execution score → lead measures → one constraint → commitments |
| Mid-week check | Wednesday | 15 min | On track for lead measures? At ≥50% planned actions? What gets dropped/escalated? |
| Score reporting | Friday | 15 min | Publish: execution %, lead measures hit/miss, pipeline movement, proof events |

### Exec WAM Agenda (20 minutes)

1. Results: actual vs lag goal trend
2. Execution score: each leader (60–90 seconds, facts only)
3. Lead measures: hit/miss + why (no storytelling)
4. One constraint: what is blocking and what decision is needed today
5. Commitments: what actions will be complete by next WAM

---

## Immediate Sprint Priorities (Current Week)

| Priority | Action | Deadline |
|---|---|---|
| **P0** | Outreach to Composio/Karan with PASS/BLOCK demo link + txhash | 48 hours |
| **P0** | Ship shareable audit page on inntris.com (public, read-only, beautiful) | 1 week |
| **P1** | Add Stripe — free → paid upgrade flow | 1 week |
| **P1** | Post on LinkedIn/X: "We verified an agent PR, here's the receipt" | 72 hours |
| **P2** | List inntris-verify on GitHub Marketplace (official) | 2 weeks |

---

## Open Architecture Questions (Resolve This Week)

1. What fields does a verified PR audit record store in Postgres?
2. Is there an existing public-facing route on FastAPI or is everything auth-gated?
3. Stripe — existing account connected or starting from zero?

---

## Risks and Mitigations

### Go-to-Market Risks

**Enterprise sales cycles too slow for runway**
- Mitigation: sell "paid pilots" with fixed scope and timebox; price meaningfully enough to count as ARR
- Early warning: demos high but pilots low; stage times keep expanding

**Chasing too many use cases, failing to dominate one wedge**
- Mitigation: for 12 weeks, wedge is strict — PR governance + action verification for highest-risk tool calls (payments, data export, admin)
- Early warning: building integrations that don't directly increase pilots or conversions

### Product and Trust Risks

**False positives block real work, create backlash**
- Mitigation: tiered enforcement modes (warn/approve/block), fast policy tuning turnaround
- Early warning: pilot stakeholders trying to bypass the system; usage drops after install

**Audit/evidence claims not believable under scrutiny**
- Mitigation: make "audit completeness" measurable; expose cryptographic verification and log anchoring clearly; do NOT over-promise legal admissibility
- Early warning: security teams request detail and you can't answer quickly

### Competitive Risks

**Larger vendors integrate basic guardrails, commoditise Inntris**
- Mitigation: differentiate on independence — cross-framework verification + cryptographic identity + tamper-evident evidence is NOT a content filter
- NIST and OWASP language positions this as a governance necessity, not a feature
- Early warning: buyers compare you to content safety filters

**MCP tool boundaries create new attack surfaces**
- Mitigation: treat tool boundaries as PEPs; maintain strict allowlist; keep verification fail-closed
- Early warning: agent achieves side effects without a successful verification call

### Contingency Plans

**Miss $0.3M conservative by Week 8:**
Narrow to one vertical (fintech, procurement, DevSecOps); increase paid pilot pricing; replace low-intent leads with referrals/partners.

**Hit ARR but pilots churn:**
Shift cycle goal from new logos to conversion + retention; instrument usage; fix root cause (false positives, latency, unclear ROI).

**Strongest pull is general agent verification, not PR governance:**
Keep PR governance as proof demo; sell the broader trust layer (identity + policy + proof) to teams deploying agents for payments, data export, and external APIs.

---

## The One-Sentence Pitch

> "AI agents are writing your production code. Inntris is the cryptographic proof of what they actually did."

---

## Acquisition Thesis (24-Month Horizon)

**Likely acquirers and why:**

| Acquirer | Why They Buy Inntris | Est. Multiple |
|---|---|---|
| GitHub / Microsoft | Becomes native to every AI PR workflow globally | $2–5B |
| Google (via DeepMind) | Agent accountability layer for Gemini ecosystem | $2–4B |
| Coinbase / Base | Flagship enterprise use case for Base L2 | $500M–2B |
| Palo Alto / CrowdStrike | AI agent security = next frontier of their market | $1–3B |
| ServiceNow / Salesforce | Compliance + audit layer for enterprise AI agents | $1–2B |

**Wiz sold for $32B after solving cloud visibility. Inntris solves AI agent accountability. The ceiling is higher because the market is larger and earlier.**

---

## North Star Metric

**Verified agent actions per month (on-chain).**
Everything else — revenue, badge installs, enterprise contracts — is downstream of this number.
When this number is in the hundreds of millions, Inntris is infrastructure. Infrastructure gets acquired or IPOs.
