# Inntris

**Protecting Intellect.**
The universal liability shield for autonomous agents.

---

## The Problem

AI agents are taking real actions — moving money, sending email, exporting data — with **no cryptographic accountability**.

- No proof of who authorized what
- No tamper-evident audit trail
- No enforceable policy at the decision point
- Regulators, auditors, and customers can't verify agent behavior after the fact

When an agent does the wrong thing, **the operator owns the liability**.

---

## The Solution

Inntris is a **runtime verification + cryptographic audit layer** that sits in front of every consequential agent action.

1. **Verify** — Ed25519 signature, policy hash, nonce, clock-skew checks
2. **Decide** — Policy engine returns `APPROVED` (with HMAC token) or `BLOCKED`
3. **Record** — Every decision is a signed receipt, hashed into a Merkle tree every 10 minutes, **anchored to Base L2 mainnet**

Three guarantees: **Fail Closed. Zero Trust. Tamper Evident.**

---

## How It Works

```
  Agent ──▶ MCP Server ──▶ Inntris API ──▶ Policy Engine
   (LLM)      (guard)         (verify)        (allow/deny)
                                 │
                                 ▼
                          Audit Log (append-only PG)
                                 │
                                 ▼
                      Merkle batch ──▶ Base L2 anchor
                                 │
                                 ▼
                       Public receipt + trust badge
```

A single `inntris_guard` tool drops into any MCP-compatible agent (Claude, Cursor, Lovable, Replit, LangChain).

---

## Product Surface

| Component | What it is |
|---|---|
| **MCP Server** | Universal adapter — exposes `inntris_guard` tool to any agent |
| **Enforcer API** | FastAPI policy decision point — Ed25519, rate limits, trust scoring |
| **Audit Engine** | Append-only Postgres + 10-minute Merkle batches + Base L2 anchoring |
| **Trust Badge Widget** | Embeddable React component showing live agent trust score |
| **Admin Console** | Org / policy / key management, audit search, usage metrics |
| **Public Verify** | `inntris.com/verify/{id}` — anyone can independently check a receipt |

---

## Differentiators

- **Cryptographic receipts, not just logs.** Every decision is signed and blockchain-anchored — provable years later, with no trust in Inntris.
- **Fail closed by default.** Unverified agents cannot act. Most observability tools log *after* damage.
- **Policy hash binding (Schema v2).** The exact policy in effect at decision time is bound to the signed payload — compliance becomes a math proof.
- **Real-time trust scoring (0–100).** Dynamic scores with behavioral decay, exposed to downstream systems via the badge.
- **Drop-in via MCP.** No SDK lock-in — works with any MCP-compatible runtime.

---

## Technical Foundation

- **Backend:** FastAPI · Python 3.12 · Postgres + TimescaleDB · Redis
- **Frontend:** Next.js 18 · Tailwind · Trust Badge (React)
- **Crypto:** Ed25519 signatures · SHA-256 canonical leaf hashes · keccak256 Merkle tree (Solidity-native) · HMAC approval tokens
- **Chain:** Base L2 mainnet (chain 8453) · `AnchorRegistry` at `0x0600eA15…321480` · up to 1,000 logs / 10-minute batch
- **Deploy:** Docker Compose · Railway · Render · K8s-compatible (12-factor)

Canonical receipt anchored at Base block **44,401,999** — already live.

---

## Why Now

- Agentic AI is hitting production in regulated industries (finance, healthcare, gov) **faster than governance tooling exists**.
- EU AI Act, SEC, and SOC2 auditors are starting to ask: *"Show me what the agent decided, and prove it."*
- MCP just became the de-facto standard for agent tool use — the integration surface is finally stable.
- L2s made on-chain anchoring cheap enough to do **every 10 minutes, for every customer**.

---

## Market & Customer

**Who buys:**
- Enterprises deploying agents in finance, healthcare, legal, gov
- Agent platforms (Lovable, Replit-style) that need to show their users are safe
- Compliance / risk teams who today have no instrumentation

**Why they buy:**
- Convert agent liability into provable compliance
- Insurance-grade audit trails
- Customer-facing trust badges

---

## Pricing (tiers in product today)

- **Free** — developer sandbox
- **Starter** — solo builders, low volume
- **Professional** — production teams
- **Enterprise** — SLA, dedicated anchoring cadence, custom policy engine

Billing tier is a first-class entity in the data model (`api/models.py :: BillingTier`).

---

## What's Live Today

- Public API: `https://api.inntris.com` (`/health`, `/verify`, `/public/agent/{id}`, `/docs`)
- MCP server shipping the `inntris_guard` tool
- Admin console, audit explorer, public verify pages
- Trust Badge npm package (`@inntris/trust-badge`)
- Production anchor contract live on Base mainnet
- Schema v2 with policy-hash binding

---

## The Ask

**[ fill in: round size, use of funds, design partners wanted ]**

Contact: **sales@inntris.com**
