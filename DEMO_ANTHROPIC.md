# Inntris Core: Anthropic Demo Package

**Prepared for:** Anthropic Partnership Discussion
**Date:** February 2026
**Presenter:** [Your Name]

---

## Executive Summary (30 seconds)

**Inntris Core** is the **VISA Network for AI Agents** — a universal verification and liability infrastructure that provides:

- **Identity**: Cryptographic proof of which agent acted (Ed25519 signatures)
- **Control**: Policy-based limits on what agents can do (spending caps, rate limits, allowlists)
- **Audit**: Court-admissible logs with blockchain proof (Merkle roots on Base L2)

**The Ask**: Position Inntris as the **recommended trust standard** for MCP-enabled agents.

---

## Part 1: Demo Script (15-20 minutes)

### Demo Flow Overview

```
1. The Problem (2 min)     → Why this matters now
2. Live Demo (10 min)      → Show the system working
3. Technical Deep-Dive (3 min) → How it works under the hood
4. Partnership Ask (3 min) → MCP integration strategy
```

---

### Scene 1: The Problem (2 minutes)

**Script:**

> "Today's AI agents are making real decisions with real consequences. They're sending emails, making purchases, calling APIs, managing finances. But there's a critical gap:
>
> - **Who** authorized this action?
> - **What** were the limits?
> - **Can we prove** what happened?
>
> When an AI agent sends a $10,000 wire transfer to the wrong account, or leaks confidential data via email, **who is liable?**
>
> Right now, the answer is: 'We don't know.' There's no industry standard for agent verification. No cryptographic identity. No audit trail that holds up in court.
>
> **Inntris solves this.**"

---

### Scene 2: Live Demo (10 minutes)

#### Setup Before Demo
1. Have terminal open with MCP server running
2. Have frontend dashboard open in browser
3. Have an agent ready to make requests

#### Demo Step 2.1: Show the Dashboard (2 min)

1. **Open Admin Console** (`/admin`)
   - Show organization overview
   - Show registered agents with trust scores
   - Show security alerts (hopefully empty!)

2. **Open Agent Portal** (`/portal`)
   - Show an agent's profile
   - Point out: Trust Score, Daily Limit, Per-Action Limit
   - Show the Ed25519 public key registered

**Script:**
> "Every agent registered with Inntris has a cryptographic identity — an Ed25519 keypair. The public key is registered here, the private key stays with the agent. This is the same cryptography used by Signal, SSH, and Solana."

#### Demo Step 2.2: Show a Successful Verification (3 min)

1. **Trigger an action** from your agent (or use the playground)
   ```
   Action: financial_transaction
   Amount: $50.00
   Recipient: demo@example.com
   ```

2. **Show the verification flow:**
   - MCP server signs the request
   - Core API verifies signature
   - Policy engine checks limits
   - Returns APPROVED

3. **Show it in the audit log:**
   - Open Audit Explorer (`/audit`)
   - Find the transaction
   - Show: timestamp, action_hash, signature, verdict, response_time

**Script:**
> "Watch what happens. The agent wants to send $50. Before it can, it MUST call `inntris_guard`. The MCP server signs the request with the agent's private key, sends it to our verification API, and gets back APPROVED or BLOCKED.
>
> This happened in [X] milliseconds. The agent can now proceed — but only because it passed verification.
>
> And here's the audit log. This is forensic-grade: timestamp, cryptographic signature, the exact payload, IP address, everything a court would need."

#### Demo Step 2.3: Show a Blocked Action (3 min)

1. **Trigger an action that violates policy:**
   ```
   Action: financial_transaction
   Amount: $5,000.00  (over the $100 per-action limit)
   ```

2. **Show the block:**
   - MCP server returns BLOCKED
   - Reason: "Amount $5000 exceeds per-action limit of $100"

3. **Show the security alert:**
   - Open Admin Console
   - Show the alert that was auto-generated
   - Show trust score decreased

**Script:**
> "Now watch what happens when someone tries to exceed their limits. This agent has a $100 per-action cap. It tries to send $5,000.
>
> BLOCKED. The action never happens. The admin gets an alert. The agent's trust score just dropped.
>
> This is fail-closed security. If verification fails, if the signature is wrong, if limits are exceeded — the action is BLOCKED. Not logged and allowed. Blocked."

#### Demo Step 2.4: Show Blockchain Anchoring (2 min)

1. **Open Audit Explorer**
   - Find a log with a Merkle proof
   - Click "Verify on Blockchain"

2. **Show the Base L2 transaction:**
   - Open Basescan
   - Show the Merkle root anchored on-chain

**Script:**
> "Every hour, we batch all audit logs, compute a Merkle root, and anchor it to Base L2. This is immutable proof. Even if someone compromises our database, the blockchain has the receipt.
>
> This log? I can prove it existed at this exact time, and it hasn't been modified since. That's the standard for legal discovery."

---

### Scene 3: Technical Architecture (3 minutes)

**Show the architecture diagram:**

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Agent (Claude, etc.)                  │
└─────────────────────────┬───────────────────────────────────┘
                          │ MCP Protocol
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   Inntris MCP Server                        │
│  • inntris_guard    - Verify before action                  │
│  • inntris_check    - Query limits & trust                  │
│  • inntris_log      - Audit without verification            │
│                                                             │
│  Ed25519 Signing ─── SHA-256 Hashing ─── Nonce Protection  │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTPS
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   Core Enforcer API                         │
│  • Signature Verification (Ed25519)                         │
│  • Policy Engine (limits, allowlists, trust scores)         │
│  • Replay Protection (Redis nonce cache)                    │
│  • Audit Logging (append-only PostgreSQL)                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
    PostgreSQL        Redis         Base L2
    (Audit Logs)     (Nonces)    (Merkle Anchors)
```

**Script:**
> "The architecture is simple but powerful. The MCP server is the universal adapter — it works with any MCP-compatible agent. Claude, Lovable, Replit, LangChain, anything.
>
> The Core API is the 'central bank' — it verifies signatures, enforces policies, and logs everything. Sub-100ms latency.
>
> Everything is cryptographically secured. Ed25519 signatures prove identity. SHA-256 hashes prove integrity. Nonces prevent replay attacks. Blockchain anchoring proves immutability."

---

### Scene 4: The Partnership Ask (3 minutes)

**Script:**
> "Here's where Anthropic comes in.
>
> MCP is becoming the standard for agent interoperability. But there's no standard for agent TRUST. When an MCP-enabled agent wants to do something consequential, how does the world know it's authorized?
>
> We want to be that standard.
>
> **Our ask:**
> 1. **Recommended Integration**: Position Inntris as the recommended trust verification layer for MCP agents handling sensitive actions
> 2. **Documentation**: Include Inntris in MCP best practices for financial transactions, data access, and external communications
> 3. **Co-marketing**: Joint announcement about agent safety infrastructure
>
> **What you get:**
> - Every MCP agent using Inntris becomes more trustworthy
> - Enterprise customers get the compliance infrastructure they need
> - The MCP ecosystem has a liability answer
>
> We're not asking for exclusivity. We're asking to be the recommended solution for a problem that MUST be solved."

---

## Part 2: Value Proposition

### The Core Problem

| Stakeholder | Pain Point | Cost |
|-------------|-----------|------|
| **Enterprises** | No audit trail for AI actions | Compliance failures, legal liability |
| **Developers** | No standard way to limit agent capabilities | Runaway agents, security breaches |
| **Users** | No way to verify agent trustworthiness | Fraud, unauthorized actions |
| **Regulators** | No framework for AI accountability | Policy uncertainty |

### The Inntris Solution

| Capability | Description | Benefit |
|-----------|-------------|---------|
| **Cryptographic Identity** | Ed25519 signatures for every action | Prove exactly which agent acted |
| **Policy Enforcement** | Spending limits, rate limits, allowlists | Control what agents can do |
| **Forensic Audit Trail** | Append-only logs, blockchain anchoring | Court-admissible evidence |
| **Trust Scoring** | Dynamic 0-100 score based on behavior | Automatic risk management |
| **Universal Adapter** | MCP-native integration | Works with any MCP agent |

### Competitive Positioning

| Competitor | Their Approach | Inntris Advantage |
|-----------|---------------|-------------------|
| **None (DIY)** | Build custom verification | 6+ months saved, proven security |
| **API Gateways** | Rate limiting only | No cryptographic identity, no blockchain proof |
| **Audit Services** | Post-hoc logging | No pre-execution blocking |
| **Blockchain-Only** | Everything on-chain | Too slow, too expensive for real-time |

**Inntris is the only solution that provides pre-execution verification + forensic-grade audit + blockchain anchoring + MCP-native integration.**

---

## Part 3: Rollout Proposition

### Phase 1: MCP Ecosystem (Months 1-3)

**Goal:** Become the default trust layer for MCP agents

**Tactics:**
1. **Open Source MCP Server** — Release `inntris-mcp-server` as MIT-licensed
2. **Anthropic Partnership** — Get included in MCP documentation
3. **Developer Adoption** — Target Lovable, Replit, LangChain integrations
4. **Freemium Model** — Free tier: 2 agents, 1K verifications/month

**Success Metrics:**
- 100+ registered agents
- 10+ integrations with MCP-compatible platforms
- Anthropic partnership announced

### Phase 2: Enterprise Adoption (Months 4-6)

**Goal:** Land 5-10 enterprise customers

**Tactics:**
1. **Compliance Packages** — SOC 2, GDPR, HIPAA-ready reporting
2. **Enterprise Features** — SSO, dedicated support, custom policies
3. **Case Studies** — Document early adopter success stories
4. **Sales Motion** — Target fintech, healthcare, legal tech

**Success Metrics:**
- $100K+ ARR
- 3+ enterprise contracts
- SOC 2 Type II certification in progress

### Phase 3: Industry Standard (Months 7-12)

**Goal:** Establish Inntris as THE agent verification standard

**Tactics:**
1. **Standards Body** — Propose agent verification RFC
2. **Multi-Chain** — Expand anchoring to Ethereum mainnet, Polygon
3. **API Ecosystem** — SDKs for every major language
4. **Partnerships** — Cloud provider integrations (AWS, GCP, Azure)

**Success Metrics:**
- 1,000+ registered agents
- $1M+ ARR
- Industry recognition as the standard

---

## Part 4: MCP Strategy Deep-Dive

### Why MCP is the Right Bet

1. **Anthropic Backing** — MCP is Anthropic's standard, and they're pushing it hard
2. **Growing Ecosystem** — Lovable, Replit, Cursor, and others adopting MCP
3. **No Incumbent** — No one owns "trust" in MCP yet
4. **Perfect Fit** — MCP tools are the natural place to inject verification

### Integration Strategy

**Step 1: Be the Easiest Integration**
```json
// claude_desktop_config.json
{
  "mcpServers": {
    "inntris-guard": {
      "command": "npx",
      "args": ["inntris-mcp-server"],
      "env": {
        "INNTRIS_API_KEY": "your-key"
      }
    }
  }
}
```
One line to add verification to any Claude agent.

**Step 2: Be in the Documentation**
- Work with Anthropic to include Inntris in MCP best practices
- "For financial transactions, use a verification layer like Inntris"
- "For sensitive data access, implement pre-execution verification"

**Step 3: Be the Default**
- Partner with MCP platform providers
- Pre-installed in Lovable, Replit templates
- "Batteries included" for enterprise deployments

### Messaging for MCP Community

**Tagline:** "Trust Infrastructure for MCP Agents"

**Key Messages:**
1. "Your agent is powerful. Prove it's trustworthy."
2. "MCP gives agents capabilities. Inntris gives them accountability."
3. "The missing piece for enterprise MCP adoption."

### Community Building

1. **Discord/Slack** — Inntris developer community
2. **GitHub** — Open source MCP server, examples, SDKs
3. **Blog** — Technical deep-dives on agent security
4. **Conference Talks** — Present at AI/ML conferences

---

## Part 5: Important Notes for the Meeting

### Technical Differentiators to Emphasize

1. **Fail-Closed Architecture** — If verification fails, action is BLOCKED, not logged-and-allowed
2. **Sub-100ms Latency** — Real-time verification doesn't slow down agents
3. **Cryptographic Rigor** — Ed25519 + SHA-256 + nonce protection is battle-tested
4. **Blockchain-Optional** — Anchoring adds proof but isn't required for basic operation

### Potential Objections & Responses

| Objection | Response |
|-----------|----------|
| "Why not build this in-house?" | "6+ months of security engineering vs. 1 day integration. Plus, Inntris is audited and battle-tested." |
| "Adds latency to every action" | "Sub-100ms verification. Most API calls take longer. This is negligible." |
| "Another dependency to manage" | "We're infrastructure, like Stripe for payments. You don't build your own payment processor." |
| "Blockchain is overkill" | "It's optional. But for enterprises, court-admissible proof is table stakes." |

### Questions to Ask Anthropic

1. "What's your roadmap for enterprise MCP adoption?"
2. "How are you thinking about agent accountability and trust?"
3. "Would you consider recommending verification layers in MCP documentation?"
4. "What would make Inntris the obvious choice for MCP trust infrastructure?"

### Follow-Up Actions

After the meeting:
1. Send technical documentation package
2. Offer sandbox access for their team
3. Propose joint blog post on agent safety
4. Schedule technical deep-dive with their engineering team

---

## Appendix: Quick Reference

### Key URLs
- **Live Demo**: [Your deployed URL]
- **GitHub**: [Your repo URL]
- **Documentation**: [Your docs URL]

### Key Metrics to Know
- Verification latency: <100ms p99
- Supported signatures: Ed25519
- Hash algorithm: SHA-256
- Blockchain: Base L2 (chain ID 8453)
- Audit log retention: Configurable (default: forever)

### Pricing Tiers
| Tier | Agents | Verifications/mo | Price |
|------|--------|------------------|-------|
| Free | 2 | 1,000 | $0 |
| Starter | 10 | 10,000 | $49/mo |
| Pro | 50 | 100,000 | $199/mo |
| Enterprise | Unlimited | Unlimited | Custom |

---

## Demo Checklist

Before the meeting:

- [ ] MCP server running locally
- [ ] Frontend dashboard accessible
- [ ] Test agent configured and working
- [ ] Successful verification test completed
- [ ] Blocked verification test completed
- [ ] Audit logs populated with examples
- [ ] Blockchain anchor verified on Basescan
- [ ] Backup: Screenshots/video if live demo fails

---

**Good luck with the demo!**

*"Protecting Intellect. The Universal Liability Shield for Autonomous Agents."*
