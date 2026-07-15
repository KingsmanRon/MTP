# Inntris — Four Agent-Governance Scenarios — End-to-End PoC Runbook

A live, screen-recordable demo of the four enterprise use cases, all riding the
same **verify-before-execute** primitive: an AI agent signs an action with its
own key, Inntris evaluates it against policy, and emits a **signed, publicly
verifiable receipt** — PASS or BLOCK. Authorised, in-policy actions are approved;
unauthorised or out-of-policy actions are **blocked (fail closed)** and still
auditable. The `card` scenario adds a **Layer 2 MoonPay executor** downstream of
the approval — simulated by default, or via the MoonPay CLI where available — so
the demo proves the control layer without depending on a live MoonPay spend.

Driver script: `scripts/usecase_poc_demo.py`

| Scenario | Use case | The killer beat |
|---|---|---|
| `card` | Agent card spend control | Over-limit + unauthorised-category spend → BLOCK |
| `treasury` | Stablecoin (USDC) treasury movement | Large move fails closed; trust demote blocks |
| `accounting` | Accounting agent decisions | Tamper-evidence: altered decision breaks the fingerprint |
| `refund` | Refund abuse prevention | An agent issues a refund it was never authorised to issue → BLOCK |

---

## Quickstart (copy-paste)

> Runs against the **live** API — no local stack. You need an **admin-scoped API
> key** for your org (admin portal → API Keys). The run creates real, publicly
> verifiable records (incl. one deliberate `SIGNATURE_INVALID`) under throwaway
> agents in your org.

**PowerShell** (from the repo root):

```powershell
cd C:\path\to\Inntris
$env:INNTRIS_ADMIN_API_KEY = "inntris_live_sk_********"

# sanity-run one scenario first (small blast radius)
.\.venv\Scripts\python.exe scripts\usecase_poc_demo.py --scenario card

# then the production recording set
.\.venv\Scripts\python.exe scripts\usecase_poc_demo.py --scenario all --production-demo
```

**Git Bash** — only the env line changes:

```bash
export INNTRIS_ADMIN_API_KEY=inntris_live_sk_********
.venv/Scripts/python.exe scripts/usecase_poc_demo.py --scenario card --production-demo
```

`INNTRIS_API_URL` already defaults to `https://api.inntris.com`. A bad or
under-scoped key fails fast (`could not resolve org … HTTP 401`) — that's why
`--scenario card` goes first. Full setup, troubleshooting, and cleanup are below.

---

## What it proves (the story for the recording)

1. **Identity** — every action is signed with the agent's own Ed25519 key; a
   tampered signature is rejected (`signature_invalid`, HTTP 401).
2. **Policy** — one engine, evaluated fail-closed in a fixed order: agent status →
   action-type allow/block → trust threshold → timestamp → rate limit → per-action
   cap → daily cap. The **first** failing check blocks the action.
3. **Receipt** — PASS *and* BLOCK produce an Ed25519-signed, queryable record
   carrying `verdict`, `policy_hash`, `action_hash`, `agent_id`, and a
   `receipt_fingerprint`. A non-null `policy_hash` marks it a v2 receipt — the
   decision is bound to the exact policy in force.
4. **Execute gate** — for an APPROVED action the demo hands the approval token
   back to `POST /verify-token`; the executor proceeds only when the token is
   authentic, unexpired, and re-binds to *this* action's hash.
5. **On-chain** — local receipts await anchoring; a **real Base-mainnet** receipt
   is referenced as proof anchoring works (chain_id 8453).

---

## Prerequisites

Nothing runs locally — no Docker, no database, no API process. The demo talks to
the **live hosted Inntris API** and provisions throwaway demo agents under your
own organization.

- Network access to the live API (default `https://api.inntris.com`)
- An **admin-scoped API key** for your org (admin portal → API Keys)
- Python with `requests` + `pynacl` (the repo's `.venv` already has them)

---

## 1. Point at the live API + set your key

```bash
export INNTRIS_API_URL=https://api.inntris.com         # the default; shown for clarity
export INNTRIS_ADMIN_API_KEY=inntris_live_sk_********   # admin-scoped key for your org
```

Confirm the API is healthy — **against the real URL**:

```bash
curl -s https://api.inntris.com/health
# {"status":"healthy","version":"1.0.0","database":"connected","redis":"connected",...}
```

> `redis: connected` matters: the nonce/replay check is fail-closed, so a healthy
> Redis is what lets approvals happen at all.

## 2. Run the demo

The default is sandbox mode. It creates verifiable test receipts but deliberately
refuses token consumption, downstream execution, and on-chain anchoring. Use the
explicit `--production-demo` flag for a recording that must show the execute gate
and later Base anchoring. That flag promotes only the agents created by that run
through the audited admin promotion endpoint.

All four scenarios in order:

```bash
.venv/Scripts/python.exe scripts/usecase_poc_demo.py --scenario all --production-demo
```

Or one at a time (good for focused recordings):

```bash
.venv/Scripts/python.exe scripts/usecase_poc_demo.py --scenario card --production-demo
.venv/Scripts/python.exe scripts/usecase_poc_demo.py --scenario treasury --production-demo
.venv/Scripts/python.exe scripts/usecase_poc_demo.py --scenario accounting --production-demo
.venv/Scripts/python.exe scripts/usecase_poc_demo.py --scenario refund --production-demo
```

The driver resolves your org from the admin key (`GET /admin/organization`),
provisions throwaway demo agents under it, then signs and submits actions through
the **real agent client** (`api/agent_client.py`) — the same signing path the MCP
`inntris_guard` tool uses. No cryptography lives in the demo; if the product's
signing changes, the demo changes with it. Rendered receipt pages
(`https://inntris.com/verify/{id}`) are linked automatically.

> **What this creates on the live system:** real, publicly verifiable audit
> records — APPROVED, BLOCKED, and one deliberate SIGNATURE_INVALID — under
> throwaway agents in **your** org. That is the point: the receipts are shareable.
> The agents are disposable; suspend them in the admin portal after the demo.

---

## Scenario walkthroughs

Each scenario prints provisioning, then a sequence of **beats**. Every beat is a
real signed `/verify` call; the verdict, violation, and HTTP status below are what
the policy engine actually returns.

### `card` — Agent card spend control

**Agent policy:** `allow [financial_transaction]`, `$100/action`, `$500/day`,
`trust 85`.

| Beat | Action | Verdict | Why |
|---|---|---|---|
| A | $49.99 at an allowed vendor | **APPROVED** (200) | within caps, category allowed, signature valid → approval token issued, execute gate confirms |
| B | $750 purchase | **BLOCKED** (403) | `per_action_limit_exceeded` — over the $100 ceiling |
| C | `admin_action` | **BLOCKED** (403) | `action_not_allowed` — category never granted to this agent |
| D | tampered signature | **BLOCKED** (401) | `signature_invalid` — identity check fails, trust docked −20 |

On beat A the approval token clears the execute gate and the **MoonPay executor**
runs (simulated by default); on B/C/D execution is **skipped** because Inntris
blocked the action. See *MoonPay execution (Layer 2)* below.

**Say:** "The card agent is pre-authorised for one category with hard caps. A
legit purchase clears and produces a receipt the card rail confirms before
authorising. Over-limit spend, an unauthorised category, and a forged identity all
fail closed — and each block is itself a signed receipt."

Maps your five questions → real gates: *authorised agent?* = signature + status;
*category allowed?* = action-type allow-list; *amount within limit?* = per-action +
daily caps; *user approved this type of spend?* = the allow-list + caps + trust
threshold the org configured.

### `treasury` — Stablecoin (USDC) treasury movement

**Agent policy:** `allow [financial_transaction]`, `$2,000/action`, `$3,000/day`,
`trust 85`.

| Beat | Action | Verdict | Why |
|---|---|---|---|
| A | move $1,500 USDC | **APPROVED** (200) | within thresholds; receipt records `to_wallet` + `business_purpose` |
| B | move $5,000 USDC | **BLOCKED** (403) | `per_action_limit_exceeded` — above the ceiling, the "stronger approval" line |
| C | another $1,500, then another | first **APPROVED** (at the $3k ceiling), next **BLOCKED** (403) | `daily_limit_exceeded` |
| D | trust demoted to 25, tiny move | **BLOCKED** (403) | `trust_score_too_low` — below the financial threshold (30) |

**Say:** "Treasury moves are gated by amount thresholds and agent trust. The
$2,000-per-move ceiling *is* the 'require stronger approval for large amounts'
control — above it the move fails closed. Demoting a suspected-compromised agent's
trust instantly blocks further moves without touching the caps."

> The destination wallet and business purpose are **cryptographically captured in
> the receipt** (fully attributable, non-repudiable) but are not themselves hard
> gates today — see *Scope* below.

### `accounting` — Accounting agent decisions (attestation + tamper-evidence)

**Agent policy:** `allow [classify_transaction, reconcile_ledger, close_books,
data_export]`, non-financial, `trust 85`.

| Beat | Action | Verdict | Why |
|---|---|---|---|
| A | classify a ledger entry | **APPROVED** (200) | decision recorded as a signed receipt |
| B | recompute the receipt fingerprint, then mutate a field | match → **then mismatch** | tamper-evidence: altering who/what/policy/verdict breaks the fingerprint |
| C | a separate low-trust agent exports the books | **BLOCKED** (403) | `trust_score_too_low` — `data_export` needs trust ≥ 40 |

**Say:** "For an Entendre-style agent the receipt answers four questions: **which
agent** decided (`agent_id` + valid signature), **which policy** allowed it
(`policy_hash` bound into the receipt), **what** was approved (`action_type` +
signed payload → `action_hash`), and **whether it was altered later** — beat B
recomputes the fingerprint live, then shows that changing a single field makes it
no longer match."

### `refund` — Refund abuse prevention

**Two agents:** an authorised *Refund Service Agent* (`allow [refund_issue]`,
`$200/action`, `$500/day`) and a *Support Chatbot Agent* (`allow [tool_call,
api_call]` — **not** `refund_issue`).

| Beat | Agent | Action | Verdict | Why |
|---|---|---|---|---|
| A | Refund Service | $40 refund | **APPROVED** (200) | authorised + within caps; execute gate confirms |
| B | Support Chatbot | $40 refund | **BLOCKED** (403) | `action_not_allowed` — refunds were never granted to this agent |
| C | Refund Service | $5,000 refund | **BLOCKED** (403) | `per_action_limit_exceeded` |
| D | Refund Service | repeated $200 refunds | APPROVED until cap, then **BLOCKED** (403) | `daily_limit_exceeded` |

**Say:** "This is the headline: *'an AI agent issued refunds it was not authorised
to issue.'* Beat B is exactly that — the support bot's refund is blocked because
`refund_issue` isn't in its allow-list. Oversized and high-velocity refunds from
even the authorised agent fail closed too, and every attempt is a queryable
receipt."

---

## MoonPay execution (Layer 2)

Inntris is the **control plane**; MoonPay is the **executor**. The two layers are
deliberately separate so the demo proves the control layer without depending on a
live MoonPay spend — which can be gated by KYC/KYB, card availability, funding,
region support, or CLI setup, none of which you want failing mid-recording.

The flow (the `card` scenario):

```
agent wants to spend
        |
        v
Inntris  POST /verify          -->  PASS or BLOCK   (signed receipt either way)
        | (PASS only)
        v
Inntris  POST /verify-token    -->  execute gate: token valid + bound to THIS action
        | (valid only)
        v
MoonPay execution              -->  mock  |  moonpay-cli
```

A BLOCK never reaches MoonPay — the driver prints `MoonPay execution: skipped —
Inntris blocked the action`. Execution is also hard-guarded in code:
`moonpay_execute()` refuses unless the execute gate returned `valid` and the action
is hash-bound, so "execute only after PASS" is enforced, not just narrated.

### Modes

| Mode | Flags | What runs | When |
|---|---|---|---|
| Simulated (default) | `--execution-mode mock` | A labelled MoonPay-style execution + a mock ref | Recording; no MoonPay account needed |
| MoonPay CLI (dry-run) | `--execution-mode moonpay-cli` | Detects the CLI on PATH, prints the intended spend, **no money moves** | Prove the real execution path is wired |
| MoonPay CLI (live) | `--production-demo --execution-mode moonpay-cli --moonpay-live` | Runs your `INNTRIS_MOONPAY_CLI_CMD` template | A real, **tiny**, pre-arranged spend only |

Config for the CLI path:

```bash
export INNTRIS_MOONPAY_CLI_BIN=moonpay        # binary on PATH (default "moonpay")
export INNTRIS_MOONPAY_CLI_CMD='<your-moonpay-cli-command> --amount {amount} --currency {currency} --memo {vendor}'
# placeholders: {amount} {currency} {vendor} {mcc} {wallet} {asset}
```

> The CLI command is intentionally **operator-provided** — the adapter shells out
> to *your* command rather than hard-coding a MoonPay interface that can't be
> verified here. If the CLI is absent, `moonpay-cli` falls back to simulated.

### Recording guidance

1. Record **mock** first with `--production-demo` so the execute receipt and anchor path are real.
2. If demoing the CLI, record a **dry-run** (`--production-demo --execution-mode moonpay-cli` without `--moonpay-live`).
3. Only do a real spend if it is **tiny and pre-funded**, and dry-run it first.

### The honest framing (say this)

> "This is a live Inntris control demo for MoonPay-style agent spend. The Inntris
> identity, policy, execute gate, and receipt flow are real. MoonPay execution can
> run through a CLI adapter where available, otherwise it is simulated."

Do **not** claim vendor/MCC enforcement (e.g. "Inntris blocks GitHub but allows
Vercel") — those fields are captured in the signed receipt but are not hard gates
yet. See **Scope** below; vendor allowlists are the next hard-gate extension.

---

## What Inntris returns (the artifacts on screen)

| You asked for… | Field / endpoint |
|---|---|
| PASS / BLOCK | `verdict` (`approved` / `blocked` / `rate_limited` / `signature_invalid`) |
| policy hash | `policy_hash` — SHA-256 of the agent's *effective* governing policy (status + allow/block + caps + rate + trust) at decision time |
| action hash | `action_hash` — SHA-256 over agent_id + action_type + payload hash + nonce + canonical timestamp |
| agent ID | `agent_id` |
| receipt fingerprint | `receipt_fingerprint` — SHA-256 of the canonical core fields |
| verifiable audit record | `audit_id` → `GET /public/verify/{audit_id}` + Merkle proof at `/public/verify/{audit_id}/proof` |
| (PASS only) execute gate | `approval_token` → `POST /verify-token` re-binds the token to the action hash |

---

## Verify a receipt yourself (no auth)

```bash
# The public receipt
curl -s https://api.inntris.com/public/verify/<AUDIT_ID> | python -m json.tool

# The Merkle proof (pending_anchor until the anchor worker batches to Base — default every 10 minutes)
curl -s https://api.inntris.com/public/verify/<AUDIT_ID>/proof | python -m json.tool
```

The `accounting` scenario recomputes the `receipt_fingerprint` **client-side**
from the public receipt and shows it matches the server's — then mutates one field
and shows it no longer matches. That is the tamper-evidence, demonstrated rather
than asserted.

Already live and anchored on Base mainnet (chain_id 8453):

- Receipt page — `https://inntris.com/verify/3030c27c-87c4-4464-b4af-605fbe638e0e`
- Merkle proof — `https://api.inntris.com/public/verify/3030c27c-87c4-4464-b4af-605fbe638e0e/proof`
- On-chain — `https://basescan.org/address/0x0600eA15802c8d2EA429371b2EB0aacCFe321480`

---

## Scope — hard gates vs. signed receipt metadata (be straight in the demo)

**Enforced as hard gates today:** signature validity, nonce/replay, agent status,
**action-type** allow/block, trust-score threshold (financial 30, data_export 40,
admin 70, CI/deploy 80; custom types default 20), timestamp skew (±5 min), rate
limit, per-action cap, daily cap.

**Captured in the signed, tamper-evident receipt but *not* gated:**
vendor/merchant, destination wallet, business purpose, asset, MCC/category label,
`risk_flags`. They are bound into `action_hash` and the receipt (auditable,
non-repudiable) but the engine does not block on them.

**To turn any of those into a hard gate, two paths:**
- **Zero-code** — model the distinction as a distinct `action_type` and use the
  allow/block lists + per-type trust thresholds (how `card`, `accounting`, and
  `refund` already work cleanly: category, decision type, and `refund_issue` are
  just action types).
- **Small extension** — add a check inside `PolicyEngine.evaluate()` (e.g. a
  vendor/wallet allowlist on the agent record), following the existing fail-closed
  pattern.

**One gap not to oversell:** the verdict set is `APPROVED / BLOCKED /
RATE_LIMITED / SIGNATURE_INVALID` — there is **no `ESCALATE` / step-up** verdict.
"Require stronger approval for large amounts" is expressed today as a lower cap
(hard block above it) or a higher trust threshold, not a human-in-the-loop hold.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `API not reachable` | Network/DNS, or wrong `INNTRIS_API_URL`. |
| `could not resolve org` / HTTP 401 | `INNTRIS_ADMIN_API_KEY` is missing or not admin-scoped. |
| `create agent failed` HTTP 403 | The key needs admin/`write` scope to register agents. |
| `/health` shows `redis: disconnected` | Server-side issue — `/verify` fails closed (503) without Redis; don't demo until it's green. |
| Receipt shows `integrity_status: pending_anchor` | Expected — anchoring batches to Base L2 every 10 minutes by default; the receipt is already signed and verifiable. |
| A beat asserts the wrong verdict | The driver `die()`s loudly with the HTTP status + body so you can see which gate fired. |

---

## Cleanup

Nothing local to tear down. The demo leaves throwaway agents (and their audit
records) under your org on the live system. Suspend or revoke them from the admin
portal (or `PATCH /admin/agents/{id}/status?new_status=suspended`) when you're
done; the audit receipts they produced remain valid and publicly verifiable by
design.
