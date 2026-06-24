#!/usr/bin/env python3
"""
Inntris — Four Agent-Governance Scenarios (live, screen-recordable PoC).

One driver, four enterprise scenarios, all riding the same verify-before-execute
primitive: POST /verify -> PolicyEngine -> a signed, publicly verifiable receipt.

  card        Use case 1 — Agent card spend control
  treasury    Use case 2 — Stablecoin (USDC) treasury movement
  accounting  Use case 3 — Accounting agent decisions (attestation + tamper-evidence)
  refund      Use case 4 — Refund abuse prevention
  all         run all four, in order

Each scenario provisions its own agent(s) through the **real Inntris admin API**
and then drives the **real Inntris agent client** (``api.agent_client``) — the same
signing path the MCP ``inntris_guard`` tool uses. There is no cryptography in this
file; if the product's signing changes, this demo changes with it.

For an APPROVED action the demo also runs the downstream *execute gate*: it hands
the approval token back to ``POST /verify-token`` and only "executes" when the
token verifies and is cryptographically bound to *exactly this* action.

This runs against the **live hosted Inntris API** (default https://api.inntris.com)
— nothing local. It authenticates with an **admin-scoped API key for your own
organization** and provisions throwaway demo agents under that org (the same
production-safe pattern as scripts/demo_verification.py). It never creates tenants
and needs no operator master key.

Run
---
    export INNTRIS_ADMIN_API_KEY=...        # admin-scoped key for your org
    python scripts/usecase_poc_demo.py --scenario all
    python scripts/usecase_poc_demo.py --scenario refund

Env:
    INNTRIS_ADMIN_API_KEY   required — admin-scoped API key for your org
    INNTRIS_API_URL         default https://api.inntris.com
    INNTRIS_APP_URL         web app that renders /verify/{id} (default inntris.com)

Layer 2 (the ``card`` scenario): after the execute gate passes, a downstream
MoonPay executor runs — simulated by default (``--execution-mode mock``) or via the
MoonPay CLI (``--execution-mode moonpay-cli``). Execution never happens before
Inntris approves, and a blocked action is never executed.

    INNTRIS_EXECUTION_MODE  mock | moonpay-cli            (default mock; or --execution-mode)
    INNTRIS_MOONPAY_CLI_BIN MoonPay CLI binary on PATH    (default "moonpay")
    INNTRIS_MOONPAY_CLI_CMD live spend command template   ({amount} {currency} {vendor}
                                                           {mcc} {wallet} {asset})
    INNTRIS_MOONPAY_LIVE    "1" to allow a real spend     (or --moonpay-live; off by default)
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys

# Allow `import api...` when run as `python scripts/usecase_poc_demo.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Windows consoles default to cp1252; force UTF-8 so output never crashes.
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

try:
    import requests
    from nacl.signing import SigningKey
except ImportError:
    print("Missing deps. Run: pip install requests pynacl")
    sys.exit(1)

from api.agent_client import build_signed_verify_request  # the real product signer

API_URL = os.environ.get("INNTRIS_API_URL", "https://api.inntris.com").rstrip("/")
ADMIN_API_KEY = os.environ.get("INNTRIS_ADMIN_API_KEY", "")
APP_URL = (os.environ.get("INNTRIS_APP_URL") or "").rstrip("/") or None

# Resolved at startup from the admin API key (the key's own organization). The
# demo provisions throwaway agents under this org; it never creates tenants.
ORG_ID = ""

# A real, Base-mainnet-anchored Inntris receipt — referenced at the end as proof
# that production receipts land on Base L2 (chain_id 8453). Anyone can verify it.
LIVE_MAINNET_RECEIPT = "3030c27c-87c4-4464-b4af-605fbe638e0e"
ANCHOR_CONTRACT = "0x0600eA15802c8d2EA429371b2EB0aacCFe321480"

# --- Layer 2: downstream MoonPay execution --------------------------------- #
# Inntris is the control plane; MoonPay is the executor. Execution runs ONLY
# after the /verify-token execute gate confirms a valid, action-bound approval —
# never before, and never for a blocked action.
EXECUTION_MODE = os.environ.get("INNTRIS_EXECUTION_MODE", "mock")  # mock | moonpay-cli
MOONPAY_LIVE = os.environ.get("INNTRIS_MOONPAY_LIVE", "").lower() in ("1", "true", "yes")
MOONPAY_CLI_BIN = os.environ.get("INNTRIS_MOONPAY_CLI_BIN", "moonpay")
# Operator-provided command template for a REAL spend, e.g.
#   "<your-moonpay-cli-command> --amount {amount} --currency {currency} --memo {vendor}"
# Placeholders available: {amount} {currency} {vendor} {mcc} {wallet} {asset}.
# Left unset, the CLI path stays a dry-run even with --moonpay-live.
MOONPAY_CLI_CMD = os.environ.get("INNTRIS_MOONPAY_CLI_CMD", "")


# --------------------------------------------------------------------------- #
# Pretty printing
# --------------------------------------------------------------------------- #
def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(f"  {text}")
    print("=" * 74)


def step(n: str, text: str) -> None:
    print(f"\n[{n}] {text}")


def kv(label: str, value, indent: int = 6) -> None:
    print(f"{' ' * indent}{label:<22}: {value}")


def verdict_line(text: str) -> None:
    print(f"\n  >>> {text}")


def die(msg: str) -> None:
    print(f"\nERROR: {msg}")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Inntris API helpers (admin provisioning + the agent's verify path)
# --------------------------------------------------------------------------- #
def preflight() -> None:
    try:
        h = requests.get(f"{API_URL}/health", timeout=5).json()
    except Exception:
        die(f"API not reachable at {API_URL} — start it first (see runbook).")
    if h.get("status") != "healthy":
        die(f"API not healthy: {h}")
    if h.get("redis") != "connected":
        die(
            f"Redis not connected (health: {h}). /verify fails closed (503) without "
            "Redis — don't record until it's green."
        )


def resolve_org(api_key: str) -> str:
    """Return the org_id that owns this admin API key (GET /admin/organization).

    Production-safe: the demo provisions throwaway agents under the API key's own
    organization rather than creating a new tenant.
    """
    r = requests.get(
        f"{API_URL}/admin/organization",
        headers={"X-API-Key": api_key},
        timeout=15,
    )
    if r.status_code != 200:
        die(
            f"could not resolve org from admin API key (HTTP {r.status_code}): {r.text}\n"
            "  The key must be admin-scoped. Set INNTRIS_ADMIN_API_KEY / --api-key."
        )
    return r.json()["id"]


def provision_agent(
    api_key: str,
    org_id: str,
    name: str,
    *,
    allowed: list[str],
    blocked: list[str] | None = None,
    per_action: float | str = 0,
    daily: float | str = 0,
    trust: int = 85,
    rate: int = 120,
    metadata: dict | None = None,
) -> tuple[str, SigningKey, str]:
    """Create -> activate -> apply trust/caps/allow-block. Returns (agent_id, key, fp).

    The private seed is generated here and never leaves the process; only the
    public key is registered.
    """
    admin = {"Content-Type": "application/json", "X-API-Key": api_key}
    signing_key = SigningKey.generate()
    public_b64 = base64.b64encode(bytes(signing_key.verify_key)).decode()

    created = requests.post(
        f"{API_URL}/admin/agents",
        headers=admin,
        json={
            "org_id": org_id,
            "name": name,
            "public_key": public_b64,
            "daily_limit_usd": daily,
            "per_action_limit_usd": per_action,
            "allowed_actions": list(allowed),
            "metadata": metadata or {"demo": True},
        },
        timeout=15,
    )
    if created.status_code not in (200, 201):
        die(f"create agent '{name}' failed (HTTP {created.status_code}): {created.text}")
    agent_id = created.json()["agent_id"]
    fingerprint = created.json().get("public_key_fingerprint", "")

    requests.patch(
        f"{API_URL}/admin/agents/{agent_id}/status",
        headers=admin,
        params={"new_status": "active"},
        timeout=15,
    )

    patch: dict = {
        "trust_score": trust,
        "allowed_actions": list(allowed),
        "rate_limit_per_minute": rate,
    }
    if blocked:
        patch["blocked_actions"] = list(blocked)
    requests.patch(f"{API_URL}/admin/agents/{agent_id}", headers=admin, json=patch, timeout=15)
    return agent_id, signing_key, fingerprint


def set_trust(api_key: str, agent_id: str, trust: int) -> None:
    requests.patch(
        f"{API_URL}/admin/agents/{agent_id}",
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        json={"trust_score": trust},
        timeout=15,
    )


def act(
    agent_id: str,
    signing_key: SigningKey,
    action_type: str,
    payload: dict,
    *,
    tamper_sig: bool = False,
) -> tuple[int, dict, dict]:
    """Sign an action with the agent key and submit it to POST /verify.

    Returns (http_status, response_json, wire_body). The wire body carries the
    exact nonce + canonical timestamp used, so the caller can re-present them to
    /verify-token for the execute gate.
    """
    body = build_signed_verify_request(
        agent_id=agent_id,
        signing_key=signing_key,
        action_type=action_type,
        payload=payload,
    )
    if tamper_sig:
        # Flip one character of the (valid) signature -> Ed25519 verify fails.
        sig = body["signature"]
        body["signature"] = ("B" if sig[0] != "B" else "A") + sig[1:]

    r = requests.post(
        f"{API_URL}/verify",
        headers={"Content-Type": "application/json"},
        json=body,
        timeout=20,
    )
    try:
        return r.status_code, r.json(), body
    except ValueError:
        return r.status_code, {"detail": r.text}, body


def execute_gate(agent_id: str, body: dict, approval_token: str | None) -> dict:
    """Downstream verify-before-execute: confirm the token authorizes THIS action.

    A real executor (card rail, treasury mover, ledger writer) calls this and
    proceeds only if ``valid`` is true and the token re-binds to the action hash.
    """
    if not approval_token:
        return {}
    r = requests.post(
        f"{API_URL}/verify-token",
        headers={"Content-Type": "application/json"},
        json={
            "approval_token": approval_token,
            "agent_id": agent_id,
            "action_type": body["action_type"],
            "payload": body["payload"],
            "nonce": body["nonce"],
            "timestamp": body["timestamp"],
            "sig_version": body.get("sig_version", 2),
        },
        timeout=15,
    )
    try:
        return r.json()
    except ValueError:
        return {}


def show_receipt(audit_id: str | None) -> dict | None:
    """Fetch + print the public (no-auth) verification receipt."""
    if not audit_id:
        return None
    r = requests.get(f"{API_URL}/public/verify/{audit_id}", timeout=15)
    if r.status_code != 200:
        kv("public receipt", f"HTTP {r.status_code} (availability/anchoring pending)")
        return None
    rec = r.json()
    kv("verdict", rec.get("verdict"))
    kv("action_type", rec.get("action_type"))
    kv("agent_id", rec.get("agent_id"))
    kv("signature_valid", rec.get("signature_valid"))
    kv("policy_hash", rec.get("policy_hash"))
    kv("action_hash", rec.get("action_hash"))
    kv("receipt_fingerprint", rec.get("receipt_fingerprint"))
    kv("schema_version", rec.get("schema_version"))
    kv("integrity_status", rec.get("integrity_status"))
    app = APP_URL or ("https://inntris.com" if "api.inntris.com" in API_URL else None)
    if app:
        kv("receipt page", f"{app}/verify/{audit_id}")
    kv("raw API receipt", f"{API_URL}/public/verify/{audit_id}")
    return rec


def latest_blocked(api_key: str, agent_id: str) -> str | None:
    """Most recent BLOCKED audit row for an agent (blocks are receipts too)."""
    r = requests.get(
        f"{API_URL}/admin/audit/search",
        headers={"X-API-Key": api_key},
        params={"agent_id": agent_id, "verdict": "blocked", "limit": 1},
        timeout=15,
    )
    if r.status_code == 200 and r.json().get("logs"):
        return r.json()["logs"][0]["id"]
    return None


def recompute_fingerprint(rec: dict) -> str:
    """Recompute the receipt fingerprint client-side from the public receipt.

    Mirrors the server's canonical field set + encoding exactly
    (api/main.py: fingerprint_payload). The timestamp on the wire is already in
    canonical UTC (``Z``) form, so it is used verbatim. Any change to who
    (agent_id), what (action_hash/action_type), which policy (policy_hash), the
    verdict, or the time breaks the match — that is the tamper-evidence.
    """
    fp_payload = {
        "action_hash": rec["action_hash"],
        "action_type": rec["action_type"],
        "agent_id": str(rec["agent_id"]),
        "audit_id": str(rec["audit_id"]),
        "policy_hash": rec.get("policy_hash"),
        "timestamp": rec["timestamp"],
        "verdict": rec["verdict"],
    }
    canonical = json.dumps(fp_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def expect_approved(code: int, j: dict, what: str) -> None:
    if code != 200 or j.get("verdict") != "approved":
        die(f"expected APPROVED for {what}, got HTTP {code}: {j}")
    verdict_line(f"APPROVED  [OK]  ({what})")


def expect_block(code: int, j: dict, want_code: int, label: str) -> None:
    if code != want_code:
        die(f"expected BLOCK HTTP {want_code} ({label}), got HTTP {code}: {j}")
    verdict_line(f"BLOCKED (HTTP {code})  [FAIL CLOSED]  — {label}")
    kv("reason", j.get("detail"))


# --------------------------------------------------------------------------- #
# Layer 2 — downstream MoonPay execution (runs only AFTER Inntris approves)
# --------------------------------------------------------------------------- #
def moonpay_execute(payload: dict, gate: dict) -> None:
    """Execute a MoonPay-style spend — only after a valid, action-bound approval.

    Inntris is the control plane; MoonPay is the executor. This is called after the
    /verify-token execute gate and refuses to do anything unless the gate confirmed
    the approval token is valid and bound to exactly this action. Modes:

      mock         MoonPay-style execution simulated (default; safe to record).
      moonpay-cli  Shell out to the MoonPay CLI (INNTRIS_MOONPAY_CLI_BIN). Dry-run
                   unless --moonpay-live AND an INNTRIS_MOONPAY_CLI_CMD template is
                   set; falls back to simulated if the CLI is not on PATH.
    """
    # Hard guard: no valid, action-bound approval => no execution. The "execute
    # only after PASS" promise is enforced here in code, not merely narrated.
    # Require action_hash_matches to be *exactly* True: a missing/None field
    # (e.g. the gate ran without action params, or a server change) must refuse,
    # not fall through on a truthy ``valid`` alone.
    if not gate.get("valid") or gate.get("action_hash_matches") is not True:
        verdict_line("MoonPay execution REFUSED — approval token not valid/bound")
        return

    amount = payload.get("amount")
    currency = payload.get("currency", "USD")
    vendor = payload.get("vendor", "merchant")
    mcc = payload.get("mcc", "----")
    intent = f"authorize ${amount} {currency} at {vendor} (mcc {mcc})"

    if EXECUTION_MODE != "moonpay-cli":
        verdict_line(f"MoonPay execution [simulated] — {intent}")
        kv("mode", "mock — MoonPay-style execution simulated (no real spend)")
        kv("ref", "MOCK-" + hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()).hexdigest()[:12])
        return

    found = shutil.which(MOONPAY_CLI_BIN)
    if not found:
        verdict_line(f"MoonPay execution [simulated] — {intent}")
        kv("mode", f"moonpay-cli requested but '{MOONPAY_CLI_BIN}' not on PATH — fell back to simulated")
        return

    if not MOONPAY_LIVE or not MOONPAY_CLI_CMD:
        verdict_line(f"MoonPay execution [dry-run] — would {intent}")
        why = "omit --moonpay-live for dry-run" if not MOONPAY_LIVE else "set INNTRIS_MOONPAY_CLI_CMD to enable"
        kv("mode", f"MoonPay CLI path — '{MOONPAY_CLI_BIN}' detected at {found}; no spend ({why})")
        return

    # Live path: run the operator-provided command template (their machine, their
    # credentials, their explicit opt-in). Keep amounts tiny; record a dry run first.
    cmd = MOONPAY_CLI_CMD.format(
        amount=amount, currency=currency, vendor=vendor, mcc=mcc,
        wallet=payload.get("wallet_address", ""),
        asset=payload.get("crypto_asset", payload.get("asset", "")),
    )
    verdict_line(f"MoonPay execution [LIVE] — {cmd}")
    try:
        out = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=60)
        kv("exit", out.returncode)
        if out.stdout.strip():
            kv("stdout", out.stdout.strip()[:300])
        if out.stderr.strip():
            kv("stderr", out.stderr.strip()[:300])
    except Exception as e:  # surface any CLI failure; never crash the demo
        kv("error", str(e))


def skip_execution() -> None:
    """Print the 'not executed' line for a blocked action (execute-after-PASS)."""
    kv("MoonPay execution", "skipped — Inntris blocked the action")


# --------------------------------------------------------------------------- #
# Use case 1 — Agent card spend control
# --------------------------------------------------------------------------- #
def scenario_card() -> None:
    banner("USE CASE 1 — AGENT CARD SPEND CONTROL")
    print(
        "\n  Before an AI agent spends on a MoonPay-style card, Inntris checks:\n"
        "  authorised agent? category allowed? amount within limit? then PASS/BLOCK.\n"
        f"  On PASS, MoonPay runs as the downstream executor (mode: {EXECUTION_MODE}); on\n"
        "  BLOCK, execution is skipped. Inntris is the control plane, not the spender."
    )
    api_key, org_id = ADMIN_API_KEY, ORG_ID
    agent_id, signing_key, fp = provision_agent(
        api_key, org_id, "Corporate Card Agent",
        allowed=["financial_transaction"],
        per_action=100, daily=500, trust=85,
        metadata={"integration": "moonagents-card", "demo": True},
    )
    kv("agent_id", agent_id)
    kv("key_fingerprint", (fp or "")[:32] + "…")
    kv("policy", "allow financial_transaction; $100/action; $500/day; trust 85")

    # A — authorised, in-policy purchase -> APPROVED -> execute gate -> MoonPay.
    step("A", "Authorised $49.99 card purchase at an allowed vendor")
    card_payload = {
        "amount": 49.99, "currency": "USD", "vendor": "github.com",
        "mcc": "5734", "description": "SaaS subscription",
    }
    code, j, body = act(agent_id, signing_key, "financial_transaction", card_payload)
    expect_approved(code, j, "in-policy card spend")
    kv("trust_score", j.get("trust_score"))
    kv("audit_id", j.get("audit_id"))
    gate = execute_gate(agent_id, body, j.get("approval_token"))
    kv("execute-gate valid", gate.get("valid"))
    kv("action-bound", gate.get("action_hash_matches"))
    moonpay_execute(card_payload, gate)  # Layer 2: runs only because the gate passed
    print("\n  Public, no-auth receipt (link a counterparty to this):")
    show_receipt(j.get("audit_id"))

    # B — amount over the per-action ceiling.
    step("B", "Same card, $750 purchase — over the $100 per-action ceiling")
    code, j, _ = act(agent_id, signing_key, "financial_transaction", {
        "amount": 750.0, "currency": "USD", "vendor": "github.com", "mcc": "5734",
    })
    expect_block(code, j, 403, "per_action_limit_exceeded")
    skip_execution()

    # C — category (action type) not authorised for this agent.
    step("C", "Card agent attempts admin_action — a category it was never granted")
    code, j, _ = act(agent_id, signing_key, "admin_action", {"operation": "disable_2fa"})
    expect_block(code, j, 403, "action_not_allowed (category not authorised)")
    skip_execution()

    # D — tampered signature (impersonation).
    step("D", "Tampered signature — an impersonation attempt")
    code, j, _ = act(agent_id, signing_key, "financial_transaction",
                     {"amount": 20.0, "currency": "USD", "vendor": "github.com"},
                     tamper_sig=True)
    expect_block(code, j, 401, "signature_invalid (identity check failed)")
    skip_execution()

    bid = latest_blocked(api_key, agent_id)
    if bid:
        print("\n  Every BLOCK is itself a signed, queryable receipt:")
        show_receipt(bid)


# --------------------------------------------------------------------------- #
# Use case 2 — Stablecoin (USDC) treasury movement
# --------------------------------------------------------------------------- #
def scenario_treasury() -> None:
    banner("USE CASE 2 — STABLECOIN (USDC) TREASURY MOVEMENT")
    print(
        "\n  Before an agent moves USDC, Inntris checks treasury policy, amount\n"
        "  thresholds, and agent trust — large moves fail closed."
    )
    api_key, org_id = ADMIN_API_KEY, ORG_ID
    agent_id, signing_key, fp = provision_agent(
        api_key, org_id, "Treasury Movement Agent",
        allowed=["financial_transaction"],
        per_action=2000, daily=3000, trust=85,
        metadata={"integration": "treasury-ops", "asset": "USDC"},
    )
    kv("agent_id", agent_id)
    kv("policy", "allow financial_transaction; $2,000/action; $3,000/day; trust 85")

    # A — in-policy move -> APPROVED + execute gate.
    step("A", "Move $1,500 USDC to an approved ops wallet")
    code, j, body = act(agent_id, signing_key, "financial_transaction", {
        "amount": 1500.0, "asset": "USDC", "chain": "base",
        "to_wallet": "0xOPS00000000000000000000000000000000000A1",
        "business_purpose": "vendor_payment_2026Q2",
    })
    expect_approved(code, j, "in-policy treasury move")
    kv("audit_id", j.get("audit_id"))
    kv("daily_remaining", (j.get("limits_remaining") or {}).get("daily_remaining_usd"))
    gate = execute_gate(agent_id, body, j.get("approval_token"))
    kv("execute-gate valid", gate.get("valid"))
    show_receipt(j.get("audit_id"))

    # B — over the per-action ceiling ("requires stronger approval").
    step("B", "Move $5,000 USDC — above the $2,000 ceiling (needs stronger approval)")
    code, j, _ = act(agent_id, signing_key, "financial_transaction", {
        "amount": 5000.0, "asset": "USDC", "chain": "base",
        "to_wallet": "0xOPS00000000000000000000000000000000000A1",
        "business_purpose": "large_settlement",
    })
    expect_block(code, j, 403, "per_action_limit_exceeded (fail closed above ceiling)")

    # C — cumulative daily ceiling.
    step("C", "Keep moving $1,500 — the move that crosses the $3,000 daily ceiling is blocked")
    code, j, _ = act(agent_id, signing_key, "financial_transaction", {
        "amount": 1500.0, "asset": "USDC", "chain": "base",
        "to_wallet": "0xOPS00000000000000000000000000000000000A1",
        "business_purpose": "second_move",
    })
    expect_approved(code, j, "second $1,500 move (cumulative now at the $3,000 ceiling)")
    code, j, _ = act(agent_id, signing_key, "financial_transaction", {
        "amount": 1500.0, "asset": "USDC", "chain": "base",
        "to_wallet": "0xOPS00000000000000000000000000000000000A1",
        "business_purpose": "third_move",
    })
    expect_block(code, j, 403, "daily_limit_exceeded")

    # D — compromised-agent drill: demote trust below the financial threshold (30).
    step("D", "Compromised-agent drill: demote trust to 25; treasury moves now fail the threshold")
    set_trust(api_key, agent_id, 25)
    code, j, _ = act(agent_id, signing_key, "financial_transaction", {
        "amount": 50.0, "asset": "USDC", "chain": "base",
        "to_wallet": "0xOPS00000000000000000000000000000000000A1",
        "business_purpose": "tiny_move",
    })
    expect_block(code, j, 403, "trust_score_too_low (financial threshold is 30)")


# --------------------------------------------------------------------------- #
# Use case 3 — Accounting agent decisions (attestation + tamper-evidence)
# --------------------------------------------------------------------------- #
def scenario_accounting() -> None:
    banner("USE CASE 3 — ACCOUNTING AGENT DECISIONS (attestation + tamper-evidence)")
    print(
        "\n  An Entendre-style agent classifies / reconciles / closes books. Inntris\n"
        "  proves which agent decided, which policy allowed it, what was approved,\n"
        "  and whether the decision was altered later."
    )
    api_key, org_id = ADMIN_API_KEY, ORG_ID
    agent_id, signing_key, fp = provision_agent(
        api_key, org_id, "Ledger Reconciliation Agent",
        allowed=["classify_transaction", "reconcile_ledger", "close_books", "data_export"],
        per_action=0, daily=0, trust=85,
        metadata={"integration": "entendre-style-accounting"},
    )
    kv("agent_id", agent_id)
    kv("policy", "allow classify/reconcile/close/data_export; non-financial; trust 85")

    # A — record a decision -> APPROVED receipt.
    step("A", "Agent classifies a ledger entry — record the decision")
    decision = {
        "ledger_entry_id": "GL-2026-04417",
        "entry_value_usd": "12500.00",
        "classified_as": "COGS:cloud_infrastructure",
        "confidence": 0.97,
        "source": "stripe_payout_batch_88",
    }
    code, j, body = act(agent_id, signing_key, "classify_transaction", decision)
    expect_approved(code, j, "ledger classification")
    kv("audit_id", j.get("audit_id"))
    rec = show_receipt(j.get("audit_id"))

    # B — tamper-evidence: recompute the fingerprint, then mutate a field.
    if rec:
        step("B", "Prove the decision cannot be silently altered after the fact")
        mine = recompute_fingerprint(rec)
        kv("recomputed fingerprint", mine[:40] + "…")
        if mine != rec.get("receipt_fingerprint"):
            die(
                "client recompute != server receipt_fingerprint — the canonical "
                "fingerprint recipe drifted from api/main.py:fingerprint_payload. "
                "Reconcile the field set before recording (this is the tamper-evidence beat)."
            )
        kv("matches receipt", mine == rec.get("receipt_fingerprint"))
        altered = dict(rec)
        altered["verdict"] = "blocked"  # pretend someone rewrites the verdict
        mutated = recompute_fingerprint(altered)
        kv("after altering verdict", mutated[:40] + "…")
        kv("still matches?", mutated == rec.get("receipt_fingerprint"))
        verdict_line("Any change to who/what/which-policy/verdict breaks the fingerprint [TAMPER-EVIDENT]")

    # C — a different, low-trust agent cannot export the closed books.
    step("C", "A low-trust helper agent attempts data_export of the closed books")
    low_id, low_sk, _ = provision_agent(
        api_key, org_id, "Untrusted Helper Agent",
        allowed=["data_export", "tool_call"],
        per_action=0, daily=0, trust=25,
    )
    code, j, _ = act(low_id, low_sk, "data_export", {"report": "q2_close", "rows": 4821})
    expect_block(code, j, 403, "trust_score_too_low (data_export threshold is 40)")


# --------------------------------------------------------------------------- #
# Use case 4 — Refund abuse prevention
# --------------------------------------------------------------------------- #
def scenario_refund() -> None:
    banner("USE CASE 4 — REFUND ABUSE PREVENTION")
    print(
        "\n  'An AI agent issued refunds it was not authorised to issue.' Inntris\n"
        "  verifies refund actions before execution — authorisation, caps, velocity."
    )
    api_key, org_id = ADMIN_API_KEY, ORG_ID

    # The agent that IS authorised to issue refunds (with caps).
    ref_id, ref_sk, _ = provision_agent(
        api_key, org_id, "Refund Service Agent",
        allowed=["refund_issue"],
        blocked=["financial_transaction", "admin_action", "data_export"],
        per_action=200, daily=500, trust=85,
        metadata={"integration": "refund-service"},
    )
    kv("authorised agent", f"{ref_id}")
    kv("  policy", "allow refund_issue; $200/action; $500/day; trust 85")

    # A support agent that is NOT authorised to issue refunds.
    sup_id, sup_sk, _ = provision_agent(
        api_key, org_id, "Support Chatbot Agent",
        allowed=["tool_call", "api_call"],
        per_action=0, daily=0, trust=85,
        metadata={"integration": "support-chatbot"},
    )
    kv("support agent", f"{sup_id}")
    kv("  policy", "allow tool_call/api_call only — NOT refund_issue")

    # A — authorised refund -> APPROVED + execute gate.
    step("A", "Authorised refund of $40 against a real order")
    code, j, body = act(ref_id, ref_sk, "refund_issue", {
        "amount": 40.0, "order_id": "ORD-99821", "reason": "damaged_item",
    })
    expect_approved(code, j, "authorised refund")
    kv("audit_id", j.get("audit_id"))
    gate = execute_gate(ref_id, body, j.get("approval_token"))
    kv("execute-gate valid", gate.get("valid"))
    show_receipt(j.get("audit_id"))

    # B — THE headline: an agent issues a refund it is not authorised to issue.
    step("B", "Support chatbot tries to issue a refund — it was never authorised to")
    code, j, _ = act(sup_id, sup_sk, "refund_issue", {
        "amount": 40.0, "order_id": "ORD-99821", "reason": "customer_asked_nicely",
    })
    expect_block(code, j, 403, "action_not_allowed — refund_issue not in this agent's allow-list")

    # C — authorised agent, oversized refund.
    step("C", "Authorised agent, $5,000 refund — over the $200 ceiling")
    code, j, _ = act(ref_id, ref_sk, "refund_issue", {
        "amount": 5000.0, "order_id": "ORD-00007", "reason": "vip",
    })
    expect_block(code, j, 403, "per_action_limit_exceeded")

    # D — refund-drain: many small refunds until the daily cap trips.
    step("D", "Refund-drain: keep issuing $200 refunds until the $500 daily cap trips")
    for i in range(3):
        code, j, _ = act(ref_id, ref_sk, "refund_issue", {
            "amount": 200.0, "order_id": f"ORD-DR{i}", "reason": "batch",
        })
        if code == 200:
            verdict_line(f"refund #{i + 1} of $200 APPROVED")
        else:
            verdict_line(f"refund #{i + 1} of $200 BLOCKED (HTTP {code}) — daily cap reached")
            kv("reason", j.get("detail"))
            break

    bid = latest_blocked(api_key, ref_id)
    if bid:
        print("\n  The blocked refund attempts are themselves signed receipts:")
        show_receipt(bid)


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
SCENARIOS = {
    "card": scenario_card,
    "treasury": scenario_treasury,
    "accounting": scenario_accounting,
    "refund": scenario_refund,
}


def main() -> None:
    global API_URL, ADMIN_API_KEY, ORG_ID, EXECUTION_MODE, MOONPAY_LIVE

    parser = argparse.ArgumentParser(description="Inntris four-scenario PoC driver.")
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS) + ["all"],
        default="all",
        help="Which scenario to run (default: all).",
    )
    parser.add_argument("--api-url", default=API_URL, help="Inntris API base URL.")
    parser.add_argument(
        "--api-key",
        default=ADMIN_API_KEY,
        help="Admin-scoped API key for your org (or set INNTRIS_ADMIN_API_KEY).",
    )
    parser.add_argument(
        "--execution-mode",
        choices=["mock", "moonpay-cli"],
        default=EXECUTION_MODE,
        help="Downstream executor after Inntris approves (default: mock).",
    )
    parser.add_argument(
        "--moonpay-live",
        action="store_true",
        default=MOONPAY_LIVE,
        help="Allow a REAL MoonPay CLI spend (needs moonpay-cli + INNTRIS_MOONPAY_CLI_CMD). Off by default.",
    )
    args = parser.parse_args()

    API_URL = args.api_url.rstrip("/")
    ADMIN_API_KEY = args.api_key
    EXECUTION_MODE = args.execution_mode
    MOONPAY_LIVE = args.moonpay_live
    if not ADMIN_API_KEY:
        die(
            "missing admin API key — pass --api-key or set INNTRIS_ADMIN_API_KEY.\n"
            "  This demo runs against the live Inntris API and provisions throwaway\n"
            "  agents under your organization."
        )

    banner("INNTRIS — AI AGENT GOVERNANCE  (verify-before-execute, live PoC)")
    print(
        "\n  Every action an AI agent attempts is signed with the agent's Ed25519\n"
        "  identity, checked against policy, and turned into a tamper-evident,\n"
        "  publicly verifiable receipt. PASS or BLOCK — both are auditable."
    )
    preflight()
    ORG_ID = resolve_org(ADMIN_API_KEY)
    kv("api_url", API_URL)
    kv("org_id", ORG_ID)
    live = " (LIVE spend enabled)" if (EXECUTION_MODE == "moonpay-cli" and MOONPAY_LIVE) else ""
    kv("execution_mode", EXECUTION_MODE + live)

    todo = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    for name in todo:
        SCENARIOS[name]()

    banner("RESULT")
    print(
        "  Across every scenario: an authorised, in-policy action -> APPROVED,\n"
        "  signed, publicly verifiable; an out-of-policy or unauthorised action ->\n"
        "  BLOCKED (fail closed) and still auditable. Each decision is an Ed25519-\n"
        "  signed, tamper-evident receipt; in production these batch hourly into a\n"
        "  Merkle tree anchored to Base L2 (chain_id 8453)."
    )
    print(
        "\n  MoonPay execution is the downstream consumer of the approval token —\n"
        f"  it ran in '{EXECUTION_MODE}' mode, only after the execute gate passed.\n"
        "  Vendor/MCC are captured in the signed receipt; vendor allowlists are the\n"
        "  next hard-gate extension (not enforced today)."
    )
    print("\n  Already live & anchored on Base mainnet — verify yourself:")
    kv("receipt page", f"https://inntris.com/verify/{LIVE_MAINNET_RECEIPT}")
    kv("merkle proof", f"https://api.inntris.com/public/verify/{LIVE_MAINNET_RECEIPT}/proof")
    kv("on-chain", f"https://basescan.org/address/{ANCHOR_CONTRACT}")
    print()


if __name__ == "__main__":
    main()
