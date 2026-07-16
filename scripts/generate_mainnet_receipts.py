"""
Generate PASS and BLOCK receipts on the live mainnet-anchored API.

The agent is registered and explicitly promoted through the audited admin API,
then verifications are submitted through the public API.

Usage:
    export INNTRIS_ADMIN_API_KEY="inntris_live_sk_..."
    python scripts/generate_mainnet_receipts.py --api-url https://api.inntris.com

The admin key must belong to the organisation that will own the receipts.
"""

import argparse
import base64
import hashlib
import os
import sys

# Allow `import api...` when run as `python scripts/generate_mainnet_receipts.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import requests
    from nacl.signing import SigningKey
except ImportError:
    print("Missing dependencies. Run: pip install requests pynacl")
    sys.exit(1)

from api.agent_client import build_signed_verify_request

# Demo policy for the canonical homepage receipts. Per the architectural rule
# the backend never sees the raw YAML — only the SHA-256 hex of it. Computing
# the hash here mirrors what the GitHub Action does in production.
DEMO_POLICY_YAML = """\
version: 1
agent: mainnet-receipt-agent
limits:
  per_action_usd: 50
  daily_usd: 500
  rate_per_minute: 60
allowed_actions:
  - financial_transaction
  - api_call
"""
DEMO_POLICY_HASH = hashlib.sha256(DEMO_POLICY_YAML.encode("utf-8")).hexdigest()


def submit_verification(api_url: str, agent_id: str, signing_key: SigningKey,
                        action_type: str, payload: dict,
                        policy_hash: str) -> dict:
    # Signed by the shared product client — same canonicalization the server
    # verifies against (and the same path the MCP tool uses).
    request_body = build_signed_verify_request(
        agent_id=agent_id,
        signing_key=signing_key,
        action_type=action_type,
        payload=payload,
        policy_hash=policy_hash,
    )

    response = requests.post(
        f"{api_url}/verify",
        headers={"Content-Type": "application/json"},
        json=request_body,
        timeout=30,
    )

    # 200 = approved, 403 = blocked (policy violation), 429 = rate limited
    # All three are valid verdicts that create audit log entries
    if response.status_code == 200:
        return response.json()
    elif response.status_code in (403, 429):
        # Blocked/rate-limited: the audit log was created but the API returns an error
        # We need to fetch the audit_id from the database
        return {"verdict": "blocked", "detail": response.json().get("detail", ""), "_status": response.status_code}
    else:
        print(f"  ERROR {response.status_code}: {response.text}")
        sys.exit(1)


def _require(response, operation: str, expected: tuple[int, ...] = (200,)) -> dict:
    if response.status_code not in expected:
        print(f"  ERROR: {operation} failed ({response.status_code}): {response.text}")
        sys.exit(1)
    return response.json()


def setup_agent(api_url: str, api_key: str, signing_key: SigningKey) -> str:
    """Register, configure and explicitly approve the receipt agent."""
    headers = {"Content-Type": "application/json", "X-API-Key": api_key}
    org = _require(
        requests.get(f"{api_url}/admin/organization", headers=headers, timeout=15),
        "resolve organisation",
    )
    public_key = base64.b64encode(bytes(signing_key.verify_key)).decode("ascii")
    created = _require(
        requests.post(
            f"{api_url}/admin/agents",
            headers=headers,
            json={
                "org_id": org["id"],
                "name": "Mainnet Receipt Agent",
                "public_key": public_key,
                "daily_limit_usd": 500,
                "per_action_limit_usd": 50,
                "allowed_actions": ["financial_transaction", "api_call"],
                "metadata": {"description": "Agent for mainnet receipt generation"},
            },
            timeout=15,
        ),
        "register agent",
        (200, 201),
    )
    agent_id = created["agent_id"]
    _require(
        requests.patch(
            f"{api_url}/admin/agents/{agent_id}",
            headers=headers,
            json={"trust_score": 85, "rate_limit_per_minute": 60},
            timeout=15,
        ),
        "configure agent",
    )
    _require(
        requests.post(
            f"{api_url}/admin/agents/{agent_id}/promote",
            headers=headers,
            json={"approval_reference": f"mainnet-receipt-generation:{agent_id}"},
            timeout=15,
        ),
        "promote agent",
    )
    print(f"  Created and production-approved agent: {agent_id}")
    return agent_id


def fetch_latest_audit_id(
    api_url: str, api_key: str, agent_id: str, verdict: str
) -> str:
    """Fetch the most recent audit log ID through the tenant admin API."""
    result = _require(
        requests.get(
            f"{api_url}/admin/audit/search",
            headers={"X-API-Key": api_key},
            params={"agent_id": agent_id, "verdict": verdict, "limit": 1},
            timeout=15,
        ),
        "fetch audit receipt",
    )
    logs = result.get("logs") or []
    if not logs:
        print(f"  ERROR: No {verdict} audit log found for agent {agent_id}")
        sys.exit(1)
    return str(logs[0]["id"])


def main():
    parser = argparse.ArgumentParser(description="Generate mainnet PASS and BLOCK receipts")
    parser.add_argument("--api-url", required=True, help="e.g. https://api.inntris.com")
    parser.add_argument(
        "--api-key",
        default=os.getenv("INNTRIS_ADMIN_API_KEY", ""),
        help="Admin-scoped organisation key (or INNTRIS_ADMIN_API_KEY)",
    )
    args = parser.parse_args()
    if not args.api_key:
        parser.error("--api-key or INNTRIS_ADMIN_API_KEY is required")

    api_url = args.api_url.rstrip("/")

    # --- Health check ---
    print(f"\nChecking {api_url}/health ...")
    health = requests.get(f"{api_url}/health", timeout=10)
    if health.status_code != 200:
        print(f"  API not healthy: {health.status_code}")
        sys.exit(1)
    print("  OK")

    # --- Generate keypair ---
    signing_key = SigningKey.generate()
    print("\nGenerated Ed25519 keypair")
    print(f"Demo policy hash: {DEMO_POLICY_HASH}")

    # --- Register and approve agent through the audited admin API ---
    print("Setting up agent through the admin API...")
    agent_id = setup_agent(api_url, args.api_key, signing_key)

    # --- PASS receipt: $25 transaction (under $50 limit) ---
    print("\nSubmitting PASS verification ($25 transaction)...")
    pass_result = submit_verification(
        api_url=api_url,
        agent_id=agent_id,
        signing_key=signing_key,
        action_type="financial_transaction",
        payload={"amount": 25.00, "currency": "USD", "recipient": "vendor_001",
                 "description": "Mainnet verification test - approved"},
        policy_hash=DEMO_POLICY_HASH,
    )
    pass_verdict = pass_result.get("verdict", "unknown")
    pass_audit_id = pass_result.get("audit_id", "unknown")
    print(f"  Verdict: {pass_verdict}")
    print(f"  Audit ID: {pass_audit_id}")

    # --- BLOCK receipt: $75 transaction (exceeds $50 limit) ---
    # The API returns 403 for blocked actions, but still creates an audit log.
    # We fetch the audit_id from the database after submission.
    print("\nSubmitting BLOCK verification ($75 transaction, exceeds $50 limit)...")
    block_result = submit_verification(
        api_url=api_url,
        agent_id=agent_id,
        signing_key=signing_key,
        action_type="financial_transaction",
        payload={"amount": 75.00, "currency": "USD", "recipient": "vendor_002",
                 "description": "Mainnet verification test - blocked"},
        policy_hash=DEMO_POLICY_HASH,
    )
    block_verdict = block_result.get("verdict", "unknown")
    block_detail = block_result.get("detail", "")
    print(f"  Verdict: {block_verdict}")
    if block_detail:
        print(f"  Reason: {block_detail}")

    # Fetch the BLOCK audit_id through the tenant admin API.
    print("  Fetching BLOCK audit ID from admin audit search...")
    block_audit_id = fetch_latest_audit_id(
        api_url, args.api_key, agent_id, "blocked"
    )
    print(f"  Audit ID: {block_audit_id}")

    # --- Summary ---
    print("\n" + "=" * 60)
    print("  MAINNET RECEIPT GENERATION COMPLETE")
    print("=" * 60)
    print(f"\n  PASS receipt:  {pass_audit_id}")
    print(f"    Verdict:     {pass_verdict}")
    print(f"    Verify URL:  https://inntris.com/verify/{pass_audit_id}")
    print(f"\n  BLOCK receipt: {block_audit_id}")
    print(f"    Verdict:     {block_verdict}")
    print(f"    Verify URL:  https://inntris.com/verify/{block_audit_id}")
    print("\n  NOTE: Receipts will be anchored on-chain within ~60 minutes")
    print("        (next anchor worker batch run).")
    print("        After anchoring, verify pages will show BaseScan links")
    print("        pointing to basescan.org (Base Mainnet).")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
