"""
Generate PASS and BLOCK receipts on the live mainnet-anchored API.

Usage:
    python scripts/generate_mainnet_receipts.py --api-url https://api.inntris.com --admin-key YOUR_MASTER_ADMIN_KEY

The script will:
1. Create a temporary org + agent
2. Submit a PASS verification (small amount, within limits)
3. Submit a BLOCK verification (amount exceeds per-action limit)
4. Print both audit IDs — these are your new mainnet receipt IDs
"""

import argparse
import hashlib
import json
import base64
import sys
from datetime import datetime, timezone
from uuid import uuid4

try:
    import requests
    from nacl.signing import SigningKey
except ImportError:
    print("Missing dependencies. Run: pip install requests pynacl")
    sys.exit(1)


def compute_hash(data: dict) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def submit_verification(api_url: str, agent_id: str, signing_key: SigningKey,
                        action_type: str, payload: dict) -> dict:
    nonce = str(uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    payload_hash = compute_hash(payload)
    signing_data = {
        "agent_id": agent_id,
        "action_type": action_type,
        "payload_hash": payload_hash,
        "nonce": nonce,
        "timestamp": timestamp,
    }
    action_hash = compute_hash(signing_data)

    signature = signing_key.sign(bytes.fromhex(action_hash)).signature
    signature_b64 = base64.b64encode(signature).decode()

    response = requests.post(
        f"{api_url}/verify",
        headers={"Content-Type": "application/json"},
        json={
            "agent_id": agent_id,
            "action_type": action_type,
            "payload": payload,
            "nonce": nonce,
            "timestamp": timestamp,
            "signature": signature_b64,
        },
        timeout=30,
    )

    if response.status_code != 200:
        print(f"  ERROR {response.status_code}: {response.text}")
        sys.exit(1)

    return response.json()


def main():
    parser = argparse.ArgumentParser(description="Generate mainnet PASS and BLOCK receipts")
    parser.add_argument("--api-url", required=True, help="e.g. https://api.inntris.com")
    parser.add_argument("--admin-key", required=True, help="Your MASTER_ADMIN_KEY")
    args = parser.parse_args()

    api_url = args.api_url.rstrip("/")

    # --- Health check ---
    print(f"\nChecking {api_url}/health ...")
    health = requests.get(f"{api_url}/health", timeout=10)
    if health.status_code != 200:
        print(f"  API not healthy: {health.status_code}")
        sys.exit(1)
    print("  OK")

    # --- Create org ---
    print("\nCreating temporary organization...")
    org_resp = requests.post(
        f"{api_url}/admin/organizations",
        headers={"Content-Type": "application/json", "X-Admin-Key": args.admin_key},
        json={
            "name": f"Mainnet Receipt Gen {uuid4().hex[:8]}",
            "contact_email": "receipts@inntris.com",
            "billing_tier": "professional",
        },
        timeout=30,
    )
    if org_resp.status_code != 200:
        print(f"  ERROR: {org_resp.status_code} - {org_resp.text}")
        sys.exit(1)

    org_data = org_resp.json()
    api_key = org_data["api_key"]
    org_id = org_data["id"]
    print(f"  Org ID: {org_id}")

    # --- Generate keypair ---
    signing_key = SigningKey.generate()
    public_key_b64 = base64.b64encode(bytes(signing_key.verify_key)).decode()

    # --- Create agent with low per-action limit ($50) so we can trigger BLOCK ---
    print("Creating agent (per-action limit: $50)...")
    agent_resp = requests.post(
        f"{api_url}/admin/agents",
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        json={
            "org_id": org_id,
            "name": "Mainnet Receipt Agent",
            "public_key": public_key_b64,
            "daily_limit_usd": 500,
            "per_action_limit_usd": 50,
            "rate_limit_per_minute": 60,
            "allowed_actions": ["financial_transaction", "api_call"],
        },
        timeout=30,
    )
    if agent_resp.status_code != 200:
        print(f"  ERROR: {agent_resp.status_code} - {agent_resp.text}")
        sys.exit(1)

    agent_id = agent_resp.json()["id"]
    print(f"  Agent ID: {agent_id}")

    # --- PASS receipt: $25 transaction (under $50 limit) ---
    print("\nSubmitting PASS verification ($25 transaction)...")
    pass_result = submit_verification(
        api_url=api_url,
        agent_id=agent_id,
        signing_key=signing_key,
        action_type="financial_transaction",
        payload={"amount": 25.00, "currency": "USD", "recipient": "vendor_001",
                 "description": "Mainnet verification test - approved"},
    )
    pass_verdict = pass_result.get("verdict", "unknown")
    pass_audit_id = pass_result.get("audit_id", "unknown")
    print(f"  Verdict: {pass_verdict}")
    print(f"  Audit ID: {pass_audit_id}")

    # --- BLOCK receipt: $75 transaction (exceeds $50 limit) ---
    print("\nSubmitting BLOCK verification ($75 transaction, exceeds $50 limit)...")
    block_result = submit_verification(
        api_url=api_url,
        agent_id=agent_id,
        signing_key=signing_key,
        action_type="financial_transaction",
        payload={"amount": 75.00, "currency": "USD", "recipient": "vendor_002",
                 "description": "Mainnet verification test - blocked"},
    )
    block_verdict = block_result.get("verdict", "unknown")
    block_audit_id = block_result.get("audit_id", "unknown")
    print(f"  Verdict: {block_verdict}")
    print(f"  Audit ID: {block_audit_id}")
    if "verdict_reason" in block_result:
        print(f"  Reason: {block_result['verdict_reason']}")

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
    print(f"\n  NOTE: Receipts will be anchored on-chain within ~60 minutes")
    print(f"        (next anchor worker batch run).")
    print(f"        After anchoring, verify pages will show BaseScan links")
    print(f"        pointing to basescan.org (Base Mainnet).")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
