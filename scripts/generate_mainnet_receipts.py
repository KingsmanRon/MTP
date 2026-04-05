"""
Generate PASS and BLOCK receipts on the live mainnet-anchored API.

This version creates the agent directly via the database (Supabase),
then submits verifications through the API.

Usage:
    python scripts/generate_mainnet_receipts.py --api-url https://api.inntris.com --database-url "postgresql://..."

Get your DATABASE_URL from Supabase → Project Settings → Database → Connection String (URI).
"""

import argparse
import asyncio
import hashlib
import json
import base64
import sys
from datetime import datetime, timezone
from uuid import uuid4

try:
    import requests
    from nacl.signing import SigningKey
    import asyncpg
except ImportError:
    print("Missing dependencies. Run: pip install requests pynacl asyncpg")
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


async def setup_agent(database_url: str, signing_key: SigningKey) -> str:
    """Create an agent directly in the database and return its ID."""
    conn = await asyncpg.connect(database_url)
    try:
        # Find the first org
        org = await conn.fetchrow("SELECT id, name FROM organizations LIMIT 1")
        if not org:
            print("  ERROR: No organizations found in database")
            sys.exit(1)
        print(f"  Using org: {org['name']} ({org['id']})")

        public_key = bytes(signing_key.verify_key)
        fingerprint = hashlib.sha256(public_key).hexdigest()
        agent_id = uuid4()

        await conn.execute(
            """
            INSERT INTO agents (
                id, org_id, name, public_key, public_key_fingerprint,
                status, trust_score,
                daily_limit_usd, per_action_limit_usd, rate_limit_per_minute,
                allowed_actions, blocked_actions, metadata,
                total_actions_count, total_blocked_count,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $16)
            """,
            agent_id,
            org["id"],
            "Mainnet Receipt Agent",
            public_key,
            fingerprint,
            "active",
            85,
            500,     # daily limit
            50,      # per-action limit ($50 so $75 triggers BLOCK)
            60,      # rate limit per minute
            ["financial_transaction", "api_call"],
            [],
            json.dumps({"description": "Agent for mainnet receipt generation"}),
            0, 0,
            datetime.now(timezone.utc),
        )
        print(f"  Created agent: {agent_id}")
        return str(agent_id)
    finally:
        await conn.close()


def main():
    parser = argparse.ArgumentParser(description="Generate mainnet PASS and BLOCK receipts")
    parser.add_argument("--api-url", required=True, help="e.g. https://api.inntris.com")
    parser.add_argument("--database-url", required=True, help="Supabase connection string")
    args = parser.parse_args()

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
    print(f"\nGenerated Ed25519 keypair")

    # --- Create agent in database ---
    print("Setting up agent in database...")
    agent_id = asyncio.run(setup_agent(args.database_url, signing_key))

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
