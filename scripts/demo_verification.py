#!/usr/bin/env python3
"""
Inntris Demo Script - Full Verification Flow

This script demonstrates the complete Inntris agent verification flow:
1. Generate Ed25519 keypair for an agent
2. Register the agent with the API
3. Create and sign a verification request
4. Submit to /verify endpoint
5. View the result in audit logs

Usage:
    python scripts/demo_verification.py --api-url https://inntris-api.up.railway.app --api-key YOUR_KEY
"""

import argparse
import hashlib
import json
import time
import requests
from datetime import datetime, timezone
from uuid import uuid4

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: cryptography library not installed.")
    print("Run: pip install cryptography")
    exit(1)

import base64


def generate_keypair():
    """Generate an Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Get raw bytes
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_key, private_bytes, public_bytes


def compute_action_hash(agent_id: str, action_type: str, payload: dict, nonce: str, timestamp: str) -> str:
    """Compute SHA-256 hash of the action for signing."""
    # Canonical JSON encoding (sorted keys, no spaces)
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(',', ':'))

    message = f"{agent_id}|{action_type}|{canonical_payload}|{nonce}|{timestamp}"
    return hashlib.sha256(message.encode()).hexdigest()


def sign_action(private_key: Ed25519PrivateKey, action_hash: str) -> str:
    """Sign the action hash with Ed25519 and return base64 signature."""
    hash_bytes = bytes.fromhex(action_hash)
    signature = private_key.sign(hash_bytes)
    return base64.b64encode(signature).decode()


def register_agent(api_url: str, api_key: str, org_id: str, name: str, public_key_b64: str) -> dict:
    """Register a new agent with the API."""
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json"
    }

    data = {
        "org_id": org_id,
        "name": name,
        "public_key": public_key_b64,  # Base64 encoded
        "daily_limit_usd": 1000,
        "per_action_limit_usd": 100,
        "allowed_actions": ["financial_transaction", "api_call", "data_export"],
        "metadata": {"demo": True, "created_by": "inntris_demo"}
    }

    response = requests.post(f"{api_url}/admin/agents", headers=headers, json=data)
    response.raise_for_status()
    return response.json()


def verify_action(api_url: str, agent_id: str, action_type: str, payload: dict,
                  nonce: str, timestamp: str, signature: str) -> dict:
    """Submit a verification request."""
    headers = {"Content-Type": "application/json"}

    data = {
        "agent_id": agent_id,
        "action_type": action_type,
        "payload": payload,
        "nonce": nonce,
        "timestamp": timestamp,
        "signature": signature
    }

    response = requests.post(f"{api_url}/verify", headers=headers, json=data)
    return response.json(), response.status_code


def get_audit_logs(api_url: str, api_key: str, agent_id: str = None, limit: int = 5) -> dict:
    """Fetch recent audit logs."""
    headers = {"X-API-Key": api_key}
    params = {"limit": limit}
    if agent_id:
        params["agent_id"] = agent_id

    response = requests.get(f"{api_url}/admin/audit/search", headers=headers, params=params)
    response.raise_for_status()
    return response.json()


def get_organization(api_url: str, api_key: str) -> dict:
    """Get organization info."""
    headers = {"X-API-Key": api_key}
    response = requests.get(f"{api_url}/admin/organization", headers=headers)
    response.raise_for_status()
    return response.json()


def main():
    parser = argparse.ArgumentParser(description="Inntris Demo - Full Verification Flow")
    parser.add_argument("--api-url", default="https://inntris-api.up.railway.app", help="API URL")
    parser.add_argument("--api-key", required=True, help="API key")
    args = parser.parse_args()

    api_url = args.api_url.rstrip("/")
    api_key = args.api_key

    print("\n" + "="*70)
    print("  INNTRIS - AI AGENT VERIFICATION DEMO")
    print("="*70)

    # Step 1: Get organization info
    print("\n[Step 1] Fetching organization info...")
    org = get_organization(api_url, api_key)
    org_id = org["id"]
    print(f"  Organization: {org['name']}")
    print(f"  Billing Tier: {org['billing_tier']}")
    print(f"  Org ID: {org_id}")

    # Step 2: Generate Ed25519 keypair
    print("\n[Step 2] Generating Ed25519 keypair...")
    private_key, private_bytes, public_bytes = generate_keypair()
    public_key_b64 = base64.b64encode(public_bytes).decode()  # API expects base64
    print(f"  Public Key (b64): {public_key_b64[:32]}...")
    print(f"  Key Length: {len(public_bytes)} bytes (Ed25519)")

    # Step 3: Register the agent
    print("\n[Step 3] Registering demo agent...")
    agent_name = f"Demo Agent {datetime.now().strftime('%H:%M:%S')}"
    try:
        result = register_agent(api_url, api_key, org_id, agent_name, public_key_b64)
        agent_id = result["agent_id"]
        print(f"  Agent Name: {agent_name}")
        print(f"  Agent ID: {agent_id}")
        print(f"  Status: {result['status']}")
        print(f"  Fingerprint: {result['public_key_fingerprint'][:16]}...")
    except requests.exceptions.HTTPError as e:
        print(f"  Error registering agent: {e.response.text}")
        return

    # Step 4: Create a verification request
    print("\n[Step 4] Creating verification request...")
    action_type = "financial_transaction"
    payload = {
        "amount": 49.99,
        "currency": "USD",
        "recipient": "vendor_12345",
        "description": "Demo payment for API services",
        "risk_score": 0.15
    }
    nonce = str(uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    print(f"  Action Type: {action_type}")
    print(f"  Amount: ${payload['amount']} {payload['currency']}")
    print(f"  Recipient: {payload['recipient']}")
    print(f"  Nonce: {nonce[:8]}...")

    # Step 5: Sign the action
    print("\n[Step 5] Signing action with Ed25519...")
    action_hash = compute_action_hash(agent_id, action_type, payload, nonce, timestamp)
    signature = sign_action(private_key, action_hash)
    print(f"  Action Hash: {action_hash[:32]}...")
    print(f"  Signature: {signature[:32]}...")

    # Step 6: Submit verification request
    print("\n[Step 6] Submitting to /verify endpoint...")
    result, status_code = verify_action(api_url, agent_id, action_type, payload, nonce, timestamp, signature)

    if status_code == 200:
        print(f"  ✅ Verdict: {result['verdict'].upper()}")
        print(f"  Audit ID: {result.get('audit_id', 'N/A')}")
        print(f"  Trust Score: {result.get('trust_score', 'N/A')}")
        print(f"  Response Time: {result.get('response_time_ms', 'N/A')}ms")
    else:
        print(f"  ❌ Status: {status_code}")
        print(f"  Response: {json.dumps(result, indent=2)}")

    # Step 7: Check audit logs
    print("\n[Step 7] Fetching audit logs...")
    time.sleep(1)  # Wait for log to be written
    logs = get_audit_logs(api_url, api_key, agent_id, limit=3)

    if logs.get("logs"):
        print(f"  Found {logs['total']} audit log(s) for this agent:")
        for log in logs["logs"]:
            print(f"\n  📋 Log ID: {log['id'][:8]}...")
            print(f"     Action: {log['action_type']}")
            print(f"     Verdict: {log['verdict']}")
            print(f"     Signature Valid: {log['signature_valid']}")
            print(f"     Trust Score: {log['trust_score_at_time']}")
            print(f"     Time: {log['timestamp']}")
    else:
        print("  No audit logs found yet.")

    # Summary
    print("\n" + "="*70)
    print("  DEMO COMPLETE")
    print("="*70)
    print(f"""
What happened:
  1. Generated Ed25519 keypair for cryptographic signing
  2. Registered agent with public key (private key stays with agent)
  3. Created a financial transaction action ($49.99 USD)
  4. Computed SHA-256 hash of: agent_id|action_type|payload|nonce|timestamp
  5. Signed the hash with Ed25519 private key
  6. Submitted to /verify - signature verified against stored public key
  7. Action logged to immutable audit trail

Dashboard: https://inntris-frontend.vercel.app/admin

Blockchain Anchoring:
  - Audit logs can be batched into Merkle trees
  - Root hash anchored to Base Sepolia: 0x0600ea15802c8d2ea429371b2eb0aaccfe321480
  - Provides tamper-proof, cryptographic verification
""")


if __name__ == "__main__":
    main()
