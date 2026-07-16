#!/usr/bin/env python3
"""
Inntris Demo Script - Full Verification Flow

Post-deploy smoke test: against an existing organization (you supply its admin
API key), register a fresh agent, sign a financial transaction, submit it to
/verify, and read it back from the audit log.

Signing is done by the shared product client (``api.agent_client``) — the same
path the MCP ``inntris_guard`` tool uses — so this exercises the real signing
protocol, not a hand-rolled copy.

Usage:
    python scripts/demo_verification.py --api-url https://api.inntris.com --api-key YOUR_KEY
"""

import argparse
import base64
import os
import sys
import time
from datetime import datetime

import requests
from nacl.signing import SigningKey

# Allow `import api...` when run as `python scripts/demo_verification.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.agent_client import InntrisAgentClient


def register_agent(api_url: str, api_key: str, org_id: str, name: str, public_key_b64: str) -> dict:
    """Register a new agent with the API."""
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    data = {
        "org_id": org_id,
        "name": name,
        "public_key": public_key_b64,  # Base64 encoded
        "daily_limit_usd": 1000,
        "per_action_limit_usd": 100,
        "allowed_actions": ["financial_transaction", "api_call", "data_export"],
        "metadata": {"demo": True, "created_by": "inntris_demo"},
    }
    response = requests.post(f"{api_url}/admin/agents", headers=headers, json=data)
    response.raise_for_status()
    return response.json()


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
    parser.add_argument("--api-url", default="https://api.inntris.com", help="API URL")
    parser.add_argument("--api-key", required=True, help="Admin API key")
    args = parser.parse_args()

    api_url = args.api_url.rstrip("/")
    api_key = args.api_key

    print("\n" + "=" * 70)
    print("  INNTRIS - AI AGENT VERIFICATION DEMO")
    print("=" * 70)

    # Step 1: Get organization info
    print("\n[Step 1] Fetching organization info...")
    org = get_organization(api_url, api_key)
    org_id = org["id"]
    print(f"  Organization: {org['name']}")
    print(f"  Billing Tier: {org['billing_tier']}")
    print(f"  Org ID: {org_id}")

    # Step 2: Generate Ed25519 keypair
    print("\n[Step 2] Generating Ed25519 keypair...")
    signing_key = SigningKey.generate()
    public_key_b64 = base64.b64encode(bytes(signing_key.verify_key)).decode()
    print(f"  Public Key (b64): {public_key_b64[:32]}...")

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

    # Agents register as 'pending_verification'; activate before it can act.
    activate = requests.patch(
        f"{api_url}/admin/agents/{agent_id}/status",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        params={"new_status": "active"},
    )
    activate.raise_for_status()
    print("  Status: active")

    # Step 4: Sign + submit via the real product client
    print("\n[Step 4] Signing a financial transaction and submitting to /verify...")
    payload = {
        "amount": 49.99,
        "currency": "USD",
        "recipient": "vendor_12345",
        "description": "Demo payment for API services",
        "risk_score": 0.15,
    }
    print(f"  Amount: ${payload['amount']} {payload['currency']}  ->  {payload['recipient']}")

    agent = InntrisAgentClient(api_url, agent_id, signing_key)
    status_code, result = agent.verify("financial_transaction", payload)

    if status_code == 200:
        print(f"  Verdict: {result['verdict'].upper()}")
        print(f"  Audit ID: {result.get('audit_id', 'N/A')}")
        print(f"  Trust Score: {result.get('trust_score', 'N/A')}")
    else:
        print(f"  Status: {status_code}")
        print(f"  Response: {result}")

    # Step 5: Check audit logs
    print("\n[Step 5] Fetching audit logs...")
    time.sleep(1)  # Wait for log to be written
    logs = get_audit_logs(api_url, api_key, agent_id, limit=3)
    if logs.get("logs"):
        print(f"  Found {logs['total']} audit log(s) for this agent:")
        for log in logs["logs"]:
            print(f"    - {log['id'][:8]}…  {log['action_type']:<22} "
                  f"{log['verdict']:<10} sig_valid={log['signature_valid']}")
    else:
        print("  No audit logs found yet.")

    print("\n" + "=" * 70)
    print("  DEMO COMPLETE")
    print("=" * 70)
    print("""
What happened:
  1. Fetched the organization for your admin API key
  2. Generated an Ed25519 keypair (private key stays with the agent)
  3. Registered the agent with its public key
  4. Signed a $49.99 financial transaction via the shared Inntris client and
     submitted it to /verify — the signature was checked against the stored key
  5. Read the action back from the immutable audit trail

Blockchain anchoring: audit logs batch into a Merkle tree whose root is anchored
to Base Mainnet (AnchorRegistry 0x0600eA15802c8d2EA429371b2EB0aacCFe321480).
""")


if __name__ == "__main__":
    main()
