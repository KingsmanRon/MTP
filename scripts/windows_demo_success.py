"""
Windows-compatible demo script for successful end-to-end verification.
Run with: python scripts/windows_demo_success.py
"""

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

# =============================================================================
# CONFIGURATION - Modify these values
# =============================================================================
API_URL = "http://localhost:8000"
ADMIN_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def compute_hash(data: dict) -> str:
    """Compute SHA-256 hash of canonicalized JSON."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def print_step(step_num: int, description: str):
    """Print a formatted step header."""
    print(f"\n{'='*60}")
    print(f"[Step {step_num}] {description}")
    print('='*60)


def print_result(label: str, value, indent: int = 2):
    """Print a formatted result."""
    spaces = " " * indent
    print(f"{spaces}{label}: {value}")


# =============================================================================
# MAIN DEMO
# =============================================================================

def main():
    print("\n" + "="*60)
    print("  INNTRIS CORE - Successful Verification Demo (Windows)")
    print("="*60)

    # -------------------------------------------------------------------------
    # Step 1: Create Organization
    # -------------------------------------------------------------------------
    print_step(1, "Creating Organization...")

    org_response = requests.post(
        f"{API_URL}/admin/organizations",
        headers={
            "Content-Type": "application/json",
            "X-Admin-Key": ADMIN_KEY
        },
        json={
            "name": f"Demo Org {uuid4().hex[:8]}",
            "contact_email": "demo@test.com",
            "billing_tier": "professional"
        }
    )

    if org_response.status_code != 200:
        print(f"  ERROR: {org_response.status_code} - {org_response.text}")
        print("\n  Make sure the API server is running:")
        print("    uvicorn api.main:app --reload --host 0.0.0.0 --port 8000")
        return

    org_data = org_response.json()
    org_id = org_data["id"]
    api_key = org_data["api_key"]

    print_result("Organization ID", org_id)
    print_result("API Key", api_key[:20] + "...")

    # -------------------------------------------------------------------------
    # Step 2: Generate Ed25519 Keypair
    # -------------------------------------------------------------------------
    print_step(2, "Generating Ed25519 Keypair...")

    signing_key = SigningKey.generate()
    private_key_b64 = base64.b64encode(bytes(signing_key)).decode()
    public_key_b64 = base64.b64encode(bytes(signing_key.verify_key)).decode()

    print_result("Private Key (save this!)", private_key_b64[:30] + "...")
    print_result("Public Key", public_key_b64[:30] + "...")

    # -------------------------------------------------------------------------
    # Step 3: Register Agent
    # -------------------------------------------------------------------------
    print_step(3, "Registering Agent...")

    agent_response = requests.post(
        f"{API_URL}/admin/agents",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key
        },
        json={
            "org_id": org_id,
            "name": f"Demo Agent {uuid4().hex[:8]}",
            "public_key": public_key_b64,
            "daily_limit_usd": 500,
            "per_action_limit_usd": 100,
            "rate_limit_per_minute": 60,
            "allowed_actions": ["financial_transaction", "api_call", "email_send"]
        }
    )

    if agent_response.status_code != 200:
        print(f"  ERROR: {agent_response.status_code} - {agent_response.text}")
        return

    agent_data = agent_response.json()
    agent_id = agent_data["id"]

    print_result("Agent ID", agent_id)
    print_result("Trust Score", agent_data.get("trust_score", 50))
    print_result("Status", agent_data.get("status", "active"))

    # -------------------------------------------------------------------------
    # Step 4: Create Verification Request
    # -------------------------------------------------------------------------
    print_step(4, "Creating Verification Request...")

    action_type = "financial_transaction"
    payload = {
        "amount": 49.99,
        "currency": "USD",
        "recipient": "vendor_12345",
        "description": "Test payment for demo"
    }
    nonce = str(uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    print_result("Action Type", action_type)
    print_result("Amount", f"${payload['amount']}")
    print_result("Recipient", payload['recipient'])
    print_result("Nonce", nonce[:20] + "...")
    print_result("Timestamp", timestamp)

    # -------------------------------------------------------------------------
    # Step 5: Sign the Action
    # -------------------------------------------------------------------------
    print_step(5, "Signing Action with Ed25519...")

    # Compute payload hash
    payload_hash = compute_hash(payload)
    print_result("Payload Hash", payload_hash[:40] + "...")

    # Create signing data
    signing_data = {
        "agent_id": agent_id,
        "action_type": action_type,
        "payload_hash": payload_hash,
        "nonce": nonce,
        "timestamp": timestamp,
    }
    action_hash = compute_hash(signing_data)
    print_result("Action Hash", action_hash[:40] + "...")

    # Sign the hash
    signature = signing_key.sign(bytes.fromhex(action_hash)).signature
    signature_b64 = base64.b64encode(signature).decode()
    print_result("Signature", signature_b64[:40] + "...")

    # -------------------------------------------------------------------------
    # Step 6: Submit to /verify Endpoint
    # -------------------------------------------------------------------------
    print_step(6, "Submitting to /verify Endpoint...")

    verify_response = requests.post(
        f"{API_URL}/verify",
        headers={"Content-Type": "application/json"},
        json={
            "agent_id": agent_id,
            "action_type": action_type,
            "payload": payload,
            "nonce": nonce,
            "timestamp": timestamp,
            "signature": signature_b64
        }
    )

    if verify_response.status_code != 200:
        print(f"  ERROR: {verify_response.status_code}")
        print(f"  Response: {verify_response.text}")
        return

    result = verify_response.json()

    # -------------------------------------------------------------------------
    # Step 7: Display Results
    # -------------------------------------------------------------------------
    print_step(7, "VERIFICATION RESULT")

    verdict = result.get("verdict", "unknown").upper()
    if verdict == "APPROVED":
        print(f"\n  *** VERDICT: {verdict} ***")
    else:
        print(f"\n  *** VERDICT: {verdict} ***")
        if "verdict_reason" in result:
            print(f"  Reason: {result['verdict_reason']}")

    print_result("Audit ID", result.get("audit_id", "N/A"))
    print_result("Trust Score", result.get("trust_score", "N/A"))

    if "limits_remaining" in result:
        print("\n  Limits Remaining:")
        limits = result["limits_remaining"]
        print_result("Daily Limit", f"${limits.get('daily_limit_usd', 'N/A')}", 4)
        print_result("Daily Spent", f"${limits.get('daily_spent_usd', 'N/A')}", 4)
        print_result("Daily Remaining", f"${limits.get('daily_remaining_usd', 'N/A')}", 4)
        print_result("Per-Action Limit", f"${limits.get('per_action_limit_usd', 'N/A')}", 4)

    print("\n" + "="*60)
    print("  Demo completed successfully!")
    print("="*60 + "\n")

    # Return values for use in other scripts
    return {
        "org_id": org_id,
        "api_key": api_key,
        "agent_id": agent_id,
        "private_key": private_key_b64,
        "public_key": public_key_b64
    }


if __name__ == "__main__":
    main()
