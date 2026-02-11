"""
Windows-compatible demo script for BLOCKED verification scenarios.
Run with: python scripts/windows_demo_blocked.py

This demonstrates multiple ways to trigger a blocked verification:
1. Exceed per-action limit
2. Exceed daily limit
3. Exceed rate limit
4. Use blocked action type
"""

import hashlib
import json
import base64
import sys
import time
from datetime import datetime, timezone
from uuid import uuid4

try:
    import requests
    from nacl.signing import SigningKey
except ImportError:
    print("Missing dependencies. Run: pip install requests pynacl")
    sys.exit(1)

# =============================================================================
# CONFIGURATION
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


def print_header(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def print_step(step_num: int, description: str):
    print(f"\n[Step {step_num}] {description}")


def print_result(label: str, value, indent: int = 2):
    spaces = " " * indent
    print(f"{spaces}{label}: {value}")


def create_org_and_agent(name: str, daily_limit: float, per_action_limit: float,
                         rate_limit: int = 60, allowed_actions: list = None,
                         blocked_actions: list = None):
    """Create organization and agent with specified limits."""

    if allowed_actions is None:
        allowed_actions = ["financial_transaction", "api_call", "email_send"]
    if blocked_actions is None:
        blocked_actions = []

    # Create org
    org_response = requests.post(
        f"{API_URL}/admin/organizations",
        headers={"Content-Type": "application/json", "X-Admin-Key": ADMIN_KEY},
        json={
            "name": f"{name} {uuid4().hex[:8]}",
            "contact_email": "demo@test.com",
            "billing_tier": "professional"
        }
    )

    if org_response.status_code != 200:
        print(f"  ERROR creating org: {org_response.text}")
        return None

    org_data = org_response.json()
    org_id = org_data["id"]
    api_key = org_data["api_key"]

    # Generate keypair
    signing_key = SigningKey.generate()
    private_key_b64 = base64.b64encode(bytes(signing_key)).decode()
    public_key_b64 = base64.b64encode(bytes(signing_key.verify_key)).decode()

    # Create agent
    agent_response = requests.post(
        f"{API_URL}/admin/agents",
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        json={
            "org_id": org_id,
            "name": f"{name} Agent",
            "public_key": public_key_b64,
            "daily_limit_usd": daily_limit,
            "per_action_limit_usd": per_action_limit,
            "rate_limit_per_minute": rate_limit,
            "allowed_actions": allowed_actions,
            "blocked_actions": blocked_actions
        }
    )

    if agent_response.status_code != 200:
        print(f"  ERROR creating agent: {agent_response.text}")
        return None

    agent_data = agent_response.json()

    return {
        "org_id": org_id,
        "api_key": api_key,
        "agent_id": agent_data["id"],
        "signing_key": signing_key,
        "private_key": private_key_b64,
        "public_key": public_key_b64
    }


def submit_verification(agent_id: str, signing_key: SigningKey, action_type: str,
                        payload: dict) -> dict:
    """Submit a verification request and return the response."""

    nonce = str(uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    # Compute hashes
    payload_hash = compute_hash(payload)
    signing_data = {
        "agent_id": agent_id,
        "action_type": action_type,
        "payload_hash": payload_hash,
        "nonce": nonce,
        "timestamp": timestamp,
    }
    action_hash = compute_hash(signing_data)

    # Sign
    signature = signing_key.sign(bytes.fromhex(action_hash)).signature
    signature_b64 = base64.b64encode(signature).decode()

    # Submit
    response = requests.post(
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

    return response.json()


# =============================================================================
# DEMO 1: EXCEED PER-ACTION LIMIT
# =============================================================================

def demo_per_action_limit():
    print_header("DEMO 1: Exceed Per-Action Limit")
    print("Creating agent with $50 per-action limit, then requesting $75...")

    print_step(1, "Creating agent with low per-action limit...")
    setup = create_org_and_agent(
        name="Per-Action Limited",
        daily_limit=500,
        per_action_limit=50  # <-- Low limit
    )

    if not setup:
        return

    print_result("Agent ID", setup["agent_id"])
    print_result("Per-Action Limit", "$50")

    print_step(2, "Submitting $75 transaction (exceeds $50 limit)...")

    result = submit_verification(
        agent_id=setup["agent_id"],
        signing_key=setup["signing_key"],
        action_type="financial_transaction",
        payload={
            "amount": 75.00,  # Exceeds $50 limit
            "currency": "USD",
            "recipient": "vendor_123"
        }
    )

    print_step(3, "RESULT")
    verdict = result.get("verdict", "unknown").upper()
    print(f"\n  *** VERDICT: {verdict} ***")
    if "verdict_reason" in result:
        print(f"  Reason: {result['verdict_reason']}")


# =============================================================================
# DEMO 2: EXCEED DAILY LIMIT
# =============================================================================

def demo_daily_limit():
    print_header("DEMO 2: Exceed Daily Limit")
    print("Creating agent with $100 daily limit, spending it, then trying more...")

    print_step(1, "Creating agent with low daily limit...")
    setup = create_org_and_agent(
        name="Daily Limited",
        daily_limit=100,  # <-- Low daily limit
        per_action_limit=80
    )

    if not setup:
        return

    print_result("Agent ID", setup["agent_id"])
    print_result("Daily Limit", "$100")
    print_result("Per-Action Limit", "$80")

    print_step(2, "Submitting first transaction: $70...")

    result1 = submit_verification(
        agent_id=setup["agent_id"],
        signing_key=setup["signing_key"],
        action_type="financial_transaction",
        payload={"amount": 70.00, "currency": "USD", "recipient": "vendor_1"}
    )

    verdict1 = result1.get("verdict", "unknown").upper()
    print(f"  First transaction: {verdict1}")
    if "limits_remaining" in result1:
        remaining = result1["limits_remaining"].get("daily_remaining_usd", "?")
        print(f"  Daily remaining: ${remaining}")

    print_step(3, "Submitting second transaction: $50 (would exceed remaining)...")

    result2 = submit_verification(
        agent_id=setup["agent_id"],
        signing_key=setup["signing_key"],
        action_type="financial_transaction",
        payload={"amount": 50.00, "currency": "USD", "recipient": "vendor_2"}
    )

    print_step(4, "RESULT")
    verdict2 = result2.get("verdict", "unknown").upper()
    print(f"\n  *** VERDICT: {verdict2} ***")
    if "verdict_reason" in result2:
        print(f"  Reason: {result2['verdict_reason']}")


# =============================================================================
# DEMO 3: EXCEED RATE LIMIT
# =============================================================================

def demo_rate_limit():
    print_header("DEMO 3: Exceed Rate Limit")
    print("Creating agent with 3 requests/minute limit, then making 5 requests...")

    print_step(1, "Creating agent with low rate limit...")
    setup = create_org_and_agent(
        name="Rate Limited",
        daily_limit=1000,
        per_action_limit=100,
        rate_limit=3  # <-- Only 3 requests per minute
    )

    if not setup:
        return

    print_result("Agent ID", setup["agent_id"])
    print_result("Rate Limit", "3 requests/minute")

    print_step(2, "Submitting 5 rapid requests...")

    for i in range(5):
        result = submit_verification(
            agent_id=setup["agent_id"],
            signing_key=setup["signing_key"],
            action_type="api_call",
            payload={"action": f"test_action_{i}", "data": "test"}
        )

        verdict = result.get("verdict", "unknown").upper()
        reason = result.get("verdict_reason", "")

        if verdict == "RATE_LIMITED":
            print(f"  Request {i+1}: {verdict} - {reason}")
        else:
            print(f"  Request {i+1}: {verdict}")

        time.sleep(0.1)  # Small delay (still within 1 minute)

    print_step(3, "RESULT")
    print("\n  Requests 1-3: APPROVED")
    print("  Requests 4-5: RATE_LIMITED")


# =============================================================================
# DEMO 4: BLOCKED ACTION TYPE
# =============================================================================

def demo_blocked_action():
    print_header("DEMO 4: Blocked Action Type")
    print("Creating agent with 'data_export' blocked, then trying it...")

    print_step(1, "Creating agent with blocked action...")
    setup = create_org_and_agent(
        name="Action Restricted",
        daily_limit=500,
        per_action_limit=100,
        allowed_actions=["api_call", "email_send", "data_export"],
        blocked_actions=["data_export"]  # <-- Explicitly blocked
    )

    if not setup:
        return

    print_result("Agent ID", setup["agent_id"])
    print_result("Blocked Actions", "['data_export']")

    print_step(2, "Submitting 'data_export' action...")

    result = submit_verification(
        agent_id=setup["agent_id"],
        signing_key=setup["signing_key"],
        action_type="data_export",
        payload={"export_type": "csv", "data": "sensitive_data"}
    )

    print_step(3, "RESULT")
    verdict = result.get("verdict", "unknown").upper()
    print(f"\n  *** VERDICT: {verdict} ***")
    if "verdict_reason" in result:
        print(f"  Reason: {result['verdict_reason']}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("\n" + "="*60)
    print("  INNTRIS CORE - Blocked Verification Demos (Windows)")
    print("="*60)
    print("\nThis script demonstrates 4 ways to trigger a BLOCKED verdict:")
    print("  1. Exceed per-action limit")
    print("  2. Exceed daily limit")
    print("  3. Exceed rate limit")
    print("  4. Use blocked action type")

    # Check API is running
    try:
        health = requests.get(f"{API_URL}/health", timeout=5)
        if health.status_code != 200:
            raise Exception("API not healthy")
    except Exception as e:
        print(f"\nERROR: Cannot connect to API at {API_URL}")
        print("Make sure the API server is running:")
        print("  uvicorn api.main:app --reload --host 0.0.0.0 --port 8000")
        return

    # Run all demos
    demo_per_action_limit()
    demo_daily_limit()
    demo_rate_limit()
    demo_blocked_action()

    print("\n" + "="*60)
    print("  All demos completed!")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
