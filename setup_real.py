import requests
import json
import base64
from nacl.signing import SigningKey

# ==========================================
# CONFIGURATION
# ==========================================
API_URL = "https://inntris-api.up.railway.app"
# The new key you provided (Raw string to handle special chars)
MASTER_KEY = r"xUtQP7w0$zX,738(cap%avv,PA"

def setup():
    print(f"🚀 Connecting to Brain at: {API_URL}")

    # ---------------------------------------------------------
    # STEP 1: BRUTE FORCE THE ORGANIZATION TIER
    # ---------------------------------------------------------
    print("\n[1] Creating Organization (Attempting Tiers)...")
    
    # List of likely tier names to try
    tiers_to_try = [
        "starter", "STARTER",
        "basic", "BASIC",
        "pro", "PRO",
        "professional", "PROFESSIONAL",
        "business", "BUSINESS",
        "developer", "DEVELOPER",
        "team", "TEAM",
        "free", "FREE" # Retrying just in case
    ]

    org_id = None
    api_key = None

    for tier in tiers_to_try:
        print(f"   > Trying tier: '{tier}'...")
        try:
            org_res = requests.post(
                f"{API_URL}/admin/organizations",
                headers={"X-Admin-Key": MASTER_KEY},
                json={
                    "name": "Global Bank Corp",
                    "billing_tier": tier,
                    "contact_email": "demo@bank.com",
                    "webhook_url": "https://bank.com/webhook"
                }
            )

            if org_res.status_code == 201:
                print(f"   ✅ SUCCESS! Accepted Tier: '{tier}'")
                org_data = org_res.json()
                org_id = org_data['organization_id']
                api_key = org_data['api_key']
                break # Exit the loop, we found it!
            elif org_res.status_code == 422:
                continue # Try the next one
            else:
                print(f"   ❌ Error {org_res.status_code}: {org_res.text}")
                return

        except Exception as e:
            print(f"   ❌ Connection Failed: {e}")
            return

    if not org_id:
        print("\n❌ ALL TIERS FAILED. The API uses a custom Enum we can't guess.")
        print("💡 Action: Please check 'api/models.py' in your source code to see valid 'BillingTier' values.")
        return

    print(f"✅ Organization Created: {org_id}")

    # ---------------------------------------------------------
    # STEP 2: GENERATE KEYS
    # ---------------------------------------------------------
    print("\n[2] Generating Cryptographic Identity...")
    signing_key = SigningKey.generate()
    
    # EXPORT RAW SEED (32 bytes)
    private_key_seed_b64 = base64.b64encode(bytes(signing_key)).decode('utf-8')
    public_key_b64 = base64.b64encode(bytes(signing_key.verify_key)).decode('utf-8')
    print("✅ Keys Generated")

    # ---------------------------------------------------------
    # STEP 3: REGISTER AGENT
    # ---------------------------------------------------------
    print("\n[3] Registering Agent...")
    agent_res = requests.post(
        f"{API_URL}/admin/agents",
        headers={"X-API-Key": api_key},
        json={
            "org_id": org_id,
            "name": "Transfer Agent 007",
            "public_key": public_key_b64,
            "daily_limit_usd": 10000.0,
            "per_action_limit_usd": 5000.0,
            "allowed_actions": ["transfer_funds"],
            "metadata": {"department": "treasury"}
        }
    )

    if agent_res.status_code != 201:
        print(f"❌ Failed to register agent: {agent_res.status_code} - {agent_res.text}")
        return

    agent_id = agent_res.json()['agent_id']
    print(f"✅ Agent Registered: {agent_id}")

    print("\n" + "="*60)
    print("📋 SAVE THESE CREDENTIALS FOR LOVABLE")
    print("="*60)
    print(f"AGENT_ID:    {agent_id}")
    print(f"PRIVATE_KEY: {private_key_seed_b64}")
    print("="*60)

if __name__ == "__main__":
    setup()
