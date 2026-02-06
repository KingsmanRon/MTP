import requests
import json
import base64
from nacl.signing import SigningKey

# ==========================================
# CONFIGURATION
# ==========================================
API_URL = "https://inntris-api.up.railway.app"
# The r"" tells Python to ignore the backslashes in your password
MASTER_KEY = r"xUtQP7w0$zX,738(cap%avv,PA"

def setup():
    print(f"🚀 Connecting to Brain at: {API_URL}")

    # ---------------------------------------------------------
    # STEP 1: CREATE ORGANIZATION
    # ---------------------------------------------------------
    print("\n[1] Creating Organization...")
    
    # We remove "billing_tier" to let backend use default (bypassing enum error)
    org_payload = {
        "name": "Global Bank Corp",
        "contact_email": "demo@bank.com",
        "webhook_url": "https://bank.com/webhook"
    }
    
    try:
        org_res = requests.post(
            f"{API_URL}/admin/organizations",
            headers={"X-Admin-Key": MASTER_KEY},
            json=org_payload
        )
        
        if org_res.status_code != 201:
            print(f"❌ Failed to create org: {org_res.status_code} - {org_res.text}")
            return

        org_data = org_res.json()
        org_id = org_data['organization_id']
        api_key = org_data['api_key']
        print(f"✅ Organization Created: {org_id}")

        # ---------------------------------------------------------
        # STEP 2: GENERATE KEYS
        # ---------------------------------------------------------
        print("\n[2] Generating Cryptographic Identity...")
        signing_key = SigningKey.generate()
        
        # EXPORT RAW SEED (32 bytes) for JS Compatibility
        private_key_seed_b64 = base64.b64encode(bytes(signing_key)).decode('utf-8')
        public_key_b64 = base64.b64encode(bytes(signing_key.verify_key)).decode('utf-8')
        print("✅ Keys Generated")

        # ---------------------------------------------------------
        # STEP 3: REGISTER AGENT (The Fix)
        # ---------------------------------------------------------
        print("\n[3] Registering Agent...")
        agent_res = requests.post(
            f"{API_URL}/admin/agents",
            headers={"X-API-Key": api_key},
            json={
                "org_id": str(org_id), # Ensure this is a string
                "name": "Transfer Agent 007",
                "public_key": public_key_b64,
                "daily_limit_usd": "10000.00",      # FIX: Send as String for Decimal Strict Mode
                "per_action_limit_usd": "5000.00",  # FIX: Send as String for Decimal Strict Mode
                "allowed_actions": ["transfer_funds", "financial_transaction"],
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

    except Exception as e:
        print(f"❌ Connection Error: {str(e)}")

if __name__ == "__main__":
    setup()
