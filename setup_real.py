import requests
import json
import base64
from nacl.signing import SigningKey

# ==========================================
# CONFIGURATION
# ==========================================
API_URL = "https://inntris-api.up.railway.app"
# The r"" tells Python to ignore backslashes
MASTER_KEY = r"xUtQP7w0$zX,738(cap%avv,PA"

def setup():
    print(f"🚀 Connecting to Brain at: {API_URL}")

    # 1. Create Organization
    print("\n[1] Creating Organization...")
    # Removing billing_tier to let backend default to 'free' (bypasses validation bug)
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
        
        # Handle case where Org already exists or other errors
        if org_res.status_code not in [200, 201]:
            print(f"❌ Failed to create org: {org_res.status_code} - {org_res.text}")
            return

        org_data = org_res.json()
        org_id = org_data.get('organization_id') or org_data.get('id')
        api_key = org_data.get('api_key')
        
        # If we re-connected to existing org, we might not get an API key back.
        # But for a fresh run, we should.
        print(f"✅ Organization ID: {org_id}")

        # 2. Generate Crypto Identity
        print("\n[2] Generating Cryptographic Identity...")
        signing_key = SigningKey.generate()
        private_key_seed_b64 = base64.b64encode(bytes(signing_key)).decode('utf-8')
        public_key_b64 = base64.b64encode(bytes(signing_key.verify_key)).decode('utf-8')
        print("✅ Keys Generated")

        # 3. Register Agent (THE FIX IS HERE)
        print("\n[3] Registering Agent...")
        agent_payload = {
            "org_id": str(org_id),                # Force String
            "name": "Transfer Agent 007",
            "public_key": public_key_b64,
            "daily_limit_usd": "10000",           # <--- STRING (Fixes Decimal Error)
            "per_action_limit_usd": "5000",       # <--- STRING (Fixes Decimal Error)
            "allowed_actions": ["transfer_funds", "financial_transaction"],
            "metadata": {"department": "treasury"}
        }

        agent_res = requests.post(
            f"{API_URL}/admin/agents",
            headers={"X-API-Key": api_key},
            json=agent_payload
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
        print(f"❌ Execution Error: {str(e)}")

if __name__ == "__main__":
    setup()
