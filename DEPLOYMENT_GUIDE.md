# 🚀 Inntris Core - Production Deployment Guide

**CRITICAL: Read this entire guide before deploying to production.**

This guide provides step-by-step instructions for deploying Inntris to production using:
- **Railway** (API + Worker + Redis)
- **Supabase** (PostgreSQL Database)
- **Coinbase/Base** (Blockchain Anchoring)

---

## 📋 Pre-Deployment Checklist

### Required Accounts (You Should Have These)
- ✅ Railway account (railway.app)
- ✅ Supabase account (supabase.com)
- ✅ Coinbase account (coinbase.com)
- ⬜ GitHub account (for Railway deployment)

### Required Tools
```bash
# Install Railway CLI
npm install -g @railway/cli

# Install Supabase CLI (optional, for local testing)
brew install supabase/tap/supabase

# Install Node.js (for testing scripts)
# Already installed if you have Railway CLI

# Python 3.12+ (for local testing)
python3 --version
```

---

## 🔐 STEP 1: Generate Production Secrets

**CRITICAL: Generate these BEFORE starting deployment. Store them in a password manager.**

```bash
# Navigate to your Inntris directory
cd .

# Generate SERVER_SECRET (64-byte hex string for HMAC signing)
openssl rand -hex 64

# Generate MASTER_ADMIN_KEY (for creating organizations)
openssl rand -hex 32

# Generate REDIS_PASSWORD (for Redis authentication)
openssl rand -base64 32

# Generate DATABASE_PASSWORD (Supabase will generate this, but have a backup)
openssl rand -base64 32
```

**Save these values immediately!** You'll need them in Step 4.

---

## 🗄️ STEP 2: Set Up Supabase Database

### 2.1 Create Supabase Project
1. Go to https://supabase.com/dashboard
2. Click **"New Project"**
3. Fill in:
   - **Name**: `inntris-production` (or your preferred name)
   - **Database Password**: Use a strong password (save it!)
   - **Region**: Choose closest to your users (e.g., `us-east-1`)
   - **Pricing Plan**: **Pro** (Required for production workloads)
4. Click **"Create new project"** and wait 2-3 minutes

### 2.2 Enable Required Extensions
1. In Supabase dashboard, go to **Database** → **Extensions**
2. Search and enable:
   - ✅ **`timescaledb`** (for audit log partitioning) - OPTIONAL but recommended
   - ✅ **`pg_stat_statements`** (for query monitoring)
   - ✅ **`pgcrypto`** (for UUID generation)

### 2.3 Apply Database Schema
1. In Supabase dashboard, go to **SQL Editor**
2. Click **"New query"**
3. Copy the ENTIRE contents of `./database/schemas.sql`
4. Paste into the SQL editor
5. Click **"Run"** (bottom right)
6. **Verify**: You should see "Success. No rows returned" and no errors
7. **Confirm tables created**:
   ```sql
   SELECT table_name FROM information_schema.tables
   WHERE table_schema = 'public'
   ORDER BY table_name;
   ```
   Expected tables:
   - `agents`
   - `api_keys`
   - `audit_logs`
   - `merkle_proofs`
   - `organizations`
   - `policy_rules`
   - `rate_limit_windows`
   - `security_alerts`

### 2.4 Get Connection Details
1. Go to **Project Settings** → **Database**
2. Find **Connection Pooling** section (NOT direct connection)
3. Mode: **Transaction**
4. Save the pooled connection string and the project reference (``xxx``):
   ```
   postgresql://postgres.xxx:[PASSWORD]@aws-0-<region>.pooler.supabase.com:6543/postgres
   ```
5. **Important (RLS role model):** Migration ``005_rls_policies.sql`` creates:
   - ``inntris_api`` as **NOLOGIN** (cannot be used in DATABASE_URL)
   - ``inntris_worker`` as **LOGIN BYPASSRLS** (recommended DATABASE_URL user)
6. Set a password for ``inntris_worker`` in Supabase SQL Editor:
   ```sql
   ALTER ROLE inntris_worker WITH LOGIN PASSWORD 'YOUR_STRONG_PASSWORD';
   ```
7. Build your production app DSN with the worker role:
   ```
   postgresql://inntris_worker.xxx:YOUR_STRONG_PASSWORD@aws-0-<region>.pooler.supabase.com:6543/postgres
   ```
   > If your pooler host uses a different pattern in the dashboard, use exactly what Supabase shows.

---

## ⛓️ STEP 3: Deploy Smart Contract to Base L2

### 3.1 RPC URL

Inntris uses PublicNode as the Base L2 RPC provider. PublicNode is required — Base's official RPC (`mainnet.base.org`) blocks cloud provider IPs including Railway. Do not switch providers.

- **Mainnet**: `https://base-rpc.publicnode.com`
- **Testnet (Sepolia)**: `https://base-sepolia-rpc.publicnode.com`

No API key or account required for PublicNode.

### 3.2 Create Deployment Wallet
```bash
# Option 1: Create new wallet with cast (Foundry)
# Install Foundry if not already installed
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Create new wallet
cast wallet new

# Save the private key and address!
# Address: 0x...
# Private key: 0x...

# Option 2: Use existing MetaMask/Coinbase Wallet
# Export private key from MetaMask:
# MetaMask → Account Details → Export Private Key
```

### 3.3 Fund Deployment Wallet
1. Send **0.01 ETH** to your deployment wallet address
2. For **Base Mainnet**: Bridge ETH from Ethereum L1
   - Go to https://bridge.base.org
   - Connect wallet and bridge ETH
3. For **Base Sepolia Testnet**: Get free test ETH
   - Go to https://www.coinbase.com/faucets/base-ethereum-goerli-faucet
   - Or use https://sepoliafaucet.com/

### 3.4 Deploy Smart Contract

**METHOD A: Using Foundry (Recommended)**
```bash
# Navigate to contracts directory
cd .

# Install dependencies (if not already done)
forge install OpenZeppelin/openzeppelin-contracts

# Deploy to Base Sepolia (Testnet) first for testing
forge create contracts/AnchorRegistry.sol:AnchorRegistry \
  --rpc-url https://base-sepolia-rpc.publicnode.com \
  --private-key YOUR_PRIVATE_KEY_HERE \
  --constructor-args YOUR_DEPLOYMENT_WALLET_ADDRESS

# If successful, deploy to Base Mainnet
forge create contracts/AnchorRegistry.sol:AnchorRegistry \
  --rpc-url https://base-rpc.publicnode.com \
  --private-key YOUR_PRIVATE_KEY_HERE \
  --constructor-args YOUR_DEPLOYMENT_WALLET_ADDRESS \
  --verify

# SAVE THE CONTRACT ADDRESS! Format: 0x...
```

**METHOD B: Using Remix IDE (Alternative)**
1. Go to https://remix.ethereum.org
2. Create new file: `AnchorRegistry.sol`
3. Paste contents from `./contracts/AnchorRegistry.sol`
4. Compile with Solidity 0.8.20
5. Deploy:
   - Environment: **Injected Provider - MetaMask**
   - Connect to Base Sepolia or Base Mainnet
   - Constructor arg: Your deployment wallet address
   - Click **Deploy**
6. **SAVE THE CONTRACT ADDRESS!**

### 3.5 Grant Submitter Role
```bash
# Your API will need SUBMITTER_ROLE to anchor batches
# Get the role hash
SUBMITTER_ROLE=$(cast call YOUR_CONTRACT_ADDRESS "SUBMITTER_ROLE()(bytes32)" --rpc-url https://base-rpc.publicnode.com)

# Grant role to your deployment wallet (it will submit batches)
cast send YOUR_CONTRACT_ADDRESS \
  "grantRole(bytes32,address)" \
  $SUBMITTER_ROLE \
  YOUR_DEPLOYMENT_WALLET_ADDRESS \
  --private-key YOUR_PRIVATE_KEY \
  --rpc-url https://base-rpc.publicnode.com
```

---

## 🚂 STEP 4: Deploy to Railway

### 4.1 Repository Access

The Inntris Core repository is access-controlled.

Contact **sales@inntris.com** to request repository access. You will receive onboarding instructions within 24 hours.

### 4.2 Create Railway Project
1. Go to https://railway.app/dashboard
2. Click **"New Project"**
3. Select **"Deploy from GitHub repo"**
4. Authenticate GitHub and select your Inntris repository
5. Select branch: `master`

### 4.3 Add Redis Service
1. In your Railway project, click **"+ New"**
2. Select **"Database"** → **"Add Redis"**
3. Railway will automatically provision Redis
4. **No configuration needed** - Railway handles this

### 4.4 Configure Environment Variables

1. Click on your **Inntris service** (the one deployed from GitHub)
2. Go to **"Variables"** tab
3. Add **ALL** of these variables:

```bash
# ============================================================================
# DATABASE CONFIGURATION (from Supabase)
# ============================================================================
DATABASE_URL=postgresql://inntris_worker.xxx:[inntris_worker_password]@aws-0-<region>.pooler.supabase.com:6543/postgres
# Note:
# - Do NOT set DATABASE_USER/HOST/PORT/NAME separately; the app reads DATABASE_URL.
# - Do NOT use inntris_api in DATABASE_URL; that role is NOLOGIN by design.

# ============================================================================
# REDIS CONFIGURATION (Auto-configured by Railway)
# ============================================================================
REDIS_URL=${{Redis.REDIS_URL}}  # Railway auto-fills this

# ============================================================================
# BLOCKCHAIN CONFIGURATION (from Step 3)
# ============================================================================
BLOCKCHAIN_PROVIDER_URL=https://base-rpc.publicnode.com  # Base Mainnet (or https://base-sepolia-rpc.publicnode.com for testnet)
BLOCKCHAIN_PRIVATE_KEY=[from Step 3.2]
ANCHOR_CONTRACT_ADDRESS=[from Step 3.4]
ANCHOR_BATCH_SIZE=1000
ANCHOR_INTERVAL_MINUTES=60
BLOCKCHAIN_CHAIN_ID=8453  # Base Mainnet (use 84532 for Sepolia testnet)

# ============================================================================
# API SECURITY (from Step 1)
# ============================================================================
SERVER_SECRET=[from Step 1]
MASTER_ADMIN_KEY=[from Step 1]
JWT_EXPIRY_HOURS=24

# ============================================================================
# CORS CONFIGURATION
# ============================================================================
ALLOWED_ORIGINS=https://inntris.com

# ============================================================================
# RATE LIMITING
# ============================================================================
RATE_LIMIT_PER_MINUTE=100
RATE_LIMIT_BURST=200

# ============================================================================
# APPLICATION SETTINGS
# ============================================================================
ENVIRONMENT=production
LOG_LEVEL=INFO
PORT=8000
WORKERS=4
```

### 4.5 Deploy Services

Railway will automatically deploy your API service. Now add the worker:

1. In Railway project, click **"+ New"** → **"Service"**
2. Select **"GitHub Repo"** (same repo)
3. Branch: `master`
4. **Service name**: `inntris-worker`
5. Go to **"Settings"** → **"Deploy"**
6. **Build Command**: Leave empty (uses Dockerfile)
7. **Start Command**:
   ```bash
   python -m workers.anchor_worker
   ```
8. **Copy all environment variables** from the API service to the worker

### 4.6 Configure Health Checks
1. Go to API service → **"Settings"** → **"Networking"**
2. **Health Check Path**: `/health`
3. **Health Check Timeout**: 30 seconds
4. Enable **"Public Networking"**
5. **SAVE YOUR PUBLIC URL**: `https://inntris-api.up.railway.app`

### 4.7 Monitor Deployment
1. Check **"Deployments"** tab - should show "Success"
2. Check **"Logs"** tab:
   ```
   Expected logs:
   - "Inntris Core API starting"
   - "Database connection pool established"
   - "Redis connection established"
   ```
3. For worker, check logs:
   ```
   Expected logs:
   - "Anchor Worker starting"
   - "Connected to blockchain"
   - "Monitoring for new audit logs to anchor"
   ```

---

## ✅ STEP 5: Verification & Testing

### 5.1 Verify API Health
```bash
# Check API health
curl https://YOUR_RAILWAY_URL.up.railway.app/health

# Expected response:
{
  "status": "healthy",
  "version": "1.0.0",
  "database": "connected",
  "redis": "connected",
  "timestamp": "2026-01-15T..."
}
```

### 5.2 Create First Organization
```bash
# Use the test script (see Step 6)
cd ./tests
./production_test.sh
```

Or manually:
```bash
curl -X POST https://YOUR_RAILWAY_URL.up.railway.app/admin/organizations \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: YOUR_MASTER_ADMIN_KEY" \
  -d '{
    "name": "Test Organization",
    "contact_email": "admin@example.com",
    "billing_tier": "professional"
  }'

# RESPONSE - SAVE THIS!
{
  "organization_id": "uuid-here",
  "api_key": "inntris_live_...",  # SAVE THIS - SHOWN ONLY ONCE!
  "message": "Store this API key securely..."
}
```

### 5.3 Register First Agent
```bash
# Generate Ed25519 keypair for agent
python3 << 'EOF'
from nacl.signing import SigningKey
import base64

signing_key = SigningKey.generate()
private_key_b64 = base64.b64encode(signing_key._signing_key).decode()
public_key_b64 = base64.b64encode(signing_key.verify_key._key).decode()

print(f"Private Key (save securely): {private_key_b64}")
print(f"Public Key: {public_key_b64}")
EOF

# Register agent
curl -X POST https://YOUR_RAILWAY_URL.up.railway.app/admin/agents \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_ORG_API_KEY" \
  -d '{
    "org_id": "YOUR_ORG_UUID",
    "name": "Test Agent",
    "public_key": "PUBLIC_KEY_FROM_ABOVE",
    "daily_limit_usd": 1000.00,
    "per_action_limit_usd": 100.00,
    "allowed_actions": ["financial_transaction", "email_send"]
  }'

# RESPONSE - SAVE AGENT ID!
{
  "agent_id": "agent-uuid-here",
  "message": "Agent registered successfully",
  ...
}
```

### 5.4 Test Action Verification
```bash
# This requires the MCP server setup - see MCP_SETUP.md
# Or test directly with the API:

# See production_test.sh script for full example
```

---

## 🔍 STEP 6: Run Production Test Suite

### 6.1 Run Automated Tests
```bash
cd .
chmod +x tests/production_test.sh
./tests/production_test.sh https://YOUR_RAILWAY_URL.up.railway.app YOUR_MASTER_ADMIN_KEY
```

Expected output:
```
✅ Health check passed
✅ Organization created
✅ Agent registered
✅ Action verification passed
✅ Public agent info retrieved
✅ All tests passed!
```

---

## 📊 STEP 7: Set Up Monitoring

### 7.1 Railway Monitoring
1. Go to Railway project → **"Metrics"**
2. Monitor:
   - CPU usage (should be < 50% at idle)
   - Memory usage (should be < 80%)
   - Network traffic

### 7.2 Database Monitoring
1. In Supabase → **"Database"** → **"Statistics"**
2. Monitor:
   - Active connections (should be < 10 at idle)
   - Query performance
   - Table sizes

### 7.3 Blockchain Monitoring
1. Check contract on BaseScan:
   - Mainnet: `https://basescan.org/address/YOUR_CONTRACT_ADDRESS`
   - Testnet: `https://sepolia.basescan.org/address/YOUR_CONTRACT_ADDRESS`
2. Verify anchoring transactions appear every hour

### 7.4 Set Up Alerts
1. Railway: Go to **"Settings"** → **"Integrations"**
2. Add **Slack** or **Discord** webhook for deployment alerts
3. Add **PagerDuty** for critical errors (optional)

---

## 🔐 STEP 8: Security Hardening

### 8.1 Enable IP Whitelisting (Optional)
```bash
# In Railway, go to Settings → Networking → IP Allowlist
# Add your office/VPN IP addresses
```

### 8.2 Rotate Secrets Quarterly
- Set calendar reminder to rotate `SERVER_SECRET`, `MASTER_ADMIN_KEY` every 90 days
- Use the `/admin/api-keys/rotate` endpoint for organization keys

### 8.3 Enable Audit Log Monitoring
```bash
# Set up cron job to check for security alerts
# Run daily:
SELECT * FROM security_alerts WHERE created_at > NOW() - INTERVAL '24 hours';
```

### 8.4 Backup Strategy
1. **Supabase**: Enable Point-in-Time Recovery (PITR)
   - Go to **Project Settings** → **Backup**
   - Enable PITR (Pro plan feature)
2. **Blockchain**: Merkle proofs are immutably anchored (no backup needed)
3. **Environment Variables**: Store in password manager + offline backup

---

## 🚨 TROUBLESHOOTING

### Issue: API Health Check Fails
**Symptom**: `/health` returns 503 or times out

**Solutions**:
1. Check Railway logs: `railway logs`
2. Verify database connection:
   ```bash
   railway run python3 -c "
   import asyncpg
   import asyncio
   import os
   async def test():
       conn = await asyncpg.connect(os.getenv('DATABASE_URL'))
       print('Connected:', await conn.fetchval('SELECT 1'))
       await conn.close()
   asyncio.run(test())
   "
   ```
3. Check Redis connection: `railway run redis-cli ping`

### Issue: `password authentication failed for user "inntris_api"` (or `inntris_worker`)
**Symptom**: Railway logs show DB auth failures during API/worker startup.

**Why this happens**:
1. `inntris_api` is intentionally created as `NOLOGIN` in migration `005_rls_policies.sql`.
2. `inntris_worker` is `LOGIN` but has no password until you set one.
3. The app only reads `DATABASE_URL`; setting split DB vars in Railway won't be used.

**Fix**:
1. In Supabase SQL Editor:
   ```sql
   ALTER ROLE inntris_worker WITH LOGIN PASSWORD 'YOUR_STRONG_PASSWORD';
   ```
2. Set Railway `DATABASE_URL` to:
   ```bash
   postgresql://inntris_worker.<project_ref>:YOUR_STRONG_PASSWORD@<pooler-host>:6543/postgres
   ```
3. Redeploy API and worker services.

### Issue: Worker Not Anchoring
**Symptom**: No transactions appearing on BaseScan

**Solutions**:
1. Check worker logs for errors
2. Verify wallet has ETH: `cast balance YOUR_WALLET_ADDRESS --rpc-url YOUR_RPC_URL`
3. Check if audit logs exist: `SELECT COUNT(*) FROM audit_logs WHERE merkle_root_id IS NULL;`
4. Manually trigger worker: `railway run python -m workers.anchor_worker`

### Issue: Signature Verification Failing
**Symptom**: 401 errors on `/verify`

**Solutions**:
1. Verify public key matches private key
2. Check timestamp is not skewed (< 5 minutes difference)
3. Verify nonce is unique
4. Test with the MCP server test script

### Issue: Rate Limiting Too Aggressive
**Symptom**: 429 errors frequently

**Solutions**:
1. Increase `RATE_LIMIT_PER_MINUTE` in Railway
2. Check Redis connection (rate limiting requires Redis)
3. Verify rate limit windows are expiring: `redis-cli TTL rate:agent:uuid`

---

## 📚 NEXT STEPS

1. ✅ **Complete this deployment guide**
2. ⬜ **Set up MCP Server**: See `MCP_SETUP.md`
3. ⬜ **Integrate with your AI agents**: See `INTEGRATION_GUIDE.md`
4. ⬜ **Configure Trust Badge**: See `trust_widget/README.md`
5. ⬜ **Set up monitoring dashboards**: See `MONITORING.md`

---

## 🆘 SUPPORT

If you encounter issues during deployment:

1. **Check logs first**: Railway → Logs tab
2. **Review security alerts**: `SELECT * FROM security_alerts ORDER BY created_at DESC LIMIT 10;`
3. **Test database connection**: Use Supabase SQL editor
4. **Verify blockchain**: Check BaseScan for your contract
5. **Run test suite**: `./tests/production_test.sh`

---

## ✅ POST-DEPLOYMENT CHECKLIST

After completing all steps above:

- ⬜ API health check returns 200
- ⬜ Worker logs show "Monitoring for audit logs"
- ⬜ Created at least one organization
- ⬜ Registered at least one agent
- ⬜ Verified at least one action
- ⬜ Confirmed blockchain anchoring works (wait 1 hour after first action)
- ⬜ Set up monitoring alerts
- ⬜ Backed up environment variables
- ⬜ Documented organization IDs and API keys
- ⬜ Configured CORS for your production domains
- ⬜ Tested rate limiting
- ⬜ Reviewed security settings

**Congratulations! Your Inntris Core is now live in production! 🎉**

---

**Last Updated**: 2026-03-18
**Version**: 1.0.0
**Status**: Production Ready
