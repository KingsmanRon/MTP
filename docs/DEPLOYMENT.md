# Inntris Deployment Guide

## Overview

This guide covers deploying Inntris for a live demonstration using:
- **Supabase** — PostgreSQL database
- **Railway** or **Render** — API and Worker hosting
- **MetaMask** — Blockchain wallet for anchoring
- **Vercel** — Frontend dashboard
- **Remix** — Smart contract deployment (already on Base L2)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     DEPLOYMENT ARCHITECTURE                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│   │   Vercel    │    │   Railway   │    │   Railway   │    │
│   │  Frontend   │───▶│   Core API  │───▶│   Worker    │    │
│   │  (Next.js)  │    │  (FastAPI)  │    │  (Anchor)   │    │
│   └─────────────┘    └──────┬──────┘    └──────┬──────┘    │
│                             │                   │           │
│                      ┌──────▼──────┐     ┌──────▼──────┐   │
│                      │  Supabase   │     │   Base L2   │   │
│                      │ (PostgreSQL)│     │ (Blockchain)│   │
│                      └─────────────┘     └─────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Step 1: Database Setup (Supabase)

### 1.1 Create Supabase Project

1. Go to [supabase.com](https://supabase.com) and sign in
2. Click **New Project**
3. Configure:
   - **Name:** `mtp-production`
   - **Database Password:** Generate a strong password (save this!)
   - **Region:** Choose closest to your users
4. Click **Create new project**

### 1.2 Get Connection Details

1. Go to **Settings** → **Database**
2. Copy the **Connection string (URI)**:
   ```
   postgresql://postgres:[PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres
   ```
3. Save this as `DATABASE_URL`

### 1.3 Run Database Schema

1. Go to **SQL Editor** in Supabase dashboard
2. Copy the contents of `database/schemas.sql`
3. Paste and click **Run**
4. Verify tables were created in **Table Editor**

**Expected Tables:**
- `organizations`
- `agents`
- `api_keys`
- `audit_logs`
- `security_alerts`
- `rate_limit_windows`
- `merkle_proofs`

### 1.4 Enable Row Level Security (Optional but Recommended)

In SQL Editor, run:
```sql
-- Enable RLS on sensitive tables
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
```

---

## Step 2: Blockchain Setup (MetaMask + Base L2)

### 2.1 Configure MetaMask for Base L2

1. Open MetaMask
2. Click network dropdown → **Add Network**
3. Add Base Mainnet:
   ```
   Network Name: Base
   RPC URL: https://mainnet.base.org
   Chain ID: 8453
   Currency Symbol: ETH
   Block Explorer: https://basescan.org
   ```

### 2.2 Get ETH for Gas (Base L2)

1. Bridge ETH from Ethereum mainnet to Base using [bridge.base.org](https://bridge.base.org)
2. Or purchase directly on Base via an exchange
3. You need ~0.01 ETH for contract deployment and anchoring

### 2.3 Deploy AnchorRegistry Contract (via Remix)

1. Go to [remix.ethereum.org](https://remix.ethereum.org)
2. Create new file: `AnchorRegistry.sol`
3. Copy contents from `contracts/AnchorRegistry.sol`
4. Compile:
   - Compiler version: `0.8.19`
   - Enable optimization: `200 runs`
5. Deploy:
   - Environment: **Injected Provider - MetaMask**
   - Select Base network in MetaMask
   - Click **Deploy**
6. Save the **contract address**

### 2.4 Export Wallet Private Key

1. In MetaMask, click account → **Account Details**
2. Click **Export Private Key**
3. Enter password and copy the key
4. Save as `BLOCKCHAIN_PRIVATE_KEY` (keep secret!)

---

## Step 3: Generate Secrets

Run these commands locally to generate secure secrets:

```bash
# Generate SERVER_SECRET (64 bytes hex)
python -c "import secrets; print(secrets.token_hex(64))"

# Generate MASTER_ADMIN_KEY (32 bytes hex)
python -c "import secrets; print(secrets.token_hex(32))"

# Generate test API key (for demo)
python -c "import secrets; print(f'mtp_{secrets.token_urlsafe(32)}')"
```

Save these values:
- `SERVER_SECRET` — For HMAC token signing
- `MASTER_ADMIN_KEY` — For admin operations
- Test API key — For demo purposes

---

## Step 4: Deploy Backend (Railway)

### 4.1 Create Railway Account

1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub

### 4.2 Create New Project

1. Click **New Project**
2. Select **Deploy from GitHub repo**
3. Connect your Inntris repository
4. Railway will detect the project

### 4.3 Configure API Service

1. Click on the deployed service
2. Go to **Settings** → **General**
3. Set **Root Directory:** `/` (or leave empty)
4. Set **Start Command:**
   ```bash
   uvicorn api.main:app --host 0.0.0.0 --port $PORT
   ```

### 4.4 Add Environment Variables

Go to **Variables** tab and add:

```env
# Database
DATABASE_URL=postgresql://postgres:[PASSWORD]@db.[REF].supabase.co:5432/postgres

# Redis (Railway provides this)
REDIS_URL=${{Redis.REDIS_URL}}

# Secrets
SERVER_SECRET=your_64_byte_hex_secret
MASTER_ADMIN_KEY=your_32_byte_hex_key

# Blockchain
BLOCKCHAIN_PROVIDER_URL=https://mainnet.base.org
ANCHOR_CONTRACT_ADDRESS=0xYourContractAddress
BLOCKCHAIN_PRIVATE_KEY=your_metamask_private_key
BASE_CHAIN_ID=8453

# Environment
ENVIRONMENT=production
ALLOWED_ORIGINS=https://your-frontend-domain.vercel.app
```

### 4.5 Add Redis Service

1. In Railway project, click **New**
2. Select **Database** → **Redis**
3. Redis URL will auto-populate via `${{Redis.REDIS_URL}}`

### 4.6 Deploy

1. Railway auto-deploys on push
2. Or click **Deploy** manually
3. Wait for build to complete
4. Copy the public URL (e.g., `https://mtp-api-production.up.railway.app`)

### 4.7 Verify Deployment

```bash
curl https://your-api-url.up.railway.app/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "database": "connected",
  "redis": "connected",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## Step 5: Deploy Worker (Railway)

### 5.1 Create Worker Service

1. In same Railway project, click **New** → **GitHub Repo**
2. Select same repository
3. Go to **Settings**
4. Set **Start Command:**
   ```bash
   python -m workers.anchor_worker
   ```

### 5.2 Add Same Environment Variables

Copy all variables from API service, then add:

```env
ANCHOR_INTERVAL_MINUTES=60
ANCHOR_BATCH_SIZE=1000
ANCHOR_MAX_RETRIES=5
```

### 5.3 Deploy

Worker will start and run on schedule.

---

## Step 6: Deploy Frontend (Vercel)

### 6.1 Create Vercel Account

1. Go to [vercel.com](https://vercel.com)
2. Sign up with GitHub

### 6.2 Import Project

1. Click **Add New** → **Project**
2. Import your Inntris repository
3. Configure:
   - **Framework Preset:** Next.js
   - **Root Directory:** `frontend`

### 6.3 Add Environment Variables

```env
NEXT_PUBLIC_API_URL=https://your-api-url.up.railway.app
NEXT_PUBLIC_BLOCKCHAIN_EXPLORER=https://basescan.org
NEXT_PUBLIC_ANCHOR_CONTRACT=0xYourContractAddress
```

### 6.4 Deploy

1. Click **Deploy**
2. Wait for build
3. Copy the URL (e.g., `https://mtp-dashboard.vercel.app`)

### 6.5 Update CORS

Go back to Railway API service and update:
```env
ALLOWED_ORIGINS=https://mtp-dashboard.vercel.app
```

---

## Step 7: Initialize Demo Data

### 7.1 Create Organization

```bash
curl -X POST https://your-api-url.up.railway.app/admin/organizations \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: your_master_admin_key" \
  -d '{
    "name": "Demo Organization",
    "contact_email": "demo@example.com",
    "billing_tier": "professional"
  }'
```

Save the returned `organization_id` and `api_key`.

### 7.2 Generate Agent Keypair

```bash
python -c "
from nacl.signing import SigningKey
import base64
sk = SigningKey.generate()
print(f'Private Key (B64): {base64.b64encode(bytes(sk)).decode()}')
print(f'Public Key (B64): {base64.b64encode(bytes(sk.verify_key)).decode()}')
"
```

### 7.3 Register Demo Agent

```bash
curl -X POST https://your-api-url.up.railway.app/admin/agents \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "org_id": "your_org_id",
    "name": "Demo Payment Agent",
    "public_key": "base64_public_key",
    "daily_limit_usd": 500,
    "per_action_limit_usd": 100,
    "allowed_actions": ["financial_transaction", "email_send", "api_call"]
  }'
```

Save the returned `agent_id`.

---

## Step 8: Test the Deployment

### 8.1 Test Verification (Approved)

```bash
# You'll need to sign this properly - use the MCP server for real tests
curl -X POST https://your-api-url.up.railway.app/verify \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "your_agent_id",
    "action_type": "financial_transaction",
    "payload": {"amount": 50, "currency": "USD", "recipient": "test@example.com"},
    "signature": "base64_signature",
    "nonce": "unique_nonce_123",
    "timestamp": "2024-01-15T10:30:00Z"
  }'
```

### 8.2 Test Dashboard

1. Open `https://your-frontend.vercel.app`
2. Navigate to `/admin`
3. Verify you see the dashboard

### 8.3 Test Public Verification

1. Open `https://your-frontend.vercel.app/verify`
2. Enter your agent ID
3. Verify trust status displays

---

## Step 9: Domain Setup (Optional)

### Custom Domain for API

1. In Railway, go to service **Settings** → **Networking**
2. Add custom domain: `api.yourdomain.com`
3. Add DNS record as instructed

### Custom Domain for Frontend

1. In Vercel, go to project **Settings** → **Domains**
2. Add custom domain: `app.yourdomain.com`
3. Add DNS record as instructed

---

## Environment Variables Reference

### API Service (Railway)

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | Supabase connection string | `postgresql://...` |
| `REDIS_URL` | Railway Redis URL | Auto-populated |
| `SERVER_SECRET` | 64-byte hex for HMAC | `a1b2c3...` |
| `MASTER_ADMIN_KEY` | 32-byte hex for admin | `d4e5f6...` |
| `BLOCKCHAIN_PROVIDER_URL` | Base L2 RPC | `https://mainnet.base.org` |
| `ANCHOR_CONTRACT_ADDRESS` | Deployed contract | `0x...` |
| `BLOCKCHAIN_PRIVATE_KEY` | MetaMask export | `0x...` |
| `BASE_CHAIN_ID` | Chain ID | `8453` |
| `ENVIRONMENT` | Environment name | `production` |
| `ALLOWED_ORIGINS` | CORS origins | `https://app.yourdomain.com` |

### Worker Service (Railway)

Same as API, plus:

| Variable | Description | Example |
|----------|-------------|---------|
| `ANCHOR_INTERVAL_MINUTES` | Batch interval | `60` |
| `ANCHOR_BATCH_SIZE` | Max logs per batch | `1000` |
| `ANCHOR_MAX_RETRIES` | Retry attempts | `5` |

### Frontend (Vercel)

| Variable | Description | Example |
|----------|-------------|---------|
| `NEXT_PUBLIC_API_URL` | Backend API URL | `https://api.yourdomain.com` |
| `NEXT_PUBLIC_BLOCKCHAIN_EXPLORER` | Block explorer | `https://basescan.org` |
| `NEXT_PUBLIC_ANCHOR_CONTRACT` | Contract address | `0x...` |

---

## Troubleshooting

### Database Connection Failed

```
Error: connection to server failed
```

**Solution:**
1. Check Supabase project is active
2. Verify `DATABASE_URL` format
3. Check if IP is allowlisted (Supabase → Settings → Database → Connection Pooling)

### Redis Connection Failed

```
Error: Redis connection refused
```

**Solution:**
1. Ensure Redis service is running in Railway
2. Check `REDIS_URL` is using Railway variable reference

### Blockchain Transaction Failed

```
Error: insufficient funds for gas
```

**Solution:**
1. Add more ETH to your wallet on Base L2
2. Check `BLOCKCHAIN_PRIVATE_KEY` is correct

### CORS Error

```
Error: CORS policy blocked
```

**Solution:**
1. Update `ALLOWED_ORIGINS` in Railway
2. Include full URL with protocol
3. Redeploy API service

### Frontend Build Failed

```
Error: Module not found
```

**Solution:**
1. Check `frontend/package.json` dependencies
2. Run `npm install` locally to verify
3. Check Vercel build logs

---

## Monitoring

### Railway Logs

1. Go to service → **Deployments** → **View Logs**
2. Or use Railway CLI: `railway logs`

### Supabase Logs

1. Go to **Logs** in Supabase dashboard
2. Filter by `postgres` for database logs

### Vercel Logs

1. Go to project → **Deployments** → **Functions**
2. View real-time logs

---

## Demo Checklist

Before presentation, verify:

- [ ] API health endpoint returns `healthy`
- [ ] Dashboard loads at frontend URL
- [ ] Can view agents in Admin Console
- [ ] Can create test verification
- [ ] Audit logs appear in Audit Explorer
- [ ] Public verification page works
- [ ] Blockchain explorer shows contract

---

## Quick Commands

```bash
# Check API health
curl https://your-api.up.railway.app/health

# Create organization
curl -X POST https://your-api.up.railway.app/admin/organizations \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: YOUR_ADMIN_KEY" \
  -d '{"name": "Test Org", "contact_email": "test@test.com", "billing_tier": "professional"}'

# List agents
curl https://your-api.up.railway.app/admin/agents \
  -H "X-API-Key: YOUR_API_KEY"

# Check agent public info
curl https://your-api.up.railway.app/public/agent/AGENT_UUID
```
