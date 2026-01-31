# Inntris Core

> **Protecting Intellect. The Universal Liability Shield for Autonomous Agents.**

Inntris INC provides advanced security infrastructure and defensive protocols for artificial intelligence systems and third-party platforms. We serve as a protective shell that safeguards high-level cognitive models and ensures their integrity across diverse digital ecosystems.

## The Universal Trust Layer for AI Agents

Inntris Core is a production-ready **Verification & Liability Platform** for AI Agents. Think of it as the **"VISA Network" for AI** — providing Identity, Audit, and Control for any AI agent through a standardized Model Context Protocol (MCP) Server.

### Core Philosophy

- **"Fail Closed"** — If an agent cannot be verified, it cannot act
- **"Zero Trust"** — Never trust the client; always verify the signature
- **"Forensic Grade"** — Audit logs are not for debugging; they are for court

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AI AGENT (Lovable/Replit/LangChain)               │
│                                      │                                       │
│                          ┌───────────▼───────────┐                          │
│                          │   MCP Server (Inntris)│                          │
│                          │   "Universal Adapter" │                          │
│                          └───────────┬───────────┘                          │
└──────────────────────────────────────┼──────────────────────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │        Core Enforcer API            │
                    │        "The Central Bank"           │
                    │  ┌─────────────────────────────┐   │
                    │  │ Identity Service (Ed25519)  │   │
                    │  │ Policy Engine (Limits)      │   │
                    │  │ Trust Scorer (0-100)        │   │
                    │  └─────────────────────────────┘   │
                    └──────────────────┬──────────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
        ▼                              ▼                              ▼
┌───────────────┐           ┌───────────────────┐           ┌───────────────┐
│   PostgreSQL  │           │   Anchor Worker   │           │  Trust Badge  │
│  (Supabase)   │           │ "Forensic Recorder"│          │   (React)     │
│  + TimescaleDB│           │  Merkle → Base L2 │           │ "Verified UI" │
└───────────────┘           └───────────────────┘           └───────────────┘
                                                                    │
                                       ┌────────────────────────────┘
                                       ▼
                    ┌──────────────────────────────────────┐
                    │       Frontend Dashboard             │
                    │       "Management Console"           │
                    │  ┌────────────┬────────────────────┐ │
                    │  │Admin Console│   Agent Portal    │ │
                    │  │Audit Explorer│ Public Verify    │ │
                    │  └────────────┴────────────────────┘ │
                    └──────────────────────────────────────┘
```

---

## Components

### Component A: MCP Server (`mcp_server/`)

The **"Universal Adapter"** that runs alongside any AI agent.

- Exposes `inntris_guard` tool via Model Context Protocol
- Intercepts critical actions before execution
- Signs requests with Ed25519 private key
- Returns APPROVED (with token) or BLOCKED (raises exception)

### Component B: Core Enforcer API (`api/`)

The **"Central Bank"** for agent verification.

- **Identity Service**: Validates Ed25519 signatures against registered public keys
- **Policy Engine**: Enforces limits (daily caps, per-action limits, rate limiting)
- **Trust Scorer**: Real-time trust scores (0-100) based on agent behavior

### Component C: Audit Engine (`workers/`)

The **"Forensic Recorder"** for immutable audit trails.

- Ingests all verification events into PostgreSQL
- Batches logs into Merkle trees every hour
- Anchors Merkle roots to Base L2 blockchain
- Provides cryptographic proof of audit existence

### Component D: Trust Badge (`trust_widget/`)

The **"Embeddable Widget"** for end-user verification.

- Lightweight React component
- Displays verified status and trust score
- Queries public API endpoint
- Real-time refresh capability

### Component E: Frontend Dashboard (`frontend/`)

The **"Management Console"** for organizations and developers.

- **Admin Console**: Organization management, agent policies, security alerts, API keys
- **Agent Portal**: Developer dashboard, credentials, verification playground
- **Audit Explorer**: Log search, Merkle proof verification, compliance exports
- **Public Verification**: Public agent trust verification page

---

## Quick Start

### Prerequisites

- Python 3.12+
- Docker & Docker Compose
- Node.js 18+ (for Frontend Dashboard and Trust Badge widget)

### 1. Clone & Configure

```bash
git clone https://github.com/inntris/inntris-core.git
cd inntris-core

# Copy environment template
cp .env.example .env

# Edit .env with your configuration
# IMPORTANT: Generate secure secrets for production!
```

### 2. Start Services

```bash
# Start all services (PostgreSQL, Redis, API, Worker)
docker compose up -d

# View logs
docker compose logs -f api

# Check health
curl http://localhost:8000/health
```

### 3. Register an Organization & Agent

```bash
# Create organization (returns API key - save it!)
curl -X POST http://localhost:8000/admin/organizations \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: YOUR_ADMIN_KEY" \
  -d '{
    "name": "My AI Company",
    "contact_email": "admin@example.com",
    "billing_tier": "professional"
  }'

# Generate Ed25519 keypair for your agent
python -c "
from nacl.signing import SigningKey
import base64
sk = SigningKey.generate()
print(f'Private Key (B64): {base64.b64encode(bytes(sk)).decode()}')
print(f'Public Key (B64): {base64.b64encode(bytes(sk.verify_key)).decode()}')
"

# Register agent with the public key
curl -X POST http://localhost:8000/admin/agents \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "org_id": "YOUR_ORG_ID",
    "name": "My AI Agent",
    "public_key": "BASE64_PUBLIC_KEY_HERE",
    "daily_limit_usd": 500,
    "per_action_limit_usd": 100
  }'
```

### 4. Configure MCP Server

Add to your AI agent's MCP configuration:

```json
{
  "mcpServers": {
    "inntris-guard": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "env": {
        "INNTRIS_API_URL": "http://localhost:8000",
        "INNTRIS_AGENT_ID": "YOUR_AGENT_UUID",
        "INNTRIS_PRIVATE_KEY_B64": "YOUR_BASE64_PRIVATE_KEY"
      }
    }
  }
}
```

### 5. Start Frontend Dashboard (Optional)

```bash
cd frontend

# Install dependencies
npm install

# Copy environment template
cp .env.example .env.local
# Edit .env.local with your API URL

# Start development server
npm run dev
```

The dashboard will be available at `http://localhost:3000` with four interfaces:

| Interface | URL | Purpose |
|-----------|-----|---------|
| Admin Console | `/admin` | Manage agents, alerts, API keys |
| Agent Portal | `/portal` | Developer dashboard, test verification |
| Audit Explorer | `/audit` | Search logs, verify proofs, export |
| Public Verify | `/verify` | Public agent trust verification |

---

## API Reference

### POST `/verify`

Verify an agent action before execution.

**Request:**
```json
{
  "agent_id": "uuid",
  "action_type": "financial_transaction",
  "payload": {
    "amount": 99.99,
    "currency": "USD",
    "recipient": "user@example.com",
    "description": "Payment for services"
  },
  "signature": "base64_ed25519_signature",
  "nonce": "unique_random_string",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response (200 OK):**
```json
{
  "verdict": "approved",
  "verdict_reason": "All verification checks passed",
  "approval_token": "base64_token",
  "trust_score": 85,
  "audit_id": "uuid",
  "timestamp": "2024-01-15T10:30:01Z",
  "limits_remaining": {
    "daily_limit_usd": "500.00",
    "daily_spent_usd": "99.99",
    "daily_remaining_usd": "400.01"
  }
}
```

**Error Responses:**
- `401 Unauthorized` - Signature verification failed
- `403 Forbidden` - Policy violation (limits exceeded, blocked action)
- `404 Not Found` - Agent not registered
- `429 Too Many Requests` - Rate limit exceeded

### GET `/public/agent/{agent_id}`

Get public trust information for the Trust Badge.

**Response:**
```json
{
  "agent_id": "uuid",
  "name": "My AI Agent",
  "organization_name": "My AI Company",
  "trust_score": 85,
  "status": "active",
  "is_verified": true,
  "verified_since": "2024-01-01T00:00:00Z",
  "total_actions": 1234,
  "last_action_at": "2024-01-15T10:30:00Z"
}
```

### Admin API Endpoints (Authenticated)

All admin endpoints require the `X-API-Key` header.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/agents` | GET | List all agents for organization |
| `/admin/agents/{id}` | GET | Get specific agent details |
| `/admin/agents/{id}` | PATCH | Update agent configuration |
| `/admin/agents/{id}/status` | PATCH | Update agent status |
| `/admin/alerts` | GET | List security alerts |
| `/admin/alerts/{id}/acknowledge` | POST | Acknowledge an alert |
| `/admin/alerts/{id}/resolve` | POST | Resolve an alert |
| `/admin/audit/search` | GET | Search audit logs with filters |
| `/admin/audit/{id}` | GET | Get specific audit log |
| `/admin/audit/{id}/proof` | GET | Get Merkle proof for verification |
| `/admin/usage` | GET | Get usage metrics |
| `/admin/organization` | GET | Get organization info |
| `/admin/api-keys` | GET | List API keys |
| `/admin/api-keys/rotate` | POST | Rotate API key |
| `/admin/api-keys/{prefix}` | DELETE | Revoke API key |

---

## MCP Tool Usage

When the MCP server is configured, AI agents can use the `inntris_guard` tool:

```
CRITICAL: You MUST call inntris_guard before executing any financial transaction
or sending external emails. Failure to call this tool will result in liability.

Tool: inntris_guard
Arguments:
  - action_type: "financial_transaction" | "email_send" | "api_call" | "data_export"
  - amount: number (required for financial_transaction)
  - recipient: string
  - description: string (required)
  - metadata: object (optional)
```

**Example Agent Prompt:**
```
Before sending this $50 payment to user@example.com, I need to verify
this action with Inntris.

[Agent calls inntris_guard with action_type="financial_transaction", amount=50, ...]

Response: APPROVED - You may proceed with the action.
```

---

## Blockchain Anchoring

Inntris uses the Base L2 blockchain for immutable audit anchoring.

### AnchorRegistry Contract

The `AnchorRegistry.sol` contract stores Merkle roots of audit batches:

- Each batch contains up to 1,000 audit log hashes
- Merkle root is computed and submitted hourly
- On-chain proof verification available
- Gas-efficient batch operations

### Verifying Audit Proofs

```solidity
// Verify a specific log was part of an anchored batch
function verifyProof(
    bytes32 merkleRoot,
    bytes32 leaf,           // SHA-256 hash of the audit log
    bytes32[] proof,        // Merkle proof path
    uint8[] positions       // 0=left, 1=right for each level
) returns (bool valid)
```

---

## Security Considerations

### Cryptographic Security

- **Ed25519 Signatures**: All agent actions are signed with Ed25519
- **Nonce Protection**: Each request requires a unique nonce (replay attack prevention)
- **Timestamp Validation**: Maximum 5-minute clock skew allowed
- **HMAC Approval Tokens**: Server-signed tokens for approved actions

### Database Security

- **Append-Only Audit Logs**: Triggers prevent UPDATE/DELETE on `audit_logs`
- **Row-Level Security**: PostgreSQL RLS enabled on all tables
- **API Key Hashing**: Keys stored as SHA-256 hashes only

### Operational Security

- **Rate Limiting**: Per-minute, per-day limits per agent
- **Security Alerts**: Automatic alerts on signature failures
- **Trust Score Decay**: Scores decay toward baseline over time

---

## Deployment

### Railway / Render

1. Connect your repository
2. Set environment variables from `.env.example`
3. Deploy with Procfile:
   - `web`: Core API
   - `worker`: Anchor Worker

### Docker Production

```bash
# Build production images
docker compose build

# Deploy with external database
DATABASE_URL=postgresql://... docker compose up -d api anchor-worker
```

### Kubernetes

Helm charts available in `deploy/kubernetes/` (coming soon).

---

## Development

### Local Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy api/ mcp_server/ workers/

# Linting
ruff check .
black --check .
```

### Running Tests

```bash
# Unit tests
pytest tests/unit/

# Integration tests (requires Docker)
pytest tests/integration/ --docker

# Blockchain tests (requires testnet)
pytest tests/blockchain/ -m blockchain
```

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Support

- **Documentation**: [docs.inntris.io](https://docs.inntris.io)
- **Issues**: [GitHub Issues](https://github.com/inntris/inntris-core/issues)
- **Discord**: [Inntris Community](https://discord.gg/inntris)

---

*Protecting Intellect. The Universal Liability Shield for Autonomous Agents.*

**© 2024 Inntris INC. All rights reserved.**
