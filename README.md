#Inntris Core

> **Cryptographic verification and policy enforcement for AI agent actions.** 

Inntris is a runtime verification and cryptographic audit layer for AI agents. It verifies agent actions before execution, signs decisions with agent identity, and produces a tamper-evident receipt for every decision.

## What Inntris Is

A **policy decision point and evidence system** for AI agent actions — not observability, logging, or prompt guardrails.

### Core Philosophy

- **"Fail Closed"** — If an agent cannot be verified, it cannot act
- **"Zero Trust"** — Never trust the client; always verify the signature
- **"Tamper-Evident"** — Every decision produces a signed, verifiable record

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AI AGENT (Lovable/Replit/LangChain)               │
│                                      │                                      │
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
│  (Supabase)   │        │ "Tamper-Evident Recorder"│       │   (React)     │
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

The **"Tamper-Evident Recorder"** for immutable audit trails.

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
git clone https://github.com/KingsmanRon/MTP
cd MTP

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
# Create organization (operator-only; returns an API key shown ONCE — save it).
# Requires MASTER_ADMIN_KEY (>= 32 chars) set in the API environment; the
# X-Master-Key header value below must equal that env var. Partners are usually
# handed an org_id + API key directly, or can self-serve (see "Alternative" below).
curl -X POST http://localhost:8000/admin/organizations \
  -H "Content-Type: application/json" \
  -H "X-Master-Key: $MASTER_ADMIN_KEY" \
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

### Alternative: self-serve agent (no admin key)

If you don't have an operator master key, bootstrap an agent against the live
API with no auth. You generate the keypair locally and only ever send the
**public** key:

```bash
# Generate an Ed25519 keypair locally (the private seed stays on your machine)
python -c "
from nacl.signing import SigningKey
import base64
sk = SigningKey.generate()
print('INNTRIS_PRIVATE_KEY_B64 =', base64.b64encode(bytes(sk)).decode())
print('public_key             =', base64.b64encode(bytes(sk.verify_key)).decode())
"

# Register it (returns an immediately-usable agent_id)
curl -X POST https://api.inntris.com/public/agents/register \
  -H "Content-Type: application/json" \
  -d '{ "email": "you@example.com", "public_key": "BASE64_PUBLIC_KEY_HERE" }'
```

Self-serve agents start with `allowed_actions = ["tool_call", "api_call"]` and
default limits — enough for your first verified call. To enable
`financial_transaction`, higher limits, or AI-PR-Guard action types, you need a
provisioned org with an admin key (those controls live behind authenticated
`/admin` endpoints). Rate limit: 5 registrations per IP per hour.

### 4. Configure MCP Server

Add to your AI agent's MCP configuration:

```json
{
  "mcpServers": {
    "inntris-guard": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "env": {
        "INNTRIS_API_URL": "https://api.inntris.com",
        "INNTRIS_AGENT_ID": "<your-agent-id>",
        "INNTRIS_PRIVATE_KEY_B64": "<agent-ed25519-seed-b64>"
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

## Try it in 30 seconds

Returns a live, Base-mainnet-anchored receipt. No auth required.

```bash
curl -s https://api.inntris.com/public/verify/3030c27c-87c4-4464-b4af-605fbe638e0e | jq
```

Fetch the Merkle proof for the same receipt:

```bash
curl -s https://api.inntris.com/public/verify/3030c27c-87c4-4464-b4af-605fbe638e0e/proof | jq
```

- The first call returns the public verification receipt.
- The second call returns the Merkle proof.
- `chain_id` must be `8453` (Base mainnet).
- `integrity_status` should be `verified`.

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
  "timestamp": "2026-01-15T10:30:00Z",
  "sig_version": 2,
  "policy_hash": null
}
```

- `signature` — Ed25519 signature of the action hash. See
  **[docs/REQUEST_SIGNING.md](docs/REQUEST_SIGNING.md)** for the exact
  construction, or POST the same body to **`/verify/debug`** (no side effects) to
  get the server-computed `expected_action_hash` and confirm `signature_valid`
  before going live.
- `sig_version` — signing-envelope version (default `2`; use `3` for RFC 8785 JCS
  from non-Python SDKs).
- `policy_hash` — only for AI-PR-Guard action types (`repo_change`,
  `ci_workflow_change`, `protected_branch_merge`, `production_deployment`): the
  canonical hash of the registered `.inntris.yml`. Omit/`null` for other actions.

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

**Error format:** errors return `{ "detail": "<message>", ... }`. A `401`
signature failure additionally includes `expected_action_hash`,
`canonical_timestamp`, and `sig_version` to help you debug signing; a `422`
validation error includes a stable `"error": "validation_error"` code and a
`details.fields` list. Every response carries an `X-Request-ID` header.

**Trust scores:** new agents start at **50**. Common runtime actions pass at that
level (financial 30, email 20, api/tool 10, data_export 40), but higher-risk
types require more: `admin_action` 70, and `ci_workflow_change`,
`protected_branch_merge`, `production_deployment` 80. Trust accrues +1 per
approval (−20 on a bad signature). To promote a vetted agent immediately,
`PATCH /admin/agents/{id}` with `{ "trust_score": 85 }`.

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

Fetch the proof from `GET /public/verify/{audit_id}/proof` (no auth). It returns
`action_hash` (the leaf), `proof` (sibling hashes), `positions` (`true` = sibling
on the right), `merkle_root`, and `tx_hash`. Recompute the root and compare it to
what the `AnchorRegistry` contract has anchored:

- **Leaf** = the `action_hash` (lowercase SHA-256 hex of the action).
- **Parent** = `keccak256(left || right)` over the 32-byte concatenation —
  Ethereum keccak, **not** SHA-256, so it matches the Solidity contract. When a
  level has an odd number of nodes, the last node is duplicated.
- Walk `proof`/`positions` from the leaf upward, then `0x`-prefix the result and
  confirm the batch on-chain:

```solidity
// On-chain: confirm a Merkle root was anchored
function getBatch(bytes32 merkleRoot)
    returns (uint256 batchId, uint256 logCount, uint256 timestamp, address submitter)
```

Reference implementation: `workers/anchor_worker.py` (`compute_merkle_root` /
`compute_merkle_proof`); end-to-end checker: `scripts/verify_receipt.py`.

---

## Security Considerations

### Cryptographic Security

- **Ed25519 Signatures**: All agent actions are signed with Ed25519
- **Nonce Protection**: Each request requires a unique nonce (replay attack prevention)
- **Timestamp Validation**: Maximum 5-minute clock skew allowed
- **HMAC Approval Tokens**: Server-signed tokens for approved actions

### Database Security

- **Append-Only Audit Logs**: Triggers prevent UPDATE/DELETE on `audit_logs`
- **Row-Level Security**: Tenant RLS migrations and integration tests are included; confirm the production runtime role and applied migrations before relying on RLS
- **API Key Hashing**: Keys stored as SHA-256 hashes only

### Operational Security

- **Rate Limiting**: Per-minute, per-day limits per agent
- **Security Alerts**: Automatic alerts on signature failures
- **Trust Score Decay**: Scores decay toward baseline over time

For buyer-facing security material, deployment-evidence boundaries, and the
14-day pilot SOW, start with the [Inntris Trust Pack](docs/trust/README.md).

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

Kubernetes manifests and a Helm chart are not shipped in this repository. Anchor-worker and API are standard 12-factor processes that read configuration from environment variables (see `.env.example`) and can be run under any orchestrator.

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

Backend unit tests live in `tests/` and run against the Python package with `PYTHONPATH=.`:

```bash
# Python unit tests
PYTHONPATH=. pytest tests/

# Frontend (Jest — type-check, lint, invariant & unit tests)
cd frontend && npm test
```

Integration tests (end-to-end against a real Postgres + Redis + anchored chain) and blockchain-specific test suites are not included in this repository yet — see `docs/ENTERPRISE_READINESS_ASSESSMENT.md` for the planned rollout.

---

## License

Business Source Licence 1.1 — See [LICENSE](LICENSE) for details.

You may use this code for internal purposes. You may not use it to offer a competing hosted verification or audit service without a commercial licence from Inntris INC. Converts to Apache 2.0 on 2030-03-18.

Commercial licensing: sales@inntris.com

---

## Contributing

We welcome contributions! Please open an issue to discuss proposed changes before submitting a PR.

---

## Support

- **Documentation**: See the `/docs` page in the frontend dashboard
- **Issues**: Open an issue in this repository
- **Contact**: sales@inntris.com

---

*Inntris — Cryptographic verification for AI agents.*

**© 2026 Inntris INC. All rights reserved.**
