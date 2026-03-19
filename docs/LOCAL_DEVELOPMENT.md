# Inntris Local Development Guide

## Quick Start (5 minutes)

### Prerequisites

- Python 3.12+
- Node.js 18+
- Docker & Docker Compose

### 1. Clone and Setup

```bash
git clone https://github.com/KingsmanRon/MTP
cd inntris-core

# Create Python virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -e ".[dev]"

# Install frontend dependencies
cd frontend && npm install && cd ..
```

### 2. Start Infrastructure

```bash
# Start PostgreSQL and Redis
docker compose up -d postgres redis

# Wait for services to be ready
sleep 5

# Verify services
docker compose ps
```

### 3. Initialize Database

```bash
# Run schema
docker compose exec postgres psql -U postgres -d inntris -f /docker-entrypoint-initdb.d/schemas.sql

# Or connect manually and run schemas.sql
psql postgresql://postgres:postgres@localhost:5432/inntris < database/schemas.sql
```

### 4. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your settings (defaults work for local dev)
```

Default `.env` for local development:

```env
# Generate real values using the commands in Step 3 of DEPLOYMENT_GUIDE.md
# NEVER commit real secrets to version control

# Database
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/inntris

# Redis
REDIS_URL=redis://localhost:6379

# Secrets (use these for local dev only!)
SERVER_SECRET=<generate-using-command-in-step-3-of-DEPLOYMENT_GUIDE.md>
MASTER_ADMIN_KEY=<generate-using-command-in-step-3-of-DEPLOYMENT_GUIDE.md>

# Blockchain (optional for local dev)
BLOCKCHAIN_PROVIDER_URL=https://base.publicnode.com
ANCHOR_CONTRACT_ADDRESS=0x0000000000000000000000000000000000000000
BLOCKCHAIN_PRIVATE_KEY=0000000000000000000000000000000000000000000000000000000000000000
BASE_CHAIN_ID=8453

# Environment
ENVIRONMENT=development
```

### 5. Start API Server

```bash
# Terminal 1: Start API
source venv/bin/activate
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

API will be available at: `http://localhost:8000`
- Docs: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`

### 6. Start Frontend (Optional)

```bash
# Terminal 2: Start Frontend
cd frontend
npm run dev
```

Frontend will be available at: `http://localhost:3000`

### 7. Create Test Data

```bash
# Create organization
curl -X POST http://localhost:8000/admin/organizations \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: YOUR_MASTER_ADMIN_KEY" \
  -d '{
    "name": "Test Organization",
    "contact_email": "admin@test.com",
    "billing_tier": "professional"
  }'

# Save the returned API key and org_id!
```

```bash
# Generate keypair for agent
python -c "
from nacl.signing import SigningKey
import base64
sk = SigningKey.generate()
print(f'PRIVATE_KEY={base64.b64encode(bytes(sk)).decode()}')
print(f'PUBLIC_KEY={base64.b64encode(bytes(sk.verify_key)).decode()}')
"
```

```bash
# Create agent (use your org_id and API key)
curl -X POST http://localhost:8000/admin/agents \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "org_id": "YOUR_ORG_ID",
    "name": "Test Agent",
    "public_key": "YOUR_PUBLIC_KEY",
    "daily_limit_usd": 500,
    "per_action_limit_usd": 100,
    "allowed_actions": ["financial_transaction", "email_send", "api_call"]
  }'
```

---

## Running Tests

```bash
# Activate virtual environment
source venv/bin/activate

# Run all tests
pytest

# Run with coverage
pytest --cov=api --cov=mcp_server --cov-report=html

# Run specific test file
pytest tests/test_verification.py

# Run with verbose output
pytest -v
```

---

## Docker Compose (Full Stack)

To run everything in Docker:

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f api

# Stop all services
docker compose down
```

Services:
- API: `http://localhost:8000`
- Frontend: `http://localhost:3000`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

---

## MCP Server Testing

### Configure Claude Desktop

Add to `~/.config/claude/claude_desktop_config.json`:

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

### Test MCP Tools

In Claude Desktop, ask:
> "Use the inntris_guard tool to verify a $50 financial transaction to vendor@example.com"

Expected response:
```
APPROVED - Action verified successfully.
Audit ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Trust Score: 50
```

---

## Common Development Tasks

### Reset Database

```bash
# Drop and recreate
docker compose exec postgres psql -U postgres -c "DROP DATABASE IF EXISTS inntris;"
docker compose exec postgres psql -U postgres -c "CREATE DATABASE inntris;"
docker compose exec postgres psql -U postgres -d inntris -f /docker-entrypoint-initdb.d/schemas.sql
```

### View Database

```bash
# Connect to PostgreSQL
docker compose exec postgres psql -U postgres -d inntris

# Common queries
SELECT * FROM organizations;
SELECT * FROM agents;
SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10;
```

### Clear Redis

```bash
docker compose exec redis redis-cli FLUSHALL
```

### Regenerate API Key

```python
from api.crypto import CryptoService
key, hash = CryptoService.generate_api_key()
print(f"Key: {key}")
print(f"Hash: {hash}")
```

---

## Project Structure

```
inntris/
├── api/                    # Core API (FastAPI)
│   ├── __init__.py
│   ├── main.py            # Application entry point
│   ├── crypto.py          # Cryptographic operations
│   ├── database.py        # Database operations
│   ├── models.py          # Pydantic models
│   └── policy.py          # Policy engine
├── mcp_server/            # MCP Server
│   ├── __init__.py
│   └── server.py          # MCP tool definitions
├── workers/               # Background workers
│   └── anchor_worker.py   # Blockchain anchoring
├── contracts/             # Smart contracts
│   └── AnchorRegistry.sol # Solidity contract
├── database/              # Database schemas
│   └── schemas.sql        # PostgreSQL schema
├── frontend/              # Next.js dashboard
│   ├── src/
│   │   ├── app/           # Pages
│   │   ├── components/    # React components
│   │   └── lib/           # Utilities
│   └── package.json
├── trust_widget/          # React trust badge
├── tests/                 # Test suite
├── docs/                  # Documentation
├── docker-compose.yml     # Docker orchestration
├── pyproject.toml         # Python project config
├── requirements.txt       # Python dependencies
└── README.md
```

---

## IDE Setup

### VS Code

Recommended extensions:
- Python
- Pylance
- ESLint
- Prettier
- Tailwind CSS IntelliSense

`.vscode/settings.json`:
```json
{
  "python.defaultInterpreterPath": "./venv/bin/python",
  "python.formatting.provider": "black",
  "python.linting.enabled": true,
  "python.linting.mypyEnabled": true,
  "editor.formatOnSave": true
}
```

### PyCharm

1. Set Python interpreter to `venv/bin/python`
2. Mark `api/`, `mcp_server/`, `workers/` as Sources Root
3. Enable Black formatter

---

## Debugging

### API Debugging

```python
# Add to api/main.py for debugging
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Frontend Debugging

```bash
# Start with debug output
DEBUG=* npm run dev
```

### Database Debugging

```bash
# Enable query logging
docker compose exec postgres psql -U postgres -c "ALTER SYSTEM SET log_statement = 'all';"
docker compose exec postgres psql -U postgres -c "SELECT pg_reload_conf();"
```

---

## Performance Testing

```bash
# Install locust
pip install locust

# Create locustfile.py (example)
# Run load test
locust -f locustfile.py --host=http://localhost:8000
```

---

## Troubleshooting

### Port Already in Use

```bash
# Find process using port
lsof -i :8000
# Kill it
kill -9 <PID>
```

### Docker Issues

```bash
# Reset Docker
docker compose down -v
docker system prune -f
docker compose up -d
```

### Python Import Errors

```bash
# Reinstall in editable mode
pip install -e ".[dev]"
```

### Frontend Build Errors

```bash
# Clear cache and reinstall
cd frontend
rm -rf node_modules .next
npm install
npm run dev
```
