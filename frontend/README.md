# MTP Frontend Dashboard

The **Management Console** for the Machine Trust Protocol - a Next.js 14 application providing comprehensive interfaces for organizations, developers, and compliance teams.

## Overview

The frontend consists of four distinct interfaces:

| Interface | URL | Purpose | Users |
|-----------|-----|---------|-------|
| **Admin Console** | `/admin` | Organization management | Org Admins |
| **Agent Portal** | `/portal` | Developer tools & testing | Developers |
| **Audit Explorer** | `/audit` | Forensic log search & verification | Compliance |
| **Public Verify** | `/verify` | Public trust verification | Anyone |

## Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **State Management**: TanStack Query (React Query)
- **Charts**: Recharts
- **Blockchain**: ethers.js v6 (for Merkle proof verification)

## Quick Start

```bash
# Install dependencies
npm install

# Copy environment template
cp .env.example .env.local

# Edit .env.local with your configuration
# NEXT_PUBLIC_API_URL=http://localhost:8000

# Start development server
npm run dev
```

The application will be available at `http://localhost:3000`.

## Project Structure

```
frontend/
├── src/
│   ├── app/                    # Next.js App Router pages
│   │   ├── admin/              # Admin Console
│   │   │   ├── page.tsx        # Dashboard
│   │   │   ├── agents/         # Agent management
│   │   │   ├── alerts/         # Security alerts
│   │   │   ├── api-keys/       # API key management
│   │   │   └── settings/       # Organization settings
│   │   ├── portal/             # Agent Portal
│   │   │   ├── page.tsx        # Agent dashboard
│   │   │   ├── credentials/    # Key management
│   │   │   ├── playground/     # Verification testing
│   │   │   └── logs/           # Activity logs
│   │   ├── audit/              # Audit Explorer
│   │   │   ├── page.tsx        # Log search
│   │   │   ├── verify/         # Merkle verification
│   │   │   └── exports/        # Compliance exports
│   │   ├── verify/             # Public Verification
│   │   │   ├── page.tsx        # Landing page
│   │   │   └── [agentId]/      # Agent verification
│   │   ├── layout.tsx          # Root layout
│   │   ├── page.tsx            # Home page
│   │   └── globals.css         # Global styles
│   ├── components/
│   │   ├── ui/                 # Reusable UI components
│   │   │   ├── button.tsx
│   │   │   ├── card.tsx
│   │   │   ├── input.tsx
│   │   │   ├── table.tsx
│   │   │   └── ...
│   │   ├── layout/             # Layout components
│   │   │   ├── dashboard-layout.tsx
│   │   │   └── sidebar.tsx
│   │   ├── providers/          # Context providers
│   │   │   ├── query-provider.tsx
│   │   │   └── theme-provider.tsx
│   │   ├── trust-score.tsx     # Trust score visualization
│   │   ├── verdict-badge.tsx   # Verdict status badges
│   │   └── stats-card.tsx      # Metrics cards
│   └── lib/
│       ├── api.ts              # Type-safe API client
│       └── utils.ts            # Utility functions
├── public/                     # Static assets
├── .env.example                # Environment template
├── next.config.mjs             # Next.js configuration
├── tailwind.config.ts          # Tailwind configuration
├── tsconfig.json               # TypeScript configuration
└── package.json                # Dependencies
```

## Features by Interface

### Admin Console (`/admin`)

**Dashboard**
- Real-time metrics (verifications, approvals, blocks)
- Trust score distribution charts
- Daily verification trends
- Recent activity feed
- Security alert notifications

**Agent Management** (`/admin/agents`)
- List all organization agents
- Create new agents with Ed25519 key generation
- Configure agent policies:
  - Daily spending limits
  - Per-action limits
  - Allowed/blocked action types
  - Rate limits
- Update agent status (active/suspended/revoked)
- View agent trust score history

**Security Alerts** (`/admin/alerts`)
- Real-time security alert queue
- Filter by severity (critical/high/medium/low)
- Acknowledge and resolve alerts
- View alert evidence and context
- Alert statistics dashboard

**API Keys** (`/admin/api-keys`)
- List all API keys with metadata
- Create new keys with custom scopes
- Rotate keys securely
- Revoke compromised keys
- View key usage statistics

**Settings** (`/admin/settings`)
- Organization profile management
- Billing tier and usage
- Webhook configuration
- Security policy settings
- Audit log retention settings

### Agent Portal (`/portal`)

**Dashboard**
- Agent trust score visualization
- Verification success/failure rates
- Limit usage meters
- Recent activity timeline

**Credentials** (`/portal/credentials`)
- View agent ID and public key
- Download keypair for integration
- Integration code examples (Python, Node.js, cURL)
- Signature verification testing

**Verification Playground** (`/portal/playground`)
- Interactive verification testing
- Pre-built action templates
- Real-time signature generation
- Response inspection
- Error debugging

**Activity Logs** (`/portal/logs`)
- Agent-specific audit logs
- Filter by verdict, action type, date range
- Export individual logs
- View payload details

### Audit Explorer (`/audit`)

**Log Search** (`/audit`)
- Full-text search across all logs
- Advanced filters:
  - Agent ID
  - Action type
  - Verdict (approved/blocked/rate_limited)
  - Date range
  - IP address
- Pagination and sorting
- Quick actions (verify, export)

**Merkle Verification** (`/audit/verify`)
- On-chain proof verification
- Merkle tree visualization
- Block explorer integration
- Verification certificate generation
- Batch verification

**Exports** (`/audit/exports`)
- Generate compliance reports
- Export formats: CSV, JSON, PDF
- Custom date range selection
- Agent filtering
- Pre-built compliance templates:
  - SOC 2 Audit
  - GDPR Data Access
  - Financial Audit

### Public Verification (`/verify`)

**Landing Page**
- Agent ID search
- Example verified agents
- Trust score explanation

**Agent Verification** (`/verify/[agentId]`)
- Public trust status display
- Trust score visualization
- Verification history
- Organization information
- Embeddable badge code

## Environment Variables

```env
# Required
NEXT_PUBLIC_API_URL=http://localhost:8000

# Optional
NEXT_PUBLIC_BLOCKCHAIN_EXPLORER=https://basescan.org
NEXT_PUBLIC_ANCHOR_CONTRACT=0x...
NEXT_PUBLIC_DEBUG=false
```

## API Integration

The frontend uses a type-safe API client (`src/lib/api.ts`) that provides:

```typescript
// Public API (no auth required)
publicApi.getAgentPublicInfo(agentId)
publicApi.health()

// Authenticated API
const api = createAuthenticatedApi(apiKey)

// Agents
api.listAgents()
api.getAgent(agentId)
api.registerAgent(data)
api.updateAgent(agentId, updates)
api.updateAgentStatus(agentId, status)

// Audit Logs
api.searchAuditLogs(params)
api.getAuditLog(logId)
api.getMerkleProof(logId)
api.exportAuditLogs(params)

// Alerts
api.listAlerts(params)
api.acknowledgeAlert(alertId)
api.resolveAlert(alertId, resolution)

// API Keys
api.listAPIKeys()
api.createAPIKey(data)
api.revokeAPIKey(keyPrefix)
api.rotateAPIKey()

// Usage
api.getUsageMetrics(params)
api.getOrganization()
```

## Development

```bash
# Run development server
npm run dev

# Build for production
npm run build

# Start production server
npm start

# Run linting
npm run lint

# Type checking
npm run type-check
```

## Deployment

### Vercel (Recommended)

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel
```

### Docker

```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:18-alpine AS runner
WORKDIR /app
ENV NODE_ENV production
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
EXPOSE 3000
CMD ["node", "server.js"]
```

### Railway / Render

1. Connect your repository
2. Set environment variables
3. Build command: `npm run build`
4. Start command: `npm start`

## Contributing

1. Follow the existing code style
2. Use TypeScript strict mode
3. Add tests for new features
4. Update documentation

## License

MIT License - See [LICENSE](../LICENSE) for details.
