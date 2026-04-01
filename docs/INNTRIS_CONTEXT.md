# Inntris Infrastructure Context

## Live Services

```
api.inntris.com — LIVE
  Routes to: Railway web service (inntris-api.up.railway.app)
  Port: 8080
  SSL: Cloudflare proxy (managed by Railway)
  Health check: https://api.inntris.com/health → 200 OK
  Confirmed: 2026-03-18
```

## Blockchain Anchoring

```
Chain: Base Mainnet (chain ID 8453)
RPC: https://base-rpc.publicnode.com (PublicNode — required, Base official RPC blocks Railway IPs)
Contract: AnchorRegistry (deployed via Foundry, same source as Sepolia)
Deployer/Admin: 0x2300Fc9eff12ff5ca39621259B121fa3417773bf
Sepolia (historical): chain ID 84532, contract 0x0600ea15802c8d2ea429371b2eb0aaccfe321480
  — Old receipts still verify against sepolia.basescan.org via chain-aware routing
```
