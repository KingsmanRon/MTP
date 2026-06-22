# Inntris × MoonPay — End-to-End PoC Runbook

A live, screen-recordable demo: an AI agent attempts payments through a
MoonPay-style onramp; Inntris verifies-before-execute, approving a legit
purchase and **blocking** a rogue one — each producing a signed, publicly
verifiable receipt.

Driver script: `scripts/moonpay_poc_demo.py`

---

## What it proves (the story for the recording)

1. **Identity** — the agent signs every action with its own Ed25519 key.
2. **Policy** — a legit **$49.99** MoonPay ETH buy → **APPROVED** (within the
   $100/action, $500/day caps), trust score ticks up, an approval token is issued.
3. **Fail closed** — a prompt-injected agent tries a **$5,000** buy → **BLOCKED**
   (HTTP 403). The block is *also* a signed, queryable receipt.
4. **On-chain** — local receipts await anchoring; a **real Base-mainnet** receipt
   is referenced as proof anchoring works (chain_id 8453).

---

## Prerequisites

- Docker Desktop running
- The repo's `.venv` (already has `fastapi`, `uvicorn`, `pynacl`, `requests`, …)

---

## 1. Start Postgres + Redis

> Note: this machine already runs a **native Postgres on :5432**, so the
> container Postgres is mapped to host **:55432** to avoid the clash.

```bash
POSTGRES_PORT=55432 docker compose up -d postgres redis
```

## 2. Apply the schema (migrations)

```bash
DATABASE_URL="postgresql://inntris:inntris_secure_password@localhost:55432/inntris" \
  .venv/Scripts/python.exe -m alembic upgrade head
```

## 3. Start the Inntris API (dev mode)

```bash
ENVIRONMENT=development \
DATABASE_URL="postgresql://inntris:inntris_secure_password@localhost:55432/inntris" \
REDIS_URL="redis://localhost:6379" \
SERVER_SECRET="demo_server_secret_change_me_0123456789abcdef0123" \
MASTER_ADMIN_KEY="demo_master_admin_key_0123456789abcdef" \
  .venv/Scripts/python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Health check (new terminal):

```bash
curl -s http://127.0.0.1:8000/health
# {"status":"healthy","database":"connected","redis":"connected",...}
```

## 4. Run the MoonPay PoC

```bash
INNTRIS_API_URL="http://127.0.0.1:8000" \
INNTRIS_MASTER_KEY="demo_master_admin_key_0123456789abcdef" \
  .venv/Scripts/python.exe scripts/moonpay_poc_demo.py
```

Each run provisions a fresh org/agent, so you can re-run it as many times as you
like for the recording.

---

## 5. (Optional) On-chain proof to show on camera

These are **live** and verifiable by anyone:

- Receipt:      https://api.inntris.com/public/verify/3030c27c-87c4-4464-b4af-605fbe638e0e
- Merkle proof: https://api.inntris.com/public/verify/3030c27c-87c4-4464-b4af-605fbe638e0e/proof
- Contract:     https://basescan.org/address/0x0600eA15802c8d2EA429371b2EB0aacCFe321480

The receipt's `merkle_root` (`ab24703d…`) appears verbatim in the on-chain
transaction input — that's the tamper-evidence.

---

## Teardown

```bash
docker compose stop postgres redis     # keep data
# or: docker compose down -v            # wipe everything
```
