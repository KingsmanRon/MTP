# Self-host deployment and recovery

Reference: PostgreSQL 17.6, Redis 7.4.7, Core API; anchoring is opt-in. This is a deployment runbook, not live payout certification. Run fresh-install, restart and restore checks against the exact revision being deployed. A clean merchant machine and its network still need a separate rehearsal.

## 1. Configure a fresh installation

Install Docker with Compose v2 / BuildKit. Copy `.env.example` to `.env` on the target host and restrict it with `chmod 600 .env`. Do not commit or paste it into tickets. Generate **separate** random values using `openssl rand -hex 32` for owner, worker, tenant, Redis, server and master secrets. Set:

- `ENVIRONMENT=production`, `POSTGRES_USER=inntris_migrator`, `POSTGRES_DB=inntris`.
- `POSTGRES_PASSWORD`, `RUNTIME_DATABASE_PASSWORD`, `TENANT_DATABASE_PASSWORD` to three distinct values.
- `ALEMBIC_DATABASE_URL=postgresql://inntris_migrator:<owner-password>@postgres:5432/inntris`.
- `DATABASE_URL=postgresql://inntris_worker:<worker-password>@postgres:5432/inntris`.
- `TENANT_DATABASE_URL=postgresql://inntris_tenant_login:<tenant-password>@postgres:5432/inntris`.
- `REDIS_PASSWORD` and matching `REDIS_URL=redis://:<redis-password>@redis:6379/0`.
- Fresh `SERVER_SECRET`, `MASTER_ADMIN_KEY` and actual `ALLOWED_ORIGINS`. Provisioning is disabled if the master key is absent; the local smoke test requires it.

Hex passwords avoid URI-escaping ambiguity. For other formats, URL-encode DSN passwords. Keep the owner credential away from the API and workers. The API needs both worker and tenant connections; workers get only the worker DSN. Migrations provision and verify the isolated `inntris_tenant_login` role without granting additional privileges. Failed checks prevent API startup.

```bash
docker compose up -d --build
docker compose ps -a
docker compose logs migrate
curl --fail http://127.0.0.1:8000/health
```

Do not publish the API beyond loopback until TLS, authentication and the merchant's network controls are configured. PostgreSQL and Redis have no host port in this reference. Never use `docker compose config` output as a public diagnostic attachment: resolved configuration contains secrets.

### Restricted networks / enterprise CA

If the build's pip cannot validate your organization's TLS proxy, supply its trusted CA bundle as a BuildKit secret. Keep certificate verification on. An optional override file can contain:

```yaml
services:
  api:
    build:
      secrets: [build_ca_bundle]
  migrate:
    build:
      secrets: [build_ca_bundle]
secrets:
  build_ca_bundle:
    file: /absolute/path/to/trusted-ca-bundle.pem
```

Build with `docker compose -f docker-compose.yml -f ca-build.yml build api migrate`, then start normally. Apply the same build secret to other image targets if enabling them. The Dockerfile mounts this certificate only for dependency installation; it is not copied into the runtime image. Runtime integrations behind the same proxy need separately approved trust configuration. In a restricted cloud home directory, set `BUILDX_CONFIG` to a private writable workspace directory.

## 2. Exercise tenant routes and receipts

Health alone cannot prove tenant access works. On a **disposable local** deployment, install the repository's Python dependencies in a virtual environment and run:

```bash
# Export the local MASTER_ADMIN_KEY securely in this shell first.
python -m scripts.self_host_smoke --api http://127.0.0.1:8000 --output smoke.json
```

The script creates two synthetic organizations and agents, checks tenant listing isolation, then checks public sandbox ALLOW/BLOCK receipts, action signatures and fingerprints. It never prints issued API keys. It intentionally accepts only loopback URLs, but loopback does not itself guarantee a disposable database: check the deployment before running it. Do not run it on a production dataset. It does not test payout execution, gateway bypass resistance, on-chain anchoring or independently signed verdicts. Keep assertions enabled (do not use `python -O`).

Restart the API, Redis and PostgreSQL; check health and retrieve the recorded receipt IDs. Avoid any `down -v` command on data you need to preserve.

## 3. Rehearse database restore in a separate project

Protect backups as sensitive data. Use the same code revision and PostgreSQL major; record image digests, migration revision, backup time and restore duration. Preserve needed application secrets in a separate managed recovery process. Example commands below use explicit projects; substitute your real project carefully.

```bash
umask 077
docker compose -p original exec -T postgres sh -c \
  'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > inntris.dump

# Separate project => separate volumes and network. Configure a different API_PORT.
API_PORT=18001 docker compose -p recovery up -d postgres redis
API_PORT=18001 docker compose -p recovery run --rm --build migrate
API_PORT=18001 docker compose -p recovery exec -T postgres sh -c \
  'pg_restore --clean --if-exists --exit-on-error -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < inntris.dump
API_PORT=18001 docker compose -p recovery up -d --build
```

Use the correct `--env-file` on **every** command if not using `.env`. `pg_dump` does not include cluster-wide roles: running migrations first establishes the roles; migration startup reprovisions credentials and verifies them after restore. Stop writers while performing a coordinated production recovery. Keep workers disabled and external integrations disconnected until checking restored state. Verify pre-backup receipt IDs/verdicts plus new tenant access in the recovered project. Define RPO/RTO with the merchant; this local rehearsal is not a production SLA.

The rehearsal restores PostgreSQL into fresh Redis. It does not prove preservation of every Redis-backed ephemeral state or an operational full-system disaster recovery process. Inventory those states before production. Any future payout integration additionally needs provider reconciliation before resubmission after restore.

### Existing PostgreSQL 15 / Timescale volumes

Do **not** attach a PostgreSQL 15 volume to the PostgreSQL 17 image. This runbook tests a fresh PostgreSQL 17.6 install and same-major logical restore. Existing Timescale hypertables or extension objects require a separate, version-compatible upgrade/export procedure and rehearsal. Plain PostgreSQL is supported by the schema's optional Timescale fallback, but that does not make an existing Timescale database directly portable. Take verified backups and preserve the old installation until a tested migration succeeds.

## 4. Optional anchoring

Set the verified chain RPC, contract and dedicated signing wallet before using `docker compose --profile anchoring up -d --build anchor-worker`. These credentials are not necessary for local receipt/sandbox checks. A worker explicitly started without its key/contract rejects startup. Do not describe sandbox receipts or unanchored records as on-chain proofs. Enabling mainnet signing spends real funds and needs explicit operational authorization.

## 5. Before a merchant pilot

Repeat on the merchant's clean host; record system requirements, installation time and operator steps. Check the trust boundary and secret inventory; rehearse rotation using [secrets_rotation.md](secrets_rotation.md), and update tenant-login steps for this deployment. Obtain independent assessment of the gateway once implemented, remediate blocking issues, and obtain merchant acceptance before live payouts. Neither these smoke checks nor unit tests replace that assessment.

## Release validation — 21 October 2026

The deployment change was rehearsed on top of default-branch commit `7dc9f62`
using isolated projects and fresh volumes on the managed cloud host:

- Fresh PostgreSQL 17.6/Redis installation, all migrations, separate login
  provisioning and tenant postconditions passed; API health was healthy.
- Real HTTP smoke passed two-tenant listing isolation, ALLOW/BLOCK retrieval,
  action signature verification and receipt fingerprints.
- API/PostgreSQL/Redis restart retained the original receipt verdicts.
- A custom-format database backup restored into a second project with fresh
  Redis. Tenant startup checks passed, original receipts remained available,
  and new tenant/receipt smoke checks passed.
- Backend suite: 690 passed, 32 service-dependent skips. A separate real
  PostgreSQL run passed all 16 selected tenant, Merkle visibility and ACL tests,
  including NULL/empty ACL acceptance and rejection of a PUBLIC table grant.
  These runs do not imply all skipped tests were exercised locally.
- Ruff and Git whitespace checks passed. Hosted CI results are recorded on the PR.

No payment provider was mocked or contacted, no live payouts or blockchain
transactions were attempted, and no production environment was deployed.
This evidence covers this host and the tested configuration; it is not an
independent application assessment or a clean merchant-machine certification.
