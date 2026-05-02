"""
Inntris Core API - Full Implementation

Complete API with all endpoints for:
- Agent management
- Audit log operations
- Security alerts
- API key management
- Usage metrics
- Public verification
"""

import hashlib
import logging
import os
import secrets
import time
import json
import base64
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Optional
from uuid import UUID, uuid4

import asyncpg
import redis.asyncio as redis
from fastapi import FastAPI, Depends, HTTPException, Request, status, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
import io
import csv

from api.database import (
    Database,
    AgentNotFoundError,
    OrganizationNotFoundError,
)
from api.models import (
    VerifyActionRequest,
    VerifyActionResponse,
    TestVerifyRequest,
    RegisterAgentRequest,
    HealthResponse,
    ErrorResponse,
    ActionVerdict,
    AuditLogEntry,
    AgentStatus,
    PublicVerificationRecord,
    PublicProofResponse,
    PublicRegisterAgentRequest,
    PublicRegisterAgentResponse,
)
from api.crypto import (
    CryptoService,
    SignatureVerificationError,
)
from api.policy import PolicyEngine, TrustScorer
from api.schemas.admin import (
    OrganizationResponse,
    AgentSummary,
    AgentDetail,
    AuditSearchResponse,
    AuditLogDetail,
    AuditProof,
)

# Configure logging. Phase 2C: switch to structured JSON output when
# ``INNTRIS_JSON_LOGS=1`` so log aggregators can parse the stream directly.
# Default stays as the legacy text format so local dev output is still
# grep-friendly.
if os.getenv("INNTRIS_JSON_LOGS") == "1":
    from api.observability import configure_json_logging
    configure_json_logging(level=logging.INFO)
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@db:5432/inntris")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
SERVER_SECRET_RAW = os.getenv("SERVER_SECRET")

# SECURITY: Validate secrets in production
if ENVIRONMENT != "development":
    if not SERVER_SECRET_RAW:
        raise SystemExit("FATAL: SERVER_SECRET environment variable is required in production")
    if len(SERVER_SECRET_RAW) < 32:
        raise SystemExit("FATAL: SERVER_SECRET must be at least 32 characters")

SERVER_SECRET = (SERVER_SECRET_RAW or "dev-secret-do-not-use-in-production").encode("utf-8")


def canonical_wire_timestamp(dt: datetime) -> str:
    """Format ``dt`` to match pydantic v2's JSON wire output exactly.

    Pydantic v2 serialises a UTC ``datetime`` with a ``Z`` suffix
    (``2026-04-07T22:22:25Z``) while ``datetime.isoformat`` produces
    ``2026-04-07T22:22:25+00:00``. The receipt fingerprint is computed on
    the backend over the canonical core fields and recomputed on the
    frontend over the wire-format strings, so the two MUST agree on the
    timestamp encoding or every receipt fails its integrity check.
    """
    s = dt.isoformat()
    if s.endswith("+00:00"):
        s = s[:-6] + "Z"
    return s


def _compute_integrity_status(tx_hash: "Optional[str]") -> str:
    """Return integrity_status reflecting whether the receipt has been anchored.

    - ``"verified"``       — receipt exists and is anchored on-chain
    - ``"pending_anchor"`` — receipt exists but anchor batch not yet submitted
    """
    return "verified" if tx_hash else "pending_anchor"


app = FastAPI(
    title="Inntris Core API",
    description="Forensic-grade AI Agent Verification & Audit System",
    version="1.0.0",
)

# Phase 2D.2: CORS lockdown.
#
# Wildcard origins in production are a cross-site request forgery vector:
# any site can make credentialed (or credential-forwarding) calls against
# our API. The previous code *honored* ALLOWED_ORIGINS=* even in production,
# which silently defeated the defense. We now fail-closed at boot instead.
#
# Rules:
#   * development  -> "*" is allowed (local tools, no creds).
#   * non-development:
#       - ALLOWED_ORIGINS must be a non-empty comma list of explicit
#         scheme+host origins.
#       - "*" anywhere in the list is a fatal misconfiguration.
#       - Each origin must parse as http(s)://host[:port]; no wildcards,
#         no "null", no path suffix (CORS origins have no path).

def _resolve_cors_origins(environment: str, raw: str) -> list[str]:
    raw = (raw or "").strip()
    if environment == "development":
        return ["*"] if not raw or raw == "*" else [
            o.strip() for o in raw.split(",") if o.strip()
        ]

    if not raw:
        raise SystemExit(
            "FATAL: ALLOWED_ORIGINS is required when ENVIRONMENT != development"
        )
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    if any(o == "*" for o in origins):
        raise SystemExit(
            "FATAL: ALLOWED_ORIGINS=* is not permitted outside development"
        )
    from urllib.parse import urlparse
    for o in origins:
        u = urlparse(o)
        if u.scheme not in ("http", "https") or not u.netloc or "*" in u.netloc:
            raise SystemExit(
                f"FATAL: invalid CORS origin {o!r} — expected scheme://host[:port]"
            )
        if u.path not in ("", "/") or u.query or u.fragment:
            raise SystemExit(
                f"FATAL: CORS origin {o!r} must not include a path/query/fragment"
            )
    return origins


origins = _resolve_cors_origins(ENVIRONMENT, os.getenv("ALLOWED_ORIGINS", ""))

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False if origins == ["*"] else True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Phase 2C: request ID correlation for log/trace joins.
from api.observability import RequestIdMiddleware, metrics_endpoint  # noqa: E402
app.add_middleware(RequestIdMiddleware)

# Phase 2C: Prometheus scrape endpoint. Unauthenticated by design — the
# operator is expected to expose /metrics only on an internal network or
# scrape via kube-prometheus's ServiceMonitor. If you terminate TLS at a
# reverse proxy, add a ``deny`` rule there for non-internal CIDRs.
app.add_route("/metrics", metrics_endpoint, methods=["GET"])

# Global Database Pool
db_pool: Optional[Database] = None

# Global Redis Pool
redis_pool: Optional[redis.Redis] = None

# =============================================================================
# DEPENDENCIES
# =============================================================================

async def get_db() -> Database:
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not initialized")
    return db_pool

async def get_redis() -> Optional[redis.Redis]:
    """Return the global Redis connection pool."""
    return redis_pool

async def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    database: Database = Depends(get_db),
) -> dict:
    """
    Verify API key and return organization info.
    For development, accepts any key starting with 'dev_' or 'test_'.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )

    # Development mode: accept dev keys
    if ENVIRONMENT == "development" and (x_api_key.startswith("dev_") or x_api_key.startswith("test_")):
        # Return a mock org for development
        return {
            "org_id": UUID("00000000-0000-0000-0000-000000000001"),
            "org_name": "Development Organization",
            "billing_tier": "enterprise",
            "scopes": ["admin", "read", "write"],
        }

    # Production: verify against database
    try:
        # Hash the API key to compare
        key_hash = hashlib.sha256(x_api_key.encode()).digest()

        async with database.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT ak.id, ak.org_id, ak.scopes, ak.is_active, ak.expires_at,
                       o.name as org_name, o.billing_tier
                FROM api_keys ak
                JOIN organizations o ON ak.org_id = o.id
                WHERE ak.key_hash = $1
                """,
                key_hash,
            )

        if not row:
            raise HTTPException(status_code=401, detail="Invalid API key")

        if not row["is_active"]:
            raise HTTPException(status_code=401, detail="API key is inactive")

        if row["expires_at"] and row["expires_at"] < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="API key has expired")

        # Update last_used_at
        async with database.acquire() as conn:
            await conn.execute(
                "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
                row["id"],
            )

        return {
            "org_id": row["org_id"],
            "org_name": row["org_name"],
            "billing_tier": row["billing_tier"],
            "scopes": row["scopes"] or ["read"],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API key verification error: {e}")
        raise HTTPException(status_code=401, detail="Invalid API key")


async def _check_public_rate_limit(
    request: Request,
    redis_conn: Optional[redis.Redis],
    key_prefix: str,
    max_per_hour: int = 5,
) -> None:
    """
    Enforce per-IP hourly rate limit for unauthenticated public endpoints.

    Uses Redis INCR + EXPIRE (sliding window by hour). Fail-open when Redis
    is unavailable — registration is not a security gate, and availability
    matters more than strict limiting here.

    Raises HTTP 429 when the caller exceeds ``max_per_hour``.
    """
    if redis_conn is None:
        return  # fail-open: Redis unavailable
    ip = request.client.host if request.client else "unknown"
    hour_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H")
    window_key = f"inntris:{key_prefix}:{ip}:{hour_str}"
    count = await redis_conn.incr(window_key)
    if count == 1:
        await redis_conn.expire(window_key, 3600)
    if count > max_per_hour:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Max {max_per_hour} registrations per IP per hour.",
        )

# =============================================================================
# STARTUP / SHUTDOWN
# =============================================================================

@app.on_event("startup")
async def startup_event():
    global db_pool, redis_pool
    logger.info("Starting Inntris Core API v1.0.0")

    # Initialize database pool
    dsn = os.getenv("DATABASE_URL", DATABASE_URL)
    try:
        db_pool = await Database.create(dsn)
        logger.info("Database connection established")
    except Exception as e:
        logger.critical(f"Failed to connect to database: {e}")

    # Initialize Redis pool
    try:
        redis_url = os.getenv("REDIS_URL", REDIS_URL)
        redis_pool = redis.from_url(redis_url, decode_responses=True)
        await redis_pool.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}. Continuing without Redis.")
        redis_pool = None

@app.on_event("shutdown")
async def shutdown_event():
    global db_pool, redis_pool
    if db_pool:
        await db_pool.close()
        logger.info("Database connection closed")
    if redis_pool:
        await redis_pool.close()
        logger.info("Redis connection closed")

# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check(
    database: Database = Depends(get_db),
    redis_conn: Optional[redis.Redis] = Depends(get_redis),
):
    """System health check."""
    db_healthy = await database.health_check()

    # Check Redis connection
    redis_status = "not_configured"
    if redis_conn:
        try:
            await redis_conn.ping()
            redis_status = "connected"
        except Exception as e:
            logger.warning(f"Redis health check failed: {e}")
            redis_status = "disconnected"

    return HealthResponse(
        status="healthy" if db_healthy else "degraded",
        version="1.0.0",
        database="connected" if db_healthy else "disconnected",
        redis=redis_status,
        timestamp=datetime.now(timezone.utc),
    )

# =============================================================================
# SCHEMA ENDPOINTS
# =============================================================================

RECEIPT_SCHEMA_V1 = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "/schema/receipt/v1.json",
    "title": "Inntris Verification Receipt v1",
    "description": "Public, read-only verification receipt for an AI agent action. Schema version v1.",
    "type": "object",
    "required": [
        "audit_id", "timestamp", "verdict", "action_type",
        "agent_id", "action_hash", "schema_version", "receipt_fingerprint",
    ],
    "properties": {
        "audit_id": {"type": "string", "format": "uuid"},
        "timestamp": {"type": "string", "format": "date-time"},
        "verdict": {"type": "string", "enum": ["approved", "blocked", "rate_limited", "signature_invalid"]},
        "verdict_reason": {"type": ["string", "null"]},
        "action_type": {"type": "string"},
        "agent_id": {"type": "string", "format": "uuid"},
        "agent_name": {"type": "string"},
        "organization_name": {"type": "string"},
        "trust_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "risk_level": {"type": ["string", "null"]},
        "violations": {"type": "array", "items": {"type": "string"}},
        "policy_hash": {"type": ["string", "null"], "pattern": "^[a-f0-9]{64}$", "description": "SHA-256 hash of the adapter-specific governing policy contract at verification time. Meaning depends on the adapter (e.g. .inntris.yml for the default adapter, a promptfoo config hash for the promptfoo adapter)."},
        "action_hash": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "signature_valid": {"type": "boolean"},
        "merkle_root": {"type": ["string", "null"]},
        "tx_hash": {"type": ["string", "null"], "pattern": "^0x[a-fA-F0-9]{64}$"},
        "block_number": {"type": ["integer", "null"]},
        "chain_id": {"type": "integer", "default": 8453, "description": "Chain ID. Public receipts are always 8453 (Base Mainnet)."},
        "anchored_at": {"type": ["string", "null"], "format": "date-time"},
        "schema_version": {"type": "string", "enum": ["v1", "v2"]},
        "receipt_fingerprint": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "integrity_status": {"type": "string", "enum": ["verified", "pending_anchor", "failed"]},
    },
    "additionalProperties": False,
}


@app.get("/schema/receipt/v1.json", tags=["Schema"])
async def get_receipt_schema_v1():
    """Return the canonical JSON Schema for receipt v1."""
    return JSONResponse(content=RECEIPT_SCHEMA_V1)


# =============================================================================
# PUBLIC ENDPOINTS (No Auth Required)
# =============================================================================

@app.get("/public/agent/{agent_id}", tags=["Public"])
async def get_public_agent_info(
    agent_id: UUID,
    database: Database = Depends(get_db),
):
    """Get public agent information for trust badge display."""
    try:
        agent = await database.get_agent_by_id(agent_id)

        # Get organization name
        org = await database.get_organization_by_id(agent.org_id)

        return {
            "agent_id": str(agent.id),
            "name": agent.name,
            "organization_name": org.name,
            "trust_score": agent.trust_score,
            "status": agent.status.value,
            "is_verified": agent.status == AgentStatus.ACTIVE,
            "verified_since": agent.created_at.isoformat() if agent.status == AgentStatus.ACTIVE else None,
            "total_actions": agent.total_actions_count,
            "last_action_at": agent.last_action_at.isoformat() if agent.last_action_at else None,
        }
    except AgentNotFoundError:
        raise HTTPException(status_code=404, detail="Agent not found")
    except OrganizationNotFoundError:
        raise HTTPException(status_code=404, detail="Organization not found")


@app.post(
    "/public/agents/register",
    response_model=PublicRegisterAgentResponse,
    status_code=201,
    tags=["Public"],
)
async def public_register_agent(
    request_data: PublicRegisterAgentRequest,
    request: Request,
    database: Database = Depends(get_db),
    redis_conn: Optional[redis.Redis] = Depends(get_redis),
):
    """
    Bootstrap a new agent without an API key.

    Creates (or reuses) an organization keyed by email, then registers the
    agent with the provided Ed25519 public key. Rate-limited to 5 per IP
    per hour to prevent abuse.
    """
    await _check_public_rate_limit(request, redis_conn, key_prefix="pub_register")

    # Decode and validate the public key
    try:
        public_key_bytes = base64.b64decode(request_data.public_key)
    except Exception:
        raise HTTPException(status_code=400, detail="public_key must be valid base64")
    if len(public_key_bytes) != 32:
        raise HTTPException(status_code=400, detail="public_key must decode to exactly 32 bytes (Ed25519)")

    fingerprint = CryptoService.compute_public_key_fingerprint(public_key_bytes)

    # Find or create a default public organization for this email
    async with database.acquire() as conn:
        org_row = await conn.fetchrow(
            "SELECT id FROM organizations WHERE contact_email = $1 LIMIT 1",
            request_data.email,
        )
        if org_row:
            org_id = org_row["id"]
        else:
            # api_key_hash is NOT NULL — generate a placeholder hash for
            # publicly-registered orgs (they authenticate via agent keys, not API keys)
            placeholder_key_hash = hashlib.sha256(os.urandom(32)).digest()
            org_id = await conn.fetchval(
                """
                INSERT INTO organizations (name, contact_email, billing_tier, api_key_hash)
                VALUES ($1, $2, 'free', $3)
                RETURNING id
                """,
                f"Public Org — {request_data.email}",
                request_data.email,
                placeholder_key_hash,
            )

    # Register the agent
    adapter_meta = dict(request_data.adapter_metadata or {})
    allowed_actions = adapter_meta.pop("allowed_actions", ["tool_call", "api_call", "data_export"])
    agent_id = await database.create_agent(
        org_id=org_id,
        name=f"agent-{fingerprint[:8]}",
        public_key=public_key_bytes,
        allowed_actions=allowed_actions,
        metadata={"source": "public_registration", **adapter_meta},
    )

    return PublicRegisterAgentResponse(
        agent_id=str(agent_id),
        public_key_fingerprint=fingerprint,
        org_id=str(org_id),
        status="active",
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        message="Agent registered. Use agent_id with POST /verify.",
    )


@app.post(
    "/public/agents/register-promptfoo",
    response_model=PublicRegisterAgentResponse,
    status_code=201,
    tags=["Public"],
)
async def public_register_promptfoo_agent(
    request_data: PublicRegisterAgentRequest,
    request: Request,
    database: Database = Depends(get_db),
    redis_conn: Optional[redis.Redis] = Depends(get_redis),
):
    """
    Promptfoo-specific agent registration alias.

    Pre-fills Promptfoo platform defaults:
    - allowed_actions includes ``promptfoo_eval``
    - adapter_metadata tagged with ``platform: promptfoo``

    Same rate limiting as /public/agents/register.
    """
    await _check_public_rate_limit(request, redis_conn, key_prefix="pub_register")

    # Decode and validate the public key
    try:
        public_key_bytes = base64.b64decode(request_data.public_key)
    except Exception:
        raise HTTPException(status_code=400, detail="public_key must be valid base64")
    if len(public_key_bytes) != 32:
        raise HTTPException(status_code=400, detail="public_key must decode to exactly 32 bytes (Ed25519)")

    fingerprint = CryptoService.compute_public_key_fingerprint(public_key_bytes)

    # Inject Promptfoo defaults
    meta = dict(request_data.adapter_metadata or {})
    meta.setdefault("platform", "promptfoo")
    meta.setdefault("version", "unknown")
    allowed_actions = meta.pop("allowed_actions", ["promptfoo_eval", "tool_call", "api_call"])

    # Find or create organization
    async with database.acquire() as conn:
        org_row = await conn.fetchrow(
            "SELECT id FROM organizations WHERE contact_email = $1 LIMIT 1",
            request_data.email,
        )
        if org_row:
            org_id = org_row["id"]
        else:
            placeholder_key_hash = hashlib.sha256(os.urandom(32)).digest()
            org_id = await conn.fetchval(
                """
                INSERT INTO organizations (name, contact_email, billing_tier, api_key_hash)
                VALUES ($1, $2, 'free', $3)
                RETURNING id
                """,
                f"Promptfoo Org — {request_data.email}",
                request_data.email,
                placeholder_key_hash,
            )

    agent_id = await database.create_agent(
        org_id=org_id,
        name=f"promptfoo-{fingerprint[:8]}",
        public_key=public_key_bytes,
        allowed_actions=allowed_actions,
        metadata={"source": "public_registration_promptfoo", **meta},
    )

    return PublicRegisterAgentResponse(
        agent_id=str(agent_id),
        public_key_fingerprint=fingerprint,
        org_id=str(org_id),
        status="active",
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        message="Promptfoo agent registered. Use agent_id with POST /verify.",
    )


@app.get(
    "/public/verify/{record_id}",
    response_model=PublicVerificationRecord,
    responses={404: {"model": ErrorResponse, "description": "Verification record not found"}},
    tags=["Public"],
)
async def get_public_verification_record(
    record_id: str,
    database: Database = Depends(get_db),
):
    """
    Get a public, read-only verification receipt.

    Accepts either an audit log UUID or a transaction hash (0x-prefixed).
    Returns the shareable verification record for the audit page.
    """
    try:
        async with database.acquire() as conn:
            # Determine lookup strategy: tx hash (0x...) or audit UUID
            if record_id.startswith("0x") and len(record_id) == 66:
                # Lookup by transaction hash via merkle_proofs
                row = await conn.fetchrow(
                    """
                    SELECT al.*, a.name AS agent_name, a.org_id,
                           mp.root_hash AS merkle_root,
                           mp.transaction_hash AS tx_hash,
                           mp.block_number,
                           mp.chain_id,
                           mp.confirmed_at AS anchored_at
                    FROM merkle_proofs mp
                    JOIN audit_logs al ON al.merkle_root_id = mp.id
                    JOIN agents a ON al.agent_id = a.id
                    WHERE mp.transaction_hash = $1
                    ORDER BY al.timestamp DESC
                    LIMIT 1
                    """,
                    record_id,
                )
            else:
                # Lookup by audit log UUID
                try:
                    log_uuid = UUID(record_id)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid record ID format")

                row = await conn.fetchrow(
                    """
                    SELECT al.*, a.name AS agent_name, a.org_id,
                           mp.root_hash AS merkle_root,
                           mp.transaction_hash AS tx_hash,
                           mp.block_number,
                           mp.chain_id,
                           mp.confirmed_at AS anchored_at
                    FROM audit_logs al
                    JOIN agents a ON al.agent_id = a.id
                    LEFT JOIN merkle_proofs mp ON al.merkle_root_id = mp.id
                    WHERE al.id = $1
                    """,
                    log_uuid,
                )
    except asyncpg.InsufficientPrivilegeError as e:
        logger.exception(
            "Public verify DB privilege error — runtime DATABASE_URL role "
            "lacks SELECT on merkle_proofs (see migration 005). Detail: %s",
            e,
        )
        raise HTTPException(
            status_code=503,
            detail="Verification temporarily unavailable. Please retry.",
        )

    if not row:
        raise HTTPException(status_code=404, detail="Verification record not found")

    # Public verify is mainnet-only.
    # Sepolia (84532) receipts are testnet artefacts; direct callers to the
    # admin portal instead of exposing them on the unauthenticated public path.
    # NULL chain_id means the record has no proof row yet (unanchored).
    # Treat it as mainnet-eligible so pending receipts are still accessible.
    record_chain_id = row.get("chain_id") or 8453
    if record_chain_id != 8453:
        raise HTTPException(
            status_code=410,
            detail=(
                "This receipt was anchored on a testnet or legacy chain "
                f"(chain_id={record_chain_id}). "
                "Public verification is only available for Base Mainnet (chain_id=8453). "
                "Access this record via the authenticated admin portal."
            ),
        )

    # Get organization name
    try:
        org = await database.get_organization_by_id(row["org_id"])
        org_name = org.name
    except OrganizationNotFoundError:
        org_name = "Unknown"

    # Extract risk_level and violations from payload
    payload = row["payload"] if isinstance(row["payload"], dict) else json.loads(row["payload"]) if row["payload"] else {}
    risk_level = payload.get("risk_level")
    violations: list[str] = []
    if row["verdict_reason"]:
        # Parse violations from verdict_reason (format: "Policy violations: x, y, z")
        reason = row["verdict_reason"]
        if "violations:" in reason.lower():
            parts = reason.split(":", 1)
            if len(parts) > 1:
                violations = [v.strip() for v in parts[1].split(",") if v.strip()]
        elif row["verdict"] != "approved":
            violations = [reason]

    # ── DO NOT MODIFY FIELD SET OR ORDER — MUST MATCH FRONTEND EXACTLY ──
    #
    # The frontend recomputes this fingerprint from the wire JSON it receives,
    # so each value here MUST be the exact string that pydantic will emit on
    # the wire. In particular, ``timestamp`` must use the ``Z`` suffix for UTC
    # (pydantic v2 wire format) rather than ``datetime.isoformat``'s ``+00:00``.
    fingerprint_payload = {
        "action_hash": row["action_hash"],
        "action_type": row["action_type"],
        "agent_id": str(row["agent_id"]),
        "audit_id": str(row["id"]),
        "policy_hash": row.get("policy_hash"),
        "timestamp": canonical_wire_timestamp(row["timestamp"]),
        "verdict": row["verdict"],
    }
    canonical = json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":"))
    receipt_fingerprint = hashlib.sha256(canonical.encode()).hexdigest()

    # Receipt schema versioning.
    #
    # v2: policy_hash is part of the canonical JSON used to compute the receipt
    #     fingerprint for any policy-evaluated decision. The presence of a
    #     non-null policy_hash on the audit row marks the receipt as a v2
    #     receipt — the policy was evaluated and is bound to the decision.
    # v1: legacy receipts that pre-date the v2 cutover, where policy_hash may
    #     or may not have been bound. Old receipts remain valid under their
    #     own version; their fingerprint already includes the same field set.
    #
    # The fingerprint field set itself is identical across v1 and v2 — what
    # changes is the *guarantee*: a v2 receipt is asserted to bind a policy.
    schema_version = "v2" if row.get("policy_hash") else "v1"

    return PublicVerificationRecord(
        audit_id=row["id"],
        timestamp=row["timestamp"],
        verdict=ActionVerdict(row["verdict"]),
        verdict_reason=row["verdict_reason"],
        action_type=row["action_type"],
        agent_id=row["agent_id"],
        agent_name=row["agent_name"],
        organization_name=org_name,
        trust_score=row["trust_score_at_time"],
        risk_level=risk_level,
        violations=violations,
        policy_hash=row.get("policy_hash"),
        action_hash=row["action_hash"],
        signature_valid=row["signature_valid"],
        merkle_root=row.get("merkle_root"),
        tx_hash=row.get("tx_hash"),
        block_number=row.get("block_number"),
        chain_id=row.get("chain_id") or 8453,
        anchored_at=row.get("anchored_at"),
        schema_version=schema_version,
        receipt_fingerprint=receipt_fingerprint,
        integrity_status=_compute_integrity_status(row.get("tx_hash")),
    )


@app.get(
    "/public/verify/{audit_id}/proof",
    response_model=PublicProofResponse,
    responses={
        404: {"model": ErrorResponse, "description": "Audit log not found"},
    },
    tags=["Public"],
)
async def get_public_proof(
    audit_id: UUID,
    database: Database = Depends(get_db),
):
    """
    Public, unauthenticated Merkle proof for an audit log entry.

    Returns the full proof path needed to verify inclusion in the on-chain
    Merkle root. If the receipt exists but has not yet been anchored, returns
    a pending-anchor state rather than 404.
    """
    async with database.acquire() as conn:
        log_row = await conn.fetchrow(
            """
            SELECT al.id, al.action_hash, al.merkle_root_id,
                   al.merkle_leaf_index, al.policy_hash,
                   al.timestamp
            FROM audit_logs al
            WHERE al.id = $1
            """,
            audit_id,
        )

    if not log_row:
        raise HTTPException(status_code=404, detail="Audit log not found")

    # Unanchored: return pending state explicitly rather than 404
    if not log_row["merkle_root_id"]:
        return PublicProofResponse(
            audit_id=str(log_row["id"]),
            status="pending_anchor",
            action_hash=log_row["action_hash"],
            proof=[],
            positions=[],
            merkle_root=None,
            tx_hash=None,
            chain_id=None,
            block_number=None,
            anchored_at=None,
            submitter=None,
            receipt_fingerprint=None,
            policy_hash=log_row["policy_hash"],
            timestamp=canonical_wire_timestamp(log_row["timestamp"]) if log_row["timestamp"] else None,
        )

    # Anchored: fetch proof record
    async with database.acquire() as conn:
        proof_row = await conn.fetchrow(
            "SELECT * FROM merkle_proofs WHERE id = $1",
            log_row["merkle_root_id"],
        )

    if not proof_row:
        raise HTTPException(status_code=404, detail="Merkle proof record not found")

    leaf_hashes = proof_row["leaf_hashes"]
    leaf_index = log_row["merkle_leaf_index"]

    from workers.anchor_worker import compute_merkle_proof
    try:
        proof_path = compute_merkle_proof(leaf_hashes, leaf_index)
    except Exception:
        proof_path = []

    return PublicProofResponse(
        audit_id=str(log_row["id"]),
        status="anchored",
        action_hash=log_row["action_hash"],
        proof=[p["hash"] for p in proof_path],
        positions=[p["position"] == 1 for p in proof_path],
        merkle_root=proof_row["root_hash"],
        tx_hash=proof_row["transaction_hash"],
        chain_id=proof_row.get("chain_id") or 8453,
        block_number=proof_row.get("block_number"),
        anchored_at=proof_row["confirmed_at"].isoformat() if proof_row["confirmed_at"] else None,
        submitter=proof_row.get("submitted_by"),
        receipt_fingerprint=None,
        policy_hash=log_row["policy_hash"],
        timestamp=canonical_wire_timestamp(log_row["timestamp"]) if log_row["timestamp"] else None,
    )


# =============================================================================
# VERIFICATION ENDPOINT
# =============================================================================

@app.post(
    "/verify",
    response_model=VerifyActionResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Signature verification failed"},
        403: {"model": ErrorResponse, "description": "Policy violation"},
        404: {"model": ErrorResponse, "description": "Agent not found"},
    },
    tags=["Verification"],
)
async def verify_action(
    request_data: VerifyActionRequest,
    request: Request,
    database: Database = Depends(get_db),
    redis_conn: Optional[redis.Redis] = Depends(get_redis),
):
    """Verify an agent action using strict forensic logging."""
    start_time = time.time()
    signature_valid = False
    verdict = ActionVerdict.BLOCKED
    verdict_reason: Optional[str] = None
    audit_id: Optional[UUID] = None

    try:
        # STEP 1: Fetch Agent
        try:
            agent = await database.get_agent_by_id(request_data.agent_id)
        except AgentNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Agent {request_data.agent_id} not found",
            )

        # STEP 2: Verify Ed25519 Signature
        # The signing envelope version is echoed from the client so legacy
        # agents signing with sig_version=1 continue to verify. New agents
        # should pin sig_version=2 (the default), which normalizes the
        # timestamp to canonical UTC. See Phase 0.3 / 0.4 in the
        # enterprise-readiness plan.
        action_hash = CryptoService.compute_action_hash(
            agent_id=str(request_data.agent_id),
            action_type=request_data.action_type,
            payload=request_data.payload,
            nonce=request_data.nonce,
            timestamp=request_data.timestamp,
            sig_version=request_data.sig_version,
        )

        try:
            signature_valid = CryptoService.verify_ed25519_signature(
                public_key=agent.public_key,
                message_hash=action_hash,
                signature_b64=request_data.signature,
            )
        except SignatureVerificationError as e:
            logger.error(f"Signature error for agent {agent.id}: {e}")
            signature_valid = False

        if not signature_valid:
            verdict = ActionVerdict.SIGNATURE_INVALID
            verdict_reason = "Ed25519 signature verification failed. Potential attack detected."

            # Phase 2C: bump signature-failure counter before logging so the
            # alerting rule (rate(inntris_signature_failures_total[5m]) > N)
            # fires even if the audit insert later fails.
            from api.observability import signature_failures_total, verify_requests_total
            signature_failures_total.inc()
            verify_requests_total.labels(verdict="invalid_signature").inc()

            logger.warning(f"SECURITY ALERT: Invalid signature from {agent.id}")

            # Log failure
            audit_entry = AuditLogEntry(
                agent_id=agent.id,
                action_type=request_data.action_type,
                action_hash=action_hash,
                payload=request_data.payload,
                verdict=verdict,
                verdict_reason=verdict_reason,
                signature=base64.b64decode(request_data.signature),
                signature_valid=False,
                request_ip=request.client.host if request.client else None,
                request_user_agent=request.headers.get("User-Agent"),
                response_time_ms=int((time.time() - start_time) * 1000),
                trust_score_at_time=agent.trust_score,
                chain_previous_hash=await database.get_last_audit_hash(agent.id),
                policy_hash=request_data.policy_hash,
                metadata={},
            )
            audit_id = await database.insert_audit_log(audit_entry)

            # Create security alert for invalid signature
            await database.create_security_alert(
                alert_type="signature_invalid",
                severity="high",
                title=f"Invalid signature from agent {agent.name}",
                description=f"Agent {agent.id} submitted an action with invalid Ed25519 signature.",
                agent_id=agent.id,
                org_id=agent.org_id,
                evidence={"action_type": request_data.action_type, "action_hash": action_hash},
                audit_log_ids=[audit_id],
            )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=verdict_reason,
            )

        # STEP 3: Replay Check (Nonce) - FAIL-CLOSED
        # If Redis is unavailable, we MUST block the request to prevent replay attacks
        if not redis_conn:
            logger.error("SECURITY: Redis unavailable, cannot verify nonce - blocking request")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Verification service temporarily unavailable. Please retry.",
            )

        nonce_key = f"inntris:nonce:{agent.id}:{request_data.nonce}"
        try:
            nonce_set = await redis_conn.set(nonce_key, "1", ex=600, nx=True)
            if not nonce_set:
                # Phase 2C — count before raising. A replay attempt is a
                # security-relevant event; we want the metric even if the
                # raised HTTPException short-circuits the rest of the handler.
                from api.observability import nonce_replays_total, verify_requests_total
                nonce_replays_total.inc()
                verify_requests_total.labels(verdict="replay").inc()
                raise HTTPException(status_code=401, detail="Nonce already used - possible replay attack")
        except Exception as e:
            logger.error(f"SECURITY: Redis error during nonce check: {e} - blocking request")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Verification service temporarily unavailable. Please retry.",
            )

        # STEP 4: Policy Check - Full PolicyEngine evaluation
        # Get current limits from database
        now = datetime.now(timezone.utc)
        minute_start = now.replace(second=0, microsecond=0)
        minute_count, _ = await database.get_rate_limit_count(
            agent.id, "minute", minute_start
        )
        daily_spend = await database.get_daily_spend(agent.id)

        # Initialize PolicyEngine with current state
        policy_engine = PolicyEngine(
            daily_spend=daily_spend,
            minute_request_count=minute_count,
        )

        # Parse timestamp from request
        request_timestamp = request_data.timestamp
        if isinstance(request_timestamp, str):
            request_timestamp = datetime.fromisoformat(request_timestamp.replace("Z", "+00:00"))

        # Evaluate all policies
        policy_result = policy_engine.evaluate(
            agent=agent,
            action_type=request_data.action_type,
            payload=request_data.payload,
            timestamp=request_timestamp,
        )

        verdict = policy_result.verdict
        verdict_reason = policy_result.reason or "All verification checks passed"
        limits_remaining = policy_result.limits_remaining or {}

        # STEP 5: Handle policy violations
        if not policy_result.allowed:
            # Phase 2C metrics — count the block before audit/HTTP work, so
            # dashboards reflect reality even if a downstream exception
            # prevents us from reaching the raise.
            from api.observability import rate_limit_trips_total, verify_requests_total
            if verdict == ActionVerdict.RATE_LIMITED:
                rate_limit_trips_total.labels(window="tenant_minute").inc()
                verify_requests_total.labels(verdict="rate_limited").inc()
            else:
                verify_requests_total.labels(verdict="blocked").inc()

            logger.warning(
                f"Policy violation for agent {agent.id}: {policy_result.violation} - {verdict_reason}"
            )

            # Log the blocked action
            audit_entry = AuditLogEntry(
                agent_id=agent.id,
                action_type=request_data.action_type,
                action_hash=action_hash,
                payload=request_data.payload,
                verdict=verdict,
                verdict_reason=verdict_reason,
                signature=base64.b64decode(request_data.signature),
                signature_valid=True,
                request_ip=request.client.host if request.client else None,
                request_user_agent=request.headers.get("User-Agent"),
                response_time_ms=int((time.time() - start_time) * 1000),
                trust_score_at_time=agent.trust_score,
                chain_previous_hash=await database.get_last_audit_hash(agent.id),
                policy_hash=request_data.policy_hash,
                metadata={"violation": policy_result.violation.value if policy_result.violation else None},
            )
            audit_id = await database.insert_audit_log(audit_entry)

            # Update trust score and counters for blocked action
            new_trust_score = TrustScorer.calculate_adjustment(
                current_score=agent.trust_score,
                event_type="action_blocked_policy" if verdict == ActionVerdict.BLOCKED else "action_blocked_rate_limit",
            )
            await database.update_agent_after_verification(agent.id, new_trust_score, was_approved=False)

            # Determine appropriate HTTP status code
            if verdict == ActionVerdict.RATE_LIMITED:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=verdict_reason,
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=verdict_reason,
                )

        # STEP 6: Audit Log for approved action
        audit_entry = AuditLogEntry(
            agent_id=agent.id,
            action_type=request_data.action_type,
            action_hash=action_hash,
            payload=request_data.payload,
            verdict=verdict,
            verdict_reason=verdict_reason,
            signature=base64.b64decode(request_data.signature),
            signature_valid=True,
            request_ip=request.client.host if request.client else None,
            request_user_agent=request.headers.get("User-Agent"),
            response_time_ms=int((time.time() - start_time) * 1000),
            trust_score_at_time=agent.trust_score,
            chain_previous_hash=await database.get_last_audit_hash(agent.id),
            policy_hash=request_data.policy_hash,
            metadata={},
        )
        audit_id = await database.insert_audit_log(audit_entry)

        # STEP 7: Update rate limit counters
        amount = policy_engine._extract_amount(request_data.payload) or Decimal("0")
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        await database.increment_rate_limit(agent.id, "minute", minute_start, Decimal("0"))
        await database.increment_rate_limit(agent.id, "day", day_start, amount)

        # STEP 8: Update trust score and counters for approved action
        new_trust_score = TrustScorer.calculate_adjustment(
            current_score=agent.trust_score,
            event_type="action_approved",
        )
        await database.update_agent_after_verification(agent.id, new_trust_score, was_approved=True)

        # Generate Approval Token
        token = CryptoService.generate_approval_token(
            agent_id=str(agent.id),
            action_hash=action_hash,
            verdict=verdict.value,
            server_secret=SERVER_SECRET
        )

        # Phase 2C — successful verification. Observed after the audit insert
        # and trust-score update so the counter reflects a fully-processed
        # approval, not one that might have partially failed.
        from api.observability import verify_latency_seconds, verify_requests_total
        verify_requests_total.labels(verdict="approved").inc()
        verify_latency_seconds.observe(time.time() - start_time)

        return VerifyActionResponse(
            verdict=verdict,
            verdict_reason=verdict_reason,
            approval_token=token,
            trust_score=new_trust_score,
            audit_id=audit_id,
            timestamp=datetime.now(timezone.utc),
            limits_remaining=limits_remaining
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post(
    "/admin/test-verify",
    response_model=VerifyActionResponse,
    tags=["Admin - Testing"],
)
async def test_verify_action(
    request_data: TestVerifyRequest,
    request: Request,
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Test verification endpoint for playground only.

    SECURITY NOTE: This endpoint is NOT a proof-eligible verification path.
    - Audit log entries created here are marked with ``test_request: True``
      in metadata and are excluded from Merkle batch anchoring.
    - The signature field is set to ``b"TEST_REQUEST"`` as a sentinel marker.
    - Do NOT direct public demos or external documentation to this endpoint.
    - No public demo scripts should reference this path.

    Runs full policy evaluation without requiring a cryptographic signature.
    Use this to test how the policy engine will evaluate different actions.
    """
    start_time = time.time()

    try:
        # Fetch agent and verify org ownership
        try:
            agent = await database.get_agent_by_id(request_data.agent_id)
        except AgentNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Agent {request_data.agent_id} not found",
            )

        if agent.org_id != auth["org_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Agent does not belong to your organization",
            )

        # Get current limits from database
        now = datetime.now(timezone.utc)
        minute_start = now.replace(second=0, microsecond=0)
        minute_count, _ = await database.get_rate_limit_count(
            agent.id, "minute", minute_start
        )
        daily_spend = await database.get_daily_spend(agent.id)

        # Initialize PolicyEngine with current state
        policy_engine = PolicyEngine(
            daily_spend=daily_spend,
            minute_request_count=minute_count,
        )

        # Evaluate all policies
        policy_result = policy_engine.evaluate(
            agent=agent,
            action_type=request_data.action_type,
            payload=request_data.payload,
            timestamp=now,
        )

        verdict = policy_result.verdict
        verdict_reason = policy_result.reason or "All verification checks passed"
        limits_remaining = policy_result.limits_remaining or {}

        # Generate a test action hash (no real signature)
        test_nonce = f"test_{uuid4()}"
        action_hash = CryptoService.compute_action_hash(
            agent_id=str(request_data.agent_id),
            action_type=request_data.action_type,
            payload=request_data.payload,
            nonce=test_nonce,
            timestamp=now.isoformat(),
        )

        # Log to audit (marked as test)
        audit_entry = AuditLogEntry(
            agent_id=agent.id,
            action_type=request_data.action_type,
            action_hash=action_hash,
            payload=request_data.payload,
            verdict=verdict,
            verdict_reason=verdict_reason,
            signature=b"TEST_REQUEST",  # Marker for test requests
            signature_valid=True,  # N/A for test
            request_ip=request.client.host if request.client else None,
            request_user_agent=request.headers.get("User-Agent"),
            response_time_ms=int((time.time() - start_time) * 1000),
            trust_score_at_time=agent.trust_score,
            chain_previous_hash=await database.get_last_audit_hash(agent.id),
            metadata={"test_request": True, "tested_by": auth.get("org_name", "API")},
        )
        audit_id = await database.insert_audit_log(audit_entry)

        # Generate approval token for approved requests
        approval_token = None
        if policy_result.allowed:
            approval_token = CryptoService.generate_approval_token(
                agent_id=str(agent.id),
                action_hash=action_hash,
                verdict=verdict.value,
                server_secret=SERVER_SECRET
            )

        return VerifyActionResponse(
            verdict=verdict,
            verdict_reason=verdict_reason,
            approval_token=approval_token,
            trust_score=agent.trust_score,
            audit_id=audit_id,
            timestamp=now,
            limits_remaining=limits_remaining,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Test verify error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# =============================================================================
# ADMIN ENDPOINTS - AGENTS
# =============================================================================

@app.get("/admin/agents", tags=["Admin - Agents"], response_model=list[AgentSummary])
async def list_agents(
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """List all agents for the organization."""
    org_id = auth["org_id"]

    async with database.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                id, org_id, name, public_key_fingerprint,
                trust_score, status, daily_limit_usd, per_action_limit_usd,
                allowed_actions, blocked_actions, rate_limit_per_minute,
                last_action_at, total_actions_count, total_blocked_count,
                metadata, created_at, updated_at
            FROM agents
            WHERE org_id = $1
            ORDER BY created_at DESC
            """,
            org_id,
        )

    agents = []
    for row in rows:
        agents.append({
            "id": str(row["id"]),
            "org_id": str(row["org_id"]),
            "name": row["name"],
            "public_key_fingerprint": row["public_key_fingerprint"],
            "trust_score": row["trust_score"],
            "status": row["status"],
            "daily_limit_usd": float(row["daily_limit_usd"]),
            "per_action_limit_usd": float(row["per_action_limit_usd"]),
            "allowed_actions": list(row["allowed_actions"]) if row["allowed_actions"] else [],
            "blocked_actions": list(row["blocked_actions"]) if row["blocked_actions"] else [],
            "rate_limit_per_minute": row["rate_limit_per_minute"],
            "last_action_at": row["last_action_at"].isoformat() if row["last_action_at"] else None,
            "total_actions_count": row["total_actions_count"],
            "total_blocked_count": row["total_blocked_count"],
            "metadata": row["metadata"] if row["metadata"] else {},
            "created_at": row["created_at"].isoformat(),
            "updated_at": row["updated_at"].isoformat(),
        })

    return agents

@app.get("/admin/agents/{agent_id}", tags=["Admin - Agents"], response_model=AgentDetail)
async def get_agent(
    agent_id: UUID,
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Get a specific agent."""
    try:
        agent = await database.get_agent_by_id(agent_id)

        # Verify ownership
        if agent.org_id != auth["org_id"]:
            raise HTTPException(status_code=403, detail="Access denied")

        return {
            "id": str(agent.id),
            "org_id": str(agent.org_id),
            "name": agent.name,
            "public_key_fingerprint": agent.public_key_fingerprint,
            "trust_score": agent.trust_score,
            "status": agent.status.value,
            "daily_limit_usd": float(agent.daily_limit_usd),
            "per_action_limit_usd": float(agent.per_action_limit_usd),
            "allowed_actions": agent.allowed_actions,
            "blocked_actions": agent.blocked_actions,
            "rate_limit_per_minute": agent.rate_limit_per_minute,
            "last_action_at": agent.last_action_at.isoformat() if agent.last_action_at else None,
            "total_actions_count": agent.total_actions_count,
            "total_blocked_count": agent.total_blocked_count,
            "metadata": agent.metadata,
            "created_at": agent.created_at.isoformat(),
            "updated_at": agent.updated_at.isoformat(),
        }
    except AgentNotFoundError:
        raise HTTPException(status_code=404, detail="Agent not found")

@app.get("/admin/agents/{agent_id}/dashboard", tags=["Admin - Agents"])
async def get_agent_dashboard(
    agent_id: UUID,
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Get dashboard data for an agent (for portal view)."""
    try:
        agent = await database.get_agent_by_id(agent_id)

        # Verify ownership
        if agent.org_id != auth["org_id"]:
            raise HTTPException(status_code=403, detail="Access denied")

        # Get organization name
        async with database.acquire() as conn:
            org_row = await conn.fetchrow(
                "SELECT name FROM organizations WHERE id = $1",
                agent.org_id,
            )
        org_name = org_row["name"] if org_row else "Unknown Organization"

        # Get daily spend
        daily_spend = await database.get_daily_spend(agent_id)

        # Get today's stats from audit logs
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        async with database.acquire() as conn:
            today_stats = await conn.fetchrow(
                """
                SELECT
                    COUNT(*) FILTER (WHERE verdict = 'approved') as approved_today,
                    COUNT(*) FILTER (WHERE verdict IN ('blocked', 'rate_limited', 'signature_invalid')) as blocked_today
                FROM audit_logs
                WHERE agent_id = $1 AND timestamp >= $2
                """,
                agent_id,
                today_start,
            )

        approved_today = today_stats["approved_today"] if today_stats else 0
        blocked_today = today_stats["blocked_today"] if today_stats else 0

        # Get recent activity
        async with database.acquire() as conn:
            recent_logs = await conn.fetch(
                """
                SELECT id, action_type, verdict, verdict_reason, timestamp,
                       payload, trust_score_at_time
                FROM audit_logs
                WHERE agent_id = $1
                ORDER BY timestamp DESC
                LIMIT 10
                """,
                agent_id,
            )

        recent_activity = [
            {
                "id": str(row["id"]),
                "action_type": row["action_type"],
                "verdict": row["verdict"],
                "verdict_reason": row["verdict_reason"],
                "timestamp": row["timestamp"].isoformat(),
                "payload": row["payload"] if row["payload"] else {},
                "trust_score_at_time": row["trust_score_at_time"],
            }
            for row in recent_logs
        ]

        # Get trust score history (last 7 days) - simplified: just return current score
        # In production, you'd track this in a separate table
        trust_history = []
        for i in range(6, -1, -1):
            day = now - timedelta(days=i)
            trust_history.append({
                "date": day.strftime("%a"),
                "score": agent.trust_score,  # Would track historical values in production
            })

        return {
            "agent": {
                "id": str(agent.id),
                "name": agent.name,
                "status": agent.status.value,
                "trust_score": agent.trust_score,
                "organization": org_name,
                "daily_limit_usd": float(agent.daily_limit_usd),
                "per_action_limit_usd": float(agent.per_action_limit_usd),
                "rate_limit_per_minute": agent.rate_limit_per_minute,
                "total_actions_count": agent.total_actions_count,
                "public_key_fingerprint": agent.public_key_fingerprint,
            },
            "daily_stats": {
                "daily_spend": float(daily_spend),
                "daily_remaining": float(agent.daily_limit_usd - daily_spend),
                "approved_today": approved_today,
                "blocked_today": blocked_today,
            },
            "trust_history": trust_history,
            "recent_activity": recent_activity,
        }
    except AgentNotFoundError:
        raise HTTPException(status_code=404, detail="Agent not found")

@app.post("/admin/agents", tags=["Admin - Agents"])
async def register_agent(
    request_data: RegisterAgentRequest,
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Register a new agent."""
    # Verify org_id matches authenticated org
    if request_data.org_id != auth["org_id"]:
        raise HTTPException(status_code=403, detail="Cannot register agent for another organization")

    try:
        public_key = base64.b64decode(request_data.public_key)
        if len(public_key) != 32:
            raise HTTPException(status_code=400, detail="Public key must be 32 bytes (Ed25519)")

        agent_id = await database.create_agent(
            org_id=request_data.org_id,
            name=request_data.name,
            public_key=public_key,
            daily_limit_usd=request_data.daily_limit_usd,
            per_action_limit_usd=request_data.per_action_limit_usd,
            allowed_actions=request_data.allowed_actions,
            metadata=request_data.metadata,
        )

        fingerprint = hashlib.sha256(public_key).hexdigest()

        return {
            "agent_id": str(agent_id),
            "public_key_fingerprint": fingerprint,
            "status": "pending_verification",
        }
    except Exception:
        logger.exception("Admin agent registration failed")
        raise HTTPException(
            status_code=400,
            detail="Agent registration failed. Check input and retry.",
        )

@app.patch("/admin/agents/{agent_id}", tags=["Admin - Agents"])
async def update_agent(
    agent_id: UUID,
    updates: dict,
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Update agent configuration."""
    try:
        agent = await database.get_agent_by_id(agent_id)

        if agent.org_id != auth["org_id"]:
            raise HTTPException(status_code=403, detail="Access denied")

        # Build update query dynamically
        allowed_fields = [
            "name", "daily_limit_usd", "per_action_limit_usd",
            "allowed_actions", "blocked_actions", "rate_limit_per_minute", "metadata"
        ]

        set_clauses = []
        params = [agent_id]
        param_idx = 2

        for field in allowed_fields:
            if field in updates:
                if field == "metadata":
                    set_clauses.append(f"metadata = ${param_idx}::jsonb")
                    params.append(json.dumps(updates[field]))
                elif field in ["allowed_actions", "blocked_actions"]:
                    set_clauses.append(f"{field} = ${param_idx}")
                    params.append(updates[field])
                else:
                    set_clauses.append(f"{field} = ${param_idx}")
                    params.append(updates[field])
                param_idx += 1

        if not set_clauses:
            raise HTTPException(status_code=400, detail="No valid fields to update")

        set_clauses.append("updated_at = NOW()")

        query = f"""
            UPDATE agents
            SET {", ".join(set_clauses)}
            WHERE id = $1
            RETURNING *
        """

        async with database.acquire() as conn:
            row = await conn.fetchrow(query, *params)

        return {
            "id": str(row["id"]),
            "org_id": str(row["org_id"]),
            "name": row["name"],
            "public_key_fingerprint": row["public_key_fingerprint"],
            "trust_score": row["trust_score"],
            "status": row["status"],
            "daily_limit_usd": float(row["daily_limit_usd"]),
            "per_action_limit_usd": float(row["per_action_limit_usd"]),
            "allowed_actions": list(row["allowed_actions"]) if row["allowed_actions"] else [],
            "blocked_actions": list(row["blocked_actions"]) if row["blocked_actions"] else [],
            "rate_limit_per_minute": row["rate_limit_per_minute"],
            "last_action_at": row["last_action_at"].isoformat() if row["last_action_at"] else None,
            "total_actions_count": row["total_actions_count"],
            "total_blocked_count": row["total_blocked_count"],
            "metadata": row["metadata"] if row["metadata"] else {},
            "created_at": row["created_at"].isoformat(),
            "updated_at": row["updated_at"].isoformat(),
        }
    except AgentNotFoundError:
        raise HTTPException(status_code=404, detail="Agent not found")

@app.patch("/admin/agents/{agent_id}/status", tags=["Admin - Agents"])
async def update_agent_status(
    agent_id: UUID,
    new_status: AgentStatus = Query(...),
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Update agent status."""
    try:
        agent = await database.get_agent_by_id(agent_id)

        if agent.org_id != auth["org_id"]:
            raise HTTPException(status_code=403, detail="Access denied")

        await database.update_agent_status(agent_id, new_status)

        return {
            "agent_id": str(agent_id),
            "status": new_status.value,
        }
    except AgentNotFoundError:
        raise HTTPException(status_code=404, detail="Agent not found")

# =============================================================================
# ADMIN ENDPOINTS - AUDIT LOGS
# =============================================================================

@app.get("/admin/audit/search", tags=["Admin - Audit"], response_model=AuditSearchResponse)
async def search_audit_logs(
    agent_id: Optional[UUID] = None,
    action_type: Optional[str] = None,
    verdict: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    limit: int = Query(default=50, le=1000),
    offset: int = Query(default=0, ge=0),
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Search audit logs with filters."""
    org_id = auth["org_id"]

    # Build query with filters
    where_clauses = ["a.org_id = $1"]
    params: list = [org_id]
    param_idx = 2

    if agent_id:
        where_clauses.append(f"al.agent_id = ${param_idx}")
        params.append(agent_id)
        param_idx += 1

    if action_type:
        where_clauses.append(f"al.action_type = ${param_idx}")
        params.append(action_type)
        param_idx += 1

    if verdict:
        where_clauses.append(f"al.verdict = ${param_idx}")
        params.append(verdict)
        param_idx += 1

    if start:
        where_clauses.append(f"al.timestamp >= ${param_idx}")
        params.append(datetime.fromisoformat(start.replace("Z", "+00:00")))
        param_idx += 1

    if end:
        where_clauses.append(f"al.timestamp <= ${param_idx}")
        params.append(datetime.fromisoformat(end.replace("Z", "+00:00")))
        param_idx += 1

    where_sql = " AND ".join(where_clauses)

    # Count total
    count_query = f"""
        SELECT COUNT(*)
        FROM audit_logs al
        JOIN agents a ON al.agent_id = a.id
        WHERE {where_sql}
    """

    # Fetch logs
    query = f"""
        SELECT al.id, al.agent_id, a.name as agent_name, al.timestamp,
               al.action_type, al.action_hash, al.payload, al.verdict,
               al.verdict_reason, al.signature_valid, al.request_ip,
               al.request_user_agent, al.response_time_ms, al.trust_score_at_time,
               al.merkle_root_id, al.merkle_leaf_index
        FROM audit_logs al
        JOIN agents a ON al.agent_id = a.id
        WHERE {where_sql}
        ORDER BY al.timestamp DESC
        LIMIT ${param_idx} OFFSET ${param_idx + 1}
    """
    params.extend([limit, offset])

    async with database.acquire() as conn:
        total = await conn.fetchval(count_query, *params[:-2])
        rows = await conn.fetch(query, *params)

    logs = []
    for row in rows:
        logs.append({
            "id": str(row["id"]),
            "agent_id": str(row["agent_id"]),
            "agent_name": row["agent_name"],
            "timestamp": row["timestamp"].isoformat(),
            "action_type": row["action_type"],
            "action_hash": row["action_hash"],
            "payload": row["payload"] if isinstance(row["payload"], dict) else json.loads(row["payload"]) if row["payload"] else {},
            "verdict": row["verdict"],
            "verdict_reason": row["verdict_reason"],
            "signature_valid": row["signature_valid"],
            "request_ip": row["request_ip"],
            "request_user_agent": row["request_user_agent"],
            "response_time_ms": row["response_time_ms"],
            "trust_score_at_time": row["trust_score_at_time"],
            "merkle_root_id": str(row["merkle_root_id"]) if row["merkle_root_id"] else None,
            "merkle_leaf_index": row["merkle_leaf_index"],
        })

    return {"logs": logs, "total": total, "limit": limit, "offset": offset}

@app.get("/admin/audit/{log_id}", tags=["Admin - Audit"], response_model=AuditLogDetail)
async def get_audit_log(
    log_id: UUID,
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Get a specific audit log."""
    org_id = auth["org_id"]

    async with database.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT al.*, a.name as agent_name, a.org_id
            FROM audit_logs al
            JOIN agents a ON al.agent_id = a.id
            WHERE al.id = $1
            """,
            log_id,
        )

    if not row:
        raise HTTPException(status_code=404, detail="Audit log not found")

    if row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return {
        "id": str(row["id"]),
        "agent_id": str(row["agent_id"]),
        "agent_name": row["agent_name"],
        "timestamp": row["timestamp"].isoformat(),
        "action_type": row["action_type"],
        "action_hash": row["action_hash"],
        "payload": row["payload"] if isinstance(row["payload"], dict) else json.loads(row["payload"]) if row["payload"] else {},
        "verdict": row["verdict"],
        "verdict_reason": row["verdict_reason"],
        "signature_valid": row["signature_valid"],
        "request_ip": row["request_ip"],
        "request_user_agent": row["request_user_agent"],
        "response_time_ms": row["response_time_ms"],
        "trust_score_at_time": row["trust_score_at_time"],
        "merkle_root_id": str(row["merkle_root_id"]) if row["merkle_root_id"] else None,
        "merkle_leaf_index": row["merkle_leaf_index"],
    }

@app.get("/admin/audit/{log_id}/proof", tags=["Admin - Audit"], response_model=AuditProof)
async def get_merkle_proof(
    log_id: UUID,
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Get Merkle proof for an audit log."""
    org_id = auth["org_id"]

    # Get audit log
    async with database.acquire() as conn:
        log_row = await conn.fetchrow(
            """
            SELECT al.*, a.org_id
            FROM audit_logs al
            JOIN agents a ON al.agent_id = a.id
            WHERE al.id = $1
            """,
            log_id,
        )

    if not log_row:
        raise HTTPException(status_code=404, detail="Audit log not found")

    if log_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    if not log_row["merkle_root_id"]:
        raise HTTPException(status_code=404, detail="Audit log has not been anchored yet")

    # Get merkle proof record
    async with database.acquire() as conn:
        proof_row = await conn.fetchrow(
            """
            SELECT * FROM merkle_proofs WHERE id = $1
            """,
            log_row["merkle_root_id"],
        )

    if not proof_row:
        raise HTTPException(status_code=404, detail="Merkle proof not found")

    # Compute the actual proof path
    leaf_hashes = proof_row["leaf_hashes"]
    leaf_index = log_row["merkle_leaf_index"]

    # Generate proof
    from workers.anchor_worker import compute_merkle_proof
    try:
        proof_path = compute_merkle_proof(leaf_hashes, leaf_index)
    except Exception:
        proof_path = []

    return {
        "leaf": log_row["action_hash"],
        "proof": [p["hash"] for p in proof_path],
        "positions": [p["position"] == 1 for p in proof_path],  # True = right, False = left
        "merkle_root": proof_row["root_hash"],
        "tx_hash": proof_row["transaction_hash"],
        "block_number": proof_row["block_number"],
        "anchored_at": proof_row["confirmed_at"].isoformat() if proof_row["confirmed_at"] else None,
    }

@app.get("/admin/audit/export", tags=["Admin - Audit"])
async def export_audit_logs(
    format: str = Query(..., pattern="^(csv|json)$"),
    start: Optional[str] = None,
    end: Optional[str] = None,
    agent_id: Optional[UUID] = None,
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Export audit logs as CSV or JSON."""
    org_id = auth["org_id"]

    # Build query
    where_clauses = ["a.org_id = $1"]
    params: list = [org_id]
    param_idx = 2

    if agent_id:
        where_clauses.append(f"al.agent_id = ${param_idx}")
        params.append(agent_id)
        param_idx += 1

    if start:
        where_clauses.append(f"al.timestamp >= ${param_idx}")
        params.append(datetime.fromisoformat(start.replace("Z", "+00:00")))
        param_idx += 1

    if end:
        where_clauses.append(f"al.timestamp <= ${param_idx}")
        params.append(datetime.fromisoformat(end.replace("Z", "+00:00")))
        param_idx += 1

    where_sql = " AND ".join(where_clauses)

    query = f"""
        SELECT al.id, al.agent_id, a.name as agent_name, al.timestamp,
               al.action_type, al.action_hash, al.verdict, al.verdict_reason,
               al.signature_valid, al.trust_score_at_time
        FROM audit_logs al
        JOIN agents a ON al.agent_id = a.id
        WHERE {where_sql}
        ORDER BY al.timestamp DESC
        LIMIT 10000
    """

    async with database.acquire() as conn:
        rows = await conn.fetch(query, *params)

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "agent_id", "agent_name", "timestamp", "action_type",
                        "action_hash", "verdict", "verdict_reason", "signature_valid", "trust_score"])

        for row in rows:
            writer.writerow([
                str(row["id"]),
                str(row["agent_id"]),
                row["agent_name"],
                row["timestamp"].isoformat(),
                row["action_type"],
                row["action_hash"],
                row["verdict"],
                row["verdict_reason"] or "",
                row["signature_valid"],
                row["trust_score_at_time"],
            ])

        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=audit_logs_{datetime.now().strftime('%Y%m%d')}.csv"}
        )
    else:
        logs = []
        for row in rows:
            logs.append({
                "id": str(row["id"]),
                "agent_id": str(row["agent_id"]),
                "agent_name": row["agent_name"],
                "timestamp": row["timestamp"].isoformat(),
                "action_type": row["action_type"],
                "action_hash": row["action_hash"],
                "verdict": row["verdict"],
                "verdict_reason": row["verdict_reason"],
                "signature_valid": row["signature_valid"],
                "trust_score_at_time": row["trust_score_at_time"],
            })

        return StreamingResponse(
            iter([json.dumps(logs, indent=2)]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=audit_logs_{datetime.now().strftime('%Y%m%d')}.json"}
        )

# =============================================================================
# ADMIN ENDPOINTS - ALERTS
# =============================================================================

@app.get("/admin/alerts", tags=["Admin - Alerts"])
async def list_alerts(
    status: Optional[str] = Query(None, pattern="^(open|acknowledged|resolved)$"),
    severity: Optional[str] = None,
    limit: int = Query(default=50, le=1000),
    offset: int = Query(default=0, ge=0),
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """List security alerts."""
    org_id = auth["org_id"]

    where_clauses = ["sa.org_id = $1"]
    params: list = [org_id]
    param_idx = 2

    if status == "open":
        where_clauses.append("acknowledged = false AND resolved = false")
    elif status == "acknowledged":
        where_clauses.append("acknowledged = true AND resolved = false")
    elif status == "resolved":
        where_clauses.append("resolved = true")

    if severity:
        where_clauses.append(f"severity = ${param_idx}")
        params.append(severity)
        param_idx += 1

    where_sql = " AND ".join(where_clauses)

    count_query = f"SELECT COUNT(*) FROM security_alerts sa WHERE {where_sql}"

    query = f"""
        SELECT sa.*, a.name as agent_name
        FROM security_alerts sa
        LEFT JOIN agents a ON sa.agent_id = a.id
        WHERE {where_sql}
        ORDER BY sa.created_at DESC
        LIMIT ${param_idx} OFFSET ${param_idx + 1}
    """
    params.extend([limit, offset])

    async with database.acquire() as conn:
        total = await conn.fetchval(count_query, *params[:-2])
        rows = await conn.fetch(query, *params)

    alerts = []
    for row in rows:
        alerts.append({
            "id": str(row["id"]),
            "agent_id": str(row["agent_id"]) if row["agent_id"] else None,
            "agent_name": row["agent_name"],
            "severity": row["severity"],
            "alert_type": row["alert_type"],
            "title": row["title"],
            "description": row["description"],
            "evidence": row["evidence"] if isinstance(row["evidence"], dict) else json.loads(row["evidence"]) if row["evidence"] else {},
            "acknowledged": row["acknowledged"],
            "acknowledged_by": row["acknowledged_by"],
            "acknowledged_at": row["acknowledged_at"].isoformat() if row["acknowledged_at"] else None,
            "resolved": row["resolved"],
            "resolved_at": row["resolved_at"].isoformat() if row["resolved_at"] else None,
            "created_at": row["created_at"].isoformat(),
        })

    return {"alerts": alerts, "total": total}

@app.post("/admin/alerts/{alert_id}/acknowledge", tags=["Admin - Alerts"])
async def acknowledge_alert(
    alert_id: UUID,
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Acknowledge a security alert."""
    org_id = auth["org_id"]

    async with database.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE security_alerts
            SET acknowledged = true, acknowledged_at = NOW(), acknowledged_by = $3
            WHERE id = $1 AND org_id = $2
            """,
            alert_id, org_id, auth.get("org_name", "API User"),
        )

    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"alert_id": str(alert_id), "acknowledged": True}

@app.post("/admin/alerts/{alert_id}/resolve", tags=["Admin - Alerts"])
async def resolve_alert(
    alert_id: UUID,
    body: dict,
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Resolve a security alert."""
    org_id = auth["org_id"]
    resolution = body.get("resolution", "")

    async with database.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE security_alerts
            SET resolved = true, resolved_at = NOW(), resolution_notes = $3, resolved_by = $4
            WHERE id = $1 AND org_id = $2
            """,
            alert_id, org_id, resolution, auth.get("org_name", "API User"),
        )

    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"alert_id": str(alert_id), "resolved": True}

# =============================================================================
# ADMIN ENDPOINTS - API KEYS
# =============================================================================

@app.get("/admin/api-keys", tags=["Admin - API Keys"])
async def list_api_keys(
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """List API keys for the organization."""
    org_id = auth["org_id"]

    async with database.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, org_id, key_prefix, name, scopes, is_active,
                   expires_at, last_used_at, created_at
            FROM api_keys
            WHERE org_id = $1
            ORDER BY created_at DESC
            """,
            org_id,
        )

    keys = []
    for row in rows:
        keys.append({
            "id": str(row["id"]),
            "org_id": str(row["org_id"]),
            "key_prefix": row["key_prefix"],
            "name": row["name"],
            "scopes": row["scopes"] or [],
            "is_active": row["is_active"],
            "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
            "last_used_at": row["last_used_at"].isoformat() if row["last_used_at"] else None,
            "created_at": row["created_at"].isoformat(),
        })

    return keys

@app.post("/admin/api-keys", tags=["Admin - API Keys"])
async def create_api_key(
    body: dict,
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Create a new API key."""
    org_id = auth["org_id"]
    name = body.get("name", "Unnamed Key")
    scopes = body.get("scopes", ["read"])
    expires_at = body.get("expires_at")

    # Generate secure API key
    raw_key = f"inntris_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).digest()
    key_prefix = raw_key[:12]

    async with database.acquire() as conn:
        key_id = await conn.fetchval(
            """
            INSERT INTO api_keys (org_id, key_hash, key_prefix, name, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            """,
            org_id, key_hash, key_prefix, name, scopes,
            datetime.fromisoformat(expires_at.replace("Z", "+00:00")) if expires_at else None,
        )

    return {
        "api_key": raw_key,  # Only returned once!
        "key_id": str(key_id),
    }

@app.delete("/admin/api-keys/{key_prefix}", tags=["Admin - API Keys"])
async def revoke_api_key(
    key_prefix: str,
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Revoke an API key."""
    org_id = auth["org_id"]

    async with database.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE api_keys
            SET is_active = false
            WHERE key_prefix = $1 AND org_id = $2
            """,
            key_prefix, org_id,
        )

    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="API key not found")

    return {"message": "API key revoked"}

@app.post("/admin/api-keys/rotate", tags=["Admin - API Keys"])
async def rotate_api_key(
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Rotate all API keys - creates new key and revokes old ones."""
    org_id = auth["org_id"]

    # Generate new key
    raw_key = f"inntris_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).digest()
    key_prefix = raw_key[:12]

    async with database.acquire() as conn:
        # Revoke all existing keys
        await conn.execute(
            "UPDATE api_keys SET is_active = false WHERE org_id = $1",
            org_id,
        )

        # Create new key
        await conn.execute(
            """
            INSERT INTO api_keys (org_id, key_hash, key_prefix, name, scopes)
            VALUES ($1, $2, $3, 'Rotated Key', ARRAY['admin', 'read', 'write'])
            """,
            org_id, key_hash, key_prefix,
        )

    return {
        "api_key": raw_key,
        "message": "All previous keys revoked. Use this new key.",
    }

# =============================================================================
# ADMIN ENDPOINTS - USAGE & ORGANIZATION
# =============================================================================

@app.get("/admin/usage", tags=["Admin - Usage"])
async def get_usage_metrics(
    start: str = Query(...),
    end: str = Query(...),
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Get usage metrics for the organization."""
    org_id = auth["org_id"]

    start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))

    # Get overall metrics
    async with database.acquire() as conn:
        # Total counts
        totals = await conn.fetchrow(
            """
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN al.verdict = 'approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN al.verdict != 'approved' THEN 1 ELSE 0 END) as blocked
            FROM audit_logs al
            JOIN agents a ON al.agent_id = a.id
            WHERE a.org_id = $1 AND al.timestamp BETWEEN $2 AND $3
            """,
            org_id, start_dt, end_dt,
        )

        # Active agents
        active_agents = await conn.fetchval(
            """
            SELECT COUNT(DISTINCT al.agent_id)
            FROM audit_logs al
            JOIN agents a ON al.agent_id = a.id
            WHERE a.org_id = $1 AND al.timestamp BETWEEN $2 AND $3
            """,
            org_id, start_dt, end_dt,
        )

        # Total spend from rate_limit_windows
        total_spend = await conn.fetchval(
            """
            SELECT COALESCE(SUM(rlw.amount_usd), 0)
            FROM rate_limit_windows rlw
            JOIN agents a ON rlw.agent_id = a.id
            WHERE a.org_id = $1
              AND rlw.window_type = 'day'
              AND rlw.window_start BETWEEN $2 AND $3
            """,
            org_id, start_dt, end_dt,
        )

        # Daily breakdown with spend
        daily = await conn.fetch(
            """
            SELECT
                DATE(al.timestamp) as date,
                COUNT(*) as verifications,
                SUM(CASE WHEN al.verdict = 'approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN al.verdict != 'approved' THEN 1 ELSE 0 END) as blocked
            FROM audit_logs al
            JOIN agents a ON al.agent_id = a.id
            WHERE a.org_id = $1 AND al.timestamp BETWEEN $2 AND $3
            GROUP BY DATE(al.timestamp)
            ORDER BY date
            """,
            org_id, start_dt, end_dt,
        )

        # Get daily spend breakdown
        daily_spend = await conn.fetch(
            """
            SELECT
                DATE(rlw.window_start) as date,
                COALESCE(SUM(rlw.amount_usd), 0) as spend_usd
            FROM rate_limit_windows rlw
            JOIN agents a ON rlw.agent_id = a.id
            WHERE a.org_id = $1
              AND rlw.window_type = 'day'
              AND rlw.window_start BETWEEN $2 AND $3
            GROUP BY DATE(rlw.window_start)
            """,
            org_id, start_dt, end_dt,
        )

    # Convert daily spend to a lookup dict
    spend_by_date = {row["date"]: float(row["spend_usd"]) for row in daily_spend}

    daily_breakdown = []
    for row in daily:
        daily_breakdown.append({
            "date": row["date"].isoformat(),
            "verifications": row["verifications"],
            "approved": row["approved"],
            "blocked": row["blocked"],
            "spend_usd": spend_by_date.get(row["date"], 0.0),
        })

    return {
        "total_verifications": totals["total"] or 0,
        "approved_count": totals["approved"] or 0,
        "blocked_count": totals["blocked"] or 0,
        "total_spend_usd": float(total_spend) if total_spend else 0.0,
        "active_agents": active_agents or 0,
        "period_start": start,
        "period_end": end,
        "daily_breakdown": daily_breakdown,
    }

@app.get("/admin/organization", tags=["Admin - Organization"], response_model=OrganizationResponse)
async def get_organization(
    auth: dict = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Get organization information."""
    org_id = auth["org_id"]

    try:
        org = await database.get_organization_by_id(org_id)

        return {
            "id": str(org.id),
            "name": org.name,
            "billing_tier": org.billing_tier.value if hasattr(org.billing_tier, 'value') else str(org.billing_tier),
            "contact_email": org.contact_email,
            "webhook_url": org.webhook_url,
            "daily_limit_usd": float(org.daily_limit_usd),
            "monthly_limit_usd": float(org.monthly_limit_usd),
            "metadata": org.metadata if isinstance(org.metadata, dict) else {},
            "created_at": org.created_at.isoformat(),
            "updated_at": org.updated_at.isoformat(),
        }
    except OrganizationNotFoundError:
        raise HTTPException(status_code=404, detail="Organization not found")
    except Exception as e:
        logger.error(f"Error fetching organization {org_id}: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching organization: {type(e).__name__}")
