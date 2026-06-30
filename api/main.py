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
import binascii
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Any, Optional
from uuid import UUID, uuid4

import asyncpg
import redis.asyncio as redis
from fastapi import FastAPI, Depends, HTTPException, Request, status, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
import io
import csv

from api.database import (
    Database,
    AgentNotFoundError,
    OrganizationNotFoundError,
    LimitReservationError,
)
from api.models import (
    VerifyActionRequest,
    VerifyActionResponse,
    VerifyTokenRequest,
    VerifyTokenResponse,
    VerifyDebugResponse,
    TestVerifyRequest,
    RegisterAgentRequest,
    UpdateAgentRequest,
    RegisterPolicyRequest,
    RotateAgentKeyRequest,
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
from api.policy import PolicyEngine, TrustScorer, canonical_policy_hash
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

# Master admin key — gates org provisioning. Unset means the feature is
# disabled (operator must bootstrap orgs by direct DB insert or seed script).
# When set in production, MUST be at least 32 chars to resist guessing.
MASTER_ADMIN_KEY_RAW = os.getenv("MASTER_ADMIN_KEY")


def _resolve_master_admin_key(raw: Optional[str]) -> Optional[str]:
    """Normalize ``MASTER_ADMIN_KEY`` and fail closed on weak values.

    Behavior:
    - unset / empty / whitespace-only -> ``None`` (feature disabled)
    - length < 32 -> ``None`` with an explicit warning (feature disabled)
    - otherwise return the trimmed key

    This avoids crash-loop deployments when operators accidentally set a short
    key while preserving security: org provisioning remains unavailable until
    a strong key is configured.
    """
    if raw is None:
        return None

    candidate = raw.strip()
    if not candidate:
        return None

    if len(candidate) < 32:
        logger.warning(
            "MASTER_ADMIN_KEY is set but shorter than 32 characters; "
            "organization provisioning is disabled until a strong key is configured"
        )
        return None

    return candidate


MASTER_ADMIN_KEY = _resolve_master_admin_key(MASTER_ADMIN_KEY_RAW)
API_KEY_PREFIX_LENGTH = 8
PUBLIC_REGISTRATION_METADATA_BLOCKLIST = {
    "allowed_actions",
    "blocked_actions",
    "daily_limit_usd",
    "per_action_limit_usd",
    "rate_limit_per_minute",
    "status",
    "trust_score",
}

# SECURITY: Validate secrets in production
if ENVIRONMENT != "development":
    if not SERVER_SECRET_RAW:
        raise SystemExit("FATAL: SERVER_SECRET environment variable is required in production")
    if len(SERVER_SECRET_RAW) < 32:
        raise SystemExit("FATAL: SERVER_SECRET must be at least 32 characters")

SERVER_SECRET = (SERVER_SECRET_RAW or "dev-secret-do-not-use-in-production").encode("utf-8")

# Optional previous secret for zero-downtime SERVER_SECRET rotation: approval
# tokens signed with the old secret keep verifying while clients roll over. Set
# SERVER_SECRET_PREVIOUS=<old value> during the rotation window, then remove it.
# New tokens are always signed with the current SERVER_SECRET.
_SERVER_SECRET_PREVIOUS_RAW = os.getenv("SERVER_SECRET_PREVIOUS")
SERVER_SECRETS = [SERVER_SECRET] + (
    [_SERVER_SECRET_PREVIOUS_RAW.encode("utf-8")]
    if _SERVER_SECRET_PREVIOUS_RAW
    else []
)


async def _deliver_webhook(
    webhook_url: str,
    event: str,
    payload: dict,
    org_id: UUID,
) -> None:
    """
    Fire-and-forget webhook delivery.

    Signs the payload with SERVER_SECRET (HMAC-SHA256) so receivers can verify
    the request originated from Inntris. Failures are logged but never raised
    — the audit log is already persisted, the webhook is a notification.
    """
    import httpx
    import hmac

    body = {
        "event": event,
        "org_id": str(org_id),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "data": payload,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    signature = hmac.new(SERVER_SECRET, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                webhook_url,
                content=canonical,
                headers={
                    "Content-Type": "application/json",
                    "X-Inntris-Signature": signature,
                    "X-Inntris-Event": event,
                    "User-Agent": "Inntris-Webhook/1.0",
                },
            )
            if response.status_code >= 400:
                logger.warning(
                    "Webhook delivery returned %s for org %s event %s",
                    response.status_code, org_id, event,
                )
    except Exception as e:
        logger.warning("Webhook delivery failed for org %s event %s: %s", org_id, event, e)


async def _dispatch_verdict_webhook(
    database: "Database",
    org_id: UUID,
    event: str,
    agent_id: UUID,
    audit_id: Optional[UUID],
    action_type: str,
    verdict: str,
    verdict_reason: Optional[str],
) -> None:
    """
    Look up the org's webhook_url and schedule a fire-and-forget delivery.

    Returns immediately if the org has no webhook configured. The actual HTTP
    request is dispatched via ``asyncio.create_task`` so /verify's response
    time is unaffected.
    """
    try:
        async with database.acquire() as conn:
            webhook_url = await conn.fetchval(
                "SELECT webhook_url FROM organizations WHERE id = $1",
                org_id,
            )
        if not webhook_url:
            return
        import asyncio
        asyncio.create_task(
            _deliver_webhook(
                webhook_url=webhook_url,
                event=event,
                payload={
                    "agent_id": str(agent_id),
                    "audit_id": str(audit_id) if audit_id else None,
                    "action_type": action_type,
                    "verdict": verdict,
                    "verdict_reason": verdict_reason,
                },
                org_id=org_id,
            )
        )
    except Exception as e:
        logger.warning("Failed to schedule webhook for org %s: %s", org_id, e)


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


def _compute_integrity_status(
    tx_hash: "Optional[str]",
    proof_status: "Optional[str]" = None,
) -> str:
    """Return integrity_status reflecting whether the receipt has been anchored.

    - ``"verified"``       — receipt exists and is anchored on-chain
    - ``"pending_anchor"`` — receipt exists but anchor batch not yet submitted
    """
    if proof_status in {"failed", "dead_letter"}:
        return "failed"
    if tx_hash and proof_status in {None, "confirmed"}:
        return "verified"
    return "pending_anchor"


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


@app.exception_handler(RequestValidationError)
async def _validation_exception_handler(request: Request, exc: RequestValidationError):
    """Normalize 422 validation errors into the standard error envelope.

    Additive and back-compatible: keeps the original pydantic ``detail`` array
    so existing callers do not break, and adds a stable ``error`` code, a human
    ``message``, a flattened ``details.fields`` summary, and the ``request_id``
    so a partner can branch on the error type instead of parsing free text.
    """
    from api.observability import current_request_id

    errors = exc.errors()
    fields = []
    for err in errors:
        loc = ".".join(str(p) for p in err.get("loc", []) if p != "body")
        fields.append({"field": loc or "(body)", "message": err.get("msg", "invalid")})
    return JSONResponse(
        status_code=422,
        content=jsonable_encoder(
            {
                "error": "validation_error",
                "message": "Request validation failed. See 'detail' for the offending fields.",
                "detail": errors,
                "details": {"fields": fields},
                "request_id": current_request_id(),
            }
        ),
    )


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


async def verify_master_admin_key(
    x_master_key: Optional[str] = Header(None, alias="X-Master-Key"),
) -> None:
    """
    Gate for operator-level endpoints that provision new organizations.

    Compares the inbound ``X-Master-Key`` header against the ``MASTER_ADMIN_KEY``
    env var with constant-time equality. If the env var is unset the endpoint
    is administratively disabled and always returns 503 — this avoids accidentally
    leaving the bootstrap endpoint open after the first org has been created
    if the operator forgot to remove the env var.
    """
    if not MASTER_ADMIN_KEY:
        raise HTTPException(
            status_code=503,
            detail="Organization provisioning disabled. Set MASTER_ADMIN_KEY env var to enable.",
        )
    if not x_master_key or not secrets.compare_digest(x_master_key, MASTER_ADMIN_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing X-Master-Key")


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
            "scopes": ["admin", "read", "write", "verify"],
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


def _normalise_scopes(scopes: Any) -> set[str]:
    if not scopes:
        return {"read"}
    if isinstance(scopes, (list, tuple, set)):
        return {str(scope).strip().lower() for scope in scopes if str(scope).strip()}
    return {str(scopes).strip().lower()} if str(scopes).strip() else {"read"}


def require_api_scope(scope: str):
    required = scope.strip().lower()

    async def _dependency(auth: dict = Depends(verify_api_key)) -> dict:
        scopes = _normalise_scopes(auth.get("scopes"))
        if "admin" in scopes or required in scopes:
            return auth
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API key requires '{required}' scope",
        )

    return _dependency


def _api_key_prefix(raw_key: str) -> str:
    for marker in ("inntris_live_sk_", "inntris_"):
        if raw_key.startswith(marker):
            return raw_key[len(marker):len(marker) + API_KEY_PREFIX_LENGTH]
    return raw_key[:API_KEY_PREFIX_LENGTH]


def _decode_signature_for_audit(signature_b64: str) -> bytes:
    try:
        decoded = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        digest = hashlib.sha256(signature_b64.encode("utf-8")).hexdigest()[:16]
        return f"INVALID_SIGNATURE:{digest}".encode("ascii")
    if decoded:
        return decoded
    digest = hashlib.sha256(signature_b64.encode("utf-8")).hexdigest()[:16]
    return f"EMPTY_SIGNATURE:{digest}".encode("ascii")


def _effective_policy_hash(agent: Any) -> str:
    policy_payload = {
        "version": "effective_agent_policy_v1",
        "agent_id": str(agent.id),
        "status": agent.status.value if hasattr(agent.status, "value") else str(agent.status),
        "allowed_actions": sorted(agent.allowed_actions or []),
        "blocked_actions": sorted(agent.blocked_actions or []),
        "daily_limit_usd": str(agent.daily_limit_usd),
        "per_action_limit_usd": str(agent.per_action_limit_usd),
        "rate_limit_per_minute": int(agent.rate_limit_per_minute),
        "trust_score": int(agent.trust_score),
    }
    canonical = json.dumps(policy_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _audit_metadata(
    *,
    client_policy_hash: Optional[str],
    key_fingerprint: Optional[str] = None,
    sandbox: bool = False,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    metadata = dict(extra or {})
    if client_policy_hash:
        metadata["client_policy_hash"] = client_policy_hash
    # Pin each verification to the signing key. After a key leak, rotate and
    # then scope the blast radius: query audits where key_fingerprint matches
    # the retired key.
    if key_fingerprint:
        metadata["key_fingerprint"] = key_fingerprint
    # Sandbox rows must never reach the mainnet anchor path. test_request is the
    # anchor worker's existing exclusion key (get_unanchored_logs); sandbox is
    # the human-facing flag surfaced on the public receipt.
    if sandbox:
        metadata["test_request"] = True
        metadata["sandbox"] = True
    return metadata


def _json_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _policy_context_from_audit_row(row: Any) -> dict[str, Any]:
    payload = _json_dict(row["payload"])
    metadata = _json_dict(row["metadata"])

    reason = row["verdict_reason"]
    violations: list[str] = []
    if reason:
        if "violations:" in reason.lower():
            parts = reason.split(":", 1)
            if len(parts) > 1:
                violations = [v.strip() for v in parts[1].split(",") if v.strip()]
        elif row["verdict"] != "approved":
            violations = [reason]

    risk_level = payload.get("risk_level")
    violation = metadata.get("violation")
    return {
        "payload": payload,
        "metadata": metadata,
        "risk_level": risk_level if isinstance(risk_level, str) else None,
        "violations": violations,
        "policy_rule_triggered": violation if isinstance(violation, str) else None,
    }


def _public_registration_metadata(raw_metadata: Optional[dict[str, Any]]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in dict(raw_metadata or {}).items()
        if str(key) not in PUBLIC_REGISTRATION_METADATA_BLOCKLIST
    }


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
            headers={"Retry-After": "3600"},
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
        "signature_b64": {"type": ["string", "null"], "description": "Base64 Ed25519 signature over the action hash, for independent re-verification (null unless a 64-byte signature was supplied)."},
        "public_key_b64": {"type": ["string", "null"], "description": "Base64 Ed25519 public key the signature verifies against."},
        "merkle_root": {"type": ["string", "null"]},
        "tx_hash": {"type": ["string", "null"], "pattern": "^0x[a-fA-F0-9]{64}$"},
        "block_number": {"type": ["integer", "null"]},
        "chain_id": {"type": "integer", "default": 8453, "description": "Chain ID. Public receipts are always 8453 (Base Mainnet)."},
        "anchored_at": {"type": ["string", "null"], "format": "date-time"},
        "schema_version": {"type": "string", "enum": ["v1", "v2"]},
        "receipt_fingerprint": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "integrity_status": {"type": "string", "enum": ["verified", "pending_anchor", "failed", "sandbox"]},
        "sandbox": {"type": "boolean", "default": False, "description": "True for sandbox/test receipts that never anchor on-chain."},
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
        public_key_bytes = base64.b64decode(request_data.public_key, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="public_key must be valid base64")
    if len(public_key_bytes) != 32:
        raise HTTPException(status_code=400, detail="public_key must decode to exactly 32 bytes (Ed25519)")

    fingerprint = CryptoService.compute_public_key_fingerprint(public_key_bytes)

    # Find or create a default public organization for this email
    async with database.acquire() as conn:
        org_row = await conn.fetchrow(
            """
            SELECT id FROM organizations
            WHERE contact_email = $1
              AND metadata->>'source' IN (
                  'public_registration',
                  'public_registration_promptfoo'
              )
            ORDER BY created_at ASC
            LIMIT 1
            """,
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
                INSERT INTO organizations (name, contact_email, billing_tier, api_key_hash, metadata)
                VALUES ($1, $2, 'free', $3, $4::jsonb)
                RETURNING id
                """,
                f"Public Org — {request_data.email}",
                request_data.email,
                placeholder_key_hash,
                json.dumps({"source": "public_registration"}),
            )

    # Register the agent
    adapter_meta = _public_registration_metadata(request_data.adapter_metadata)
    agent_id = await database.create_agent(
        org_id=org_id,
        name=f"agent-{fingerprint[:8]}",
        public_key=public_key_bytes,
        allowed_actions=["tool_call", "api_call"],
        metadata={**adapter_meta, "source": "public_registration", "sandbox": request_data.sandbox},
    )
    # Public bootstrap promises an immediately usable agent. Persist that
    # promise instead of returning "active" while the row remains pending.
    await database.update_agent_status(agent_id, AgentStatus.ACTIVE)

    return PublicRegisterAgentResponse(
        agent_id=str(agent_id),
        public_key_fingerprint=fingerprint,
        org_id=str(org_id),
        status="active",
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        message=(
            "Sandbox agent registered — decisions are signed and verifiable but "
            "never anchored on-chain. Use agent_id with POST /verify."
            if request_data.sandbox
            else "Agent registered. Use agent_id with POST /verify."
        ),
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
        public_key_bytes = base64.b64decode(request_data.public_key, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="public_key must be valid base64")
    if len(public_key_bytes) != 32:
        raise HTTPException(status_code=400, detail="public_key must decode to exactly 32 bytes (Ed25519)")

    fingerprint = CryptoService.compute_public_key_fingerprint(public_key_bytes)

    # Inject Promptfoo defaults
    meta = _public_registration_metadata(request_data.adapter_metadata)
    meta.setdefault("platform", "promptfoo")
    meta.setdefault("version", "unknown")

    # Find or create organization
    async with database.acquire() as conn:
        org_row = await conn.fetchrow(
            """
            SELECT id FROM organizations
            WHERE contact_email = $1
              AND metadata->>'source' IN (
                  'public_registration',
                  'public_registration_promptfoo'
              )
            ORDER BY created_at ASC
            LIMIT 1
            """,
            request_data.email,
        )
        if org_row:
            org_id = org_row["id"]
        else:
            placeholder_key_hash = hashlib.sha256(os.urandom(32)).digest()
            org_id = await conn.fetchval(
                """
                INSERT INTO organizations (name, contact_email, billing_tier, api_key_hash, metadata)
                VALUES ($1, $2, 'free', $3, $4::jsonb)
                RETURNING id
                """,
                f"Promptfoo Org — {request_data.email}",
                request_data.email,
                placeholder_key_hash,
                json.dumps({"source": "public_registration_promptfoo"}),
            )

    agent_id = await database.create_agent(
        org_id=org_id,
        name=f"promptfoo-{fingerprint[:8]}",
        public_key=public_key_bytes,
        allowed_actions=["promptfoo_eval"],
        metadata={**meta, "source": "public_registration_promptfoo", "sandbox": request_data.sandbox},
    )
    await database.update_agent_status(agent_id, AgentStatus.ACTIVE)

    return PublicRegisterAgentResponse(
        agent_id=str(agent_id),
        public_key_fingerprint=fingerprint,
        org_id=str(org_id),
        status="active",
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        message=(
            "Sandbox Promptfoo agent registered — signed and verifiable but never "
            "anchored on-chain. Use agent_id with POST /verify."
            if request_data.sandbox
            else "Promptfoo agent registered. Use agent_id with POST /verify."
        ),
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
                           a.public_key AS agent_public_key,
                           mp.root_hash AS merkle_root,
                           mp.transaction_hash AS tx_hash,
                           mp.block_number,
                           mp.chain_id,
                           mp.status AS proof_status,
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
                           a.public_key AS agent_public_key,
                           mp.root_hash AS merkle_root,
                           mp.transaction_hash AS tx_hash,
                           mp.block_number,
                           mp.chain_id,
                           mp.status AS proof_status,
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

    # Expose the raw signature + public key so a third party can re-verify the
    # Ed25519 signature over the action hash, rather than trusting signature_valid.
    # Only a real 64-byte signature is exposed; the sentinels written for
    # malformed/invalid submissions (see _decode_signature_for_audit) are not.
    # The public key is public by definition.
    sig_bytes = row.get("signature")
    signature_b64 = (
        base64.b64encode(sig_bytes).decode()
        if isinstance(sig_bytes, (bytes, bytearray)) and len(sig_bytes) == 64
        else None
    )
    pub_bytes = row.get("agent_public_key")
    public_key_b64 = (
        base64.b64encode(pub_bytes).decode()
        if isinstance(pub_bytes, (bytes, bytearray)) and len(pub_bytes) == 32
        else None
    )

    # Sandbox receipts (test_request rows) never anchor on-chain — surface that
    # explicitly so the UI/clients don't show "pending_anchor" forever.
    record_metadata = _json_dict(row.get("metadata"))
    is_sandbox = bool(record_metadata.get("sandbox") or record_metadata.get("test_request"))

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
        signature_b64=signature_b64,
        public_key_b64=public_key_b64,
        merkle_root=row.get("merkle_root"),
        tx_hash=row.get("tx_hash"),
        block_number=row.get("block_number"),
        chain_id=row.get("chain_id") or 8453,
        anchored_at=row.get("anchored_at"),
        schema_version=schema_version,
        receipt_fingerprint=receipt_fingerprint,
        integrity_status=(
            "sandbox"
            if is_sandbox
            else _compute_integrity_status(row.get("tx_hash"), row.get("proof_status"))
        ),
        sandbox=is_sandbox,
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
                   al.timestamp, al.metadata
            FROM audit_logs al
            WHERE al.id = $1
            """,
            audit_id,
        )

    if not log_row:
        raise HTTPException(status_code=404, detail="Audit log not found")

    # Sandbox rows never anchor on-chain — report a distinct "sandbox" status
    # rather than a forever-"pending_anchor".
    proof_metadata = _json_dict(log_row.get("metadata"))
    is_sandbox = bool(proof_metadata.get("sandbox") or proof_metadata.get("test_request"))

    # Unanchored: return pending (or sandbox) state explicitly rather than 404
    if not log_row["merkle_root_id"]:
        return PublicProofResponse(
            audit_id=str(log_row["id"]),
            status="sandbox" if is_sandbox else "pending_anchor",
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

    proof_status = proof_row.get("status")
    if proof_status in {"failed", "dead_letter"}:
        return PublicProofResponse(
            audit_id=str(log_row["id"]),
            status="failed",
            action_hash=log_row["action_hash"],
            proof=[],
            positions=[],
            merkle_root=proof_row["root_hash"],
            tx_hash=proof_row.get("transaction_hash"),
            chain_id=proof_row.get("chain_id") or 8453,
            block_number=proof_row.get("block_number"),
            anchored_at=None,
            submitter=proof_row.get("submitted_by"),
            receipt_fingerprint=None,
            policy_hash=log_row["policy_hash"],
            timestamp=canonical_wire_timestamp(log_row["timestamp"]) if log_row["timestamp"] else None,
        )

    if proof_status != "confirmed" or not proof_row.get("transaction_hash"):
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

        # Sandbox agents (self-serve public registrations, or any agent tagged
        # metadata.sandbox=true) are kept off the mainnet anchor path and out of
        # the production decision set: their audit rows carry test_request=true,
        # which the anchor worker already excludes (get_unanchored_logs). Real
        # signing, policy, trust, and receipts are unchanged.
        agent_meta = agent.metadata if isinstance(agent.metadata, dict) else {}
        is_sandbox = bool(agent_meta.get("sandbox"))

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
        effective_policy_hash = _effective_policy_hash(agent)
        audit_signature = _decode_signature_for_audit(request_data.signature)

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
                signature=audit_signature,
                signature_valid=False,
                request_ip=request.client.host if request.client else None,
                request_user_agent=request.headers.get("User-Agent"),
                response_time_ms=int((time.time() - start_time) * 1000),
                trust_score_at_time=agent.trust_score,
                chain_previous_hash=None,
                policy_hash=effective_policy_hash,
                metadata=_audit_metadata(
                    client_policy_hash=request_data.policy_hash,
                    key_fingerprint=agent.public_key_fingerprint,
                    sandbox=is_sandbox,
                ),
            )
            audit_id = await database.insert_audit_log(audit_entry, derive_chain_hash=True)

            await _dispatch_verdict_webhook(
                database=database,
                org_id=agent.org_id,
                event="verification.signature_invalid",
                agent_id=agent.id,
                audit_id=audit_id,
                action_type=request_data.action_type,
                verdict=verdict.value,
                verdict_reason=verdict_reason,
            )

            new_trust_score = TrustScorer.calculate_adjustment(
                current_score=agent.trust_score,
                event_type="signature_invalid",
            )
            await database.update_agent_after_verification(
                agent.id,
                new_trust_score,
                was_approved=False,
            )

            # Self-diagnosing 401: echo the action hash the server verified
            # against plus the canonical timestamp and sig_version it used.
            # These derive only from caller-supplied, non-secret inputs (they
            # do NOT help forge a signature, which needs the private key) but
            # let a legitimate integrator instantly diff their local hash and
            # find the canonicalization bug. ``detail`` is preserved as a
            # human string for back-compat. See docs/REQUEST_SIGNING.md.
            from api.observability import current_request_id

            try:
                diagnostic_ts = CryptoService.canonicalize_timestamp(request_data.timestamp)
            except Exception:
                diagnostic_ts = request_data.timestamp

            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": "signature_invalid",
                    "detail": verdict_reason,
                    "message": verdict_reason,
                    "expected_action_hash": action_hash,
                    "canonical_timestamp": diagnostic_ts,
                    "sig_version": request_data.sig_version,
                    "audit_id": str(audit_id) if audit_id else None,
                    "hint": (
                        "Sign bytes.fromhex(expected_action_hash) with the agent's "
                        "Ed25519 key. If your locally computed action hash differs "
                        "from expected_action_hash, your canonicalization differs — "
                        "see docs/REQUEST_SIGNING.md and POST /verify/debug (which "
                        "has no side effects)."
                    ),
                    "request_id": current_request_id(),
                },
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

        # Tier A: the agent's server-registered governing policy (or None).
        # The engine uses it to reject a mismatched policy hash or a downgraded
        # code/release action type. None => advisory (no block), so the feature
        # rolls out before every agent has registered.
        registered_policy = await database.get_active_agent_policy(agent.id)
        policy_binding_state = "registered" if registered_policy else "unregistered"

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
            registered_policy=registered_policy,
            client_policy_hash=request_data.policy_hash,
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
                signature=audit_signature,
                signature_valid=True,
                request_ip=request.client.host if request.client else None,
                request_user_agent=request.headers.get("User-Agent"),
                response_time_ms=int((time.time() - start_time) * 1000),
                trust_score_at_time=agent.trust_score,
                chain_previous_hash=None,
                policy_hash=effective_policy_hash,
                metadata=_audit_metadata(
                    client_policy_hash=request_data.policy_hash,
                    key_fingerprint=agent.public_key_fingerprint,
                    sandbox=is_sandbox,
                    extra={
                        "violation": (
                            policy_result.violation.value
                            if policy_result.violation
                            else None
                        ),
                        "policy_binding": policy_binding_state,
                    },
                ),
            )
            audit_id = await database.insert_audit_log(audit_entry, derive_chain_hash=True)

            await _dispatch_verdict_webhook(
                database=database,
                org_id=agent.org_id,
                event="verification.blocked" if verdict == ActionVerdict.BLOCKED else "verification.rate_limited",
                agent_id=agent.id,
                audit_id=audit_id,
                action_type=request_data.action_type,
                verdict=verdict.value,
                verdict_reason=verdict_reason,
            )

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
                    headers={"Retry-After": "60"},
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=verdict_reason,
                )

        # STEP 5b: Atomically reserve rate + spend BEFORE approving. The
        # snapshot checks in evaluate() fail fast, but this increment-and-test
        # is the authoritative gate: it closes the check-then-act race where N
        # concurrent requests all observe the same headroom and all pass. A
        # reservation that trips a limit is logged as a block/rate-limit and
        # rolls back, leaving no counter consumed.
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        reserve_amount = policy_engine._extract_amount(request_data.payload) or Decimal("0")
        try:
            _minute_count, new_daily_spend = await database.reserve_rate_and_spend(
                agent_id=agent.id,
                minute_start=minute_start,
                day_start=day_start,
                amount=reserve_amount,
                rate_limit_per_minute=agent.rate_limit_per_minute,
                daily_limit_usd=agent.daily_limit_usd,
            )
        except LimitReservationError as exc:
            reserve_verdict = (
                ActionVerdict.RATE_LIMITED if exc.kind == "rate" else ActionVerdict.BLOCKED
            )
            if exc.kind == "rate":
                reserve_reason = (
                    f"Rate limit of {agent.rate_limit_per_minute} requests/minute exceeded."
                )
            else:
                reserve_reason = (
                    f"Amount ${reserve_amount} would exceed daily limit "
                    f"${agent.daily_limit_usd}."
                )

            from api.observability import rate_limit_trips_total, verify_requests_total
            if exc.kind == "rate":
                rate_limit_trips_total.labels(window="tenant_minute").inc()
                verify_requests_total.labels(verdict="rate_limited").inc()
            else:
                verify_requests_total.labels(verdict="blocked").inc()

            logger.warning(
                "Reservation rejected for agent %s: %s limit (%s)",
                agent.id, exc.kind, exc.observed,
            )

            audit_entry = AuditLogEntry(
                agent_id=agent.id,
                action_type=request_data.action_type,
                action_hash=action_hash,
                payload=request_data.payload,
                verdict=reserve_verdict,
                verdict_reason=reserve_reason,
                signature=audit_signature,
                signature_valid=True,
                request_ip=request.client.host if request.client else None,
                request_user_agent=request.headers.get("User-Agent"),
                response_time_ms=int((time.time() - start_time) * 1000),
                trust_score_at_time=agent.trust_score,
                chain_previous_hash=None,
                policy_hash=effective_policy_hash,
                metadata=_audit_metadata(
                    client_policy_hash=request_data.policy_hash,
                    key_fingerprint=agent.public_key_fingerprint,
                    sandbox=is_sandbox,
                    extra={
                        "violation": (
                            "rate_limit_exceeded" if exc.kind == "rate"
                            else "daily_limit_exceeded"
                        )
                    },
                ),
            )
            audit_id = await database.insert_audit_log(audit_entry, derive_chain_hash=True)

            await _dispatch_verdict_webhook(
                database=database,
                org_id=agent.org_id,
                event=(
                    "verification.rate_limited" if exc.kind == "rate"
                    else "verification.blocked"
                ),
                agent_id=agent.id,
                audit_id=audit_id,
                action_type=request_data.action_type,
                verdict=reserve_verdict.value,
                verdict_reason=reserve_reason,
            )

            new_trust_score = TrustScorer.calculate_adjustment(
                current_score=agent.trust_score,
                event_type=(
                    "action_blocked_rate_limit" if exc.kind == "rate"
                    else "action_blocked_policy"
                ),
            )
            await database.update_agent_after_verification(
                agent.id, new_trust_score, was_approved=False
            )

            raise HTTPException(
                status_code=(
                    status.HTTP_429_TOO_MANY_REQUESTS if exc.kind == "rate"
                    else status.HTTP_403_FORBIDDEN
                ),
                detail=reserve_reason,
                headers={"Retry-After": "60"} if exc.kind == "rate" else None,
            )

        # Reservation succeeded — surface the authoritative post-reservation
        # daily spend in the limits echoed back to the caller.
        limits_remaining = {
            **(limits_remaining or {}),
            "daily_spent_usd": str(new_daily_spend),
            "daily_remaining_usd": str(agent.daily_limit_usd - new_daily_spend),
        }

        # STEP 6: Audit Log for approved action
        audit_entry = AuditLogEntry(
            agent_id=agent.id,
            action_type=request_data.action_type,
            action_hash=action_hash,
            payload=request_data.payload,
            verdict=verdict,
            verdict_reason=verdict_reason,
            signature=audit_signature,
            signature_valid=True,
            request_ip=request.client.host if request.client else None,
            request_user_agent=request.headers.get("User-Agent"),
            response_time_ms=int((time.time() - start_time) * 1000),
            trust_score_at_time=agent.trust_score,
            chain_previous_hash=None,
            policy_hash=effective_policy_hash,
            metadata=_audit_metadata(
                client_policy_hash=request_data.policy_hash,
                key_fingerprint=agent.public_key_fingerprint,
                sandbox=is_sandbox,
                extra={"policy_binding": policy_binding_state},
            ),
        )
        audit_id = await database.insert_audit_log(audit_entry, derive_chain_hash=True)

        await _dispatch_verdict_webhook(
            database=database,
            org_id=agent.org_id,
            event="verification.approved",
            agent_id=agent.id,
            audit_id=audit_id,
            action_type=request_data.action_type,
            verdict=verdict.value,
            verdict_reason=verdict_reason,
        )

        # STEP 7: Update trust score and counters for approved action. Rate and
        # spend counters were already advanced atomically in STEP 5b.
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
    "/verify/debug",
    response_model=VerifyDebugResponse,
    tags=["Verification"],
)
async def verify_debug(
    request_data: VerifyActionRequest,
    request: Request,
    database: Database = Depends(get_db),
    redis_conn: Optional[redis.Redis] = Depends(get_redis),
):
    """Dry-run signing diagnostics for ``/verify`` — NO side effects.

    Computes the action hash the server would verify against and, if the agent
    exists, whether the supplied signature is valid — WITHOUT writing an audit
    row, consuming the nonce, evaluating policy, adjusting the trust score, or
    emitting a signature-failure security alert.

    Use this while wiring up a new client: a wrong signature here costs nothing,
    whereas a wrong signature against ``/verify`` writes a forensic row, drops
    the agent's trust score by 20, and trips signature-failure monitoring. Once
    ``signature_valid`` is true, switch to ``POST /verify``. See
    docs/REQUEST_SIGNING.md.
    """
    await _check_public_rate_limit(
        request, redis_conn, key_prefix="verify_debug", max_per_hour=120
    )

    try:
        canonical_ts = CryptoService.canonicalize_timestamp(request_data.timestamp)
    except Exception:
        canonical_ts = request_data.timestamp

    try:
        expected_action_hash = CryptoService.compute_action_hash(
            agent_id=str(request_data.agent_id),
            action_type=request_data.action_type,
            payload=request_data.payload,
            nonce=request_data.nonce,
            timestamp=request_data.timestamp,
            sig_version=request_data.sig_version,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not compute action hash from the supplied fields: {exc}",
        )

    agent_found = False
    signature_valid: Optional[bool] = None
    fingerprint: Optional[str] = None
    try:
        agent = await database.get_agent_by_id(request_data.agent_id)
        agent_found = True
        fingerprint = agent.public_key_fingerprint
        try:
            signature_valid = CryptoService.verify_ed25519_signature(
                public_key=agent.public_key,
                message_hash=expected_action_hash,
                signature_b64=request_data.signature,
            )
        except SignatureVerificationError:
            signature_valid = False
    except AgentNotFoundError:
        agent_found = False

    return VerifyDebugResponse(
        agent_id=str(request_data.agent_id),
        agent_found=agent_found,
        action_type=request_data.action_type,
        sig_version=request_data.sig_version,
        canonical_timestamp=canonical_ts,
        expected_action_hash=expected_action_hash,
        signature_valid=signature_valid,
        public_key_fingerprint=fingerprint,
        note=(
            "Diagnostic only — no audit row, nonce, policy evaluation, or trust "
            "change. Sign bytes.fromhex(expected_action_hash) with the agent "
            "Ed25519 key; when signature_valid is true your signing is correct, "
            "so switch to POST /verify."
        ),
    )


@app.post(
    "/verify-token",
    response_model=VerifyTokenResponse,
    tags=["Verification"],
)
async def verify_token(
    request_data: VerifyTokenRequest,
    redis_conn: Optional[redis.Redis] = Depends(get_redis),
):
    """Verify an approval token issued by ``/verify``.

    This is the downstream enforcement primitive: a system about to execute a
    guarded action presents the approval token it received and proceeds only if
    this endpoint returns ``valid: true``. The token is an HMAC over
    ``SERVER_SECRET`` with an absolute expiry, so verification needs no DB
    lookup and cannot be forged without the server secret — which is why this
    surface is safe to expose unauthenticated, like the public verify routes.

    If the action parameters (``action_type``, ``payload``, ``nonce``,
    ``timestamp``) are supplied, the server recomputes the action hash and
    confirms the token authorizes *this* action and not merely *some* action —
    binding the approval to the work actually being executed.
    """
    claims = CryptoService.verify_approval_token(
        request_data.approval_token, SERVER_SECRETS
    )
    if claims is None:
        return VerifyTokenResponse(
            valid=False,
            reason="Token is invalid, tampered, or expired.",
        )

    token_agent_id = claims.get("agent_id")
    token_action_hash = claims.get("action_hash")
    verdict = claims.get("verdict")
    exp = claims.get("exp")
    expires_at = (
        datetime.fromtimestamp(exp, tz=timezone.utc) if isinstance(exp, (int, float)) else None
    )

    # Optional agent_id cross-check.
    if request_data.agent_id is not None and str(request_data.agent_id) != token_agent_id:
        return VerifyTokenResponse(
            valid=False,
            reason="Token agent_id does not match the supplied agent_id.",
            verdict=verdict,
            agent_id=token_agent_id,
            action_hash=token_action_hash,
            expires_at=expires_at,
        )

    # Optional action-binding check: recompute the action hash and confirm the
    # token authorizes exactly this action.
    action_hash_matches: Optional[bool] = None
    action_fields = (
        request_data.action_type,
        request_data.payload,
        request_data.nonce,
        request_data.timestamp,
    )
    if all(field is not None for field in action_fields):
        try:
            recomputed = CryptoService.compute_action_hash(
                agent_id=token_agent_id,
                action_type=request_data.action_type,
                payload=request_data.payload,
                nonce=request_data.nonce,
                timestamp=request_data.timestamp,
                sig_version=request_data.sig_version,
            )
        except Exception:
            return VerifyTokenResponse(
                valid=False,
                reason="Could not recompute action hash from supplied parameters.",
                verdict=verdict,
                agent_id=token_agent_id,
                action_hash=token_action_hash,
                expires_at=expires_at,
            )
        action_hash_matches = secrets.compare_digest(
            recomputed, token_action_hash or ""
        )
        if not action_hash_matches:
            return VerifyTokenResponse(
                valid=False,
                reason="Token does not authorize this action (action hash mismatch).",
                verdict=verdict,
                agent_id=token_agent_id,
                action_hash=token_action_hash,
                expires_at=expires_at,
                action_hash_matches=False,
            )

    # Single-use enforcement for the execution gate. Only consume after every
    # validity/binding check above has passed, so a rejected token is not burned.
    if request_data.consume:
        if redis_conn is None:
            return VerifyTokenResponse(
                valid=False,
                reason="Single-use enforcement unavailable (cache offline). Retry.",
                verdict=verdict,
                agent_id=token_agent_id,
                action_hash=token_action_hash,
                expires_at=expires_at,
                action_hash_matches=action_hash_matches,
            )
        ttl = 600
        if isinstance(exp, (int, float)):
            ttl = max(1, int(exp - datetime.now(timezone.utc).timestamp()))
        used_key = f"inntris:token_used:{token_action_hash}"
        try:
            first_use = await redis_conn.set(used_key, "1", ex=ttl, nx=True)
        except Exception:
            return VerifyTokenResponse(
                valid=False,
                reason="Single-use enforcement error. Retry.",
                verdict=verdict,
                agent_id=token_agent_id,
                action_hash=token_action_hash,
                expires_at=expires_at,
                action_hash_matches=action_hash_matches,
            )
        if not first_use:
            return VerifyTokenResponse(
                valid=False,
                reason="Token already used (single-use).",
                verdict=verdict,
                agent_id=token_agent_id,
                action_hash=token_action_hash,
                expires_at=expires_at,
                action_hash_matches=action_hash_matches,
            )

    return VerifyTokenResponse(
        valid=True,
        verdict=verdict,
        agent_id=token_agent_id,
        action_hash=token_action_hash,
        expires_at=expires_at,
        action_hash_matches=action_hash_matches,
    )


@app.post(
    "/admin/test-verify",
    response_model=VerifyActionResponse,
    tags=["Admin - Testing"],
)
async def test_verify_action(
    request_data: TestVerifyRequest,
    request: Request,
    auth: dict = Depends(require_api_scope("write")),
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
# PARTNER INGESTION ENDPOINTS (V1)
# =============================================================================
# Bearer-authenticated event ingestion for partner integrations that do not
# sign per-event with Ed25519. Each event becomes a single audit_logs row
# attributed to the org's synthetic ``events-v1-ingest`` agent and tagged
# ``source: "events_v1"`` so it is distinguishable from cryptographically
# signed /verify traffic. Ingested events flow through the same Merkle
# anchoring pipeline as /verify entries.

async def _verify_bearer_token(
    authorization: Optional[str],
    database: "Database",
) -> dict:
    """Validate ``Authorization: Bearer <token>`` against ``api_keys.key_hash``.

    The hashing scheme matches ``verify_api_key`` so a single issued key works
    interchangeably with the ``X-API-Key`` admin path and the bearer events
    path.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header (expected: Bearer <token>)",
        )
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty bearer token")

    key_hash = hashlib.sha256(token.encode()).digest()
    async with database.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT ak.id, ak.org_id, ak.scopes, ak.is_active, ak.expires_at
            FROM api_keys ak
            WHERE ak.key_hash = $1
            """,
            key_hash,
        )
    if not row:
        raise HTTPException(status_code=401, detail="Invalid bearer token")
    if not row["is_active"]:
        raise HTTPException(status_code=401, detail="Bearer token is inactive")
    if row["expires_at"] and row["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Bearer token has expired")
    scopes = _normalise_scopes(row.get("scopes") if hasattr(row, "get") else None)
    if "admin" not in scopes and "verify" not in scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bearer token requires 'verify' scope",
        )

    async with database.acquire() as conn:
        await conn.execute(
            "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
            row["id"],
        )

    return {"key_id": row["id"], "org_id": row["org_id"]}


async def _get_or_create_events_agent(
    database: "Database",
    org_id: UUID,
) -> UUID:
    """Return the events-v1 ingestion agent for ``org_id``, creating it if missing.

    The synthetic agent has a deterministic 32-byte ``public_key`` derived from
    ``org_id`` so repeated calls return the same agent. The key is never used
    for signature verification — the /v1/events path skips that check.
    """
    async with database.acquire() as conn:
        agent_id = await conn.fetchval(
            """
            SELECT id FROM agents
            WHERE org_id = $1 AND name = 'events-v1-ingest'
            LIMIT 1
            """,
            org_id,
        )
    if agent_id:
        return agent_id

    placeholder_pubkey = hashlib.sha256(
        f"events-v1-ingest:{org_id}".encode()
    ).digest()
    agent_id = await database.create_agent(
        org_id=org_id,
        name="events-v1-ingest",
        public_key=placeholder_pubkey,
        allowed_actions=["events_v1_ingest"],
        metadata={
            "source": "events_v1_bootstrap",
            "non_cryptographic": True,
        },
    )
    # Ingestion agents skip the Ed25519 /verify path that activates normal
    # agents, so they would stay at the DB default 'pending_verification' and
    # never count toward the admin dashboard's Active Agents tally. Mark them
    # active on creation.
    async with database.acquire() as conn:
        await conn.execute(
            "UPDATE agents SET status = 'active' WHERE id = $1",
            agent_id,
        )
    return agent_id


@app.post("/v1/events", status_code=201, tags=["Partner Ingestion"])
async def ingest_event_v1(
    body: dict,
    request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    database: Database = Depends(get_db),
):
    """Bearer-authenticated event ingestion for partner integrations.

    Accepts a free-form JSON event body and persists it as a single audit_logs
    row attributed to the org's synthetic events-v1 agent. Returns 201 with
    the assigned ``audit_id`` so partners can correlate their WAL entries with
    server-side records.
    """
    auth_info = await _verify_bearer_token(authorization, database)
    org_id = auth_info["org_id"]
    key_id = auth_info["key_id"]

    agent_id = await _get_or_create_events_agent(database, org_id)

    event_payload = body if isinstance(body, dict) else {"raw": body}
    action_type = (
        str(
            event_payload.get("event_type")
            or event_payload.get("type")
            or "events_v1"
        )[:100]
        or "events_v1"
    )

    canonical = json.dumps(event_payload, sort_keys=True, separators=(",", ":"))
    action_hash = hashlib.sha256(canonical.encode()).hexdigest()

    # Read the synthetic agent's real trust score so the audit row records a
    # truthful value instead of a fabricated 100. The audit insert trigger owns
    # activity counters and last_action_at.
    async with database.acquire() as conn:
        agent_trust_score = await conn.fetchval(
            """
            SELECT trust_score
            FROM agents
            WHERE id = $1
            """,
            agent_id,
        )
    if agent_trust_score is None:
        agent_trust_score = 0

    # These events are NOT cryptographically signed: they are partner-reported
    # facts ingested over a bearer-authenticated channel. Record them honestly.
    # signature_valid=False (there is no Ed25519 signature to validate) and an
    # explicit attestation_type so the forensic record can never be mistaken
    # for a verified, agent-signed action. The action_hash is a SHA-256 content
    # commitment over the event body, so anchoring it still proves the event was
    # recorded at batch time — it just does not assert agent authentication.
    audit_entry = AuditLogEntry(
        agent_id=agent_id,
        action_type=action_type,
        action_hash=action_hash,
        payload=event_payload,
        verdict=ActionVerdict.APPROVED,
        verdict_reason="events_v1 ingestion (unsigned partner attestation)",
        signature=b"V1_EVENTS_INGEST",
        signature_valid=False,
        request_ip=request.client.host if request.client else None,
        request_user_agent=request.headers.get("User-Agent"),
        response_time_ms=0,
        trust_score_at_time=agent_trust_score,
        chain_previous_hash=None,
        policy_hash=None,
        metadata={
            "source": "events_v1",
            "key_id": str(key_id),
            "attestation_type": "unsigned_ingestion",
            "non_cryptographic": True,
        },
    )
    audit_id = await database.insert_audit_log(audit_entry, derive_chain_hash=True)

    return {
        "status": "accepted",
        "audit_id": str(audit_id),
        "org_id": str(org_id),
        "agent_id": str(agent_id),
        "ingested_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


# =============================================================================
# ADMIN ENDPOINTS - AGENTS
# =============================================================================

@app.get("/admin/agents", tags=["Admin - Agents"], response_model=list[AgentSummary])
async def list_agents(
    auth: dict = Depends(require_api_scope("read")),
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
            "metadata": row["metadata"] if isinstance(row["metadata"], dict) else json.loads(row["metadata"]) if row["metadata"] else {},
            "created_at": row["created_at"].isoformat(),
            "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        })

    return agents

@app.get("/admin/agents/{agent_id}", tags=["Admin - Agents"], response_model=AgentDetail)
async def get_agent(
    agent_id: UUID,
    auth: dict = Depends(require_api_scope("read")),
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
            "updated_at": agent.updated_at.isoformat() if agent.updated_at else None,
            "key_version": agent.key_version,
            "key_rotated_at": agent.key_rotated_at.isoformat() if agent.key_rotated_at else None,
        }
    except AgentNotFoundError:
        raise HTTPException(status_code=404, detail="Agent not found")

@app.get("/admin/agents/{agent_id}/dashboard", tags=["Admin - Agents"])
async def get_agent_dashboard(
    agent_id: UUID,
    auth: dict = Depends(require_api_scope("read")),
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
    auth: dict = Depends(require_api_scope("write")),
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
    update_request: UpdateAgentRequest,
    auth: dict = Depends(require_api_scope("write")),
    database: Database = Depends(get_db),
):
    """Update agent configuration."""
    try:
        agent = await database.get_agent_by_id(agent_id)

        if agent.org_id != auth["org_id"]:
            raise HTTPException(status_code=403, detail="Access denied")

        updates = update_request.model_dump(exclude_unset=True)

        resulting_daily_limit = updates.get("daily_limit_usd", agent.daily_limit_usd)
        resulting_per_action_limit = updates.get(
            "per_action_limit_usd", agent.per_action_limit_usd
        )
        if resulting_per_action_limit > resulting_daily_limit:
            raise HTTPException(
                status_code=400,
                detail="per_action_limit_usd cannot exceed daily_limit_usd",
            )

        resulting_allowed = set(updates.get("allowed_actions", agent.allowed_actions))
        resulting_blocked = set(updates.get("blocked_actions", agent.blocked_actions))
        overlap = sorted(resulting_allowed & resulting_blocked)
        if overlap:
            raise HTTPException(
                status_code=400,
                detail=f"actions cannot be both allowed and blocked: {', '.join(overlap)}",
            )

        # Build update query dynamically
        allowed_fields = [
            "name", "daily_limit_usd", "per_action_limit_usd",
            "allowed_actions", "blocked_actions", "rate_limit_per_minute",
            "trust_score", "metadata"
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
            "metadata": row["metadata"] if isinstance(row["metadata"], dict) else json.loads(row["metadata"]) if row["metadata"] else {},
            "created_at": row["created_at"].isoformat(),
            "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        }
    except AgentNotFoundError:
        raise HTTPException(status_code=404, detail="Agent not found")


@app.get("/admin/agents/{agent_id}/policy", tags=["Admin - Agents"])
async def get_agent_policy(
    agent_id: UUID,
    auth: dict = Depends(require_api_scope("read")),
    database: Database = Depends(get_db),
):
    """Return the agent's active registered governing policy (AI PR Guard)."""
    try:
        agent = await database.get_agent_by_id(agent_id)
    except AgentNotFoundError:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.org_id != auth["org_id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    policy = await database.get_active_agent_policy(agent_id)
    if policy is None:
        return {"agent_id": str(agent_id), "registered": False}
    return {
        "agent_id": str(agent_id),
        "registered": True,
        "policy_hash": policy.policy_hash,
        "mapping": policy.mapping,
        "protected_branches": policy.protected_branches,
        "version": policy.version,
    }


@app.put("/admin/agents/{agent_id}/policy", tags=["Admin - Agents"])
async def register_agent_policy(
    agent_id: UUID,
    policy_request: RegisterPolicyRequest,
    auth: dict = Depends(require_api_scope("write")),
    database: Database = Depends(get_db),
):
    """Register (or re-register) the governing .inntris.yml for an agent.

    Stores the policy hash, mapping, and protected branches the server uses to
    bind /verify requests: a mismatched hash or a downgraded code/release
    action type is then BLOCKED server-side (Tier A).
    """
    try:
        agent = await database.get_agent_by_id(agent_id)
    except AgentNotFoundError:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.org_id != auth["org_id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    # Derive the canonical hash server-side from the enforced content so it
    # always matches what the action computes (canonicalPolicyHash).
    policy_hash = canonical_policy_hash(
        policy_request.mapping, policy_request.protected_branches
    )
    policy = await database.register_agent_policy(
        agent_id=agent_id,
        org_id=agent.org_id,
        policy_hash=policy_hash,
        mapping=policy_request.mapping,
        protected_branches=policy_request.protected_branches,
        registered_by=f"admin:{auth['org_id']}",
    )
    return {
        "agent_id": str(agent_id),
        "registered": True,
        "policy_hash": policy.policy_hash,
        "mapping": policy.mapping,
        "protected_branches": policy.protected_branches,
        "version": policy.version,
    }


@app.post("/admin/agents/{agent_id}/rotate-key", tags=["Admin - Agents"])
async def rotate_agent_key(
    agent_id: UUID,
    request_data: RotateAgentKeyRequest,
    auth: dict = Depends(require_api_scope("write")),
    database: Database = Depends(get_db),
):
    """Rotate an agent's Ed25519 signing key (leak response / hygiene).

    The old key stops verifying immediately; trust score, registered policy, and
    audit history are preserved. Submit only the new public key (the private
    seed is generated client-side and never sent here).
    """
    try:
        agent = await database.get_agent_by_id(agent_id)
    except AgentNotFoundError:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.org_id != auth["org_id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        new_public_key = base64.b64decode(request_data.public_key, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="public_key must be valid base64")
    if len(new_public_key) != 32:
        raise HTTPException(status_code=400, detail="Public key must be 32 bytes (Ed25519)")

    new_fingerprint = hashlib.sha256(new_public_key).hexdigest()
    if new_fingerprint == agent.public_key_fingerprint:
        raise HTTPException(
            status_code=400, detail="New key must differ from the current key"
        )

    result = await database.rotate_agent_key(
        agent_id=agent_id,
        org_id=agent.org_id,
        new_public_key=new_public_key,
        new_fingerprint=new_fingerprint,
        retired_by=f"admin:{auth['org_id']}",
        reason=request_data.reason,
    )
    return {
        "agent_id": str(agent_id),
        "key_version": result["key_version"],
        "public_key_fingerprint": result["public_key_fingerprint"],
        "key_rotated_at": (
            result["key_rotated_at"].isoformat() if result["key_rotated_at"] else None
        ),
    }


@app.patch("/admin/agents/{agent_id}/status", tags=["Admin - Agents"])
async def update_agent_status(
    agent_id: UUID,
    new_status: AgentStatus = Query(...),
    auth: dict = Depends(require_api_scope("write")),
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
    auth: dict = Depends(require_api_scope("read")),
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

    # Fetch logs.
    # LEFT JOIN merkle_proofs so each row carries its on-chain anchor state.
    # Without this join the response only had merkle_root_id (a FK), so the
    # admin dashboard/audit list — whose "On-chain" badge keys on
    # transaction_hash — showed every row as "Pending" even after the batch
    # was successfully anchored on Base. The per-row detail still has its own
    # /admin/audit/{id}/proof call; this just surfaces the same fact in lists.
    query = f"""
        SELECT al.id, al.agent_id, a.name as agent_name, al.timestamp,
               al.action_type, al.action_hash, al.payload, al.verdict,
               al.verdict_reason, al.signature_valid, al.request_ip,
               al.request_user_agent, al.response_time_ms, al.trust_score_at_time,
               al.merkle_root_id, al.merkle_leaf_index,
               mp.transaction_hash, mp.chain_id, mp.block_number
        FROM audit_logs al
        JOIN agents a ON al.agent_id = a.id
        LEFT JOIN merkle_proofs mp ON al.merkle_root_id = mp.id
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
            "request_ip": str(row["request_ip"]) if row["request_ip"] else None,
            "request_user_agent": row["request_user_agent"],
            "response_time_ms": row["response_time_ms"],
            "trust_score_at_time": row["trust_score_at_time"],
            "merkle_root_id": str(row["merkle_root_id"]) if row["merkle_root_id"] else None,
            "merkle_leaf_index": row["merkle_leaf_index"],
            # On-chain anchor info from the joined merkle_proofs row (NULL until
            # the batch is anchored). ``transaction_hash`` is the key the admin
            # UI reads; ``tx_hash`` is kept as a legacy alias for the same value.
            "transaction_hash": row.get("transaction_hash"),
            "tx_hash": row.get("transaction_hash"),
            "chain_id": row.get("chain_id"),
            "block_number": row.get("block_number"),
        })

    return {"logs": logs, "total": total, "limit": limit, "offset": offset}

@app.get("/admin/audit/{log_id}", tags=["Admin - Audit"], response_model=AuditLogDetail)
async def get_audit_log(
    log_id: UUID,
    auth: dict = Depends(require_api_scope("read")),
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

    policy_context = _policy_context_from_audit_row(row)

    return {
        "id": str(row["id"]),
        "agent_id": str(row["agent_id"]),
        "agent_name": row["agent_name"],
        "timestamp": row["timestamp"].isoformat(),
        "action_type": row["action_type"],
        "action_hash": row["action_hash"],
        "payload": policy_context["payload"],
        "verdict": row["verdict"],
        "verdict_reason": row["verdict_reason"],
        "signature_valid": row["signature_valid"],
        "request_ip": str(row["request_ip"]) if row["request_ip"] else None,
        "request_user_agent": row["request_user_agent"],
        "response_time_ms": row["response_time_ms"],
        "trust_score_at_time": row["trust_score_at_time"],
        "policy_rule_triggered": policy_context["policy_rule_triggered"],
        "risk_level": policy_context["risk_level"],
        "violations": policy_context["violations"],
        "merkle_root_id": str(row["merkle_root_id"]) if row["merkle_root_id"] else None,
        "merkle_leaf_index": row["merkle_leaf_index"],
        "policy_hash": row["policy_hash"],
        "metadata": policy_context["metadata"],
    }

@app.get("/admin/audit/{log_id}/proof", tags=["Admin - Audit"], response_model=AuditProof)
async def get_merkle_proof(
    log_id: UUID,
    auth: dict = Depends(require_api_scope("read")),
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
        "status": proof_row["status"],
        "leaf": log_row["action_hash"],
        "proof": [p["hash"] for p in proof_path],
        "positions": [p["position"] == 1 for p in proof_path],  # True = right, False = left
        "merkle_root": proof_row["root_hash"],
        "tx_hash": proof_row["transaction_hash"],
        "block_number": proof_row["block_number"],
        "anchored_at": proof_row["confirmed_at"].isoformat() if proof_row["confirmed_at"] else None,
        "chain_id": proof_row["chain_id"],
        "basescan_url": (
            f"https://basescan.org/tx/{proof_row['transaction_hash']}"
            if proof_row["transaction_hash"]
            else None
        ),
        "error_message": proof_row["error_message"],
    }

@app.get("/admin/audit/export", tags=["Admin - Audit"])
async def export_audit_logs(
    format: str = Query(..., pattern="^(csv|json)$"),
    start: Optional[str] = None,
    end: Optional[str] = None,
    agent_id: Optional[UUID] = None,
    auth: dict = Depends(require_api_scope("read")),
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
    auth: dict = Depends(require_api_scope("read")),
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
    auth: dict = Depends(require_api_scope("write")),
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
    auth: dict = Depends(require_api_scope("write")),
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
    auth: dict = Depends(require_api_scope("admin")),
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
    auth: dict = Depends(require_api_scope("admin")),
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
    key_prefix = _api_key_prefix(raw_key)

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
        "key_prefix": key_prefix,
    }

@app.delete("/admin/api-keys/{key_prefix}", tags=["Admin - API Keys"])
async def revoke_api_key(
    key_prefix: str,
    auth: dict = Depends(require_api_scope("admin")),
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
    auth: dict = Depends(require_api_scope("admin")),
    database: Database = Depends(get_db),
):
    """Rotate all API keys - creates new key and revokes old ones."""
    org_id = auth["org_id"]

    # Generate new key
    raw_key = f"inntris_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).digest()
    key_prefix = _api_key_prefix(raw_key)

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
        "key_prefix": key_prefix,
        "message": "All previous keys revoked. Use this new key.",
    }

# =============================================================================
# ADMIN ENDPOINTS - USAGE & ORGANIZATION
# =============================================================================

@app.get("/admin/usage", tags=["Admin - Usage"])
async def get_usage_metrics(
    start: str = Query(...),
    end: str = Query(...),
    auth: dict = Depends(require_api_scope("read")),
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
    auth: dict = Depends(require_api_scope("read")),
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


@app.patch("/admin/organization", tags=["Admin - Organization"])
async def update_organization(
    body: dict,
    auth: dict = Depends(require_api_scope("write")),
    database: Database = Depends(get_db),
):
    """
    Update mutable fields on the authenticated caller's organization.

    Accepted fields: ``name``, ``contact_email``, ``webhook_url``. Other fields
    are ignored. Pass ``webhook_url: null`` (or empty string) to clear an
    existing webhook.
    """
    org_id = auth["org_id"]

    updates: list[tuple[str, object]] = []
    if "name" in body:
        name = (body.get("name") or "").strip()
        if not name or len(name) > 255:
            raise HTTPException(status_code=400, detail="name must be 1–255 chars")
        updates.append(("name", name))
    if "contact_email" in body:
        email = (body.get("contact_email") or "").strip()
        if not email or len(email) > 255 or "@" not in email:
            raise HTTPException(status_code=400, detail="contact_email must be a valid email")
        updates.append(("contact_email", email))
    if "webhook_url" in body:
        raw = body.get("webhook_url")
        if raw is None or raw == "":
            updates.append(("webhook_url", None))
        else:
            url = str(raw).strip()
            if not url.startswith(("http://", "https://")) or len(url) > 2048:
                raise HTTPException(
                    status_code=400,
                    detail="webhook_url must be an http(s) URL under 2048 chars",
                )
            updates.append(("webhook_url", url))

    if not updates:
        raise HTTPException(status_code=400, detail="No updatable fields provided")

    set_clause = ", ".join(f"{col} = ${i+2}" for i, (col, _) in enumerate(updates))
    values = [v for _, v in updates]

    async with database.acquire() as conn:
        result = await conn.execute(
            f"UPDATE organizations SET {set_clause}, updated_at = NOW() WHERE id = $1",
            org_id, *values,
        )

    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Organization not found")

    return {"updated": [col for col, _ in updates]}


# =============================================================================
# OPERATOR ENDPOINTS - ORGANIZATION PROVISIONING
# =============================================================================
# Gated behind ``MASTER_ADMIN_KEY``. The first admin key for a brand-new org
# is returned plaintext exactly once — operators must capture it on the
# response. There is no way to retrieve it later.

@app.post("/admin/organizations", tags=["Operator"], status_code=201)
async def create_organization_endpoint(
    body: dict,
    database: Database = Depends(get_db),
    _: None = Depends(verify_master_admin_key),
):
    """
    Provision a new organization plus its first admin API key.

    Requires the ``X-Master-Key`` header to match the ``MASTER_ADMIN_KEY``
    environment variable. Intended for operator tooling — not for partner
    self-signup.

    Request body:
        name           (str, required) — organization display name
        contact_email  (str, required) — primary contact email
        billing_tier   (str, optional) — "free" | "starter" | "professional" | "enterprise", default "free"
        webhook_url    (str, optional) — http(s) URL for verdict callbacks

    Returns:
        organization_id, api_key (PLAINTEXT, shown once), key_id, key_prefix
    """
    name = (body.get("name") or "").strip()
    contact_email = (body.get("contact_email") or "").strip()
    billing_tier = body.get("billing_tier") or "free"
    webhook_url = body.get("webhook_url") or None

    if not name or len(name) > 255:
        raise HTTPException(status_code=400, detail="name is required (1–255 chars)")
    if not contact_email or "@" not in contact_email or len(contact_email) > 255:
        raise HTTPException(status_code=400, detail="contact_email must be a valid email")
    if billing_tier not in ("free", "starter", "professional", "enterprise"):
        raise HTTPException(
            status_code=400,
            detail="billing_tier must be one of: free, starter, professional, enterprise",
        )
    if webhook_url is not None:
        webhook_url = str(webhook_url).strip()
        if webhook_url and (
            not webhook_url.startswith(("http://", "https://")) or len(webhook_url) > 2048
        ):
            raise HTTPException(
                status_code=400,
                detail="webhook_url must be an http(s) URL under 2048 chars",
            )
        webhook_url = webhook_url or None

    raw_key = f"inntris_live_sk_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).digest()
    key_prefix = _api_key_prefix(raw_key)

    async with database.acquire() as conn:
        async with conn.transaction():
            org_id = await conn.fetchval(
                """
                INSERT INTO organizations (
                    name, contact_email, billing_tier, api_key_hash, webhook_url
                )
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id
                """,
                name, contact_email, billing_tier, key_hash, webhook_url,
            )
            key_id = await conn.fetchval(
                """
                INSERT INTO api_keys (
                    org_id, key_hash, key_prefix, name, scopes, is_active
                )
                VALUES ($1, $2, $3, $4, $5, true)
                RETURNING id
                """,
                org_id,
                key_hash,
                key_prefix,
                "Bootstrap Admin Key",
                ["admin", "read", "write", "verify"],
            )

    logger.info("Provisioned organization %s with bootstrap key %s", org_id, key_id)

    return {
        "organization_id": str(org_id),
        "key_id": str(key_id),
        "key_prefix": key_prefix,
        "api_key": raw_key,
        "message": "Save this api_key now — it will never be shown again.",
    }
