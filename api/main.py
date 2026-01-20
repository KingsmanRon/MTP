"""
Machine Trust Protocol - Core Enforcer API

The "Central Bank" for AI Agent Verification.

This API provides:
- Identity verification via Ed25519 signatures
- Policy enforcement with configurable rules
- Real-time trust scoring
- Forensic-grade audit logging

Philosophy: "Fail Closed" - If verification fails, the action is blocked.
Philosophy: "Zero Trust" - Never trust the client; always verify the signature.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Optional
from uuid import UUID

import redis.asyncio as redis
from fastapi import FastAPI, HTTPException, Request, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api import __version__
from api.crypto import CryptoService, SignatureVerificationError
from api.database import Database, AgentNotFoundError, OrganizationNotFoundError
from api.models import (
    VerifyActionRequest,
    VerifyActionResponse,
    AgentPublicInfo,
    HealthResponse,
    ErrorResponse,
    AuditLogEntry,
    ActionVerdict,
    AgentStatus,
    RegisterAgentRequest,
    CreateOrganizationRequest,
)
from api.policy import PolicyEngine, TrustScorer

# =============================================================================
# CONFIGURATION
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Environment variables
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/mtp"
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
SERVER_SECRET = os.getenv("SERVER_SECRET", "change-me-in-production").encode("utf-8")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

# =============================================================================
# GLOBAL STATE
# =============================================================================

db: Optional[Database] = None
redis_client: Optional[redis.Redis] = None


# =============================================================================
# LIFECYCLE
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    global db, redis_client

    logger.info(f"Starting MTP Core API v{__version__} in {ENVIRONMENT} mode")

    # Initialize database
    try:
        db = await Database.create(DATABASE_URL)
        logger.info("Database connection established")
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        raise

    # Initialize Redis
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=False)
        await redis_client.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.warning(f"Redis connection failed (non-fatal): {e}")
        redis_client = None

    yield

    # Cleanup
    if db:
        await db.close()
    if redis_client:
        await redis_client.close()

    logger.info("MTP Core API shutdown complete")


# =============================================================================
# APPLICATION
# =============================================================================

app = FastAPI(
    title="MTP Core Enforcer API",
    description="The Central Bank for AI Agent Verification",
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs" if ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if ENVIRONMENT != "production" else None,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if ENVIRONMENT == "development" else os.getenv("ALLOWED_ORIGINS", "").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# =============================================================================
# DEPENDENCIES
# =============================================================================

async def get_db() -> Database:
    """Dependency to get database connection."""
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database not available",
        )
    return db


async def get_redis() -> Optional[redis.Redis]:
    """Dependency to get Redis connection."""
    return redis_client


async def verify_master_admin_key(
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
) -> bool:
    """
    Verify master admin key for platform administration.

    SECURITY: This key should ONLY be used for creating organizations.
    Set MASTER_ADMIN_KEY environment variable to a secure random string.
    """
    master_key = os.getenv("MASTER_ADMIN_KEY")

    if not master_key:
        logger.critical("MASTER_ADMIN_KEY not configured! Admin endpoints are unprotected!")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin authentication not configured",
        )

    if not secrets.compare_digest(x_admin_key, master_key):
        logger.warning(f"Invalid master admin key attempted from request")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials",
        )

    return True


async def verify_api_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    database: Database = Depends(get_db),
) -> UUID:
    """
    Verify API key and return the associated organization ID.

    SECURITY: API keys are hashed before comparison.
    """
    key_hash = CryptoService.hash_api_key(x_api_key)

    try:
        # Query for the API key
        async with database.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT ak.org_id, ak.scopes, ak.is_active, ak.expires_at
                FROM api_keys ak
                WHERE ak.key_hash = $1
                """,
                key_hash,
            )

        if row is None:
            logger.warning(f"Invalid API key attempted: {x_api_key[:8]}...")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )

        if not row["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key is deactivated",
            )

        if row["expires_at"] and row["expires_at"] < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired",
            )

        return row["org_id"]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying API key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error",
        )


# =============================================================================
# EXCEPTION HANDLERS
# =============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unexpected errors."""
    logger.exception(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="internal_error",
            message="An unexpected error occurred",
            request_id=request.headers.get("X-Request-ID"),
        ).model_dump(),
    )


# =============================================================================
# HEALTH ENDPOINTS
# =============================================================================

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check(
    database: Database = Depends(get_db),
    redis_conn: Optional[redis.Redis] = Depends(get_redis),
):
    """
    Health check endpoint for load balancers and monitoring.

    Returns the status of all dependencies.
    """
    db_healthy = await database.health_check()
    redis_healthy = False

    if redis_conn:
        try:
            await redis_conn.ping()
            redis_healthy = True
        except Exception:
            pass

    return HealthResponse(
        status="healthy" if db_healthy else "degraded",
        version=__version__,
        database="connected" if db_healthy else "disconnected",
        redis="connected" if redis_healthy else "disconnected",
        timestamp=datetime.now(timezone.utc),
    )


# =============================================================================
# VERIFICATION ENDPOINTS
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
    """
    Verify an agent action.

    This is the primary endpoint for action verification. The agent must:
    1. Provide a valid Ed25519 signature over the action hash
    2. Meet all policy requirements (limits, trust score, etc.)
    3. Use a fresh nonce (replay attacks are blocked)

    SECURITY: "Fail Closed" - Any verification failure blocks the action.
    """
    start_time = time.time()
    signature_valid = False
    verdict = ActionVerdict.BLOCKED
    verdict_reason: Optional[str] = None
    audit_id: Optional[UUID] = None

    try:
        # =================================================================
        # STEP 1: Fetch Agent Record
        # =================================================================
        try:
            agent = await database.get_agent_by_id(request_data.agent_id)
        except AgentNotFoundError:
            logger.warning(f"Unknown agent attempted action: {request_data.agent_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Agent {request_data.agent_id} not found",
            )

        # =================================================================
        # STEP 2: Verify Ed25519 Signature (CRITICAL)
        # =================================================================
        action_hash = CryptoService.compute_action_hash(
            agent_id=str(request_data.agent_id),
            action_type=request_data.action_type,
            payload=request_data.payload,
            nonce=request_data.nonce,
            timestamp=request_data.timestamp,
        )

        try:
            signature_valid = CryptoService.verify_ed25519_signature(
                public_key=agent.public_key,
                message_hash=action_hash,
                signature_b64=request_data.signature,
            )
        except SignatureVerificationError as e:
            logger.error(f"Signature verification error for agent {agent.id}: {e}")
            signature_valid = False

        if not signature_valid:
            # SECURITY ALERT: Invalid signature is a critical event
            verdict = ActionVerdict.SIGNATURE_INVALID
            verdict_reason = "Ed25519 signature verification failed. Potential attack detected."

            logger.warning(
                f"SECURITY ALERT: Invalid signature from agent {agent.id} "
                f"for action {request_data.action_type}"
            )

            # Create audit entry with failed signature
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
            )
            audit_id = await database.insert_audit_log(audit_entry)

            # Push security alert to Redis for immediate processing
            if redis_conn:
                await redis_conn.lpush(
                    "mtp:security_alerts",
                    json.dumps({
                        "type": "SIGNATURE_INVALID",
                        "agent_id": str(agent.id),
                        "audit_id": str(audit_id),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }),
                )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=verdict_reason,
            )

        # =================================================================
        # STEP 3: Check Nonce (Replay Attack Prevention)
        # =================================================================
        # CRITICAL: Fail Closed - Redis is REQUIRED for replay protection
        if not redis_conn:
            logger.critical(
                f"SECURITY: Redis unavailable, cannot verify nonce for agent {agent.id}. "
                "Rejecting request to prevent replay attacks (FAIL CLOSED)."
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Verification service temporarily unavailable. Nonce verification requires cache layer.",
            )

        nonce_key = f"mtp:nonce:{agent.id}:{request_data.nonce}"
        # SETNX with 10 minute expiry
        try:
            nonce_fresh = await redis_conn.set(nonce_key, "1", ex=600, nx=True)
        except Exception as e:
            logger.critical(f"SECURITY: Redis operation failed during nonce check: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Verification service temporarily unavailable. Nonce verification failed.",
            )

        if not nonce_fresh:
            logger.warning(f"Replay attack detected for agent {agent.id}, nonce: {request_data.nonce[:16]}...")
            # Log to database for forensics
            audit_entry = AuditLogEntry(
                agent_id=agent.id,
                action_type=request_data.action_type,
                action_hash=action_hash,
                payload=request_data.payload,
                verdict=ActionVerdict.BLOCKED,
                verdict_reason="REPLAY ATTACK: Nonce already used",
                signature=signature_bytes,
                signature_valid=True,  # Signature was valid, but nonce was reused
                request_ip=request.client.host if request.client else None,
                request_user_agent=request.headers.get("user-agent"),
                response_time_ms=None,
                trust_score_at_time=agent.trust_score,
                chain_previous_hash=None,
            )
            await database.insert_audit_log(audit_entry)

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Nonce already used. Replay attack detected.",
            )

        # =================================================================
        # STEP 4: Evaluate Policies
        # =================================================================
        # Get current limits
        daily_spend = await database.get_daily_spend(agent.id)

        # Get minute window for rate limiting
        now = datetime.now(timezone.utc)
        minute_start = now.replace(second=0, microsecond=0)
        minute_count, _ = await database.get_rate_limit_count(
            agent.id, "minute", minute_start
        )

        # Create policy engine with current state
        policy_engine = PolicyEngine(
            daily_spend=daily_spend,
            minute_request_count=minute_count,
        )

        # Evaluate all policies
        policy_result = policy_engine.evaluate(
            agent=agent,
            action_type=request_data.action_type,
            payload=request_data.payload,
            timestamp=request_data.timestamp,
        )

        if not policy_result.allowed:
            verdict = policy_result.verdict
            verdict_reason = policy_result.reason

            # Create audit entry for policy violation
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
            )
            audit_id = await database.insert_audit_log(audit_entry)

            status_code = (
                status.HTTP_429_TOO_MANY_REQUESTS
                if verdict == ActionVerdict.RATE_LIMITED
                else status.HTTP_403_FORBIDDEN
            )

            raise HTTPException(status_code=status_code, detail=verdict_reason)

        # =================================================================
        # STEP 5: Action Approved - Record and Return
        # =================================================================
        verdict = ActionVerdict.APPROVED
        verdict_reason = "All verification checks passed"

        # Create audit entry
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
        )
        audit_id = await database.insert_audit_log(audit_entry)

        # Update rate limit counters
        amount = Decimal(str(request_data.payload.get("amount", 0)))
        await database.increment_rate_limit(agent.id, "minute", minute_start, amount)
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        await database.increment_rate_limit(agent.id, "day", day_start, amount)

        # Push audit event to Redis queue for async processing
        if redis_conn:
            await redis_conn.lpush(
                "mtp:audit_events",
                json.dumps({
                    "audit_id": str(audit_id),
                    "agent_id": str(agent.id),
                    "action_type": request_data.action_type,
                    "action_hash": action_hash,
                    "timestamp": now.isoformat(),
                }),
            )

        # Generate approval token
        approval_token = CryptoService.generate_approval_token(
            agent_id=str(agent.id),
            action_hash=action_hash,
            verdict=verdict.value,
            server_secret=SERVER_SECRET,
        )

        return VerifyActionResponse(
            verdict=verdict,
            verdict_reason=verdict_reason,
            approval_token=approval_token,
            trust_score=agent.trust_score,
            audit_id=audit_id,
            timestamp=datetime.now(timezone.utc),
            limits_remaining=policy_result.limits_remaining,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during verification: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Verification failed due to internal error",
        )


# =============================================================================
# PUBLIC ENDPOINTS (For Trust Badge)
# =============================================================================

@app.get(
    "/public/agent/{agent_id}",
    response_model=AgentPublicInfo,
    tags=["Public"],
)
async def get_agent_public_info(
    agent_id: UUID,
    database: Database = Depends(get_db),
):
    """
    Get public information about an agent for the trust badge.

    This endpoint is public and does not require authentication.
    It returns only non-sensitive information suitable for display.
    """
    try:
        agent = await database.get_agent_by_id(agent_id)
        org = await database.get_organization_by_id(agent.org_id)

        return AgentPublicInfo(
            agent_id=agent.id,
            name=agent.name,
            organization_name=org.name,
            trust_score=agent.trust_score,
            status=agent.status,
            is_verified=agent.status == AgentStatus.ACTIVE,
            verified_since=agent.created_at if agent.status == AgentStatus.ACTIVE else None,
            total_actions=agent.total_actions_count,
            last_action_at=agent.last_action_at,
        )

    except AgentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )


# =============================================================================
# ADMIN ENDPOINTS (Protected)
# =============================================================================

@app.post(
    "/admin/organizations",
    tags=["Admin"],
    status_code=status.HTTP_201_CREATED,
)
async def create_organization(
    request_data: CreateOrganizationRequest,
    database: Database = Depends(get_db),
    _authenticated: bool = Depends(verify_master_admin_key),
):
    """
    Create a new organization.

    Returns the organization ID and API key (shown only once).

    SECURITY: Requires X-Admin-Key header with master admin credentials.
    """
    # Generate API key
    api_key, api_key_hash = CryptoService.generate_api_key()

    org_id = await database.create_organization(
        name=request_data.name,
        contact_email=request_data.contact_email,
        api_key_hash=api_key_hash,
        billing_tier=request_data.billing_tier.value,
        webhook_url=request_data.webhook_url,
    )

    # Store API key record
    async with database.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO api_keys (org_id, key_hash, key_prefix, name, scopes)
            VALUES ($1, $2, $3, $4, $5)
            """,
            org_id,
            api_key_hash,
            api_key[:8],
            "Primary API Key",
            ["read", "write", "verify"],
        )

    return {
        "organization_id": str(org_id),
        "api_key": api_key,  # Only shown once!
        "message": "Store this API key securely. It will not be shown again.",
    }


@app.post(
    "/admin/agents",
    tags=["Admin"],
    status_code=status.HTTP_201_CREATED,
)
async def register_agent(
    request_data: RegisterAgentRequest,
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Register a new agent.

    The agent must provide its Ed25519 public key for signature verification.
    """
    # Verify org_id matches
    if request_data.org_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot create agent for a different organization",
        )

    # Decode public key
    try:
        public_key = base64.b64decode(request_data.public_key)
        if len(public_key) != 32:
            raise ValueError("Invalid key length")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid public key format. Expected base64-encoded 32-byte Ed25519 key.",
        )

    agent_id = await database.create_agent(
        org_id=org_id,
        name=request_data.name,
        public_key=public_key,
        daily_limit_usd=request_data.daily_limit_usd,
        per_action_limit_usd=request_data.per_action_limit_usd,
        allowed_actions=request_data.allowed_actions,
        metadata=request_data.metadata,
    )

    # Activate the agent
    await database.update_agent_status(agent_id, AgentStatus.ACTIVE)

    return {
        "agent_id": str(agent_id),
        "public_key_fingerprint": CryptoService.compute_public_key_fingerprint(public_key),
        "status": "active",
    }


@app.patch(
    "/admin/agents/{agent_id}/status",
    tags=["Admin"],
)
async def update_agent_status(
    agent_id: UUID,
    new_status: AgentStatus,
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """Update an agent's status."""
    try:
        agent = await database.get_agent_by_id(agent_id)

        if agent.org_id != org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot modify agent from a different organization",
            )

        await database.update_agent_status(agent_id, new_status)

        return {"agent_id": str(agent_id), "status": new_status.value}

    except AgentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )


@app.post(
    "/admin/api-keys/rotate",
    tags=["Admin"],
)
async def rotate_api_key(
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Rotate API key for an organization.

    This generates a new API key and deactivates the old one.
    The new key is returned only once.

    CRITICAL: Store the new key immediately. The old key will be deactivated.
    """
    # Generate new API key
    new_api_key, new_api_key_hash = CryptoService.generate_api_key()

    async with database.acquire() as conn:
        # Deactivate all existing keys for this org
        await conn.execute(
            """
            UPDATE api_keys
            SET is_active = false, updated_at = NOW()
            WHERE org_id = $1 AND is_active = true
            """,
            org_id,
        )

        # Insert new API key
        await conn.execute(
            """
            INSERT INTO api_keys (org_id, key_hash, key_prefix, name, scopes)
            VALUES ($1, $2, $3, $4, $5)
            """,
            org_id,
            new_api_key_hash,
            new_api_key[:8],
            "Rotated API Key",
            ["read", "write", "verify"],
        )

    logger.warning(f"API key rotated for organization {org_id}")

    return {
        "api_key": new_api_key,
        "message": "API key rotated successfully. Store this key securely. It will not be shown again.",
        "warning": "Your previous API key has been deactivated.",
    }


@app.delete(
    "/admin/api-keys/{key_prefix}",
    tags=["Admin"],
)
async def revoke_api_key(
    key_prefix: str,
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Revoke a specific API key by its prefix.

    WARNING: This will immediately deactivate the key.
    Ensure you have another active key before revoking.
    """
    async with database.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE api_keys
            SET is_active = false, updated_at = NOW()
            WHERE org_id = $1 AND key_prefix = $2 AND is_active = true
            """,
            org_id,
            key_prefix,
        )

        if result == "UPDATE 0":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found or already revoked",
            )

    logger.warning(f"API key {key_prefix}... revoked for organization {org_id}")

    return {
        "message": f"API key {key_prefix}... has been revoked successfully.",
    }


# =============================================================================
# FRONTEND SUPPORT ENDPOINTS
# =============================================================================


@app.get(
    "/admin/agents",
    tags=["Admin"],
)
async def list_agents(
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    List all agents for the organization.
    """
    async with database.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, org_id, name, public_key_fingerprint, trust_score, status,
                   daily_limit_usd, per_action_limit_usd, allowed_actions, blocked_actions,
                   rate_limit_per_minute, last_action_at, total_actions_count,
                   total_blocked_count, metadata, created_at, updated_at
            FROM agents
            WHERE org_id = $1
            ORDER BY created_at DESC
            """,
            org_id,
        )

    return [
        {
            "id": str(row["id"]),
            "org_id": str(row["org_id"]),
            "name": row["name"],
            "public_key_fingerprint": row["public_key_fingerprint"],
            "trust_score": row["trust_score"],
            "status": row["status"],
            "daily_limit_usd": float(row["daily_limit_usd"]),
            "per_action_limit_usd": float(row["per_action_limit_usd"]),
            "allowed_actions": row["allowed_actions"],
            "blocked_actions": row["blocked_actions"],
            "rate_limit_per_minute": row["rate_limit_per_minute"],
            "last_action_at": row["last_action_at"].isoformat() if row["last_action_at"] else None,
            "total_actions_count": row["total_actions_count"],
            "total_blocked_count": row["total_blocked_count"],
            "metadata": row["metadata"],
            "created_at": row["created_at"].isoformat(),
            "updated_at": row["updated_at"].isoformat(),
        }
        for row in rows
    ]


@app.get(
    "/admin/agents/{agent_id}",
    tags=["Admin"],
)
async def get_agent(
    agent_id: UUID,
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Get a specific agent by ID.
    """
    try:
        agent = await database.get_agent_by_id(agent_id)

        if agent.org_id != org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot access agent from a different organization",
            )

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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )


@app.patch(
    "/admin/agents/{agent_id}",
    tags=["Admin"],
)
async def update_agent(
    agent_id: UUID,
    updates: dict[str, Any],
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Update agent configuration (limits, allowed_actions, etc.).
    """
    try:
        agent = await database.get_agent_by_id(agent_id)

        if agent.org_id != org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot modify agent from a different organization",
            )

        # Build update query dynamically
        allowed_fields = {
            "name", "daily_limit_usd", "per_action_limit_usd",
            "allowed_actions", "blocked_actions", "rate_limit_per_minute", "metadata"
        }

        filtered_updates = {k: v for k, v in updates.items() if k in allowed_fields}

        if not filtered_updates:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid fields to update",
            )

        set_clauses = [f"{key} = ${i+2}" for i, key in enumerate(filtered_updates.keys())]
        set_clauses.append("updated_at = NOW()")

        query = f"""
            UPDATE agents
            SET {', '.join(set_clauses)}
            WHERE id = $1
            RETURNING *
        """

        async with database.acquire() as conn:
            row = await conn.fetchrow(query, agent_id, *filtered_updates.values())

        return {
            "agent_id": str(agent_id),
            "updated_fields": list(filtered_updates.keys()),
            "message": "Agent updated successfully",
        }

    except AgentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )


@app.get(
    "/admin/alerts",
    tags=["Admin"],
)
async def list_alerts(
    status_filter: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    List security alerts for the organization.
    """
    query = """
        SELECT sa.*, a.name as agent_name
        FROM security_alerts sa
        JOIN agents a ON sa.agent_id = a.id
        WHERE a.org_id = $1
    """
    params: list[Any] = [org_id]
    param_count = 1

    if status_filter == "open":
        query += " AND sa.acknowledged = false AND sa.resolved = false"
    elif status_filter == "acknowledged":
        query += " AND sa.acknowledged = true AND sa.resolved = false"
    elif status_filter == "resolved":
        query += " AND sa.resolved = true"

    if severity:
        param_count += 1
        query += f" AND sa.severity = ${param_count}"
        params.append(severity)

    query += f" ORDER BY sa.created_at DESC LIMIT ${param_count + 1} OFFSET ${param_count + 2}"
    params.extend([limit, offset])

    async with database.acquire() as conn:
        rows = await conn.fetch(query, *params)

        # Get total count
        count_query = """
            SELECT COUNT(*) as total
            FROM security_alerts sa
            JOIN agents a ON sa.agent_id = a.id
            WHERE a.org_id = $1
        """
        count_row = await conn.fetchrow(count_query, org_id)

    return {
        "alerts": [
            {
                "id": str(row["id"]),
                "agent_id": str(row["agent_id"]),
                "agent_name": row["agent_name"],
                "severity": row["severity"],
                "alert_type": row["alert_type"],
                "title": row["title"],
                "description": row["description"],
                "evidence": row["evidence"],
                "acknowledged": row["acknowledged"],
                "acknowledged_by": row["acknowledged_by"],
                "acknowledged_at": row["acknowledged_at"].isoformat() if row["acknowledged_at"] else None,
                "resolved": row["resolved"],
                "resolved_at": row["resolved_at"].isoformat() if row["resolved_at"] else None,
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ],
        "total": count_row["total"],
    }


@app.post(
    "/admin/alerts/{alert_id}/acknowledge",
    tags=["Admin"],
)
async def acknowledge_alert(
    alert_id: UUID,
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Acknowledge a security alert.
    """
    async with database.acquire() as conn:
        # Verify alert belongs to org
        row = await conn.fetchrow(
            """
            SELECT sa.id
            FROM security_alerts sa
            JOIN agents a ON sa.agent_id = a.id
            WHERE sa.id = $1 AND a.org_id = $2
            """,
            alert_id,
            org_id,
        )

        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found",
            )

        await conn.execute(
            """
            UPDATE security_alerts
            SET acknowledged = true, acknowledged_at = NOW()
            WHERE id = $1
            """,
            alert_id,
        )

    return {"alert_id": str(alert_id), "acknowledged": True}


@app.post(
    "/admin/alerts/{alert_id}/resolve",
    tags=["Admin"],
)
async def resolve_alert(
    alert_id: UUID,
    resolution: dict[str, str],
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Resolve a security alert.
    """
    async with database.acquire() as conn:
        # Verify alert belongs to org
        row = await conn.fetchrow(
            """
            SELECT sa.id
            FROM security_alerts sa
            JOIN agents a ON sa.agent_id = a.id
            WHERE sa.id = $1 AND a.org_id = $2
            """,
            alert_id,
            org_id,
        )

        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found",
            )

        await conn.execute(
            """
            UPDATE security_alerts
            SET resolved = true, resolved_at = NOW(), resolution_notes = $2
            WHERE id = $1
            """,
            alert_id,
            resolution.get("resolution", ""),
        )

    return {"alert_id": str(alert_id), "resolved": True}


@app.get(
    "/admin/audit/search",
    tags=["Admin"],
)
async def search_audit_logs(
    agent_id: Optional[UUID] = None,
    action_type: Optional[str] = None,
    verdict: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Search audit logs with filters.
    """
    query = """
        SELECT al.*, a.name as agent_name
        FROM audit_logs al
        JOIN agents a ON al.agent_id = a.id
        WHERE a.org_id = $1
    """
    params: list[Any] = [org_id]
    param_count = 1

    if agent_id:
        param_count += 1
        query += f" AND al.agent_id = ${param_count}"
        params.append(agent_id)

    if action_type:
        param_count += 1
        query += f" AND al.action_type = ${param_count}"
        params.append(action_type)

    if verdict:
        param_count += 1
        query += f" AND al.verdict = ${param_count}"
        params.append(verdict)

    if start:
        param_count += 1
        query += f" AND al.timestamp >= ${param_count}"
        params.append(start)

    if end:
        param_count += 1
        query += f" AND al.timestamp <= ${param_count}"
        params.append(end)

    query += f" ORDER BY al.timestamp DESC LIMIT ${param_count + 1} OFFSET ${param_count + 2}"
    params.extend([limit, offset])

    async with database.acquire() as conn:
        rows = await conn.fetch(query, *params)

        # Get total count
        count_query = """
            SELECT COUNT(*) as total
            FROM audit_logs al
            JOIN agents a ON al.agent_id = a.id
            WHERE a.org_id = $1
        """
        count_row = await conn.fetchrow(count_query, org_id)

    return {
        "logs": [
            {
                "id": str(row["id"]),
                "agent_id": str(row["agent_id"]),
                "agent_name": row["agent_name"],
                "timestamp": row["timestamp"].isoformat(),
                "action_type": row["action_type"],
                "action_hash": row["action_hash"],
                "payload": row["payload"],
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
            for row in rows
        ],
        "total": count_row["total"],
    }


@app.get(
    "/admin/audit/{log_id}",
    tags=["Admin"],
)
async def get_audit_log(
    log_id: UUID,
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Get a specific audit log by ID.
    """
    async with database.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT al.*, a.name as agent_name
            FROM audit_logs al
            JOIN agents a ON al.agent_id = a.id
            WHERE al.id = $1 AND a.org_id = $2
            """,
            log_id,
            org_id,
        )

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found",
        )

    return {
        "id": str(row["id"]),
        "agent_id": str(row["agent_id"]),
        "agent_name": row["agent_name"],
        "timestamp": row["timestamp"].isoformat(),
        "action_type": row["action_type"],
        "action_hash": row["action_hash"],
        "payload": row["payload"],
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


@app.get(
    "/admin/audit/{log_id}/proof",
    tags=["Admin"],
)
async def get_merkle_proof(
    log_id: UUID,
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Get Merkle proof for an audit log for on-chain verification.
    """
    async with database.acquire() as conn:
        # Get the audit log and its merkle info
        row = await conn.fetchrow(
            """
            SELECT al.*, mp.merkle_root, mp.tx_hash, mp.block_number, mp.anchored_at
            FROM audit_logs al
            JOIN agents a ON al.agent_id = a.id
            LEFT JOIN merkle_proofs mp ON al.merkle_root_id = mp.id
            WHERE al.id = $1 AND a.org_id = $2
            """,
            log_id,
            org_id,
        )

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found",
        )

    if not row["merkle_root_id"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log has not been anchored to blockchain yet",
        )

    # In production, compute the actual Merkle proof from stored data
    # For now, return the stored proof information
    return {
        "leaf": row["action_hash"],
        "proof": [],  # Would be computed from stored Merkle tree
        "positions": [],
        "merkle_root": row["merkle_root"],
        "tx_hash": row["tx_hash"],
        "block_number": row["block_number"],
        "anchored_at": row["anchored_at"].isoformat() if row["anchored_at"] else None,
    }


@app.get(
    "/admin/usage",
    tags=["Admin"],
)
async def get_usage_metrics(
    start: str,
    end: str,
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Get usage metrics for billing and monitoring.
    """
    async with database.acquire() as conn:
        # Overall metrics
        metrics_row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) as total_verifications,
                COUNT(*) FILTER (WHERE al.verdict = 'approved') as approved_count,
                COUNT(*) FILTER (WHERE al.verdict = 'blocked') as blocked_count,
                COALESCE(SUM((al.payload->>'amount')::numeric) FILTER (WHERE al.verdict = 'approved'), 0) as total_spend_usd,
                COUNT(DISTINCT al.agent_id) as active_agents
            FROM audit_logs al
            JOIN agents a ON al.agent_id = a.id
            WHERE a.org_id = $1 AND al.timestamp >= $2 AND al.timestamp <= $3
            """,
            org_id,
            start,
            end,
        )

        # Daily breakdown
        daily_rows = await conn.fetch(
            """
            SELECT
                DATE(al.timestamp) as date,
                COUNT(*) as verifications,
                COUNT(*) FILTER (WHERE al.verdict = 'approved') as approved,
                COUNT(*) FILTER (WHERE al.verdict = 'blocked') as blocked,
                COALESCE(SUM((al.payload->>'amount')::numeric) FILTER (WHERE al.verdict = 'approved'), 0) as spend_usd
            FROM audit_logs al
            JOIN agents a ON al.agent_id = a.id
            WHERE a.org_id = $1 AND al.timestamp >= $2 AND al.timestamp <= $3
            GROUP BY DATE(al.timestamp)
            ORDER BY DATE(al.timestamp)
            """,
            org_id,
            start,
            end,
        )

    return {
        "total_verifications": metrics_row["total_verifications"],
        "approved_count": metrics_row["approved_count"],
        "blocked_count": metrics_row["blocked_count"],
        "total_spend_usd": float(metrics_row["total_spend_usd"]),
        "active_agents": metrics_row["active_agents"],
        "period_start": start,
        "period_end": end,
        "daily_breakdown": [
            {
                "date": row["date"].isoformat(),
                "verifications": row["verifications"],
                "approved": row["approved"],
                "blocked": row["blocked"],
                "spend_usd": float(row["spend_usd"]),
            }
            for row in daily_rows
        ],
    }


@app.get(
    "/admin/organization",
    tags=["Admin"],
)
async def get_organization(
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    Get organization information.
    """
    try:
        org = await database.get_organization_by_id(org_id)

        return {
            "id": str(org.id),
            "name": org.name,
            "billing_tier": org.billing_tier.value,
            "contact_email": org.contact_email,
            "webhook_url": org.webhook_url,
            "daily_limit_usd": float(org.daily_limit_usd),
            "monthly_limit_usd": float(org.monthly_limit_usd),
            "metadata": org.metadata,
            "created_at": org.created_at.isoformat(),
            "updated_at": org.updated_at.isoformat(),
        }

    except OrganizationNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )


@app.get(
    "/admin/api-keys",
    tags=["Admin"],
)
async def list_api_keys(
    org_id: UUID = Depends(verify_api_key),
    database: Database = Depends(get_db),
):
    """
    List all API keys for the organization.
    """
    async with database.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, org_id, key_prefix, name, scopes, is_active, expires_at,
                   last_used_at, created_at
            FROM api_keys
            WHERE org_id = $1
            ORDER BY created_at DESC
            """,
            org_id,
        )

    return [
        {
            "id": str(row["id"]),
            "org_id": str(row["org_id"]),
            "key_prefix": row["key_prefix"],
            "name": row["name"],
            "scopes": row["scopes"],
            "is_active": row["is_active"],
            "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
            "last_used_at": row["last_used_at"].isoformat() if row["last_used_at"] else None,
            "created_at": row["created_at"].isoformat(),
        }
        for row in rows
    ]


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=ENVIRONMENT == "development",
        log_level="info",
    )
