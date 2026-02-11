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
import hmac
import logging
import os
import secrets
import time
import json
import base64
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Optional, List
from uuid import UUID

import redis.asyncio as redis
from fastapi import FastAPI, Depends, HTTPException, Request, status, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
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
    RegisterAgentRequest,
    CreateOrganizationRequest,
    AgentPublicInfo,
    HealthResponse,
    ErrorResponse,
    ActionVerdict,
    AuditLogEntry,
    AgentStatus,
    AlertSeverity,
)
from api.crypto import (
    CryptoService,
    SignatureVerificationError,
    InvalidPublicKeyError,
)

# Configure logging
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

app = FastAPI(
    title="Inntris Core API",
    description="Forensic-grade AI Agent Verification & Audit System",
    version="1.0.0",
)

# CORS Configuration
origins = ["*"] if ENVIRONMENT == "development" else [
    origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "").split(",") if origin.strip()
]
if ENVIRONMENT != "development" and os.getenv("ALLOWED_ORIGINS", "").strip() == "*":
    origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False if origins == ["*"] else True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Global Database Pool
db_pool: Optional[Database] = None

# =============================================================================
# DEPENDENCIES
# =============================================================================

async def get_db() -> Database:
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not initialized")
    return db_pool

async def get_redis() -> Optional[redis.Redis]:
    try:
        url = os.getenv("REDIS_URL", REDIS_URL)
        return redis.from_url(url, decode_responses=True)
    except Exception:
        logger.warning("Redis connection failed or not configured")
        return None

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

# =============================================================================
# STARTUP / SHUTDOWN
# =============================================================================

@app.on_event("startup")
async def startup_event():
    global db_pool
    logger.info("Starting Inntris Core API v1.0.0")

    dsn = os.getenv("DATABASE_URL", DATABASE_URL)
    try:
        db_pool = await Database.create(dsn)
        logger.info("Database connection established")
    except Exception as e:
        logger.critical(f"Failed to connect to database: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    global db_pool
    if db_pool:
        await db_pool.close()
        logger.info("Database connection closed")

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
            logger.error(f"Signature error for agent {agent.id}: {e}")
            signature_valid = False

        if not signature_valid:
            verdict = ActionVerdict.SIGNATURE_INVALID
            verdict_reason = "Ed25519 signature verification failed. Potential attack detected."

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

        # STEP 3: Replay Check (Nonce)
        if redis_conn:
            nonce_key = f"inntris:nonce:{agent.id}:{request_data.nonce}"
            if not await redis_conn.set(nonce_key, "1", ex=600, nx=True):
                raise HTTPException(status_code=401, detail="Nonce already used")

        # STEP 4: Policy Check (Simplified for success path)
        verdict = ActionVerdict.APPROVED
        verdict_reason = "Verification passed"

        # STEP 5: Audit Log & Return
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
            metadata={},
        )
        audit_id = await database.insert_audit_log(audit_entry)

        # Generate Approval Token
        token = CryptoService.generate_approval_token(
            agent_id=str(agent.id),
            action_hash=action_hash,
            verdict=verdict.value,
            server_secret=SERVER_SECRET
        )

        return VerifyActionResponse(
            verdict=verdict,
            verdict_reason=verdict_reason,
            approval_token=token,
            trust_score=agent.trust_score,
            audit_id=audit_id,
            timestamp=datetime.now(timezone.utc),
            limits_remaining={}
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# =============================================================================
# ADMIN ENDPOINTS - AGENTS
# =============================================================================

@app.get("/admin/agents", tags=["Admin - Agents"])
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

@app.get("/admin/agents/{agent_id}", tags=["Admin - Agents"])
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
    except Exception as e:
        logger.error(f"Failed to register agent: {e}")
        raise HTTPException(status_code=400, detail=str(e))

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

@app.get("/admin/audit/search", tags=["Admin - Audit"])
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

    return {"logs": logs, "total": total}

@app.get("/admin/audit/{log_id}", tags=["Admin - Audit"])
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

@app.get("/admin/audit/{log_id}/proof", tags=["Admin - Audit"])
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
    format: str = Query(..., regex="^(csv|json)$"),
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
    status: Optional[str] = Query(None, regex="^(open|acknowledged|resolved)$"),
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
            SET resolved = true, resolved_at = NOW(), resolution_notes = $3
            WHERE id = $1 AND org_id = $2
            """,
            alert_id, org_id, resolution,
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

        # Daily breakdown
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

    daily_breakdown = []
    for row in daily:
        daily_breakdown.append({
            "date": row["date"].isoformat(),
            "verifications": row["verifications"],
            "approved": row["approved"],
            "blocked": row["blocked"],
            "spend_usd": 0.0,  # Would come from rate_limit_windows
        })

    return {
        "total_verifications": totals["total"] or 0,
        "approved_count": totals["approved"] or 0,
        "blocked_count": totals["blocked"] or 0,
        "total_spend_usd": 0.0,
        "active_agents": active_agents or 0,
        "period_start": start,
        "period_end": end,
        "daily_breakdown": daily_breakdown,
    }

@app.get("/admin/organization", tags=["Admin - Organization"])
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
