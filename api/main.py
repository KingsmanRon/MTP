import logging
import time
import json
import base64
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional, List
from uuid import UUID

import redis.asyncio as redis
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware

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

# Constants
REDIS_URL = "redis://redis:6379"  # Adjust based on Railway Redis variables if needed
DATABASE_URL = "postgresql://postgres:password@db:5432/inntris" # Adjust based on Railway
SERVER_SECRET = b"REPLACE_THIS_WITH_A_REAL_SECRET_IN_PROD"  # In prod, use os.getenv()

app = FastAPI(
    title="Inntris Core API",
    description="Forensic-grade AI Agent Verification & Audit System",
    version="1.0.0",
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, list specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Database Pool
db_pool: Optional[Database] = None

# Dependency: Get Database
async def get_db() -> Database:
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not initialized")
    return db_pool

# Dependency: Get Redis
async def get_redis() -> Optional[redis.Redis]:
    # In a real deployment, you'd manage the pool better
    # For this demo, we assume Redis might be optional or handled via env vars
    try:
        # Check for Railway Redis Variable
        import os
        url = os.getenv("REDIS_URL", REDIS_URL)
        return redis.from_url(url, decode_responses=True)
    except Exception:
        logger.warning("Redis connection failed or not configured")
        return None

@app.on_event("startup")
async def startup_event():
    global db_pool
    import os
    
    logger.info("Starting Inntris Core API v1.0.0 in production mode")
    
    # Connect to Database
    # Railway provides DATABASE_URL
    dsn = os.getenv("DATABASE_URL", DATABASE_URL)
    try:
        db_pool = await Database.create(dsn)
        logger.info("Database connection established")
    except Exception as e:
        logger.critical(f"Failed to connect to database: {e}")
        # We don't exit here to allow health checks to fail gracefully, 
        # but in strict mode, we might want to crash.

@app.on_event("shutdown")
async def shutdown_event():
    global db_pool
    if db_pool:
        await db_pool.close()
        logger.info("Database connection closed")

# =============================================================================
# ENDPOINTS
# =============================================================================

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check(database: Database = Depends(get_db)):
    """System health check."""
    db_healthy = await database.health_check()
    
    return HealthResponse(
        status="healthy" if db_healthy else "degraded",
        version="1.0.0",
        database="connected" if db_healthy else "disconnected",
        redis="unknown", # Simplified
        timestamp=datetime.now(timezone.utc),
    )

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
    Verify an agent action using strict forensic logging.
    """
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
        # CRITICAL: We pass the RAW timestamp string. We do NOT modify it.
        # This fixes the Attribute Error 'str' has no attribute 'isoformat'
        action_hash = CryptoService.compute_action_hash(
            agent_id=str(request_data.agent_id),
            action_type=request_data.action_type,
            payload=request_data.payload,
            nonce=request_data.nonce,
            timestamp=request_data.timestamp, # <--- Pass Raw String directly!
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
            
            # Raise 401
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=verdict_reason,
            )

        # STEP 3: Replay Check (Nonce)
        if redis_conn:
            nonce_key = f"inntris:nonce:{agent.id}:{request_data.nonce}"
            if not await redis_conn.set(nonce_key, "1", ex=600, nx=True):
                 # Replay detected
                 # (Log audit entry for replay here - omitted for brevity)
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
