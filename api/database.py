"""
Database connection and operations for the Inntris Core API.

Uses asyncpg for high-performance async PostgreSQL operations.
"""

import hashlib
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, AsyncGenerator, Optional
from uuid import UUID

import asyncpg
from asyncpg import Pool, Connection

from api.models import (
    AgentRecord,
    AgentStatus,
    AuditLogEntry,
    ActionVerdict,
    OrganizationRecord,
)

logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Base exception for database operations."""
    pass


class AgentNotFoundError(DatabaseError):
    """Raised when an agent is not found."""
    pass


class OrganizationNotFoundError(DatabaseError):
    """Raised when an organization is not found."""
    pass


class Database:
    """
    Async database interface for Inntris operations.

    This class provides all database operations with connection pooling
    and proper error handling for forensic-grade reliability.
    """

    def __init__(self, pool: Pool):
        self._pool = pool

    @classmethod
    async def create(
        cls,
        dsn: str,
        min_size: int = 5,
        max_size: int = 20,
    ) -> "Database":
        """Create a new database instance with a connection pool."""
        pool = await asyncpg.create_pool(
            dsn,
            min_size=min_size,
            max_size=max_size,
            command_timeout=30,
            statement_cache_size=100,
        )
        if pool is None:
            raise DatabaseError("Failed to create database pool")
        logger.info(f"Database pool created with {min_size}-{max_size} connections")
        return cls(pool)

    async def close(self) -> None:
        """Close the database connection pool."""
        await self._pool.close()
        logger.info("Database pool closed")

    @asynccontextmanager
    async def acquire(self) -> AsyncGenerator[Connection, None]:
        """Acquire a connection from the pool."""
        async with self._pool.acquire() as conn:
            yield conn

    async def health_check(self) -> bool:
        """Check database connectivity."""
        try:
            async with self.acquire() as conn:
                result = await conn.fetchval("SELECT 1")
                return result == 1
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

    # =========================================================================
    # AGENT OPERATIONS
    # =========================================================================

    async def get_agent_by_id(self, agent_id: UUID) -> AgentRecord:
        """
        Fetch an agent by ID.

        Raises:
            AgentNotFoundError: If the agent does not exist.
        """
        query = """
            SELECT
                id, org_id, name, public_key, public_key_fingerprint,
                trust_score, status, daily_limit_usd, per_action_limit_usd,
                allowed_actions, blocked_actions, rate_limit_per_minute,
                last_action_at, total_actions_count, total_blocked_count,
                metadata, created_at, updated_at
            FROM agents
            WHERE id = $1
        """
        async with self.acquire() as conn:
            row = await conn.fetchrow(query, agent_id)

        if row is None:
            raise AgentNotFoundError(f"Agent {agent_id} not found")

        return AgentRecord(
            id=row["id"],
            org_id=row["org_id"],
            name=row["name"],
            public_key=bytes(row["public_key"]),
            public_key_fingerprint=row["public_key_fingerprint"],
            trust_score=row["trust_score"],
            status=AgentStatus(row["status"]),
            daily_limit_usd=row["daily_limit_usd"],
            per_action_limit_usd=row["per_action_limit_usd"],
            allowed_actions=list(row["allowed_actions"]),
            blocked_actions=list(row["blocked_actions"]),
            rate_limit_per_minute=row["rate_limit_per_minute"],
            last_action_at=row["last_action_at"],
            total_actions_count=row["total_actions_count"],
            total_blocked_count=row["total_blocked_count"],
            metadata=dict(row["metadata"]) if row["metadata"] else {},
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    async def get_agent_by_fingerprint(self, fingerprint: str) -> AgentRecord:
        """Fetch an agent by public key fingerprint."""
        query = """
            SELECT
                id, org_id, name, public_key, public_key_fingerprint,
                trust_score, status, daily_limit_usd, per_action_limit_usd,
                allowed_actions, blocked_actions, rate_limit_per_minute,
                last_action_at, total_actions_count, total_blocked_count,
                metadata, created_at, updated_at
            FROM agents
            WHERE public_key_fingerprint = $1
        """
        async with self.acquire() as conn:
            row = await conn.fetchrow(query, fingerprint)

        if row is None:
            raise AgentNotFoundError(f"Agent with fingerprint {fingerprint} not found")

        return AgentRecord(
            id=row["id"],
            org_id=row["org_id"],
            name=row["name"],
            public_key=bytes(row["public_key"]),
            public_key_fingerprint=row["public_key_fingerprint"],
            trust_score=row["trust_score"],
            status=AgentStatus(row["status"]),
            daily_limit_usd=row["daily_limit_usd"],
            per_action_limit_usd=row["per_action_limit_usd"],
            allowed_actions=list(row["allowed_actions"]),
            blocked_actions=list(row["blocked_actions"]),
            rate_limit_per_minute=row["rate_limit_per_minute"],
            last_action_at=row["last_action_at"],
            total_actions_count=row["total_actions_count"],
            total_blocked_count=row["total_blocked_count"],
            metadata=dict(row["metadata"]) if row["metadata"] else {},
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    async def create_agent(
        self,
        org_id: UUID,
        name: str,
        public_key: bytes,
        daily_limit_usd: Decimal = Decimal("100.00"),
        per_action_limit_usd: Decimal = Decimal("50.00"),
        allowed_actions: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> UUID:
        """
        Register a new agent.

        Returns:
            The UUID of the newly created agent.
        """
        if len(public_key) != 32:
            raise ValueError("Public key must be exactly 32 bytes (Ed25519)")

        fingerprint = hashlib.sha256(public_key).hexdigest()
        allowed = allowed_actions or ["financial_transaction", "email_send", "api_call"]
        meta = metadata or {}

        query = """
            INSERT INTO agents (
                org_id, name, public_key, public_key_fingerprint,
                daily_limit_usd, per_action_limit_usd, allowed_actions, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
        """
        async with self.acquire() as conn:
            agent_id = await conn.fetchval(
                query,
                org_id,
                name,
                public_key,
                fingerprint,
                daily_limit_usd,
                per_action_limit_usd,
                allowed,
                json.dumps(meta),
            )

        logger.info(f"Created agent {agent_id} for org {org_id}")
        return agent_id

    async def update_agent_status(
        self,
        agent_id: UUID,
        status: AgentStatus,
    ) -> None:
        """Update an agent's status."""
        query = """
            UPDATE agents
            SET status = $2
            WHERE id = $1
        """
        async with self.acquire() as conn:
            result = await conn.execute(query, agent_id, status.value)

        if result == "UPDATE 0":
            raise AgentNotFoundError(f"Agent {agent_id} not found")

        logger.info(f"Updated agent {agent_id} status to {status.value}")

    async def update_agent_trust_score(
        self,
        agent_id: UUID,
        trust_score: int,
    ) -> None:
        """Update an agent's trust score."""
        if not 0 <= trust_score <= 100:
            raise ValueError("Trust score must be between 0 and 100")

        query = """
            UPDATE agents
            SET trust_score = $2
            WHERE id = $1
        """
        async with self.acquire() as conn:
            result = await conn.execute(query, agent_id, trust_score)

        if result == "UPDATE 0":
            raise AgentNotFoundError(f"Agent {agent_id} not found")

        logger.info(f"Updated agent {agent_id} trust score to {trust_score}")

    # =========================================================================
    # ORGANIZATION OPERATIONS
    # =========================================================================

    async def get_organization_by_id(self, org_id: UUID) -> OrganizationRecord:
        """Fetch an organization by ID."""
        query = """
            SELECT
                id, name, billing_tier, contact_email, webhook_url,
                daily_limit_usd, monthly_limit_usd, metadata,
                created_at, updated_at
            FROM organizations
            WHERE id = $1
        """
        async with self.acquire() as conn:
            row = await conn.fetchrow(query, org_id)

        if row is None:
            raise OrganizationNotFoundError(f"Organization {org_id} not found")

        return OrganizationRecord(
            id=row["id"],
            name=row["name"],
            billing_tier=row["billing_tier"],
            contact_email=row["contact_email"],
            webhook_url=row["webhook_url"],
            daily_limit_usd=row["daily_limit_usd"],
            monthly_limit_usd=row["monthly_limit_usd"],
            metadata=dict(row["metadata"]) if row["metadata"] else {},
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    async def create_organization(
        self,
        name: str,
        contact_email: str,
        api_key_hash: bytes,
        billing_tier: str = "free",
        webhook_url: Optional[str] = None,
    ) -> UUID:
        """Create a new organization."""
        query = """
            INSERT INTO organizations (
                name, contact_email, api_key_hash, billing_tier, webhook_url
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
        """
        async with self.acquire() as conn:
            org_id = await conn.fetchval(
                query,
                name,
                contact_email,
                api_key_hash,
                billing_tier,
                webhook_url,
            )

        logger.info(f"Created organization {org_id}")
        return org_id

    # =========================================================================
    # AUDIT LOG OPERATIONS
    # =========================================================================

    async def insert_audit_log(self, entry: AuditLogEntry) -> UUID:
        """
        Insert a new audit log entry.

        This operation is append-only. The database triggers will prevent
        any modification or deletion.

        Returns:
            The UUID of the created audit log entry.
        """
        query = """
            INSERT INTO audit_logs (
                agent_id, action_type, action_hash, payload, verdict,
                verdict_reason, signature, signature_valid, request_ip,
                request_user_agent, response_time_ms, trust_score_at_time,
                chain_previous_hash, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING id
        """
        async with self.acquire() as conn:
            log_id = await conn.fetchval(
                query,
                entry.agent_id,
                entry.action_type,
                entry.action_hash,
                json.dumps(entry.payload),
                entry.verdict.value,
                entry.verdict_reason,
                entry.signature,
                entry.signature_valid,
                entry.request_ip,
                entry.request_user_agent,
                entry.response_time_ms,
                entry.trust_score_at_time,
                entry.chain_previous_hash,
                json.dumps(entry.metadata),
            )

        return log_id

    async def get_last_audit_hash(self, agent_id: UUID) -> Optional[str]:
        """Get the hash of the last audit log entry for chain linking."""
        query = """
            SELECT action_hash
            FROM audit_logs
            WHERE agent_id = $1
            ORDER BY timestamp DESC
            LIMIT 1
        """
        async with self.acquire() as conn:
            return await conn.fetchval(query, agent_id)

    async def get_unanchored_logs(self, limit: int = 1000) -> list[dict[str, Any]]:
        """
        Get audit logs that haven't been anchored to the blockchain yet.

        These logs have merkle_root_id = NULL.
        """
        query = """
            SELECT id, action_hash, timestamp
            FROM audit_logs
            WHERE merkle_root_id IS NULL
            ORDER BY timestamp ASC
            LIMIT $1
        """
        async with self.acquire() as conn:
            rows = await conn.fetch(query, limit)

        return [dict(row) for row in rows]

    async def mark_logs_as_anchored(
        self,
        log_ids: list[UUID],
        merkle_root_id: UUID,
    ) -> None:
        """Mark audit logs as anchored to a merkle root."""
        query = """
            UPDATE audit_logs
            SET merkle_root_id = $1, merkle_leaf_index = idx.leaf_index
            FROM (
                SELECT unnest($2::uuid[]) as log_id,
                       generate_series(0, array_length($2::uuid[], 1) - 1) as leaf_index
            ) idx
            WHERE audit_logs.id = idx.log_id
        """
        # Note: This update is allowed because it only sets merkle fields,
        # and the trigger should allow this specific case.
        # For production, consider a separate linking table.
        async with self.acquire() as conn:
            await conn.execute(query, merkle_root_id, log_ids)

        logger.info(f"Marked {len(log_ids)} logs as anchored to merkle root {merkle_root_id}")

    # =========================================================================
    # RATE LIMITING
    # =========================================================================

    async def get_rate_limit_count(
        self,
        agent_id: UUID,
        window_type: str,
        window_start: datetime,
    ) -> tuple[int, Decimal]:
        """Get current rate limit counts for an agent."""
        query = """
            SELECT COALESCE(request_count, 0), COALESCE(amount_usd, 0)
            FROM rate_limit_windows
            WHERE agent_id = $1 AND window_type = $2 AND window_start = $3
        """
        async with self.acquire() as conn:
            row = await conn.fetchrow(query, agent_id, window_type, window_start)

        if row is None:
            return 0, Decimal("0")

        return row[0], row[1]

    async def increment_rate_limit(
        self,
        agent_id: UUID,
        window_type: str,
        window_start: datetime,
        amount_usd: Decimal = Decimal("0"),
    ) -> None:
        """Increment rate limit counters."""
        query = """
            INSERT INTO rate_limit_windows (agent_id, window_type, window_start, request_count, amount_usd)
            VALUES ($1, $2, $3, 1, $4)
            ON CONFLICT (agent_id, window_type, window_start)
            DO UPDATE SET
                request_count = rate_limit_windows.request_count + 1,
                amount_usd = rate_limit_windows.amount_usd + $4
        """
        async with self.acquire() as conn:
            await conn.execute(query, agent_id, window_type, window_start, amount_usd)

    async def get_daily_spend(self, agent_id: UUID) -> Decimal:
        """Get total spend for an agent today."""
        now = datetime.now(timezone.utc)
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        query = """
            SELECT COALESCE(SUM(amount_usd), 0)
            FROM rate_limit_windows
            WHERE agent_id = $1
              AND window_type = 'day'
              AND window_start >= $2
        """
        async with self.acquire() as conn:
            return await conn.fetchval(query, agent_id, day_start) or Decimal("0")

    # =========================================================================
    # MERKLE PROOF OPERATIONS
    # =========================================================================

    async def create_merkle_proof(
        self,
        root_hash: str,
        leaf_hashes: list[str],
        start_timestamp: datetime,
        end_timestamp: datetime,
        contract_address: str,
        chain_id: int = 8453,
    ) -> UUID:
        """Create a new merkle proof record."""
        query = """
            INSERT INTO merkle_proofs (
                root_hash, leaf_hashes, start_timestamp, end_timestamp,
                contract_address, chain_id, log_count, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
            RETURNING id
        """
        async with self.acquire() as conn:
            proof_id = await conn.fetchval(
                query,
                root_hash,
                leaf_hashes,
                start_timestamp,
                end_timestamp,
                contract_address,
                chain_id,
                len(leaf_hashes),
            )

        logger.info(f"Created merkle proof {proof_id} with {len(leaf_hashes)} leaves")
        return proof_id

    async def update_merkle_proof_status(
        self,
        proof_id: UUID,
        status: str,
        transaction_hash: Optional[str] = None,
        block_number: Optional[int] = None,
        gas_used: Optional[int] = None,
        gas_price_gwei: Optional[Decimal] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Update merkle proof status after blockchain submission."""
        query = """
            UPDATE merkle_proofs
            SET
                status = $2,
                transaction_hash = COALESCE($3, transaction_hash),
                block_number = COALESCE($4, block_number),
                gas_used = COALESCE($5, gas_used),
                gas_price_gwei = COALESCE($6, gas_price_gwei),
                error_message = COALESCE($7, error_message),
                confirmed_at = CASE WHEN $2 = 'confirmed' THEN NOW() ELSE confirmed_at END,
                retry_count = CASE WHEN $2 = 'failed' THEN retry_count + 1 ELSE retry_count END
            WHERE id = $1
        """
        async with self.acquire() as conn:
            await conn.execute(
                query,
                proof_id,
                status,
                transaction_hash,
                block_number,
                gas_used,
                gas_price_gwei,
                error_message,
            )

        logger.info(f"Updated merkle proof {proof_id} status to {status}")

    async def get_pending_merkle_proofs(self) -> list[dict[str, Any]]:
        """Get merkle proofs pending blockchain submission."""
        query = """
            SELECT id, root_hash, leaf_hashes, retry_count
            FROM merkle_proofs
            WHERE status IN ('pending', 'failed')
              AND retry_count < 5
            ORDER BY created_at ASC
        """
        async with self.acquire() as conn:
            rows = await conn.fetch(query)

        return [dict(row) for row in rows]

    # =========================================================================
    # SECURITY ALERT OPERATIONS
    # =========================================================================

    async def create_security_alert(
        self,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        agent_id: Optional[UUID] = None,
        org_id: Optional[UUID] = None,
        evidence: Optional[dict[str, Any]] = None,
        audit_log_ids: Optional[list[UUID]] = None,
    ) -> UUID:
        """Create a high-priority security alert."""
        query = """
            INSERT INTO security_alerts (
                agent_id, org_id, alert_type, severity, title,
                description, evidence, audit_log_ids
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
        """
        async with self.acquire() as conn:
            alert_id = await conn.fetchval(
                query,
                agent_id,
                org_id,
                alert_type,
                severity,
                title,
                description,
                json.dumps(evidence or {}),
                audit_log_ids or [],
            )

        logger.warning(
            f"SECURITY ALERT [{severity.upper()}] {alert_type}: {title} (ID: {alert_id})"
        )
        return alert_id

    # =========================================================================
    # NONCE TRACKING (Replay Attack Prevention)
    # =========================================================================

    async def check_and_store_nonce(self, agent_id: UUID, nonce: str) -> bool:
        """
        Check if a nonce has been used before and store it if not.

        Returns:
            True if nonce is fresh (not seen before), False if replay detected.
        """
        # Use a simple approach with a separate table or cache
        # For production, use Redis with TTL
        query = """
            INSERT INTO rate_limit_windows (agent_id, window_type, window_start, request_count)
            VALUES ($1, 'nonce_' || $2, NOW(), 1)
            ON CONFLICT DO NOTHING
            RETURNING id
        """
        async with self.acquire() as conn:
            result = await conn.fetchval(query, agent_id, nonce[:32])

        # If we got a result, the insert succeeded (nonce was fresh)
        return result is not None
