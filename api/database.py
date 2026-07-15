"""
Database connection and operations for the Inntris Core API.

Uses asyncpg for high-performance async PostgreSQL operations.
"""

import hashlib
import json
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

import asyncpg
from asyncpg import Connection, Pool

from api.models import (
    AgentRecord,
    AgentStatus,
    AuditLogEntry,
    BillingTier,
    OrganizationRecord,
    RegisteredPolicy,
)

logger = logging.getLogger(__name__)

_AGENT_PRODUCTION_METADATA_KEYS = frozenset(
    {
        "production_approval_reference",
        "production_approved_at",
        "production_approved_by",
        "sandbox",
    }
)


class DatabaseError(Exception):
    """Base exception for database operations."""
    pass


class AgentNotFoundError(DatabaseError):
    """Raised when an agent is not found."""
    pass


class OrganizationNotFoundError(DatabaseError):
    """Raised when an organization is not found."""
    pass


class LimitReservationError(DatabaseError):
    """Raised when an atomic rate/spend reservation would exceed a limit.

    The reservation runs inside a transaction; raising this rolls the
    transaction back so a rejected request leaves no counter incremented.
    ``kind`` is ``"rate"`` or ``"daily"``.
    """

    def __init__(self, kind: str, observed: Any):
        self.kind = kind
        self.observed = observed
        super().__init__(f"{kind} limit exceeded (observed {observed})")


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

    @asynccontextmanager
    async def acquire_as_tenant(
        self, org_id: UUID
    ) -> AsyncGenerator[Connection, None]:
        """
        Acquire a connection scoped to a tenant (Phase 1C.1).

        Opens a transaction, downgrades the session to ``inntris_api`` via
        ``SET LOCAL ROLE`` (requires the pool role to hold membership — see
        migration 005), and installs ``app.current_org_id`` via ``set_config``
        with ``is_local=true`` so the setting is torn down at transaction end.

        All RLS policies created in migration 005 filter by
        ``app.current_tenant()``, which reads this setting. Within the
        ``async with`` block, every query executes with tenant isolation
        enforced by the database — even if the application logic forgets an
        ``org_id`` predicate, cross-tenant rows are invisible.

        Usage:
            async with db.acquire_as_tenant(org_id) as conn:
                await conn.fetch("SELECT * FROM agents")  # only this org's agents

        Raises:
            asyncpg.InsufficientPrivilegeError: if the pool role does not
                hold membership of ``inntris_api`` (operator must run
                migration 005 and switch DATABASE_URL to ``inntris_worker``).
        """
        async with self._pool.acquire() as conn, conn.transaction():
            await conn.execute("SET LOCAL ROLE inntris_api")
            await conn.execute(
                "SELECT set_config('app.current_org_id', $1, true)",
                str(org_id),
            )
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
                metadata, created_at, updated_at, key_version, key_rotated_at
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
            metadata=json.loads(row["metadata"]) if isinstance(row["metadata"], str) else (row["metadata"] or {}),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            key_version=row["key_version"],
            key_rotated_at=row["key_rotated_at"],
        )

    async def get_agent_by_fingerprint(self, fingerprint: str) -> AgentRecord:
        """Fetch an agent by public key fingerprint."""
        query = """
            SELECT
                id, org_id, name, public_key, public_key_fingerprint,
                trust_score, status, daily_limit_usd, per_action_limit_usd,
                allowed_actions, blocked_actions, rate_limit_per_minute,
                last_action_at, total_actions_count, total_blocked_count,
                metadata, created_at, updated_at, key_version, key_rotated_at
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
            metadata=json.loads(row["metadata"]) if isinstance(row["metadata"], str) else (row["metadata"] or {}),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            key_version=row["key_version"],
            key_rotated_at=row["key_rotated_at"],
        )

    # =========================================================================
    # AGENT GOVERNING POLICIES (AI PR Guard — Tier A)
    # =========================================================================

    async def get_active_agent_policy(
        self, agent_id: UUID
    ) -> RegisteredPolicy | None:
        """Return the agent's active registered policy, or None.

        Read on the /verify path, which runs as ``inntris_worker`` (BYPASSRLS).
        """
        query = """
            SELECT policy_hash, mapping, protected_branches, version
            FROM agent_policies
            WHERE agent_id = $1 AND active
            LIMIT 1
        """
        async with self.acquire() as conn:
            row = await conn.fetchrow(query, agent_id)

        if row is None:
            return None

        mapping = row["mapping"]
        branches = row["protected_branches"]
        return RegisteredPolicy(
            policy_hash=row["policy_hash"],
            mapping=json.loads(mapping) if isinstance(mapping, str) else (mapping or {}),
            protected_branches=(
                json.loads(branches) if isinstance(branches, str) else (branches or [])
            ),
            version=row["version"],
        )

    async def register_agent_policy(
        self,
        agent_id: UUID,
        org_id: UUID,
        policy_hash: str,
        mapping: dict[str, Any],
        protected_branches: list[str],
        registered_by: str | None = None,
    ) -> RegisteredPolicy:
        """Register (or re-register) an agent's governing policy.

        Deactivates the prior active policy and inserts a new, higher version
        in one tenant-scoped transaction. RLS (migration 005) enforces that the
        agent belongs to ``org_id``.
        """
        async with self.acquire_as_tenant(org_id) as conn:
            await conn.execute(
                "UPDATE agent_policies SET active = false WHERE agent_id = $1 AND active",
                agent_id,
            )
            row = await conn.fetchrow(
                """
                INSERT INTO agent_policies (
                    agent_id, policy_hash, mapping, protected_branches,
                    version, registered_by, active
                )
                VALUES (
                    $1, $2, $3::jsonb, $4::jsonb,
                    COALESCE((SELECT MAX(version) FROM agent_policies WHERE agent_id = $1), 0) + 1,
                    $5, true
                )
                RETURNING policy_hash, mapping, protected_branches, version
                """,
                agent_id,
                policy_hash,
                json.dumps(mapping or {}),
                json.dumps(protected_branches or []),
                registered_by,
            )

        mapping_out = row["mapping"]
        branches_out = row["protected_branches"]
        logger.info(f"Registered policy v{row['version']} for agent {agent_id}")
        return RegisteredPolicy(
            policy_hash=row["policy_hash"],
            mapping=(
                json.loads(mapping_out) if isinstance(mapping_out, str) else (mapping_out or {})
            ),
            protected_branches=(
                json.loads(branches_out)
                if isinstance(branches_out, str)
                else (branches_out or [])
            ),
            version=row["version"],
        )

    async def rotate_agent_key(
        self,
        agent_id: UUID,
        org_id: UUID,
        new_public_key: bytes,
        new_fingerprint: str,
        retired_by: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Rotate an agent's Ed25519 signing key in place.

        Records the current key in ``agent_key_history`` and swaps in the new
        one (new fingerprint, bumped ``key_version``, ``key_rotated_at`` now) in
        one tenant-scoped transaction. Trust score, policy, and audit history are
        untouched; the old key stops verifying immediately.

        Returns the new ``key_version``, ``public_key_fingerprint``, and
        ``key_rotated_at``.
        """
        async with self.acquire_as_tenant(org_id) as conn:
            current = await conn.fetchrow(
                "SELECT public_key_fingerprint, key_version FROM agents WHERE id = $1",
                agent_id,
            )
            if current is None:
                raise AgentNotFoundError(f"Agent {agent_id} not found")

            await conn.execute(
                """
                INSERT INTO agent_key_history (
                    agent_id, public_key_fingerprint, key_version, retired_by, reason
                )
                VALUES ($1, $2, $3, $4, $5)
                """,
                agent_id,
                current["public_key_fingerprint"],
                current["key_version"],
                retired_by,
                reason,
            )

            row = await conn.fetchrow(
                """
                UPDATE agents
                SET public_key = $2,
                    public_key_fingerprint = $3,
                    key_version = key_version + 1,
                    key_rotated_at = NOW(),
                    updated_at = NOW()
                WHERE id = $1
                RETURNING key_version, public_key_fingerprint, key_rotated_at
                """,
                agent_id,
                new_public_key,
                new_fingerprint,
            )

        logger.info(
            f"Rotated signing key for agent {agent_id} to v{row['key_version']}"
        )
        return {
            "key_version": row["key_version"],
            "public_key_fingerprint": row["public_key_fingerprint"],
            "key_rotated_at": row["key_rotated_at"],
        }

    async def create_agent(
        self,
        org_id: UUID,
        name: str,
        public_key: bytes,
        daily_limit_usd: Decimal = Decimal("100.00"),
        per_action_limit_usd: Decimal = Decimal("50.00"),
        allowed_actions: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
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
        # Registration can never grant production eligibility. Only the
        # tenant-scoped promotion operation may install lifecycle approval
        # evidence and clear the sandbox flag.
        meta = {
            key: value
            for key, value in dict(metadata or {}).items()
            if key not in _AGENT_PRODUCTION_METADATA_KEYS
        }
        meta["sandbox"] = True

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

    async def promote_agent_to_production(
        self,
        *,
        agent_id: UUID,
        org_id: UUID,
        approved_by: str,
        approval_reference: str,
    ) -> dict[str, Any]:
        """Atomically clear sandbox status after explicit organisation approval."""
        approval_metadata = {
            "sandbox": False,
            "production_approved_at": datetime.now(UTC).isoformat(),
            "production_approved_by": approved_by,
            "production_approval_reference": approval_reference,
        }
        query = """
            UPDATE agents
            SET status = 'active',
                metadata = COALESCE(metadata, '{}'::jsonb) || $3::jsonb,
                updated_at = NOW()
            WHERE id = $1
              AND org_id = $2
              AND metadata @> '{"sandbox": true}'::jsonb
            RETURNING metadata
        """
        async with self.acquire() as conn, conn.transaction():
            metadata = await conn.fetchval(
                query,
                agent_id,
                org_id,
                json.dumps(approval_metadata),
            )
            if metadata is not None:
                await conn.execute(
                    """
                    INSERT INTO administrative_audit_events (
                        org_id, event_type, actor, approval_reference, details
                    ) VALUES ($1, 'agent.production_promoted', $2, $3, $4::jsonb)
                    """,
                    org_id,
                    approved_by,
                    approval_reference,
                    json.dumps({"agent_id": str(agent_id)}),
                )

        if metadata is None:
            raise ValueError("Agent is not an eligible sandbox agent")
        if isinstance(metadata, str):
            metadata = json.loads(metadata)

        logger.info(
            "Promoted sandbox agent %s for org %s with approval %s",
            agent_id,
            org_id,
            approval_reference,
        )
        return dict(metadata)

    async def update_agent_after_verification(
        self,
        agent_id: UUID,
        trust_score: int,
        was_approved: bool,
    ) -> None:
        """
        Update agent trust score after verification.

        Activity counters and last_action_at are maintained by the
        update_agent_stats_on_audit database trigger when the append-only audit
        row is inserted. Keeping this helper limited to trust_score avoids
        double counting across /verify and /v1/events.

        Args:
            agent_id: The agent's UUID
            trust_score: New trust score
            was_approved: True if action was approved, False if blocked
        """
        if not 0 <= trust_score <= 100:
            raise ValueError("Trust score must be between 0 and 100")

        query = """
            UPDATE agents
            SET trust_score = $2,
                updated_at = NOW()
            WHERE id = $1
        """

        async with self.acquire() as conn:
            result = await conn.execute(query, agent_id, trust_score)

        if result == "UPDATE 0":
            raise AgentNotFoundError(f"Agent {agent_id} not found")

        action_type = "approved" if was_approved else "blocked"
        logger.info(f"Updated agent {agent_id} trust after {action_type} action (score: {trust_score})")

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

        # Handle billing_tier - convert string to enum if needed
        billing_tier = row["billing_tier"]
        if isinstance(billing_tier, str):
            billing_tier = BillingTier(billing_tier)

        # Handle metadata - parse JSON string if needed (asyncpg may return JSONB as string)
        metadata = row["metadata"]
        if metadata is None:
            metadata = {}
        elif isinstance(metadata, str):
            metadata = json.loads(metadata) if metadata else {}

        return OrganizationRecord(
            id=row["id"],
            name=row["name"],
            billing_tier=billing_tier,
            contact_email=row["contact_email"],
            webhook_url=row["webhook_url"],
            daily_limit_usd=row["daily_limit_usd"],
            monthly_limit_usd=row["monthly_limit_usd"],
            metadata=metadata,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    async def create_organization(
        self,
        name: str,
        contact_email: str,
        api_key_hash: bytes,
        billing_tier: str = "free",
        webhook_url: str | None = None,
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

    async def ensure_organization_webhook_secret(
        self,
        org_id: UUID,
        encrypted_secret: bytes,
    ) -> dict[str, Any] | None:
        """Install an initial webhook secret without racing another request."""

        query = """
            UPDATE organizations
            SET webhook_secret_ciphertext = $2,
                webhook_secret_version = 1,
                webhook_secret_rotated_at = NOW(),
                updated_at = NOW()
            WHERE id = $1
              AND webhook_secret_ciphertext IS NULL
            RETURNING webhook_secret_version, webhook_secret_rotated_at
        """
        async with self.acquire() as conn:
            row = await conn.fetchrow(query, org_id, encrypted_secret)
        return dict(row) if row else None

    async def rotate_organization_webhook_secret(
        self,
        org_id: UUID,
        encrypted_secret: bytes,
        *,
        actor: str,
        approval_reference: str,
    ) -> dict[str, Any] | None:
        """Atomically replace a webhook secret and append approval evidence."""

        query = """
            UPDATE organizations
            SET webhook_secret_ciphertext = $2,
                webhook_secret_version = webhook_secret_version + 1,
                webhook_secret_rotated_at = NOW(),
                updated_at = NOW()
            WHERE id = $1
            RETURNING webhook_secret_version, webhook_secret_rotated_at
        """
        async with self.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(query, org_id, encrypted_secret)
            if row is not None:
                await conn.execute(
                    """
                    INSERT INTO administrative_audit_events (
                        org_id, event_type, actor, approval_reference, details
                    ) VALUES (
                        $1, 'organization.webhook_secret_rotated', $2, $3,
                        jsonb_build_object('webhook_secret_version', $4::integer)
                    )
                    """,
                    org_id,
                    actor,
                    approval_reference,
                    int(row["webhook_secret_version"]),
                )
        return dict(row) if row else None

    async def enqueue_webhook_delivery(
        self,
        org_id: UUID,
        event: str,
        payload: dict[str, Any],
    ) -> UUID | None:
        """Persist a webhook outbox row when the tenant is fully configured."""

        query = """
            INSERT INTO webhook_deliveries (org_id, event, payload)
            SELECT id, $2, $3::jsonb
            FROM organizations
            WHERE id = $1
              AND webhook_url IS NOT NULL
              AND webhook_secret_ciphertext IS NOT NULL
              AND webhook_secret_version > 0
            RETURNING id
        """
        async with self.acquire() as conn:
            return await conn.fetchval(query, org_id, event, json.dumps(payload))

    async def begin_webhook_delivery_attempt(self, delivery_id: UUID) -> Any | None:
        """Claim a pending delivery and return its current tenant configuration."""

        query = """
            UPDATE webhook_deliveries AS d
            SET status = 'delivering',
                attempt_count = d.attempt_count + 1,
                last_attempt_at = NOW(),
                updated_at = NOW()
            FROM organizations AS o
            WHERE d.id = $1
              AND d.org_id = o.id
              AND (
                    (
                        d.status IN ('pending', 'retrying')
                        AND d.next_attempt_at <= NOW()
                    )
                    OR (
                        d.status = 'delivering'
                        AND d.last_attempt_at < NOW() - INTERVAL '5 minutes'
                    )
                  )
              AND d.attempt_count < 3
            RETURNING d.id, d.org_id, d.event, d.payload, d.attempt_count,
                      o.webhook_url, o.webhook_secret_ciphertext,
                      o.webhook_secret_version
        """
        async with self.acquire() as conn, conn.transaction():
            await conn.execute(
                    """
                    UPDATE webhook_deliveries
                    SET status = 'dead_letter',
                        last_error = COALESCE(
                            last_error,
                            'Delivery ownership expired after the final attempt'
                        ),
                        dead_lettered_at = NOW(),
                        next_attempt_at = NULL,
                        updated_at = NOW()
                    WHERE id = $1
                      AND status = 'delivering'
                      AND last_attempt_at < NOW() - INTERVAL '5 minutes'
                      AND attempt_count >= 3
                    """,
                delivery_id,
            )
            return await conn.fetchrow(query, delivery_id)

    async def mark_webhook_delivery_delivered(
        self,
        delivery_id: UUID,
        response_status: int,
    ) -> None:
        query = """
            UPDATE webhook_deliveries
            SET status = 'delivered',
                response_status = $2,
                last_error = NULL,
                delivered_at = NOW(),
                next_attempt_at = NULL,
                updated_at = NOW()
            WHERE id = $1 AND status = 'delivering'
        """
        async with self.acquire() as conn:
            await conn.execute(query, delivery_id, response_status)

    async def mark_webhook_delivery_retry(
        self,
        delivery_id: UUID,
        error: str,
        response_status: int | None,
        retry_delay_seconds: float,
    ) -> None:
        query = """
            UPDATE webhook_deliveries
            SET status = 'retrying',
                response_status = $3,
                last_error = $2,
                next_attempt_at = NOW() + ($4 * INTERVAL '1 second'),
                updated_at = NOW()
            WHERE id = $1 AND status = 'delivering'
        """
        async with self.acquire() as conn:
            await conn.execute(
                query,
                delivery_id,
                error,
                response_status,
                retry_delay_seconds,
            )

    async def mark_webhook_delivery_dead_letter(
        self,
        delivery_id: UUID,
        error: str,
        response_status: int | None,
    ) -> None:
        query = """
            UPDATE webhook_deliveries
            SET status = 'dead_letter',
                response_status = $3,
                last_error = $2,
                dead_lettered_at = NOW(),
                next_attempt_at = NULL,
                updated_at = NOW()
            WHERE id = $1 AND status = 'delivering'
        """
        async with self.acquire() as conn:
            await conn.execute(query, delivery_id, error, response_status)

    async def list_webhook_deliveries(
        self,
        org_id: UUID,
        *,
        status_filter: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return recent delivery state without exposing stored payloads."""

        query = """
            SELECT id, event, status, attempt_count, response_status, last_error,
                   created_at, last_attempt_at, delivered_at, dead_lettered_at,
                   next_attempt_at
            FROM webhook_deliveries
            WHERE org_id = $1
              AND ($2::text IS NULL OR status = $2)
            ORDER BY created_at DESC
            LIMIT $3
        """
        async with self.acquire() as conn:
            rows = await conn.fetch(query, org_id, status_filter, limit)
        return [dict(row) for row in rows]

    async def list_due_webhook_delivery_ids(self, limit: int = 50) -> list[UUID]:
        """Return delivery ids that are due or whose previous owner died."""

        query = """
            SELECT id
            FROM webhook_deliveries
            WHERE (
                    status IN ('pending', 'retrying')
                    AND next_attempt_at <= NOW()
                  )
               OR (
                    status = 'delivering'
                    AND last_attempt_at < NOW() - INTERVAL '5 minutes'
                  )
            ORDER BY next_attempt_at ASC NULLS FIRST, created_at ASC
            LIMIT $1
        """
        async with self.acquire() as conn:
            rows = await conn.fetch(query, limit)
        return [row["id"] for row in rows]

    # =========================================================================
    # AUDIT LOG OPERATIONS
    # =========================================================================

    async def insert_audit_log(
        self, entry: AuditLogEntry, *, derive_chain_hash: bool = False
    ) -> UUID:
        """
        Insert a new audit log entry.

        This operation is append-only. The database triggers will prevent
        any modification or deletion.

        When ``derive_chain_hash`` is True, ``chain_previous_hash`` is computed
        inside the INSERT under a per-agent advisory lock, so concurrent
        /verify calls for the same agent cannot both read the same "previous"
        row and fork the local hash chain. When False (e.g. partner ingestion
        or callers that already hold the previous hash), the caller-supplied
        ``entry.chain_previous_hash`` is written as-is.

        Returns:
            The UUID of the created audit log entry.
        """
        if derive_chain_hash:
            # The previous-hash subquery and this INSERT run in one transaction
            # gated by a per-agent advisory lock, so the read-then-write that
            # builds the local chain is serialized per agent without
            # serializing unrelated agents.
            query = """
                INSERT INTO audit_logs (
                    agent_id, action_type, action_hash, payload, verdict,
                    verdict_reason, signature, signature_valid, request_ip,
                    request_user_agent, response_time_ms, trust_score_at_time,
                    chain_previous_hash, policy_hash, metadata
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                    (
                        SELECT action_hash FROM audit_logs
                        WHERE agent_id = $1
                        ORDER BY chain_sequence DESC
                        LIMIT 1
                    ),
                    $13, $14
                )
                RETURNING id
            """
            async with self.acquire() as conn, conn.transaction():
                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
                    str(entry.agent_id),
                )
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
                    entry.policy_hash,
                    json.dumps(entry.metadata),
                )
            return log_id

        query = """
            INSERT INTO audit_logs (
                agent_id, action_type, action_hash, payload, verdict,
                verdict_reason, signature, signature_valid, request_ip,
                request_user_agent, response_time_ms, trust_score_at_time,
                chain_previous_hash, policy_hash, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
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
                entry.policy_hash,
                json.dumps(entry.metadata),
            )

        return log_id

    async def insert_token_consumption(
        self,
        entry: AuditLogEntry,
        *,
        token_id: str,
        token_digest: bytes,
        approved_action_hash: str,
    ) -> UUID | None:
        """Atomically claim one token and append its consumption receipt.

        The database uniqueness constraints are the single use authority. A
        conflicting token id or digest rolls back the audit insert and returns
        ``None``. Redis may cache replay results but is never authoritative.
        """

        audit_query = """
            INSERT INTO audit_logs (
                agent_id, action_type, action_hash, payload, verdict,
                verdict_reason, signature, signature_valid, request_ip,
                request_user_agent, response_time_ms, trust_score_at_time,
                chain_previous_hash, policy_hash, metadata
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                NULL, $13, $14
            )
            RETURNING id
        """
        try:
            async with self.acquire() as conn, conn.transaction():
                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
                    f"approval-token:{token_id}",
                )
                already_used = await conn.fetchval(
                    """
                    SELECT 1
                    FROM approval_token_consumptions
                    WHERE token_id = $1 OR token_digest = $2
                    """,
                    token_id,
                    token_digest,
                )
                if already_used:
                    return None

                audit_id = await conn.fetchval(
                    audit_query,
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
                    entry.policy_hash,
                    json.dumps(entry.metadata),
                )
                await conn.execute(
                    """
                    INSERT INTO approval_token_consumptions (
                        token_id, token_digest, agent_id, action_hash,
                        audit_log_id
                    ) VALUES ($1, $2, $3, $4, $5)
                    """,
                    token_id,
                    token_digest,
                    entry.agent_id,
                    approved_action_hash,
                    audit_id,
                )
                return audit_id
        except asyncpg.UniqueViolationError:
            return None

    async def get_last_audit_hash(self, agent_id: UUID) -> str | None:
        """Get the hash of the last audit log entry for chain linking."""
        query = """
            SELECT action_hash
            FROM audit_logs
            WHERE agent_id = $1
            ORDER BY chain_sequence DESC
            LIMIT 1
        """
        async with self.acquire() as conn:
            return await conn.fetchval(query, agent_id)

    async def get_unanchored_logs(self, limit: int = 1000) -> list[dict[str, Any]]:
        """
        Get audit logs that haven't been anchored to the blockchain yet.

        Excludes ``metadata.test_request = true`` rows (Phase 2B) — those come
        from /admin/test-verify and carry a sentinel signature rather than a
        real attestation. They must never appear in a Merkle batch that we
        anchor publicly, because the leaf hash of a test row does not verify
        against any agent public key.
        """
        query = """
            SELECT id, action_hash, timestamp
            FROM audit_logs
            WHERE merkle_root_id IS NULL
              AND NOT COALESCE(
                  (metadata->>'test_request')::boolean,
                  false
              )
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
        now = datetime.now(UTC)
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

    async def reserve_rate_and_spend(
        self,
        agent_id: UUID,
        minute_start: datetime,
        day_start: datetime,
        amount: Decimal,
        rate_limit_per_minute: int,
        daily_limit_usd: Decimal,
    ) -> tuple[int, Decimal]:
        """Atomically reserve one request in the minute window and ``amount`` in
        the day window, enforcing both limits inside a single transaction.

        This closes the check-then-act race in /verify. Previously the handler
        read the current spend/rate, evaluated the policy, then incremented in
        separate statements — so N concurrent requests could each observe the
        same remaining headroom and all pass. Here the increment *is* the
        check: an atomic upsert returns the post-increment value, and a value
        over the limit raises :class:`LimitReservationError`, rolling the
        transaction back so nothing is reserved for a rejected request.

        Returns ``(minute_count, daily_spend)`` reflecting the counters after
        this request is included.
        """
        async with self.acquire() as conn, conn.transaction():
            minute_count = await conn.fetchval(
                """
                    INSERT INTO rate_limit_windows (
                        agent_id, window_type, window_start, request_count, amount_usd
                    )
                    VALUES ($1, 'minute', $2, 1, 0)
                    ON CONFLICT (agent_id, window_type, window_start)
                    DO UPDATE SET request_count = rate_limit_windows.request_count + 1
                    RETURNING request_count
                    """,
                agent_id,
                minute_start,
            )
            if minute_count > rate_limit_per_minute:
                raise LimitReservationError("rate", minute_count)

            daily_spend = await conn.fetchval(
                """
                    INSERT INTO rate_limit_windows (
                        agent_id, window_type, window_start, request_count, amount_usd
                    )
                    VALUES ($1, 'day', $2, 1, $3)
                    ON CONFLICT (agent_id, window_type, window_start)
                    DO UPDATE SET
                        request_count = rate_limit_windows.request_count + 1,
                        amount_usd = rate_limit_windows.amount_usd + $3
                    RETURNING amount_usd
                    """,
                agent_id,
                day_start,
                amount,
            )
            if daily_spend > daily_limit_usd:
                raise LimitReservationError("daily", daily_spend)

            return minute_count, daily_spend

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
        transaction_hash: str | None = None,
        block_number: int | None = None,
        gas_used: int | None = None,
        gas_price_gwei: Decimal | None = None,
        error_message: str | None = None,
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
        agent_id: UUID | None = None,
        org_id: UUID | None = None,
        evidence: dict[str, Any] | None = None,
        audit_log_ids: list[UUID] | None = None,
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
