#!/usr/bin/env python3
"""
Production Database Seed Script for Inntris

This script bootstraps a fresh production database with:
- A default organization
- An API key for the admin dashboard
- Optionally, a demo agent

Usage:
    # Set your Railway DATABASE_URL first
    export DATABASE_URL="postgresql://..."

    # Run the seed script
    python scripts/seed_production.py

    # Or with custom org name
    python scripts/seed_production.py --org-name "My Company"
"""

import asyncio
import argparse
import secrets
import hashlib
import os
import sys
from datetime import datetime, timezone
from uuid import uuid4

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import asyncpg
except ImportError:
    print("Error: asyncpg not installed. Run: pip install asyncpg")
    sys.exit(1)


def generate_api_key() -> tuple[str, bytes, str]:
    """Generate a secure API key and its hash."""
    # Format: inntris_live_sk_<random>
    random_part = secrets.token_urlsafe(32)
    api_key = f"inntris_live_sk_{random_part}"

    # Hash for storage (SHA-256) - as bytes for BYTEA column
    key_hash = hashlib.sha256(api_key.encode()).digest()

    # Prefix for identification (first 8 chars only - schema limit)
    key_prefix = random_part[:8]

    return api_key, key_hash, key_prefix


async def seed_database(
    database_url: str,
    org_name: str = "Inntris Admin",
    create_demo_agent: bool = True,
):
    """Seed the production database."""

    print(f"\n{'='*60}")
    print("Inntris Production Database Seeder")
    print(f"{'='*60}\n")

    # Connect to database
    print(f"Connecting to database...")
    try:
        conn = await asyncpg.connect(database_url)
        print("Connected successfully!\n")
    except Exception as e:
        print(f"Failed to connect: {e}")
        sys.exit(1)

    try:
        # Check if organization already exists
        existing_org = await conn.fetchrow(
            "SELECT id, name FROM organizations WHERE name = $1",
            org_name
        )

        # Generate API key first (needed for org creation)
        api_key, key_hash, key_prefix = generate_api_key()

        if existing_org:
            print(f"Organization '{org_name}' already exists (ID: {existing_org['id']})")
            org_id = existing_org['id']
        else:
            # Create organization with api_key_hash
            org_id = uuid4()
            await conn.execute(
                """
                INSERT INTO organizations (id, name, billing_tier, contact_email, api_key_hash, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $6)
                """,
                org_id,
                org_name,
                "enterprise",
                "admin@inntris.io",
                key_hash,
                datetime.now(timezone.utc),
            )
            print(f"Created organization: {org_name}")
            print(f"  ID: {org_id}")

        # Check if API key with this prefix exists
        existing_key = await conn.fetchrow(
            "SELECT id FROM api_keys WHERE key_prefix = $1",
            key_prefix
        )

        if existing_key:
            print(f"\nAPI key with prefix {key_prefix[:20]}... already exists")
        else:
            # Create API key
            key_id = uuid4()
            await conn.execute(
                """
                INSERT INTO api_keys (id, org_id, key_hash, key_prefix, name, scopes, is_active, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                key_id,
                org_id,
                key_hash,
                key_prefix,
                "Production Admin Key",
                ["admin", "read", "write", "verify"],
                True,
                datetime.now(timezone.utc),
            )
            print(f"\nCreated API key:")
            print(f"  Name: Production Admin Key")
            print(f"  Scopes: admin, read, write, verify")

        # Create demo agent if requested
        if create_demo_agent:
            existing_agent = await conn.fetchrow(
                "SELECT id FROM agents WHERE org_id = $1 AND name = $2",
                org_id,
                "Demo Agent"
            )

            if existing_agent:
                print(f"\nDemo agent already exists (ID: {existing_agent['id']})")
            else:
                agent_id = uuid4()
                # Generate a demo Ed25519 public key (32 bytes as BYTEA)
                demo_public_key = secrets.token_bytes(32)
                # SHA-256 fingerprint for quick lookup (64 char hex string)
                public_key_fingerprint = hashlib.sha256(demo_public_key).hexdigest()

                await conn.execute(
                    """
                    INSERT INTO agents (
                        id, org_id, name, public_key, public_key_fingerprint,
                        status, trust_score,
                        daily_limit_usd, per_action_limit_usd, rate_limit_per_minute,
                        allowed_actions, blocked_actions, metadata,
                        total_actions_count, total_blocked_count,
                        created_at, updated_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $16)
                    """,
                    agent_id,
                    org_id,
                    "Demo Agent",
                    demo_public_key,
                    public_key_fingerprint,
                    "active",
                    85,  # Starting trust score
                    10000,  # Daily limit USD
                    1000,  # Per action limit USD
                    60,  # Rate limit per minute
                    ["financial_transaction", "api_call", "email_send", "data_export"],
                    ["admin_action"],
                    {"description": "Demo agent for testing", "environment": "production"},
                    0,
                    0,
                    datetime.now(timezone.utc),
                )
                print(f"\nCreated demo agent:")
                print(f"  ID: {agent_id}")
                print(f"  Name: Demo Agent")
                print(f"  Trust Score: 85")

        print(f"\n{'='*60}")
        print("IMPORTANT: Save this API key securely!")
        print("You will NOT be able to see it again.")
        print(f"{'='*60}")
        print(f"\nAPI Key: {api_key}")
        print(f"\n{'='*60}")
        print("\nNext steps:")
        print("1. Copy the API key above")
        print("2. Go to Vercel Dashboard > Your Project > Settings > Environment Variables")
        print("3. Add: NEXT_PUBLIC_API_KEY = <paste the API key>")
        print("4. Redeploy the frontend")
        print(f"{'='*60}\n")

    finally:
        await conn.close()


def main():
    parser = argparse.ArgumentParser(description="Seed production database for Inntris")
    parser.add_argument(
        "--org-name",
        default="Inntris Admin",
        help="Organization name (default: Inntris Admin)"
    )
    parser.add_argument(
        "--no-demo-agent",
        action="store_true",
        help="Skip creating demo agent"
    )
    parser.add_argument(
        "--database-url",
        default=os.getenv("DATABASE_URL"),
        help="Database URL (default: from DATABASE_URL env var)"
    )

    args = parser.parse_args()

    if not args.database_url:
        print("Error: DATABASE_URL not set")
        print("Usage: DATABASE_URL='postgresql://...' python scripts/seed_production.py")
        sys.exit(1)

    asyncio.run(seed_database(
        database_url=args.database_url,
        org_name=args.org_name,
        create_demo_agent=not args.no_demo_agent,
    ))


if __name__ == "__main__":
    main()
