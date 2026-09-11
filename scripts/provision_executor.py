"""Provision, rotate and revoke authenticated executor identities.

Phase 7A, Gate 5. An executor is not a string in a request body — it is an
API key, and everything about who may spend which authority derives from
which key authenticated. This is the tool that creates one.

    # A payments executor for one organisation, and nothing else
    python -m scripts.provision_executor create \
        --org <uuid> --name "highnote-executor-prod" \
        --action-class financial_transaction \
        --by alice@example.com --approval CHG-2026-0044 \
        --reason "Phase 7B executor provisioning"

    # What can this organisation's executors do?
    python -m scripts.provision_executor list --org <uuid>

    # Rotate: issue the replacement, then revoke the old one once traffic
    # has moved. Two commands on purpose -- an atomic "rotate" would create
    # a window where neither key works.
    python -m scripts.provision_executor create --org <uuid> --name ... [...]
    python -m scripts.provision_executor revoke --key-id <uuid> [...]

Least privilege
---------------
A key created here holds ``execute:<action-class>`` and nothing else. It
cannot register agents, read audit logs, rotate webhook secrets, or consume
authority for an action class it was not provisioned for. That is narrower
than the ``write`` scope existing service keys carry, which is the point.

The key is printed ONCE, to stdout, and is not recoverable afterwards: only
its SHA-256 is stored. If it is lost, revoke it and create another.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import sys
from typing import Any
from uuid import UUID

from api.database import Database
from api.services.executor_context import (
    EXECUTE_SCOPE,
    EXECUTE_SCOPE_SEPARATOR,
    executor_binding_digest,
)

#: Matches the prefix convention the API's key parser recognises.
KEY_PREFIX: str = "inntris_live_sk_"
KEY_PREFIX_LENGTH: int = 8

EVENT_EXECUTOR_PROVISIONED = "authority.executor_provisioned"
EVENT_EXECUTOR_REVOKED = "authority.executor_revoked"


def _dsn() -> str:
    dsn = os.getenv("DATABASE_URL", "").strip()
    if not dsn:
        raise SystemExit("DATABASE_URL is required")
    return dsn


def _jsonable(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _emit(payload: Any) -> None:
    print(json.dumps(payload, indent=2, default=_jsonable))


def _mint_key() -> tuple[str, bytes, str]:
    """A fresh key, its stored hash, and its identifying prefix."""
    secret = secrets.token_urlsafe(32)
    raw = f"{KEY_PREFIX}{secret}"
    return raw, hashlib.sha256(raw.encode()).digest(), secret[:KEY_PREFIX_LENGTH]


async def _create(args: argparse.Namespace) -> int:
    org_id = UUID(args.org)
    action_classes = [entry.strip() for entry in (args.action_class or []) if entry.strip()]
    if not action_classes and not args.unscoped:
        raise SystemExit(
            "pass --action-class at least once, or --unscoped to deliberately "
            "create a key that may execute any action class this organisation "
            "can authorise"
        )

    scopes = (
        [EXECUTE_SCOPE]
        if args.unscoped
        else [
            f"{EXECUTE_SCOPE}{EXECUTE_SCOPE_SEPARATOR}{action}"
            for action in sorted(set(action_classes))
        ]
    )

    raw_key, key_hash, prefix = _mint_key()
    database = await Database.create(_dsn(), min_size=1, max_size=2)
    try:
        async with database.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                """
                INSERT INTO api_keys (org_id, key_hash, key_prefix, name, scopes, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id, created_at
                """,
                org_id,
                key_hash,
                prefix,
                args.name,
                scopes,
                args.expires_at,
            )
            await conn.execute(
                """
                INSERT INTO administrative_audit_events (
                    org_id, event_type, actor, approval_reference, details
                ) VALUES ($1, $2, $3, $4, $5::jsonb)
                """,
                org_id,
                EVENT_EXECUTOR_PROVISIONED,
                args.by,
                args.approval,
                json.dumps(
                    {
                        "api_key_id": str(row["id"]),
                        "name": args.name,
                        "scopes": scopes,
                        "reason": args.reason,
                    }
                ),
            )
    finally:
        await database.close()

    _emit(
        {
            "result": "provisioned",
            "api_key_id": str(row["id"]),
            "name": args.name,
            "scopes": scopes,
            # The binding a grant issued to this executor will carry. Printed
            # so an operator can correlate a grant row to the credential that
            # obtained it without having the key.
            "executor_binding_digest": executor_binding_digest(
                organisation_id=org_id, api_key_id=row["id"]
            ),
            "api_key": raw_key,
            "warning": (
                "This key is shown ONCE and is not recoverable. Only its "
                "SHA-256 is stored. Anyone holding it is this executor."
            ),
        }
    )
    return 0


async def _revoke(args: argparse.Namespace) -> int:
    database = await Database.create(_dsn(), min_size=1, max_size=2)
    try:
        async with database.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                """
                UPDATE api_keys SET is_active = FALSE
                WHERE id = $1 AND is_active
                RETURNING id, org_id, name
                """,
                UUID(args.key_id),
            )
            if row is not None:
                await conn.execute(
                    """
                    INSERT INTO administrative_audit_events (
                        org_id, event_type, actor, approval_reference, details
                    ) VALUES ($1, $2, $3, $4, $5::jsonb)
                    """,
                    row["org_id"],
                    EVENT_EXECUTOR_REVOKED,
                    args.by,
                    args.approval,
                    json.dumps(
                        {
                            "api_key_id": str(row["id"]),
                            "name": row["name"],
                            "reason": args.reason,
                        }
                    ),
                )
    finally:
        await database.close()

    if row is None:
        _emit({"result": "no_change", "detail": "no active key with that id"})
        return 1
    _emit(
        {
            "result": "revoked",
            "api_key_id": str(row["id"]),
            "effect": (
                "this credential can no longer authenticate, so it can issue no "
                "new authority and can consume none. Grants already issued to it "
                "become unspendable -- nothing else holds its binding -- and "
                "expire on their own schedule."
            ),
        }
    )
    return 0


async def _list(args: argparse.Namespace) -> int:
    database = await Database.create(_dsn(), min_size=1, max_size=2)
    try:
        async with database.acquire() as conn:
            records = await conn.fetch(
                """
                SELECT id, name, scopes, is_active, expires_at, last_used_at, created_at
                FROM api_keys
                WHERE org_id = $1
                ORDER BY created_at DESC
                """,
                UUID(args.org),
            )
    finally:
        await database.close()

    keys = []
    for record in records:
        scopes = list(record["scopes"] or [])
        narrowed = sorted(
            scope.split(EXECUTE_SCOPE_SEPARATOR, 1)[1]
            for scope in scopes
            if scope.startswith(EXECUTE_SCOPE + EXECUTE_SCOPE_SEPARATOR)
        )
        keys.append(
            {
                "api_key_id": str(record["id"]),
                "name": record["name"],
                "scopes": scopes,
                "action_classes": narrowed or "unscoped",
                "is_active": record["is_active"],
                "expires_at": record["expires_at"],
                "last_used_at": record["last_used_at"],
                "executor_binding_digest": executor_binding_digest(
                    organisation_id=args.org, api_key_id=record["id"]
                ),
            }
        )
    _emit({"organisation_id": args.org, "keys": keys})
    return 0


def _add_evidence_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--by", required=True, help="Who is making this change")
    parser.add_argument("--approval", required=True, help="Change or incident reference")
    parser.add_argument("--reason", required=True, help="Why, in one line")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="provision_executor", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Provision a least-privilege executor key")
    create.add_argument("--org", required=True)
    create.add_argument("--name", required=True, help="Human-readable key name")
    create.add_argument(
        "--action-class",
        action="append",
        help="Action class this executor may consume authority for; repeatable",
    )
    create.add_argument(
        "--unscoped",
        action="store_true",
        help="Deliberately create a key with no action-class restriction",
    )
    create.add_argument(
        "--expires-at",
        default=None,
        help="Optional expiry (any value PostgreSQL accepts as TIMESTAMPTZ)",
    )
    _add_evidence_arguments(create)
    create.set_defaults(handler=_create)

    revoke = sub.add_parser("revoke", help="Deactivate an executor credential")
    revoke.add_argument("--key-id", required=True)
    _add_evidence_arguments(revoke)
    revoke.set_defaults(handler=_revoke)

    listing = sub.add_parser("list", help="List an organisation's credentials")
    listing.add_argument("--org", required=True)
    listing.set_defaults(handler=_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(args.handler(args))


if __name__ == "__main__":
    sys.exit(main())
