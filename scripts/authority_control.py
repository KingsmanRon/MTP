"""Operator CLI for the authority requirement and its kill switches.

Phase 7A, Gates 2 and 8. This is the tool an operator actually runs during
an incident, so it is deliberately small, has no dependency on the running
API, and refuses to do anything without an actor and an approval reference.

    # Who is enrolled, and are any switches pulled?
    python -m scripts.authority_control show --org <uuid>

    # Enable the requirement for one principal and one action class
    python -m scripts.authority_control require \
        --org <uuid> --agent <uuid> --action-class financial_transaction \
        --by alice@example.com --approval CHG-2026-0042 \
        --reason "Gate 2 canary enrolment"

    # Undo a rollout that went too wide, immediately
    python -m scripts.authority_control kill \
        --control requirement_enforcement --org <uuid> \
        --by alice@example.com --approval INC-2026-0007 --reason "rollback"

    # Halt ALL new execution authority, platform-wide
    python -m scripts.authority_control kill \
        --control authority_issuance --global \
        --by alice@example.com --approval INC-2026-0008 \
        --reason "suspected issuer compromise"

    # Which issuers are trusted, and what has been revoked?
    python -m scripts.authority_control trust

    # Distrust a compromised issuer signing key, in seconds
    python -m scripts.authority_control revoke \
        --subject issuer_key --issuer acme-issuer --id <fingerprint> \
        --by alice@example.com --approval INC-2026-0009 \
        --reason "issuer disclosed key compromise"

    # Record which account a principal is, at an issuer
    python -m scripts.authority_control bind \
        --org <uuid> --agent <uuid> --issuer acme-issuer \
        --key issuer_account_reference --value acct_1234 \
        --by alice@example.com --approval CHG-2026-0043 \
        --reason "canary principal provisioning"

Every mutating command writes an immutable ``administrative_audit_events``
row in the same transaction as the change.

The DSN comes from ``DATABASE_URL`` and is never printed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any
from uuid import UUID

from api.database import Database
from api.persistence.authority_requirements import (
    CONTROL_AUTHORITY_ISSUANCE,
    CONTROL_REQUIREMENT_ENFORCEMENT,
    KNOWN_CONTROLS,
    clear_requirement,
    list_controls,
    list_requirements,
    set_control,
    set_requirement,
)
from api.trust.issuer_registry import load_registry_from_environment
from api.trust.principal_bindings import (
    clear_principal_binding,
    list_principal_bindings,
    set_principal_binding,
)
from api.trust.revocations import (
    RevocationSubject,
    list_revocations,
    set_revocation,
)


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


async def _show(args: argparse.Namespace) -> int:
    database = await Database.create(_dsn(), min_size=1, max_size=2)
    try:
        org = UUID(args.org) if args.org else None
        requirements = await list_requirements(database, organisation_id=org) if org else []
        controls = await list_controls(database, organisation_id=org)
    finally:
        await database.close()

    _emit(
        {
            "organisation_id": args.org,
            "requirements": requirements,
            "controls": controls,
            # Stated explicitly so an operator reading this during an incident
            # does not have to infer it from an empty list.
            "effective_default": ("delegated authority is NOT required where no row applies"),
        }
    )
    return 0


async def _require(args: argparse.Namespace) -> int:
    database = await Database.create(_dsn(), min_size=1, max_size=2)
    try:
        row = await set_requirement(
            database,
            organisation_id=UUID(args.org),
            agent_id=UUID(args.agent) if args.agent else None,
            action_class=args.action_class,
            required=not args.exempt,
            changed_by=args.by,
            approval_reference=args.approval,
            reason=args.reason,
        )
    finally:
        await database.close()
    _emit({"result": "configured", "row": row})
    return 0


async def _clear(args: argparse.Namespace) -> int:
    database = await Database.create(_dsn(), min_size=1, max_size=2)
    try:
        existed = await clear_requirement(
            database,
            organisation_id=UUID(args.org),
            agent_id=UUID(args.agent) if args.agent else None,
            action_class=args.action_class,
            changed_by=args.by,
            approval_reference=args.approval,
            reason=args.reason,
        )
    finally:
        await database.close()
    _emit({"result": "cleared", "row_existed": existed})
    return 0


async def _switch(args: argparse.Namespace, *, engaged: bool) -> int:
    if not args.global_scope and not args.org:
        raise SystemExit("pass --org <uuid> or --global")
    if args.global_scope and args.org:
        raise SystemExit("--org and --global are mutually exclusive")

    database = await Database.create(_dsn(), min_size=1, max_size=2)
    try:
        row = await set_control(
            database,
            control=args.control,
            organisation_id=None if args.global_scope else UUID(args.org),
            engaged=engaged,
            changed_by=args.by,
            approval_reference=args.approval,
            reason=args.reason,
        )
    finally:
        await database.close()

    _emit(
        {
            "result": "engaged" if engaged else "released",
            "row": row,
            "effect": _CONTROL_EFFECT[args.control][engaged],
        }
    )
    return 0


#: Spelled out in the command's own output so an operator sees the
#: consequence of what they just did without going to the docs.
_CONTROL_EFFECT: dict[str, dict[bool, str]] = {
    CONTROL_REQUIREMENT_ENFORCEMENT: {
        True: (
            "delegated authority is NO LONGER required in this scope; this "
            "WEAKENS enforcement and every suppressed requirement is logged"
        ),
        False: "configured requirements apply again in this scope",
    },
    CONTROL_AUTHORITY_ISSUANCE: {
        True: (
            "no NEW execution authority will be issued in this scope; "
            "consumption of already-issued authority is unaffected"
        ),
        False: "new execution authority may be issued again in this scope",
    },
}


def _add_evidence_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--by", required=True, help="Who is making this change")
    parser.add_argument("--approval", required=True, help="Change or incident reference")
    parser.add_argument("--reason", required=True, help="Why, in one line")


async def _trust(_args: argparse.Namespace) -> int:
    """Show configured issuer trust and every live revocation."""
    registry = load_registry_from_environment()
    database = await Database.create(_dsn(), min_size=1, max_size=2)
    try:
        revocations = await list_revocations(database)
    finally:
        await database.close()
    _emit(
        {
            "configured_issuers": registry.fingerprints(),
            "revocations": revocations,
            "key_discovery": (
                "none; issuer keys come from configuration only, so no network "
                "outage can change the answer"
            ),
        }
    )
    return 0


async def _revoke(args: argparse.Namespace, *, revoked: bool) -> int:
    database = await Database.create(_dsn(), min_size=1, max_size=2)
    try:
        row = await set_revocation(
            database,
            subject_type=RevocationSubject(args.subject),
            subject_id=args.id,
            issuer=args.issuer,
            revoked=revoked,
            changed_by=args.by,
            approval_reference=args.approval,
            reason=args.reason,
        )
    finally:
        await database.close()
    _emit(
        {
            "result": "revoked" if revoked else "reinstated",
            "row": row,
            "effect": (
                "no NEW delegated authority resting on this subject will resolve; "
                "grants already issued keep their own lifecycle"
                if revoked
                else "this subject is trusted again where configuration allows it"
            ),
        }
    )
    return 0


async def _bind(args: argparse.Namespace) -> int:
    database = await Database.create(_dsn(), min_size=1, max_size=2)
    try:
        row = await set_principal_binding(
            database,
            organisation_id=UUID(args.org),
            agent_id=UUID(args.agent),
            issuer=args.issuer,
            binding_key=args.key,
            binding_value=args.value,
            changed_by=args.by,
            approval_reference=args.approval,
            reason=args.reason,
        )
    finally:
        await database.close()
    _emit({"result": "bound", "row": row})
    return 0


async def _unbind(args: argparse.Namespace) -> int:
    database = await Database.create(_dsn(), min_size=1, max_size=2)
    try:
        existed = await clear_principal_binding(
            database,
            organisation_id=UUID(args.org),
            agent_id=UUID(args.agent),
            issuer=args.issuer,
            binding_key=args.key,
            changed_by=args.by,
            approval_reference=args.approval,
            reason=args.reason,
        )
    finally:
        await database.close()
    _emit({"result": "unbound", "row_existed": existed})
    return 0


async def _bindings(args: argparse.Namespace) -> int:
    database = await Database.create(_dsn(), min_size=1, max_size=2)
    try:
        rows = await list_principal_bindings(database, agent_id=UUID(args.agent))
    finally:
        await database.close()
    _emit({"agent_id": args.agent, "bindings": rows})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="authority_control", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    show = sub.add_parser("show", help="Show requirements and controls")
    show.add_argument("--org", help="Organisation UUID")
    show.set_defaults(handler=_show)

    require = sub.add_parser("require", help="Configure a requirement scope")
    require.add_argument("--org", required=True)
    require.add_argument("--agent", help="Narrow to one principal")
    require.add_argument("--action-class", help="Narrow to one action class")
    require.add_argument(
        "--exempt",
        action="store_true",
        help="Configure this scope as NOT required (overrides a broader row)",
    )
    _add_evidence_arguments(require)
    require.set_defaults(handler=_require)

    clear = sub.add_parser("clear", help="Remove a configured requirement scope")
    clear.add_argument("--org", required=True)
    clear.add_argument("--agent")
    clear.add_argument("--action-class")
    _add_evidence_arguments(clear)
    clear.set_defaults(handler=_clear)

    for name, engaged in (("kill", True), ("restore", False)):
        cmd = sub.add_parser(
            name,
            help=("Engage" if engaged else "Release") + " a kill switch",
        )
        cmd.add_argument("--control", required=True, choices=sorted(KNOWN_CONTROLS))
        cmd.add_argument("--org", help="Organisation UUID")
        cmd.add_argument(
            "--global",
            dest="global_scope",
            action="store_true",
            help="Apply platform-wide",
        )
        _add_evidence_arguments(cmd)
        cmd.set_defaults(handler=lambda args, _engaged=engaged: _switch(args, engaged=_engaged))

    trust = sub.add_parser("trust", help="Show issuer trust and live revocations")
    trust.set_defaults(handler=_trust)

    for name, revoked in (("revoke", True), ("reinstate", False)):
        cmd = sub.add_parser(
            name,
            help=("Revoke" if revoked else "Reinstate") + " an issuer, key or delegation",
        )
        cmd.add_argument(
            "--subject",
            required=True,
            choices=[subject.value for subject in RevocationSubject],
        )
        cmd.add_argument(
            "--id",
            required=True,
            help="Issuer id, key fingerprint, or the issuer's delegation reference",
        )
        cmd.add_argument(
            "--issuer",
            help="Required for everything except --subject issuer",
        )
        _add_evidence_arguments(cmd)
        cmd.set_defaults(handler=lambda args, _r=revoked: _revoke(args, revoked=_r))

    bind = sub.add_parser("bind", help="Record a principal's identity at an external issuer")
    bind.add_argument("--org", required=True)
    bind.add_argument("--agent", required=True)
    bind.add_argument("--issuer", required=True)
    bind.add_argument("--key", required=True, help="Binding key, e.g. issuer_account_reference")
    bind.add_argument("--value", required=True, help="The issuer's identifier for this principal")
    _add_evidence_arguments(bind)
    bind.set_defaults(handler=_bind)

    unbind = sub.add_parser("unbind", help="Remove one principal binding")
    unbind.add_argument("--org", required=True)
    unbind.add_argument("--agent", required=True)
    unbind.add_argument("--issuer", required=True)
    unbind.add_argument("--key", required=True)
    _add_evidence_arguments(unbind)
    unbind.set_defaults(handler=_unbind)

    bindings = sub.add_parser("bindings", help="List a principal's issuer identities")
    bindings.add_argument("--agent", required=True)
    bindings.set_defaults(handler=_bindings)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(args.handler(args))


if __name__ == "__main__":
    sys.exit(main())
