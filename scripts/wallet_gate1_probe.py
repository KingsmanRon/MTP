#!/usr/bin/env python3
"""Gate 1: prove the WalletConnect recipient allowlist is enforced in production.

Repository configuration is not proof that a control is live. This submits a
``wallet_transaction`` for a recipient that is deliberately NOT on the agent's
allowlist and asserts the deployed Core blocks it with
``wallet_recipient_not_allowed``. Run it after every Core deploy that touches
the wallet rail, before any demo capture.

Signing goes through the shared product client (``api.agent_client``), the same
path the adapter and the MCP tool use, so this exercises the real protocol
rather than a hand-rolled copy.

The probe is read-only: it submits one action that is expected to be denied and
changes no configuration.

Exit codes:
    0  Enforcement is live         -- 403 wallet_recipient_not_allowed. Proceed.
    1  Probe could not run         -- bad arguments, network, auth.
    2  Deploy did not land         -- the wallet action type is unknown to Core.
    3  FAIL-OPEN                   -- the action was APPROVED. Stop everything.
    4  Unknown state               -- some other denial. Diagnose before proceeding.

Usage:
    export INNTRIS_CORE_URL=https://api.inntris.com
    export INNTRIS_AGENT_ID=<uuid>
    export INNTRIS_PRIVATE_KEY_B64=<base64 32-byte Ed25519 seed>
    python scripts/wallet_gate1_probe.py --chain eip155:8453 \
        --recipient 0x9999999999999999999999999999999999999999
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Allow `import api...` when run as `python scripts/wallet_gate1_probe.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.agent_client import InntrisAgentClient

EXIT_ENFORCED = 0
EXIT_PROBE_FAILED = 1
EXIT_DEPLOY_MISSING = 2
EXIT_FAIL_OPEN = 3
EXIT_UNKNOWN = 4

# The verdict that proves enforcement. Anything else is a stop condition.
EXPECTED_VIOLATION = "wallet_recipient_not_allowed"

# A denial that means the deployed build predates the wallet rail, rather than
# meaning the allowlist works. Distinguished because the remedies are opposite:
# one says proceed, the other says redeploy.
DEPLOY_MISSING_VIOLATIONS = {"action_not_allowed", "action_type_unknown"}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Assert a non-allowlisted wallet recipient is blocked in production."
    )
    parser.add_argument(
        "--recipient",
        required=True,
        help="An address deliberately NOT on the agent's allowlist.",
    )
    parser.add_argument(
        "--chain",
        default="eip155:8453",
        help="CAIP-2 chain id the recipient allowlist is keyed by (default: eip155:8453).",
    )
    parser.add_argument(
        "--core-url",
        default=os.environ.get("INNTRIS_CORE_URL"),
        help="Deployed Core base URL (env: INNTRIS_CORE_URL).",
    )
    parser.add_argument(
        "--agent-id",
        default=os.environ.get("INNTRIS_AGENT_ID"),
        help="Demo agent uuid (env: INNTRIS_AGENT_ID).",
    )
    args = parser.parse_args()

    seed_b64 = os.environ.get("INNTRIS_PRIVATE_KEY_B64")
    missing = [
        name
        for name, value in (
            ("--core-url / INNTRIS_CORE_URL", args.core_url),
            ("--agent-id / INNTRIS_AGENT_ID", args.agent_id),
            ("INNTRIS_PRIVATE_KEY_B64", seed_b64),
        )
        if not value
    ]
    if missing:
        print("Gate 1 could not run. Missing: " + ", ".join(missing), file=sys.stderr)
        return EXIT_PROBE_FAILED

    client = InntrisAgentClient.from_seed_b64(
        args.core_url, args.agent_id, seed_b64
    )

    payload = {
        "chain": args.chain,
        "recipient": args.recipient,
        "operation": "sign-transaction",
        "rail": "walletconnect_cwp",
    }

    print(f"Gate 1 probe -> {args.core_url}/verify")
    print(f"  agent     : {args.agent_id}")
    print(f"  chain     : {args.chain}")
    print(f"  recipient : {args.recipient}  (expected NOT allowlisted)")
    print()

    try:
        status, body = client.verify("wallet_transaction", payload)
    except Exception as exc:  # noqa: BLE001 - the probe reports, it does not handle
        print(f"Gate 1 could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_PROBE_FAILED

    print(f"HTTP {status}")
    print(json.dumps(body, indent=2, sort_keys=True))
    print()

    violation = body.get("violation_code")

    if status == 200 or str(body.get("verdict", "")).lower() == "approved":
        print(
            "GATE 1 FAILED -- FAIL-OPEN. A recipient that is not on the allowlist "
            "was APPROVED.\n"
            "The wallet policy check is absent from the deployed build or the agent "
            "has no wallet_policy configured.\n"
            "Stop. Do not capture a demo against this deployment.",
            file=sys.stderr,
        )
        return EXIT_FAIL_OPEN

    if violation == EXPECTED_VIOLATION:
        print("GATE 1 PASSED. Recipient enforcement is live on the deployed build.")
        return EXIT_ENFORCED

    if violation in DEPLOY_MISSING_VIOLATIONS:
        print(
            f"GATE 1 FAILED -- the deploy did not land (violation_code: {violation}).\n"
            "The deployed Core does not recognise wallet_transaction.\n"
            "\n"
            "Do NOT resolve this by adding the action type to the agent's "
            "allowed_actions. Doing so produces a demo that approves every "
            "recipient while appearing to work -- precisely the failure this "
            "product exists to prevent. Redeploy Core and re-run.",
            file=sys.stderr,
        )
        return EXIT_DEPLOY_MISSING

    print(
        f"GATE 1 INCONCLUSIVE -- blocked, but for another reason "
        f"(violation_code: {violation}).\n"
        "The recipient allowlist was not what denied this action, so this run "
        "does not prove enforcement. Diagnose before proceeding: check the "
        "agent's trust score, status, promotion state, allowed_actions, and that "
        "the probe chain matches the configured allowlist key.",
        file=sys.stderr,
    )
    return EXIT_UNKNOWN


if __name__ == "__main__":
    sys.exit(main())
