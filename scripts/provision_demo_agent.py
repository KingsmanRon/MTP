#!/usr/bin/env python3
"""Provision an agent for AI PR Guard end-to-end validation.

Generates an Ed25519 keypair, creates an agent under your org, activates it,
applies the Regulated AI PR Gate controls + a trust score, and registers the
governing policy from .inntris.yml. Prints the GitHub Secrets to set.

The private seed is generated locally and printed once; it is NEVER sent to the
server (only the public key is). Treat the output as sensitive.

Trust score drives the demo:
  * --trust 85  -> high-risk categories (ci_workflow_change, protected_branch_merge,
                   production_deployment) PASS for a vetted agent.
  * --trust 50  -> those categories BLOCK (below the 80 threshold).

Usage:
  export INNTRIS_API_URL=https://core.example.com
  export INNTRIS_ADMIN_API_KEY=...        # admin-scoped API key
  export INNTRIS_ORG_ID=<uuid>            # must match the API key's org
  python scripts/provision_demo_agent.py --name "demo repo guard" --trust 85
"""
from __future__ import annotations

import argparse
import base64
import os
import sys

import httpx
import yaml
from nacl.signing import SigningKey

# Mirrors the "Regulated AI PR Gate" preset (frontend/src/lib/agent-controls.ts).
REGULATED_ALLOWED = [
    "repo_change",
    "ci_workflow_change",
    "protected_branch_merge",
    "production_deployment",
    "tool_call",
    "api_call",
]
ALL_CONTROLLED = REGULATED_ALLOWED + [
    "financial_transaction",
    "data_export",
    "email_send",
    "admin_action",
]
BLOCKED = [a for a in ALL_CONTROLLED if a not in REGULATED_ALLOWED]


def _die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def _check(resp: httpx.Response, what: str) -> dict:
    if resp.status_code // 100 != 2:
        _die(f"{what} failed (HTTP {resp.status_code}): {resp.text}")
    try:
        return resp.json()
    except ValueError:
        return {}


def main() -> None:
    p = argparse.ArgumentParser(description="Provision an AI PR Guard demo agent.")
    p.add_argument("--api-url", default=os.environ.get("INNTRIS_API_URL"))
    p.add_argument("--admin-api-key", default=os.environ.get("INNTRIS_ADMIN_API_KEY"))
    p.add_argument("--org-id", default=os.environ.get("INNTRIS_ORG_ID"))
    p.add_argument("--name", default="ai-pr-guard demo agent")
    p.add_argument("--trust", type=int, default=85)
    p.add_argument("--policy-file", default=".inntris.yml")
    p.add_argument("--daily-limit", default="0")
    p.add_argument("--per-action-limit", default="0")
    args = p.parse_args()

    for flag, val in [
        ("--api-url", args.api_url),
        ("--admin-api-key", args.admin_api_key),
        ("--org-id", args.org_id),
    ]:
        if not val:
            _die(
                f"missing {flag} "
                "(set INNTRIS_API_URL / INNTRIS_ADMIN_API_KEY / INNTRIS_ORG_ID)"
            )
    if not 0 <= args.trust <= 100:
        _die("--trust must be 0..100")

    try:
        with open(args.policy_file, encoding="utf-8") as fh:
            policy = yaml.safe_load(fh) or {}
    except OSError as exc:
        _die(f"cannot read policy file {args.policy_file}: {exc}")
    mapping = policy.get("mapping") or {}
    protected_branches = policy.get("protected_branches") or []
    if not mapping:
        _die(f"{args.policy_file} has no 'mapping:' block")

    api = args.api_url.rstrip("/")
    headers = {"X-API-Key": args.admin_api_key, "Content-Type": "application/json"}

    # 1) Keypair. SigningKey bytes() is the 32-byte seed; verify_key bytes() the
    #    32-byte public key. The seed is exactly what private-key-b64 expects.
    sk = SigningKey.generate()
    seed_b64 = base64.b64encode(bytes(sk)).decode()
    public_b64 = base64.b64encode(bytes(sk.verify_key)).decode()

    with httpx.Client(timeout=30) as client:
        # 2) Create the agent (starts pending_verification).
        created = _check(
            client.post(
                f"{api}/admin/agents",
                headers=headers,
                json={
                    "org_id": args.org_id,
                    "name": args.name,
                    "public_key": public_b64,
                    "daily_limit_usd": args.daily_limit,
                    "per_action_limit_usd": args.per_action_limit,
                    "allowed_actions": REGULATED_ALLOWED,
                    "metadata": {"provisioned_by": "provision_demo_agent"},
                },
            ),
            "create agent",
        )
        agent_id = created["agent_id"]
        fingerprint = created.get("public_key_fingerprint", "")

        # 3) Activate.
        _check(
            client.patch(
                f"{api}/admin/agents/{agent_id}/status",
                headers=headers,
                params={"new_status": "active"},
            ),
            "activate agent",
        )

        # 4) Trust + explicit allow/block so the gate reflects trust, not
        #    ACTION_NOT_ALLOWED.
        _check(
            client.patch(
                f"{api}/admin/agents/{agent_id}",
                headers=headers,
                json={
                    "trust_score": args.trust,
                    "allowed_actions": REGULATED_ALLOWED,
                    "blocked_actions": BLOCKED,
                },
            ),
            "configure agent",
        )

        # 5) Register the governing policy (server derives the canonical hash).
        reg = _check(
            client.put(
                f"{api}/admin/agents/{agent_id}/policy",
                headers=headers,
                json={"mapping": mapping, "protected_branches": protected_branches},
            ),
            "register policy",
        )

    verdict_hint = (
        "PASS for high-risk categories"
        if args.trust >= 80
        else "BLOCK for high-risk categories (trust < 80)"
    )
    print("\n=== AI PR Guard agent provisioned ===")
    print(f"agent_id           : {agent_id}")
    print(f"key fingerprint    : {fingerprint}")
    print(f"trust_score        : {args.trust}  ({verdict_hint})")
    print(f"policy version     : {reg.get('version')}")
    print(f"policy_hash        : {reg.get('policy_hash')}")
    print("\n--- GitHub repo Secrets to set ---")
    print(f"INNTRIS_API_URL          = {api}")
    print(f"INNTRIS_PRIVATE_KEY_B64  = {seed_b64}")
    print("\n--- Workflow agent-id ---")
    print(f"agent-id: {agent_id}")
    print(
        "\nNext: commit .inntris.yml + the AI PR Guard workflow (admin tab "
        "generates both), set the two secrets above, and open a PR. To flip the "
        "demo, PATCH trust_score (>=80 PASS / <80 BLOCK)."
    )
    print("Keep INNTRIS_PRIVATE_KEY_B64 secret; it is shown only here.")


if __name__ == "__main__":
    main()
