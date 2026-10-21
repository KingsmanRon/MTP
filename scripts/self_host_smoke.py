"""Exercise a local disposable deployment through its real HTTP API.

Creates synthetic organisations/agents and audit records. Never prints keys.
Run from the repository root: python -m scripts.self_host_smoke --api ...
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from nacl.signing import SigningKey, VerifyKey

from api.agent_client import build_signed_verify_request


def check_local_deployment(api_url: str, master_key: str) -> dict:
    parsed = urlsplit(api_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        raise ValueError("This smoke test only creates data in a local disposable deployment")
    if parsed.username or parsed.password or len(master_key) < 32:
        raise ValueError(
            "Use a credential-free URL and a local MASTER_ADMIN_KEY of at least 32 characters"
        )
    run_id = uuid4().hex[:10]
    with httpx.Client(base_url=api_url, timeout=30, trust_env=False) as client:
        health = client.get("/health")
        health.raise_for_status()
        assert health.json()["status"] == "healthy"
        assert health.json()["redis"] == "connected"
        tenants = []
        for number in (1, 2):
            org = client.post(
                "/admin/organizations",
                headers={"X-Master-Key": master_key},
                json={
                    "name": f"Local smoke {run_id}-{number}",
                    "contact_email": f"smoke-{run_id}-{number}@example.com",
                },
            )
            org.raise_for_status()
            auth = {"X-API-Key": org.json()["api_key"]}
            key = SigningKey.generate()
            agent = client.post(
                "/admin/agents",
                headers=auth,
                json={
                    "org_id": org.json()["organization_id"],
                    "name": f"Synthetic {number}",
                    "public_key": base64.b64encode(bytes(key.verify_key)).decode(),
                    "allowed_actions": ["tool_call"],
                },
            )
            agent.raise_for_status()
            tenants.append((auth, agent.json()["agent_id"]))
        for auth, agent_id in tenants:
            listing = client.get("/admin/agents", headers=auth)
            listing.raise_for_status()
            assert {row["id"] for row in listing.json()} == {agent_id}

        key = SigningKey.generate()
        registered = client.post(
            "/public/agents/register",
            json={
                "email": f"public-{run_id}@example.com",
                "public_key": base64.b64encode(bytes(key.verify_key)).decode(),
            },
        )
        registered.raise_for_status()
        agent_id = registered.json()["agent_id"]
        receipts = {}
        for action, expected_status, expected_verdict in (
            ("tool_call", 200, "approved"),
            ("financial_transaction", 403, "blocked"),
        ):
            body = build_signed_verify_request(
                agent_id=agent_id,
                signing_key=key,
                action_type=action,
                payload={"amount": "1.00", "currency": "USD", "purpose": "synthetic smoke"},
            )
            response = client.post("/verify", json=body)
            assert response.status_code == expected_status, f"Unexpected {action} status"
            decision = response.json()
            assert decision["verdict"] == expected_verdict
            if expected_verdict == "blocked":
                assert decision["violation_code"] == "action_not_allowed"
                assert not decision.get("approval_token")
            audit_id = decision["audit_id"]
            public = client.get(f"/public/verify/{audit_id}")
            public.raise_for_status()
            receipt = public.json()
            assert receipt["verdict"] == expected_verdict and receipt["sandbox"] is True
            fields = (
                "action_hash",
                "action_type",
                "agent_id",
                "audit_id",
                "policy_hash",
                "timestamp",
                "verdict",
            )
            canonical = json.dumps(
                {field: receipt[field] for field in fields}, sort_keys=True, separators=(",", ":")
            )
            assert hashlib.sha256(canonical.encode()).hexdigest() == receipt["receipt_fingerprint"]
            VerifyKey(bytes(key.verify_key)).verify(
                bytes.fromhex(receipt["action_hash"]),
                base64.b64decode(receipt["signature_b64"]),
            )
            proof = client.get(f"/public/verify/{audit_id}/proof")
            proof.raise_for_status()
            assert proof.json()["status"] == "sandbox"
            receipts[expected_verdict] = audit_id
    return {
        "run_id": run_id,
        "tenant_isolation": "passed",
        "receipts": receipts,
        "scope": "local sandbox; action signatures and receipt fingerprints, no payout or anchor",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check_local_deployment(args.api, os.getenv("MASTER_ADMIN_KEY", ""))
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
