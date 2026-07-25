"""Inntris agent-side client — the single source of truth for "be an agent and
call ``POST /verify``".

Historically every demo/ops script and the MCP server re-derived the signing
protocol (payload hash -> action hash -> Ed25519 signature) by hand, which drifts
from the server and silently breaks signatures. This module centralizes it:

* :func:`build_signed_verify_request` computes the action hash with
  ``api.crypto.CryptoService`` — the *exact* function the server re-runs to
  verify — so the signature is correct by construction. Nothing is
  re-implemented here.
* :class:`InntrisAgentClient` is a thin synchronous (``requests``-based) wrapper
  for scripts. The MCP server uses :func:`build_signed_verify_request` directly
  with its own async HTTP client.

Import is lightweight (nacl + stdlib via ``api.crypto``); it pulls in no FastAPI
or database code, so the MCP server and standalone scripts can use it freely.
"""
from __future__ import annotations

import base64
import secrets
from datetime import UTC, datetime
from typing import Any

from nacl.encoding import RawEncoder
from nacl.signing import SigningKey

from api.crypto import CryptoService

DEFAULT_SIG_VERSION = CryptoService.SIG_VERSION_DEFAULT

# A signing key, given either as a pynacl SigningKey or a raw 32-byte seed.
SigningKeyLike = SigningKey | bytes


def _as_signing_key(signing_key: SigningKeyLike) -> SigningKey:
    if isinstance(signing_key, SigningKey):
        return signing_key
    if isinstance(signing_key, (bytes, bytearray)):
        return SigningKey(bytes(signing_key), encoder=RawEncoder)
    raise TypeError(
        f"signing_key must be a nacl SigningKey or 32-byte seed, got {type(signing_key)!r}"
    )


def signing_key_from_seed_b64(private_key_b64: str) -> SigningKey:
    """Reconstruct an agent's SigningKey from a base64-encoded 32-byte seed."""
    seed = base64.b64decode(private_key_b64)
    if len(seed) != 32:
        raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
    return SigningKey(seed, encoder=RawEncoder)


def build_signed_verify_request(
    *,
    agent_id: str,
    signing_key: SigningKeyLike,
    action_type: str,
    payload: dict[str, Any],
    nonce: str | None = None,
    timestamp: datetime | str | None = None,
    policy_hash: str | None = None,
    sig_version: int = DEFAULT_SIG_VERSION,
) -> dict[str, Any]:
    """Build a ready-to-POST ``/verify`` request body, signed with the agent key.

    The action hash is produced by ``CryptoService.compute_action_hash`` and the
    wire ``timestamp`` is its canonical UTC (``Z``) form, so the server recomputes
    an identical hash and the Ed25519 signature validates. Callers never touch
    canonicalization.
    """
    sk = _as_signing_key(signing_key)
    nonce = nonce or secrets.token_urlsafe(32)
    ts_source = timestamp if timestamp is not None else datetime.now(UTC)
    canonical_ts = CryptoService.canonicalize_timestamp(ts_source)

    action_hash = CryptoService.compute_action_hash(
        agent_id=str(agent_id),
        action_type=action_type,
        payload=payload,
        nonce=nonce,
        timestamp=canonical_ts,
        registered_policy_hash=policy_hash,
        sig_version=sig_version,
    )
    signature = sk.sign(bytes.fromhex(action_hash)).signature

    body: dict[str, Any] = {
        "agent_id": str(agent_id),
        "action_type": action_type,
        "payload": payload,
        "nonce": nonce,
        "timestamp": canonical_ts,
        "signature": base64.b64encode(signature).decode(),
        "sig_version": sig_version,
    }
    if policy_hash is not None:
        body["policy_hash"] = policy_hash
    return body


class InntrisAgentClient:
    """Synchronous agent client for scripts/CLIs: sign + ``POST /verify``.

    ``requests`` is imported lazily so merely importing this module (e.g. from
    the async MCP server) does not require it.
    """

    def __init__(
        self,
        api_url: str,
        agent_id: str,
        signing_key: SigningKeyLike,
        *,
        sig_version: int = DEFAULT_SIG_VERSION,
        timeout: int = 30,
    ):
        import requests  # lazy

        self._requests = requests
        self.api_url = api_url.rstrip("/")
        self.agent_id = str(agent_id)
        self.signing_key = _as_signing_key(signing_key)
        self.sig_version = sig_version
        self.timeout = timeout

    @classmethod
    def from_seed_b64(
        cls, api_url: str, agent_id: str, private_key_b64: str, **kwargs: Any
    ) -> InntrisAgentClient:
        return cls(api_url, agent_id, signing_key_from_seed_b64(private_key_b64), **kwargs)

    def verify(
        self,
        action_type: str,
        payload: dict[str, Any],
        *,
        policy_hash: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Sign and submit an action. Returns ``(http_status, json_body)``.

        Does not raise on a BLOCKED/RATE_LIMITED verdict — the caller inspects
        the status (200 approved, 403 blocked, 429 rate-limited, 401 bad
        signature, 404 unknown agent).
        """
        body = build_signed_verify_request(
            agent_id=self.agent_id,
            signing_key=self.signing_key,
            action_type=action_type,
            payload=payload,
            policy_hash=policy_hash,
            sig_version=self.sig_version,
        )
        resp = self._requests.post(
            f"{self.api_url}/verify",
            headers={"Content-Type": "application/json"},
            json=body,
            timeout=self.timeout,
        )
        try:
            return resp.status_code, resp.json()
        except ValueError:
            return resp.status_code, {"detail": resp.text}
