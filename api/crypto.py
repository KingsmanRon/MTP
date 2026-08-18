"""
Cryptographic operations for the Inntris Core API.

Uses Ed25519 signatures via pynacl for agent authentication.
SECURITY: This module is critical for the integrity of the entire system.
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from nacl.encoding import RawEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from api import jcs

logger = logging.getLogger(__name__)


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class SignatureVerificationError(CryptoError):
    """Raised when signature verification fails."""
    pass


class InvalidPublicKeyError(CryptoError):
    """Raised when a public key is invalid."""
    pass


class CryptoService:
    """
    Cryptographic service for signature verification and hashing.

    SECURITY NOTES:
    - All operations use constant-time comparison where applicable
    - Signatures use Ed25519 (deterministic, no random padding)
    - Hash functions use SHA-256 (collision resistant)
    """

    @staticmethod
    def compute_payload_hash(payload: dict[str, Any]) -> str:
        """
        Compute SHA-256 hash of a JSON payload.

        The payload is canonicalized (sorted keys, no whitespace) before hashing
        to ensure deterministic results.

        CROSS-LANGUAGE COMPATIBILITY WARNING:
        - This uses Python's json.dumps() which may have subtle differences from
          other languages (e.g., floating-point precision, Unicode normalization)
        - For SDK developers in other languages (Node.js, Go, Rust):
          * Use the SAME separators: ",:" (no spaces)
          * Use the SAME key sorting: lexicographic/alphabetic
          * Use UTF-8 encoding
          * Match Python's float precision (17 significant digits)
          * Use the reference Python implementation for edge cases

        RECOMMENDED FOR PRODUCTION: Consider upgrading to RFC 8785 (JCS - JSON
        Canonicalization Scheme) for strict deterministic serialization.

        Args:
            payload: The payload dictionary to hash.

        Returns:
            Lowercase hexadecimal SHA-256 hash.
        """
        # Canonicalize: sort keys, no whitespace, ensure consistent encoding
        # ensure_ascii=False is critical for Unicode consistency
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,  # Preserve Unicode characters
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def canonicalize_timestamp(timestamp: "datetime | str") -> str:
        """
        Normalize a client-supplied timestamp into the canonical UTC wire form
        used when computing the action-hash that the agent signs.

        Output: ``YYYY-MM-DDTHH:MM:SS[.ffffff]Z`` — ISO-8601 in UTC with a
        ``Z`` suffix (matching pydantic v2's default datetime serialization
        and ``canonical_wire_timestamp`` in ``api/main.py``).

        Accepts either a ``datetime`` or a string:
        * strings are parsed with ``datetime.fromisoformat`` (with ``Z`` first
          normalised to ``+00:00``); invalid strings raise ``CryptoError``.
        * naive datetimes are assumed to be UTC — a warning is logged but the
          call succeeds so older SDKs that sent ``datetime.utcnow()`` do not
          silently produce hash mismatches. New SDKs MUST send tz-aware UTC.
        * tz-aware datetimes in any zone are converted to UTC.

        The previous implementation just called ``timestamp.isoformat()``
        with no tz handling, so a naive vs ``+00:00`` vs ``+02:00``
        datetime representing the same instant produced three different
        hashes — and therefore three different signatures over the same
        logical action. See Phase 0.3 of the enterprise-readiness plan.
        """
        if isinstance(timestamp, str):
            try:
                ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError as exc:
                raise CryptoError(
                    f"Invalid ISO-8601 timestamp string: {timestamp!r}"
                ) from exc
        elif isinstance(timestamp, datetime):
            ts = timestamp
        else:
            raise CryptoError(
                f"Unsupported timestamp type for action-hash: {type(timestamp)!r}"
            )

        if ts.tzinfo is None:
            logger.warning(
                "Naive datetime passed to action-hash canonicalization; "
                "assuming UTC. Upstream callers must send tz-aware UTC."
            )
            ts = ts.replace(tzinfo=UTC)
        else:
            ts = ts.astimezone(UTC)

        # isoformat() on a UTC datetime yields "+00:00"; swap to "Z" so the
        # canonical form matches the wire timestamp used for receipts.
        iso = ts.isoformat()
        if iso.endswith("+00:00"):
            iso = iso[:-6] + "Z"
        return iso

    # Current (default) signing-envelope version. Kept here so callers that
    # want to pin an explicit version without importing models.py don't have
    # to hard-code an integer at every site.
    #
    # Phase 1B.1 introduces SIG_VERSION_JCS (3) which swaps the payload
    # hash from Python's sort_keys serializer to strict RFC 8785 JCS so
    # non-Python SDKs can produce byte-identical canonical forms. The
    # default remains SIG_VERSION_CURRENT (2) because deployed agents
    # still sign with it; servers accept all three.
    SIG_VERSION_LEGACY = 1
    SIG_VERSION_CURRENT = 2
    SIG_VERSION_JCS = 3
    SIG_VERSION_DEFAULT = SIG_VERSION_CURRENT

    @staticmethod
    def compute_action_hash(
        agent_id: str,
        action_type: str,
        payload: dict[str, Any],
        nonce: str,
        timestamp: "datetime | str",
        sig_version: int = SIG_VERSION_DEFAULT,
    ) -> str:
        """
        Compute the hash that should be signed by the agent.

        This creates a deterministic hash of all action parameters that
        the agent must sign to prove authenticity.

        Args:
            agent_id: The agent's UUID.
            action_type: Type of action being performed.
            payload: Action-specific payload.
            nonce: Unique nonce for replay protection.
            timestamp: Client-side timestamp (datetime or ISO-8601 string).
                       Any timezone is accepted — it is converted to UTC and
                       emitted as ``YYYY-MM-DDTHH:MM:SS[.ffffff]Z`` before
                       hashing, so two callers representing the same instant
                       always produce identical hashes.
            sig_version: Signing-envelope version negotiated with the client.
                         ``1`` = pre-Phase-0.3 form: the raw input timestamp
                         (stringified via ``.isoformat()`` for datetimes) is
                         embedded verbatim. ``2`` = current form: timestamp is
                         routed through ``canonicalize_timestamp`` first.

        Returns:
            Lowercase hexadecimal SHA-256 hash.
        """
        if sig_version == CryptoService.SIG_VERSION_LEGACY:
            # Preserved for signatures produced by SDKs that predate
            # Phase 0.3. The server still needs to be able to verify those
            # signatures until all deployed agents are upgraded. Do not use
            # this path for new hashing — it is ambiguous across timezones.
            ts_repr = (
                timestamp
                if isinstance(timestamp, str)
                else timestamp.isoformat()
            )
            payload_hash = CryptoService.compute_payload_hash(payload)
            outer_hash = CryptoService.compute_payload_hash
        elif sig_version == CryptoService.SIG_VERSION_CURRENT:
            ts_repr = CryptoService.canonicalize_timestamp(timestamp)
            payload_hash = CryptoService.compute_payload_hash(payload)
            outer_hash = CryptoService.compute_payload_hash
        elif sig_version == CryptoService.SIG_VERSION_JCS:
            # RFC 8785 JCS for both the inner payload hash and the outer
            # signing envelope. Non-Python SDKs can only match this path
            # byte-for-byte. See tests/fixtures/canonicalization/jcs_vectors.json
            # for the cross-language contract.
            try:
                payload_hash = jcs.sha256_hex(payload)
                ts_repr = CryptoService.canonicalize_timestamp(timestamp)
                outer_hash = jcs.sha256_hex
            except jcs.JCSError as exc:
                raise CryptoError(f"JCS canonicalization failed: {exc}") from exc
        else:
            raise CryptoError(
                f"Unsupported sig_version: {sig_version!r}. "
                f"Expected {CryptoService.SIG_VERSION_LEGACY}, "
                f"{CryptoService.SIG_VERSION_CURRENT}, or "
                f"{CryptoService.SIG_VERSION_JCS}."
            )

        signing_data = {
            "agent_id": str(agent_id),
            "action_type": action_type,
            "payload_hash": payload_hash,
            "nonce": nonce,
            "timestamp": ts_repr,
        }
        return outer_hash(signing_data)

    @staticmethod
    def verify_ed25519_signature(
        public_key: bytes,
        message_hash: str,
        signature_b64: str,
    ) -> bool:
        """
        Verify an Ed25519 signature.

        SECURITY: This operation uses constant-time comparison internally
        via libsodium.

        Args:
            public_key: 32-byte Ed25519 public key.
            message_hash: The SHA-256 hash that was signed (hex string).
            signature_b64: Base64-encoded 64-byte Ed25519 signature.

        Returns:
            True if signature is valid, False otherwise.

        Raises:
            InvalidPublicKeyError: If the public key is malformed.
            SignatureVerificationError: If signature verification fails.
        """
        if len(public_key) != 32:
            raise InvalidPublicKeyError(
                f"Public key must be 32 bytes, got {len(public_key)}"
            )

        try:
            # Decode signature
            signature = base64.b64decode(signature_b64, validate=True)
            if len(signature) != 64:
                logger.warning(
                    f"Invalid signature length: expected 64 bytes, got {len(signature)}"
                )
                return False

            # Create verify key from public key bytes
            verify_key = VerifyKey(public_key, encoder=RawEncoder)

            # Convert hex hash to bytes for verification
            message_bytes = bytes.fromhex(message_hash)

            # Verify signature (raises BadSignatureError if invalid)
            verify_key.verify(message_bytes, signature)

            return True

        except BadSignatureError:
            logger.warning("Ed25519 signature verification failed: invalid signature")
            return False
        except binascii.Error as e:
            logger.warning(f"Ed25519 signature verification failed: malformed base64: {e}")
            return False
        except ValueError as e:
            logger.warning(f"Ed25519 signature verification failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during signature verification: {e}")
            raise SignatureVerificationError(f"Signature verification error: {e}")

    @staticmethod
    def generate_approval_token(
        agent_id: str,
        action_hash: str,
        verdict: str,
        server_secret: bytes,
        expiry_minutes: int = 5,
        *,
        sandbox: bool = False,
        token_id: str | None = None,
        expires_at: datetime | int | float | None = None,
    ) -> str:
        """
        Generate a signed approval token.

        This token proves that the server approved an action and can be
        verified without database lookup.

        Args:
            agent_id: The agent's UUID.
            action_hash: Hash of the approved action.
            verdict: The verification verdict.
            server_secret: Server's secret key for HMAC.
            expiry_minutes: Token validity period.
            sandbox: Whether the approval originated from a sandbox decision.
                The signed claim is propagated to the consumption receipt so a
                later agent promotion cannot turn test activity into a mainnet
                eligible record.

        Returns:
            Base64-encoded approval token.
        """
        if expires_at is None:
            expiry = datetime.now(UTC).timestamp() + (expiry_minutes * 60)
        elif isinstance(expires_at, datetime):
            expiry = expires_at.timestamp()
        else:
            expiry = float(expires_at)

        token_data = {
            "token_id": token_id or secrets.token_urlsafe(24),
            "agent_id": agent_id,
            "action_hash": action_hash,
            "verdict": verdict,
            "exp": int(expiry),
            "sandbox": bool(sandbox),
        }

        token_json = json.dumps(token_data, sort_keys=True, separators=(",", ":"))
        token_bytes = token_json.encode("utf-8")

        # Create HMAC signature
        mac = hmac.new(server_secret, token_bytes, hashlib.sha256)
        signature = mac.digest()

        # Combine token and signature
        combined = token_bytes + b"." + base64.b64encode(signature)
        return base64.b64encode(combined).decode("utf-8")

    @staticmethod
    def verify_approval_token(
        token_b64: str,
        server_secret: "bytes | Iterable[bytes]",
    ) -> dict[str, Any] | None:
        """
        Verify and decode an approval token.

        Args:
            token_b64: Base64-encoded approval token.
            server_secret: The server HMAC secret, OR an ordered iterable of
                secrets. The token is accepted if its HMAC matches ANY of them,
                which enables zero-downtime SERVER_SECRET rotation: serve
                [new, old] during the rollover window so tokens signed with the
                old secret keep verifying until they expire.

        Returns:
            Decoded token data if valid, None if invalid or expired.
        """
        secrets_list: list[bytes] = (
            [server_secret]
            if isinstance(server_secret, (bytes, bytearray))
            else list(server_secret)
        )
        try:
            combined = base64.b64decode(token_b64)
            parts = combined.rsplit(b".", 1)

            if len(parts) != 2:
                return None

            token_bytes, signature_b64 = parts  # gitleaks:allow parsed values, not a credential
            signature = base64.b64decode(signature_b64)

            # Verify HMAC against each candidate secret (constant-time compare).
            matched = False
            for sec in secrets_list:
                expected_mac = hmac.new(bytes(sec), token_bytes, hashlib.sha256)
                if hmac.compare_digest(expected_mac.digest(), signature):
                    matched = True
                    break
            if not matched:
                return None

            # Decode and check expiry
            token_data = json.loads(token_bytes.decode("utf-8"))
            if token_data.get("exp", 0) < datetime.now(UTC).timestamp():
                return None

            return token_data

        except Exception:
            return None

    # NOTE: Merkle tree operations are handled by workers/anchor_worker.py
    # which uses keccak256 to match the on-chain AnchorRegistry contract.
    # Do NOT add SHA-256 Merkle functions here as they would fail on-chain verification.

    @staticmethod
    def generate_api_key() -> tuple[str, bytes]:
        """
        Generate a new API key.

        Returns:
            Tuple of (plaintext_key, key_hash).
        """
        key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(key.encode("utf-8")).digest()
        return key, key_hash

    @staticmethod
    def hash_api_key(key: str) -> bytes:
        """Hash an API key for storage."""
        return hashlib.sha256(key.encode("utf-8")).digest()

    @staticmethod
    def compute_public_key_fingerprint(public_key: bytes) -> str:
        """Compute SHA-256 fingerprint of a public key."""
        return hashlib.sha256(public_key).hexdigest()

    @staticmethod
    def sign_webhook_payload(payload: dict[str, Any], secret: str) -> str:
        """
        Sign a webhook payload with HMAC-SHA256.

        This signature should be sent in the X-Inntris-Signature header.

        Args:
            payload: JSON-serializable payload to sign.
            secret: Webhook secret key from organization.

        Returns:
            Hex-encoded HMAC signature.
        """
        import json

        payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        signature = hmac.new(
            secret.encode("utf-8"),
            payload_str.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return signature

    @staticmethod
    def verify_webhook_signature(
        payload: dict[str, Any],
        signature: str,
        secret: str,
    ) -> bool:
        """
        Verify a webhook signature.

        Args:
            payload: The webhook payload.
            signature: The signature from X-Inntris-Signature header.
            secret: The webhook secret key.

        Returns:
            True if signature is valid, False otherwise.
        """
        import json

        payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected_signature = hmac.new(
            secret.encode("utf-8"),
            payload_str.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return secrets.compare_digest(signature, expected_signature)
