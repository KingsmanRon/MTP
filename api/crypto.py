"""
Cryptographic operations for the MTP Core API.

Uses Ed25519 signatures via pynacl for agent authentication.
SECURITY: This module is critical for the integrity of the entire system.
"""

import base64
import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from nacl.encoding import RawEncoder

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

        Args:
            payload: The payload dictionary to hash.

        Returns:
            Lowercase hexadecimal SHA-256 hash.
        """
        # Canonicalize: sort keys, no whitespace, ensure consistent encoding
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def compute_action_hash(
        agent_id: str,
        action_type: str,
        payload: dict[str, Any],
        nonce: str,
        timestamp: datetime,
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
            timestamp: Client-side timestamp.

        Returns:
            Lowercase hexadecimal SHA-256 hash.
        """
        # Create signing payload
        signing_data = {
            "agent_id": str(agent_id),
            "action_type": action_type,
            "payload_hash": CryptoService.compute_payload_hash(payload),
            "nonce": nonce,
            "timestamp": timestamp.isoformat(),
        }
        return CryptoService.compute_payload_hash(signing_data)

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
            signature = base64.b64decode(signature_b64)
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

        Returns:
            Base64-encoded approval token.
        """
        expiry = datetime.now(timezone.utc).timestamp() + (expiry_minutes * 60)

        token_data = {
            "agent_id": agent_id,
            "action_hash": action_hash,
            "verdict": verdict,
            "exp": int(expiry),
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
        server_secret: bytes,
    ) -> Optional[dict[str, Any]]:
        """
        Verify and decode an approval token.

        Args:
            token_b64: Base64-encoded approval token.
            server_secret: Server's secret key for HMAC verification.

        Returns:
            Decoded token data if valid, None if invalid or expired.
        """
        try:
            combined = base64.b64decode(token_b64)
            parts = combined.rsplit(b".", 1)

            if len(parts) != 2:
                return None

            token_bytes, signature_b64 = parts
            signature = base64.b64decode(signature_b64)

            # Verify HMAC
            expected_mac = hmac.new(server_secret, token_bytes, hashlib.sha256)
            if not hmac.compare_digest(expected_mac.digest(), signature):
                return None

            # Decode and check expiry
            token_data = json.loads(token_bytes.decode("utf-8"))
            if token_data.get("exp", 0) < datetime.now(timezone.utc).timestamp():
                return None

            return token_data

        except Exception:
            return None

    @staticmethod
    def compute_merkle_root(leaf_hashes: list[str]) -> str:
        """
        Compute Merkle root from a list of leaf hashes.

        Uses SHA-256 for internal nodes. If the number of leaves is odd,
        the last leaf is duplicated.

        Args:
            leaf_hashes: List of hex-encoded SHA-256 hashes.

        Returns:
            Hex-encoded Merkle root hash.
        """
        if not leaf_hashes:
            raise ValueError("Cannot compute Merkle root of empty list")

        # Convert hex strings to bytes
        nodes = [bytes.fromhex(h) for h in leaf_hashes]

        while len(nodes) > 1:
            # If odd number of nodes, duplicate the last one
            if len(nodes) % 2 == 1:
                nodes.append(nodes[-1])

            # Combine pairs
            next_level = []
            for i in range(0, len(nodes), 2):
                combined = nodes[i] + nodes[i + 1]
                next_level.append(hashlib.sha256(combined).digest())

            nodes = next_level

        return nodes[0].hex()

    @staticmethod
    def compute_merkle_proof(
        leaf_hashes: list[str],
        leaf_index: int,
    ) -> list[dict[str, Any]]:
        """
        Compute Merkle proof for a specific leaf.

        Args:
            leaf_hashes: List of all leaf hashes.
            leaf_index: Index of the leaf to prove.

        Returns:
            List of proof elements with hash and position.
        """
        if not leaf_hashes:
            raise ValueError("Cannot compute proof for empty list")

        if leaf_index < 0 or leaf_index >= len(leaf_hashes):
            raise ValueError(f"Invalid leaf index: {leaf_index}")

        nodes = [bytes.fromhex(h) for h in leaf_hashes]
        proof = []
        index = leaf_index

        while len(nodes) > 1:
            if len(nodes) % 2 == 1:
                nodes.append(nodes[-1])

            # Add sibling to proof
            sibling_index = index + 1 if index % 2 == 0 else index - 1
            proof.append({
                "hash": nodes[sibling_index].hex(),
                "position": "right" if index % 2 == 0 else "left",
            })

            # Move up the tree
            next_level = []
            for i in range(0, len(nodes), 2):
                combined = nodes[i] + nodes[i + 1]
                next_level.append(hashlib.sha256(combined).digest())

            nodes = next_level
            index = index // 2

        return proof

    @staticmethod
    def verify_merkle_proof(
        leaf_hash: str,
        proof: list[dict[str, Any]],
        root_hash: str,
    ) -> bool:
        """
        Verify a Merkle proof.

        Args:
            leaf_hash: Hash of the leaf being verified.
            proof: List of proof elements.
            root_hash: Expected Merkle root.

        Returns:
            True if proof is valid.
        """
        current = bytes.fromhex(leaf_hash)

        for element in proof:
            sibling = bytes.fromhex(element["hash"])
            if element["position"] == "right":
                combined = current + sibling
            else:
                combined = sibling + current
            current = hashlib.sha256(combined).digest()

        return current.hex() == root_hash

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
