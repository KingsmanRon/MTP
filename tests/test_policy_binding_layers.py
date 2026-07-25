"""B2.6 — an action is cryptographically bound to a policy version at both layers.

The claim Block B2 exists to make good on is:

    this action was allowed under *this* registered policy version

Proving it needs binding at two independent layers, because they fail
differently:

* the **agent signature**, so the party that requested the action committed to
  the policy it claimed to run under — an attacker who controls the server
  cannot retroactively re-label the request;
* the **anchored Merkle leaf**, so the commitment is timestamped on a chain
  nobody involved controls — an attacker who controls the agent key cannot
  re-issue history.

Both layers reduce to one value here: the action hash. Envelope v3 puts
``registered_policy_hash`` in the hash the agent signs, and
``workers/anchor_worker.py`` builds the Merkle tree from ``action_hash``
directly, so the leaf is that same hash. That is why substituting a policy
version breaks both at once — and why the AnchorRegistry contract needed no
change.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from nacl.signing import SigningKey

from api.crypto import CryptoService
from workers.anchor_worker import compute_merkle_proof, compute_merkle_root

AGENT_ID = "4f0e4fd5-5e2f-4e95-a2d5-78b0a7b0d66a"
ACTION_TYPE = "production_deployment"
PAYLOAD = {"changed_files": [".github/workflows/deploy.yml"], "base_ref": "main"}
NONCE = "nonce-b2-6"
TIMESTAMP = datetime(2026, 7, 25, 12, 0, 0, tzinfo=UTC)

POLICY_V1 = "1" * 64
POLICY_V2 = "2" * 64


def _action_hash(policy_hash: str | None) -> str:
    return CryptoService.compute_action_hash(
        agent_id=AGENT_ID,
        action_type=ACTION_TYPE,
        payload=PAYLOAD,
        nonce=NONCE,
        timestamp=TIMESTAMP,
        registered_policy_hash=policy_hash,
    )


@pytest.fixture(scope="module")
def agent_key() -> SigningKey:
    return SigningKey(b"\x42" * 32)


class TestAgentSignatureLayer:
    def test_signature_over_one_policy_does_not_verify_under_another(
        self, agent_key: SigningKey
    ) -> None:
        """Substituting the policy version invalidates the agent signature."""
        signed_hash = _action_hash(POLICY_V1)
        signature = base64.b64encode(
            agent_key.sign(bytes.fromhex(signed_hash)).signature
        ).decode()
        public_key = agent_key.verify_key.encode()

        assert CryptoService.verify_ed25519_signature(
            public_key=public_key, message_hash=signed_hash, signature_b64=signature
        )

        # Same action, same key, same everything except the policy version.
        substituted = _action_hash(POLICY_V2)
        assert substituted != signed_hash
        assert not CryptoService.verify_ed25519_signature(
            public_key=public_key, message_hash=substituted, signature_b64=signature
        )

    def test_dropping_the_policy_also_breaks_the_signature(
        self, agent_key: SigningKey
    ) -> None:
        """Claiming no policy where one was bound must not verify either.

        Otherwise the cheapest attack on policy binding is simply to omit it.
        """
        signed_hash = _action_hash(POLICY_V1)
        signature = base64.b64encode(
            agent_key.sign(bytes.fromhex(signed_hash)).signature
        ).decode()
        unbound = _action_hash(None)

        assert unbound != signed_hash
        assert not CryptoService.verify_ed25519_signature(
            public_key=agent_key.verify_key.encode(),
            message_hash=unbound,
            signature_b64=signature,
        )


class TestAnchoredLeafLayer:
    """The anchored leaf is the action hash — off-chain change, no redeploy."""

    def test_leaf_and_root_move_with_the_policy_version(self) -> None:
        siblings = ["a" * 64, "b" * 64, "c" * 64]

        leaves_v1 = [_action_hash(POLICY_V1), *siblings]
        leaves_v2 = [_action_hash(POLICY_V2), *siblings]

        assert leaves_v1[0] != leaves_v2[0], "leaf must commit to the policy"
        assert compute_merkle_root(leaves_v1) != compute_merkle_root(leaves_v2)

    def test_proof_for_one_policy_does_not_reconstruct_the_other_root(self) -> None:
        """A proof cannot be replayed against a differently-policied batch."""
        siblings = ["a" * 64, "b" * 64, "c" * 64]
        leaves_v1 = [_action_hash(POLICY_V1), *siblings]
        leaves_v2 = [_action_hash(POLICY_V2), *siblings]

        root_v1 = compute_merkle_root(leaves_v1)
        path_v1 = compute_merkle_proof(leaves_v1, 0)

        # Rebuild from the v2 leaf using the v1 proof path: the sibling hashes
        # are identical, so only the leaf differs — and that is enough.
        rebuilt = _rebuild_root(leaves_v2[0], path_v1)
        assert rebuilt != root_v1

        # Sanity: the v1 leaf with the v1 path does reconstruct.
        assert _rebuild_root(leaves_v1[0], path_v1) == root_v1


def _rebuild_root(leaf_hex: str, path: list[dict]) -> str:
    """Mirror of AnchorRegistry.verifyProof: keccak256(left || right)."""
    from workers.anchor_worker import keccak256

    current = bytes.fromhex(leaf_hex)
    for node in path:
        sibling = bytes.fromhex(node["hash"])
        # position == 1 means the sibling sits on the right.
        current = (
            keccak256(current + sibling)
            if node["position"] == 1
            else keccak256(sibling + current)
        )
    return current.hex()


class TestBothLayersFailTogether:
    def test_substituting_a_policy_version_fails_signature_and_leaf(
        self, agent_key: SigningKey
    ) -> None:
        """The B2.6 acceptance criterion, stated as one assertion.

        Substituting a different policy version must fail verification at both
        layers — not one or the other.
        """
        signed_hash = _action_hash(POLICY_V1)
        signature = base64.b64encode(
            agent_key.sign(bytes.fromhex(signed_hash)).signature
        ).decode()
        siblings = ["a" * 64, "b" * 64, "c" * 64]
        anchored_root = compute_merkle_root([signed_hash, *siblings])

        substituted = _action_hash(POLICY_V2)

        signature_holds = CryptoService.verify_ed25519_signature(
            public_key=agent_key.verify_key.encode(),
            message_hash=substituted,
            signature_b64=signature,
        )
        leaf_holds = compute_merkle_root([substituted, *siblings]) == anchored_root

        assert not signature_holds, "agent signature layer did not reject the swap"
        assert not leaf_holds, "anchored leaf layer did not reject the swap"


class TestSolidityParityVectors:
    """The constants hard-coded in the Solidity parity suite still hold.

    ``test/contracts/PolicyBoundLeafParity.t.sol`` asserts Python's roots and
    proofs on-chain, but Solidity only runs under ``forge`` — which is not
    installed everywhere and, in some environments, cannot be. Without this
    test a preimage change would silently invalidate those constants and only
    surface in the contracts CI job, framed as a Solidity failure rather than
    as the Python change that actually caused it.
    """

    # Keep in lockstep with test/contracts/PolicyBoundLeafParity.t.sol.
    # Regenerate both with scripts/generate_leaf_parity_vectors.py.
    EXPECTED_ROOT = "373fe712c363e2661fd8197c80c54dcabdadf17925212fcf0261555be376d3a6"
    EXPECTED_LEAF_0 = "2cb722cd85514fade08eaffa4c78fbd1419ce723e9226bfbfec79dd963caf484"
    EXPECTED_OTHER_POLICY_LEAF = (
        "4b4ee0bd537754c16de5fc7e980aace849fb5d080bc353f7e19176842945f188"
    )

    def test_vectors_match_the_solidity_constants(self) -> None:
        from scripts.generate_leaf_parity_vectors import action_hash

        leaves = [action_hash(i, "1" * 64) for i in range(3)]
        assert leaves[0] == self.EXPECTED_LEAF_0
        assert compute_merkle_root(leaves) == self.EXPECTED_ROOT
        assert action_hash(0, "2" * 64) == self.EXPECTED_OTHER_POLICY_LEAF
